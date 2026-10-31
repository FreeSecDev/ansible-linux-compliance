"""The records of the Molecule lifecycle harness (FREES-180).

- The filter renders, byte for byte, the lines that the Jinja templates of the harness rendered
  before it, for a recorded walk of a container and synthetic edge cases
  (``tests/fixtures/lifecycle_record``). ``record.yml`` there holds those templates unchanged and
  rendered ``expected.json`` with ansible-core; a test renders it again.
- A same-size change of content is caught in a declared file below ``/etc`` and below ``/usr``,
  through the checksum alone, and a change in place of a static file below ``/usr``, whose
  content is not read, through its ctime.
- A record kept from an earlier moment catches a change made after it.
"""

from __future__ import annotations

import hashlib
import json
import operator
import os
import posixpath
import subprocess
import sys
from pathlib import Path
from typing import SupportsIndex, cast, overload

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    lifecycle_record as record,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
FIXTURES = REPOSITORY_ROOT / "tests" / "fixtures" / "lifecycle_record"
COLLECTIONS = Path(record.__file__).parents[5]
TIMEOUT_SECONDS = 300
END = record.LINE_END
TIMES = r"^/var/lib/rpm/rpmdb\.sqlite-(shm|wal)$"
INSTANCE: dict[str, object] = {
    "declared": ["/etc/crontab", "/usr/lib/fsd-declared"],
    "rewritten": [],
    "ignored_paths": ["/var/lib/freesecdev/linux_compliance/state.json"],
    "ignored_trees": ["/var/lib/freesecdev/linux_compliance/evidence"],
    "volatile_sysctl": ["/proc/sys/fs/file-nr"],
    "volatile_sysctl_trees": ["/proc/sys/fs/quota"],
    "volatile_contents": "^$",
    "volatile_times": TIMES,
}
SNAPSHOT: dict[str, object] = {
    "paths": None,
    "volatile_directories": [],
    "volatile_contents": "^$",
    "volatile_times": TIMES,
}


def entry(path: str, **changes: object) -> dict[str, object]:
    """Return a ``find`` entry of a regular file, with ``changes`` applied."""
    values: dict[str, object] = {
        "path": path,
        "mode": "0644",
        "uid": 0,
        "gid": 0,
        "size": 10,
        "inode": 100,
        "mtime": 1.0,
        "ctime": 1.0,
        "checksum": "a",
        "isreg": True,
        "isdir": False,
        "islnk": False,
    }
    values.update(changes)
    return {key: value for key, value in values.items() if value is not None}


def sources(**changes: object) -> dict[str, object]:
    """Return the sources of a whole-instance record, with ``changes`` applied."""
    values: dict[str, object] = {
        "walk": [entry("/etc/crontab"), entry("/etc/hosts", inode=101)],
        "walk_excluded": "^$",
        "extra": [],
        "metadata": [
            entry("/usr/lib/fsd-static", inode=102, checksum=None),
            entry("/usr/lib/fsd-declared", inode=103, checksum=None),
        ],
        "checksums": {"/usr/lib/fsd-declared": "a"},
        "sysctl": [{"path": "/proc/sys/kernel/dmesg_restrict", "checksum": "a"}],
        "packages": {"cron": [{"name": "cron", "version": "1.0"}]},
        "users": {"root": ["x", "0"]},
        "groups": {"root": ["x", "0"]},
        "services": None,
    }
    values.update(changes)
    return values


def snapshot_only(given: dict[str, object]) -> dict[str, object]:
    return {key: given[key] for key in record.SOURCE_KEYS}


def instance(given: dict[str, object], **options: object) -> dict[str, object]:
    chosen = {"snapshot": SNAPSHOT, "instance": {**INSTANCE, **options}}
    return cast("dict[str, object]", record.lifecycle_record(given, chosen)["instance"])


def snapshot(given: dict[str, object], **options: object) -> dict[str, object]:
    chosen = {"snapshot": {**SNAPSHOT, **options}, "instance": None}
    return cast(
        "dict[str, object]", record.lifecycle_record(snapshot_only(given), chosen)["snapshot"]
    )


def lines(text: object) -> list[str]:
    return str(text).split(END)


def test_the_filter_is_registered() -> None:
    assert record.FilterModule().filters() == {"lifecycle_record": record.lifecycle_record}


def recorded() -> tuple[dict[str, object], dict[str, object]]:
    given = json.loads((FIXTURES / "input.json").read_text(encoding="utf-8"))
    expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    return cast("dict[str, object]", given), cast("dict[str, object]", expected)


@pytest.mark.parametrize("case_name", ["docker", "libvirt"])
def test_the_lines_are_byte_identical_to_the_jinja_templates(case_name: str) -> None:
    given, expected = recorded()
    raw = cast("dict[str, object]", given["raw"])
    [case] = [
        case
        for case in cast("list[dict[str, object]]", given["cases"])
        if case["name"] == case_name
    ]
    options = cast("dict[str, object]", case["instance"])
    walk: dict[str, object] = {
        "walk": raw["files"],
        "walk_excluded": "^$",
        "extra": [],
        "metadata": [],
        "checksums": raw["checksums"],
    }
    chosen = {
        "snapshot": {
            "paths": None,
            "volatile_directories": case["volatile_directories"],
            "volatile_contents": options["volatile_contents"],
            "volatile_times": options["volatile_times"],
        },
        "instance": options,
    }
    whole: dict[str, object] = {
        **walk,
        **{key: raw[key] for key in ("sysctl", "packages", "users", "groups")},
    }
    result = record.lifecycle_record({**whole, "services": case["services"]}, chosen)
    want = cast("dict[str, object]", expected[case_name])
    found = cast("dict[str, object]", result["snapshot"])
    assert found["lines"] == want["snapshot_lines"]
    assert found["count"] == want["snapshot_count"]
    assert found["digest"] == hashlib.sha256(str(want["snapshot_lines"]).encode()).hexdigest()
    whole_instance = cast("dict[str, object]", result["instance"])
    assert lines(whole_instance["lines"]) == want["instance_lines"]
    assert whole_instance["count"] == len(cast("list[str]", want["instance_lines"]))
    only_snapshot = record.lifecycle_record(walk, {**chosen, "instance": None})
    assert only_snapshot == {"snapshot": found}


@pytest.mark.parametrize("playbook", ["record.yml", "filter.yml"])
def test_ansible_core_renders_the_expected_lines(tmp_path: Path, playbook: str) -> None:
    """``record.yml`` renders the old templates, ``filter.yml`` the filter as the harness does."""
    output = tmp_path / "expected.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "-e",
            "ansible_python_interpreter=" + sys.executable,
            "-e",
            f"record_output_path={output}",
            str(FIXTURES / playbook),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "PYTHONPATH": os.pathsep.join(sys.path),
            "ANSIBLE_COLLECTIONS_PATH": str(COLLECTIONS),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(output.read_text(encoding="utf-8")) == recorded()[1]


class _LazyValue:
    """Stands for the wrapper in which a lazy container of ansible-core stores an item."""

    def __init__(self, value: object) -> None:
        self.value = value


class Tagged(str):
    """Stands for text that ansible-core tags, for example as trusted to be a template."""

    __slots__ = ()


class Lazy(list[object]):
    """A list that, like a lazy container, renders an item when it is read."""

    def __init__(self, stored: list[object], rendered: list[object]) -> None:
        super().__init__(stored)
        self.rendered = rendered
        self.reads: list[int] = []

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> object: ...

    @overload
    def __getitem__(self, index: slice, /) -> list[object]: ...

    def __getitem__(self, index: SupportsIndex | slice, /) -> object:
        assert not isinstance(index, slice)
        position = operator.index(index)
        self.reads.append(position)
        return self.rendered[position]


def test_items_stored_as_plain_entries_are_used_without_rendering() -> None:
    plain = entry("/etc/hosts")
    stored: list[object] = [_LazyValue(plain), plain]
    lazy = Lazy(stored, [{"rendered": 1}, {"rendered": 2}])
    assert record.stored_items(lazy, "the walk") == [plain, plain]
    assert lazy.reads == []


def test_items_that_rendering_could_change_are_rendered() -> None:
    tagged = entry("/etc/hosts", mode=Tagged("{{ mode }}"))
    nested = entry("/etc/hosts", mode=["0644"])
    stored: list[object] = [
        _LazyValue(tagged),
        _LazyValue(nested),
        _LazyValue("{{ lifecycle_broad_selfcheck_file }}"),
        Tagged("{{ entry }}"),
        _LazyValue({1: "a"}),
    ]
    rendered: list[object] = [{"index": index} for index in range(len(stored))]
    lazy = Lazy(stored, rendered)
    assert record.stored_items(lazy, "the walk") == rendered
    assert lazy.reads == [0, 1, 2, 3, 4]


def test_a_tuple_of_items_is_read_as_it_is() -> None:
    plain = entry("/etc/hosts")
    assert record.stored_items((plain,), "the walk") == [plain]


def test_a_same_size_change_of_a_declared_file_in_etc_is_caught_by_its_checksum() -> None:
    before = sources()
    after = sources(walk=[entry("/etc/crontab", checksum="b"), entry("/etc/hosts", inode=101)])
    assert instance(before)["digest"] != instance(after)["digest"]
    changed = set(lines(instance(after)["lines"])) - set(lines(instance(before)["lines"]))
    assert changed == {"file|/etc/crontab|file|0644|0|0|10|100|-|-|b"}


def test_a_same_size_change_of_an_undeclared_file_in_etc_is_caught_with_its_times_kept() -> None:
    before = sources()
    after = sources(walk=[entry("/etc/crontab"), entry("/etc/hosts", inode=101, checksum="b")])
    assert instance(before)["digest"] != instance(after)["digest"]
    assert snapshot(before)["digest"] != snapshot(after)["digest"]


def test_a_same_size_change_of_a_declared_file_in_usr_is_caught_by_its_checksum() -> None:
    before = sources()
    after = sources(checksums={"/usr/lib/fsd-declared": "b"})
    changed = set(lines(instance(after)["lines"])) - set(lines(instance(before)["lines"]))
    assert changed == {"file|/usr/lib/fsd-declared|file|0644|0|0|10|103|-|-|b"}


def test_a_change_in_place_of_a_static_file_in_usr_is_caught_by_its_ctime() -> None:
    before = sources()
    static = entry("/usr/lib/fsd-static", inode=102, checksum=None, ctime=2.0)
    declared = entry("/usr/lib/fsd-declared", inode=103, checksum=None)
    after = sources(metadata=[static, declared])
    changed = set(lines(instance(after)["lines"])) - set(lines(instance(before)["lines"]))
    assert changed == {"file|/usr/lib/fsd-static|file|0644|0|0|10|102|1.0|2.0|"}
    assert snapshot(before)["digest"] != snapshot(after)["digest"]


def test_a_kept_record_catches_a_change_made_after_it() -> None:
    kept = instance(sources())
    later = sources(walk=[entry("/etc/crontab"), entry("/etc/hosts", inode=101)])
    assert instance(later) == kept
    stray = sources(walk=[entry("/etc/crontab"), entry("/etc/hosts", inode=101), entry("/etc/x")])
    assert instance(stray)["digest"] != kept["digest"]


def test_the_snapshot_of_a_whole_instance_record_equals_a_walk_of_the_watched_paths() -> None:
    whole = sources(
        walk=[
            entry("/etc/crontab"),
            entry("/var/lib/dpkg", isreg=False, isdir=True, checksum=None),
            entry("/var/lib/dpkg/status"),
            entry("/var/lib/other"),
        ]
    )
    watched = sources(walk=[entry("/etc/crontab"), entry("/var/lib/dpkg/status")])
    derived = record.lifecycle_record(
        whole,
        {
            "snapshot": {**SNAPSHOT, "paths": ["/etc", "/usr", "/var/lib/dpkg"]},
            "instance": INSTANCE,
        },
    )["snapshot"]
    assert derived == snapshot(watched)


def test_the_walk_without_its_excluded_paths_then_the_extra_entries_are_recorded() -> None:
    given = sources(
        walk=[entry("/etc/shadow-dir/a"), entry("/etc/hosts")],
        walk_excluded="^(/etc/shadow-dir)(/|$)",
        extra=[entry("/etc/shadow-dir/a", checksum=None)],
        checksums={"/etc/shadow-dir/a": "s"},
    )
    assert lines(snapshot(given)["lines"])[:2] == [
        "/etc/hosts|0644|0|0|10|1.0|1.0|a ",
        "/etc/shadow-dir/a|0644|0|0|10|1.0|1.0|s ",
    ]


def test_the_snapshot_leaves_out_what_a_running_system_changes() -> None:
    given = sources(
        walk=[
            entry("/var/lib/freesecdev/evidence", isreg=False, isdir=True),
            entry("/var/log/syslog"),
            entry("/var/lib/rpm/rpmdb.sqlite-shm", mtime=5.0),
        ],
        metadata=[],
    )
    text = snapshot(
        given,
        volatile_directories=["/var/lib/freesecdev/evidence"],
        volatile_contents="^/var/log/syslog$",
    )["lines"]
    assert lines(text) == [
        "/var/lib/freesecdev/evidence|0644|0|0|volatile-directory ",
        "/var/lib/rpm/rpmdb.sqlite-shm|0644|0|0|10|volatile-times|a ",
        "/var/log/syslog|0644|0|0|volatile-contents ",
        "",
    ]


def test_the_instance_record_names_every_kind_and_service() -> None:
    given = sources(
        walk=[
            entry("/etc/link", islnk=True, isreg=False),
            entry("/etc/dir", isdir=True, isreg=False),
            entry("/etc/fifo", isreg=False),
            entry("/var/log/syslog", size=99),
        ],
        metadata=[],
        sysctl=[
            {"path": "/proc/sys/fs/file-nr", "checksum": "x"},
            {"path": "/proc/sys/fs/quota/syncs", "checksum": "x"},
            {"path": "/proc/sys/kernel/no-sum"},
        ],
        services={"cron.service": {"state": "running"}, "bare.service": {"status": "enabled"}},
    )
    found = lines(instance(given, volatile_contents="^/var/log/syslog$")["lines"])
    assert "file|/etc/link|link|0644|0|0|10|100|1.0|1.0|a" in found
    assert "file|/etc/dir|directory|0644|0|0|10|100|1.0|1.0|a" in found
    assert "file|/etc/fifo|other|0644|0|0|10|100|1.0|1.0|a" in found
    assert "file|/var/log/syslog|file|0644|0|0|-|-|-|-|-" in found
    assert "sysctl|/proc/sys/kernel/no-sum|" in found
    assert not any("file-nr" in line or "quota" in line for line in found)
    assert "service|bare.service||enabled" in found
    assert "service|cron.service|running|" in found


def test_the_rewritten_and_ignored_entries_are_left_out_as_listed() -> None:
    given = sources(
        walk=[
            entry("/etc/crontab", inode=999),
            entry("/var/lib/freesecdev/linux_compliance/state.json"),
            entry("/var/lib/freesecdev/linux_compliance/evidence/run/x.xml"),
        ],
        metadata=[],
    )
    found = lines(instance(given, rewritten=["/etc/crontab"])["lines"])
    assert [line for line in found if line.startswith("file|")] == [
        "file|/etc/crontab|file|0644|0|0|10|-|-|-|a"
    ]


@pytest.mark.parametrize(
    "path",
    ["", "/", "//", "///", "a", "/a", "/a/", "/a//b", "a/b", "/a/b/c", "//a", "/a/b//"],
)
def test_dirname_is_that_of_posixpath(path: str) -> None:
    assert record.dirname(path) == posixpath.dirname(path)


def test_the_digest_is_the_sha256_of_the_text() -> None:
    assert record.digest("a\udcff") == hashlib.sha256(b"a\xff").hexdigest()


@pytest.mark.parametrize(
    ("given", "options", "message"),
    [
        ([], {"snapshot": SNAPSHOT, "instance": None}, "the sources must be a mapping"),
        (sources(), [], "the options must be a mapping"),
        (sources(), {"snapshot": SNAPSHOT}, "the options must have exactly the keys"),
        (sources(), {"snapshot": SNAPSHOT, "instance": None}, "the sources must have exactly"),
        (
            snapshot_only(sources()),
            {"snapshot": {**SNAPSHOT, "paths": "/etc"}, "instance": None},
            "the snapshot paths must be a list",
        ),
        (
            snapshot_only(sources()),
            {"snapshot": {**SNAPSHOT, "volatile_directories": [1]}, "instance": None},
            "the volatile directories must be a list of strings",
        ),
        (
            snapshot_only(sources()),
            {"snapshot": {**SNAPSHOT, "volatile_times": None}, "instance": None},
            "volatile_times must be a regular expression",
        ),
        (
            snapshot_only(sources(walk=[entry("/etc/x", mode=None)])),
            {"snapshot": SNAPSHOT, "instance": None},
            "an entry lacks the key 'mode'",
        ),
        (
            snapshot_only(sources(walk=[entry("/etc/x", mode=["0644"])])),
            {"snapshot": SNAPSHOT, "instance": None},
            "expected a string or a number, got list",
        ),
        (
            snapshot_only(sources(walk=["/etc/x"])),
            {"snapshot": SNAPSHOT, "instance": None},
            "an entry must be a mapping",
        ),
        (
            snapshot_only(sources(checksums=[])),
            {"snapshot": SNAPSHOT, "instance": None},
            "the checksums must be a mapping",
        ),
        (
            sources(packages={"cron": {"version": "1.0"}}),
            {"snapshot": SNAPSHOT, "instance": INSTANCE},
            "the versions of a package must be a list",
        ),
        (
            sources(services={"cron.service": "running"}),
            {"snapshot": SNAPSHOT, "instance": INSTANCE},
            "a service must be a mapping",
        ),
    ],
)
def test_input_of_the_wrong_shape_is_refused(given: object, options: object, message: str) -> None:
    with pytest.raises(record.RecordError, match=message.replace("(", r"\(")):
        record.lifecycle_record(given, options)


def test_json_lines_serialise_nested_data_as_the_to_json_filter_does() -> None:
    given = sources(
        users={"fsd": ["x", "1001", None, True, 1.5, ("t",), {"k": "Jöhn"}]},
        packages={"multi": [{"version": "2", "epoch": None}, {"Version": "1"}]},
    )
    found = lines(instance(given)["lines"])
    assert 'user|fsd|["x", "1001", null, true, 1.5, ["t"], {"k": "J\\u00f6hn"}]' in found
    assert 'package|multi|[["epoch", null], ["version", "2"]],[["Version", "1"]]' in found


def listing(*entries: dict[str, object]) -> str:
    """Return ``entries`` as a ``tree_info`` listing."""
    kinds = {(True, False, False): "link", (False, True, False): "file"}
    fields: list[str] = []
    for item in entries:
        flags = (item["islnk"], item["isreg"], item["isdir"])
        kind = kinds.get(
            cast("tuple[bool, bool, bool]", flags), "directory" if item["isdir"] else "other"
        )
        fields.extend(
            str(value)
            for value in (
                item["path"],
                kind,
                item["mode"],
                item["uid"],
                item["gid"],
                item["size"],
                item["inode"],
                item["mtime"],
                item["ctime"],
            )
        )
    return "".join(field + record.LISTING_SEPARATOR for field in fields)


def test_a_listing_records_the_same_lines_as_find_entries() -> None:
    static = entry("/usr/lib/fsd-static", inode=102, checksum=None)
    declared = entry("/usr/lib/fsd-declared", inode=103, checksum=None)
    directory = entry("/usr/lib", inode=104, checksum=None, isreg=False, isdir=True)
    link = entry("/usr/lib/link", inode=105, checksum=None, isreg=False, islnk=True)
    other = entry("/usr/lib/fifo", inode=106, checksum=None, isreg=False)
    found = sources(metadata=[static, declared, directory, link, other])
    listed = sources(metadata=listing(static, declared, directory, link, other))
    assert instance(listed) == instance(found)
    assert snapshot(listed) == snapshot(found)
    assert snapshot(sources(metadata=""))["count"] == 2


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("/usr/lib/x\x00file\x00", "whole entries of 9 fields"),
        ("/usr/lib/x" + "\x00file" * 8, "whole entries of 9 fields"),
        ("/usr/lib/x\x00socket" + "\x000" * 7 + "\x00", "unknown type 'socket'"),
    ],
)
def test_an_incomplete_listing_is_refused(text: str, message: str) -> None:
    with pytest.raises(record.RecordError, match=message):
        snapshot(sources(metadata=text))
