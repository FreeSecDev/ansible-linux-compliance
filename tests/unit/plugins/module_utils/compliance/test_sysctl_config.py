"""The model of systemd-sysctl and procps against what the real readers write (FREES-107).

``tests/fixtures/sysctl_reader/verdicts.json`` was recorded by ``make sysctl-reader-verdicts``:
systemd 255 and procps-ng 4.0.4 in the Ubuntu 24.04 Molecule image and procps-ng 3.3.17 in the Rocky
Linux 9 image wrote each case into a private tmpfs over ``/proc/sys``, and the values were read back
from it. Every key of every case is compared with every reader. A case whose file names procps
expands as patterns must be reported as unsupported instead.
"""

from __future__ import annotations

import json
import posixpath
import re
from pathlib import Path
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sysctl_config,
)

FIXTURES = Path(__file__).resolve().parents[4] / "fixtures" / "sysctl_reader"
CASES = cast(
    "dict[str, dict[str, object]]",
    json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8")),
)
VERDICTS = cast(
    "dict[str, dict[str, dict[str, str | None]]]",
    json.loads((FIXTURES / "verdicts.json").read_text(encoding="utf-8")),
)
RP_FILTER = "net.ipv4.conf.all.rp_filter"
EXPANDED_NAMES = frozenset(
    {
        "review_filename_glob",
        "review_filename_brace",
        "filename_question_mark",
        "filename_tilde",
        "filename_star_in_usr_lib",
    }
)


def case_text(file: dict[str, object]) -> str | None:
    """Return the text that the generator writes for a fixture file."""
    if "text" in file:
        return str(file["text"])
    if "long_key" in file:
        return f"{file['long_key']} = {' ' * int(str(file['padding']))}{file['long_value']}\n"
    return None


def case_entries(name: str) -> list[dict[str, object]]:
    """Return the entries of a case as the role hands them to the model."""
    files = cast("list[dict[str, object]]", CASES[name]["files"])
    texts = {"/" + str(file["path"]): case_text(file) for file in files}
    entries: list[dict[str, object]] = []
    for file in files:
        path = "/" + str(file["path"])
        if file.get("directory"):
            entries.append({"path": path, "kind": "directory", "text": None})
        elif "link" in file:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), str(file["link"])))
            entries.append({"path": path, "kind": "link", "text": texts.get(target)})
        else:
            entries.append({"path": path, "kind": "file", "text": texts[path]})
    return entries


def case_keys(name: str) -> list[str]:
    """Return the keys of a case."""
    return [str(key) for key in cast("list[object]", CASES[name]["keys"])]


def model_values(name: str, reader: str) -> dict[str, str | None]:
    """Return what the model decides that ``reader`` writes for every key of a case."""
    entries = case_entries(name)
    return {
        key: cast("dict[str, str | None]", sysctl_config.effective(entries, key)[reader])["value"]
        for key in case_keys(name)
    }


def test_every_case_has_a_verdict_of_every_reader() -> None:
    assert sorted(VERDICTS) == sorted(CASES)
    for name, verdict in VERDICTS.items():
        assert sorted(verdict) == ["procps-3", "procps-4", "systemd"]
        for reader in verdict.values():
            assert sorted(reader) == sorted(case_keys(name))


def test_procps_3_and_4_write_the_same_values_for_every_case() -> None:
    assert {name: verdict["procps-3"] for name, verdict in VERDICTS.items()} == {
        name: verdict["procps-4"] for name, verdict in VERDICTS.items()
    }


@pytest.mark.parametrize("name", sorted(CASES))
def test_systemd_writes_what_the_model_decides(name: str) -> None:
    assert model_values(name, sysctl_config.SYSTEMD) == VERDICTS[name]["systemd"]


@pytest.mark.parametrize("name", sorted(set(CASES) - EXPANDED_NAMES))
@pytest.mark.parametrize("reader", ["procps-4", "procps-3"])
def test_procps_writes_what_the_model_decides(name: str, reader: str) -> None:
    assert model_values(name, sysctl_config.PROCPS) == VERDICTS[name][reader]


@pytest.mark.parametrize("name", sorted(CASES))
def test_only_a_name_that_procps_expands_is_unsupported(name: str) -> None:
    found = cast("list[str]", sysctl_config.effective(case_entries(name), RP_FILTER)["unsupported"])
    assert bool(found) is (name in EXPANDED_NAMES)


def test_the_readers_disagree_on_etc_sysctl_conf() -> None:
    found = sysctl_config.effective(case_entries("sysctl_conf_and_its_link"), RP_FILTER)
    assert found["systemd"] == {
        "value": "1",
        "source": "/etc/sysctl.d/999-freesecdev-sysctl-net-ipv4-conf-all-rp-filter.conf",
    }
    assert found["procps"] == {"value": "0", "source": "/etc/sysctl.conf"}


def test_a_file_read_after_boot_wins_for_both_readers() -> None:
    entries: list[dict[str, object]] = [
        *case_entries("later_name_wins"),
        {"path": "/etc/ufw/sysctl.conf", "kind": "file", "text": "net/ipv4/conf/all/rp_filter=2\n"},
    ]
    found = sysctl_config.effective(entries, RP_FILTER, after=["/etc/ufw/sysctl.conf"])
    assert {reader: found[reader] for reader in sysctl_config.READERS} == {
        "systemd": {"value": "2", "source": "/etc/ufw/sysctl.conf"},
        "procps": {"value": "2", "source": "/etc/ufw/sysctl.conf"},
    }
    assert sysctl_config.effective(entries, RP_FILTER)["systemd"] == {
        "value": "1",
        "source": "/usr/lib/sysctl.d/60-b.conf",
    }


def test_no_setting_gives_nulls() -> None:
    assert sysctl_config.effective([], RP_FILTER) == {
        "systemd": {"value": None, "source": None},
        "procps": {"value": None, "source": None},
        "unsupported": [],
    }


@pytest.mark.parametrize(
    "entry",
    [
        {"path": "etc/sysctl.d/x.conf", "kind": "file", "text": ""},
        {"path": "/etc/sysctl.d/x.conf", "kind": "socket", "text": ""},
        {"path": "/etc/sysctl.d/x.conf", "kind": "file", "text": 1},
        {"path": None, "kind": "file", "text": ""},
    ],
)
def test_a_malformed_entry_is_refused(entry: dict[str, object]) -> None:
    with pytest.raises(sysctl_config.ConfigError):
        sysctl_config.load_entries([entry])


@pytest.mark.parametrize(
    ("key", "reader", "path"),
    [
        ("net.ipv4.conf.all.rp_filter", "systemd", "net/ipv4/conf/all/rp_filter"),
        ("net/ipv4/conf/all/rp_filter", "procps", "net/ipv4/conf/all/rp_filter"),
        ("net/ipv4/conf/enp3s0.200/forwarding", "systemd", "net/ipv4/conf/enp3s0.200/forwarding"),
        ("net.ipv4.conf.enp3s0/200.forwarding", "procps", "net/ipv4/conf/enp3s0.200/forwarding"),
        ("/net//ipv4/./conf/all/rp_filter/", "systemd", "net/ipv4/conf/all/rp_filter"),
        ("net/ipv4/conf/all/rp_filter/", "procps", None),
        ("net/ipv4/conf/lo/../all/rp_filter", "systemd", None),
        ("/net/ipv4/conf/lo/../../../../../all/rp_filter", "procps", "all/rp_filter"),
        ("kernel", "systemd", "kernel"),
    ],
)
def test_each_reader_opens_its_own_path_for_a_key(key: str, reader: str, path: str | None) -> None:
    assert sysctl_config.normalise(key, reader) == path


@pytest.mark.parametrize(
    ("pattern", "path", "matches"),
    [
        ("net/ipv4/conf/*/rp_filter", "net/ipv4/conf/all/rp_filter", True),
        ("net/ipv4/conf/*/rp_filter", "net/ipv4/conf/a/b/rp_filter", False),
        ("net/ipv4/conf/al?/rp_filter", "net/ipv4/conf/all/rp_filter", True),
        ("net/ipv4/conf/a?l/rp_filter", "net/ipv4/conf/a/l/rp_filter", False),
        ("net/ipv4/conf/[ad]*/rp_filter", "net/ipv4/conf/default/rp_filter", True),
        ("net/ipv4/conf/[!a]*/rp_filter", "net/ipv4/conf/all/rp_filter", False),
        ("net/ipv4/conf/[^a]*/rp_filter", "net/ipv4/conf/default/rp_filter", True),
        ("net/ipv4/conf/[a-c]ll/rp_filter", "net/ipv4/conf/bll/rp_filter", True),
        ("net/ipv4/conf/[!x]/rp_filter", "net/ipv4/conf///rp_filter", False),
        ("net/ipv4/conf/[all/rp_filter", "net/ipv4/conf/[all/rp_filter", True),
        ("net/ipv4/conf/*/rp_filter", "net/ipv4/conf/all/rp_filter/x", False),
    ],
)
def test_a_glob_matches_as_glob_3_does(pattern: str, path: str, *, matches: bool) -> None:
    assert bool(re.fullmatch(sysctl_config.glob_pattern(pattern), path)) is matches
