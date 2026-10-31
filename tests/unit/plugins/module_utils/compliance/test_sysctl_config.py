"""The model of systemd-sysctl and procps against what the real readers write (FREES-107).

``tests/fixtures/sysctl_reader/verdicts.json`` was recorded by ``make sysctl-reader-verdicts``:
systemd 255 and procps-ng 4.0.4 in the Ubuntu 24.04 Molecule image and procps-ng 3.3.17 in the Rocky
Linux 9 image wrote each case into a private tmpfs over ``/proc/sys``, and the values were read back
from it. Every key of every case is compared with every reader. A case that the model cannot
decide for a reader (a file name that procps expands as a pattern, a procps key with a ``..``
component, a line at which systemd-sysctl stops reading) must be reported as unsupported instead.
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
PROCPS_UNSUPPORTED = frozenset(
    {
        "review_filename_glob",
        "review_filename_brace",
        "filename_question_mark",
        "filename_tilde",
        "filename_star_in_usr_lib",
        "review2_filename_backslash",
        "review2_dotdot_above_proc_sys",
        "review2_dotdot_through_missing_directory",
        "dot_dot_component",
    }
)
SYSTEMD_UNSUPPORTED = frozenset({"review2_line_over_1_mib"})
UFW = "/etc/ufw/sysctl.conf"


def case_text(file: dict[str, object]) -> str | None:
    """Return the text that the generator writes for a fixture file."""
    if "long_line" in file:
        comment = "#" + "x" * (int(str(file["long_line"])) - 1)
        return str(file["text"]).replace("@LONG_LINE@", comment)
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


@pytest.mark.parametrize("name", sorted(set(CASES) - SYSTEMD_UNSUPPORTED))
def test_systemd_writes_what_the_model_decides(name: str) -> None:
    assert model_values(name, sysctl_config.SYSTEMD) == VERDICTS[name]["systemd"]


@pytest.mark.parametrize("name", sorted(set(CASES) - PROCPS_UNSUPPORTED))
@pytest.mark.parametrize("reader", ["procps-4", "procps-3"])
def test_procps_writes_what_the_model_decides(name: str, reader: str) -> None:
    assert model_values(name, sysctl_config.PROCPS) == VERDICTS[name][reader]


@pytest.mark.parametrize("name", sorted(CASES))
def test_only_a_case_that_the_model_cannot_decide_is_unsupported(name: str) -> None:
    found = cast("list[str]", sysctl_config.effective(case_entries(name), RP_FILTER)["unsupported"])
    assert bool(found) is (name in PROCPS_UNSUPPORTED | SYSTEMD_UNSUPPORTED)


def test_a_line_just_below_the_limit_of_systemd_is_read() -> None:
    line = "#" + "x" * (sysctl_config.SYSTEMD_LINE_LIMIT - 2)
    entries: list[dict[str, object]] = [
        {"path": "/etc/sysctl.d/10-a.conf", "kind": "file", "text": f"{line}\n{RP_FILTER} = 1\n"}
    ]
    assert sysctl_config.effective(entries, RP_FILTER)["unsupported"] == []


def test_the_readers_disagree_on_etc_sysctl_conf() -> None:
    found = sysctl_config.effective(case_entries("sysctl_conf_and_its_link"), RP_FILTER)
    assert found["systemd"] == {
        "value": "1",
        "source": "/etc/sysctl.d/999-freesecdev-sysctl-net-ipv4-conf-all-rp-filter.conf",
    }
    assert found["procps"] == {"value": "0", "source": "/etc/sysctl.conf"}


def ufw_entries(enabled: str, default: str | None) -> list[dict[str, object]]:
    """Return the case ``later_name_wins`` with ufw's files, its ufw.conf and /etc/default/ufw."""
    entries: list[dict[str, object]] = [
        *case_entries("later_name_wins"),
        {"path": UFW, "kind": "file", "text": "net/ipv4/conf/all/rp_filter=2\n"},
        {"path": sysctl_config.UFW_CONF, "kind": "file", "text": f"# ufw\n{enabled}\n"},
    ]
    if default is not None:
        entries.append({"path": sysctl_config.UFW_DEFAULT, "kind": "file", "text": default})
    return entries


def readers(found: dict[str, object]) -> dict[str, object]:
    """Return what both readers set."""
    return {reader: found[reader] for reader in sysctl_config.READERS}


@pytest.mark.parametrize(
    ("enabled", "default"),
    [
        ("ENABLED=yes", "IPV6=yes\nIPT_SYSCTL=/etc/ufw/sysctl.conf\n"),
        ("export ENABLED='yes'", 'IPT_SYSCTL="/etc/ufw/sysctl.conf"\n'),
    ],
)
def test_ufw_s_file_wins_for_both_readers_when_ufw_is_enabled(enabled: str, default: str) -> None:
    found = sysctl_config.effective(ufw_entries(enabled, default), RP_FILTER)
    assert readers(found) == {
        "systemd": {"value": "2", "source": UFW},
        "procps": {"value": "2", "source": UFW},
    }
    assert found["unsupported"] == []


@pytest.mark.parametrize(
    ("enabled", "default"),
    [
        ("ENABLED=no", "IPT_SYSCTL=/etc/ufw/sysctl.conf\n"),
        ("ENABLED=yes", "IPT_SYSCTL=\n"),
        ("ENABLED=yes", "IPV6=yes\n"),
        ("ENABLED=yes", None),
    ],
)
def test_ufw_s_file_is_ignored_unless_ufw_applies_it(enabled: str, default: str | None) -> None:
    found = sysctl_config.effective(ufw_entries(enabled, default), RP_FILTER)
    assert readers(found) == {
        "systemd": {"value": "1", "source": "/usr/lib/sysctl.d/60-b.conf"},
        "procps": {"value": "1", "source": "/usr/lib/sysctl.d/60-b.conf"},
    }
    assert found["unsupported"] == []


def test_a_key_with_a_dot_dot_component_in_ufw_s_file_is_unsupported() -> None:
    entries = ufw_entries("ENABLED=yes", "IPT_SYSCTL=/etc/ufw/sysctl.conf\n")
    entries[-3] = {"path": UFW, "kind": "file", "text": "/../sys/net/ipv4/conf/all/rp_filter=0\n"}
    assert sysctl_config.effective(entries, RP_FILTER)["unsupported"] == [
        f"{UFW}: a key with a .. component, which sysctl -p resolves"
    ]


def test_ufw_s_file_is_ignored_without_ufw_conf() -> None:
    entries = [entry for entry in ufw_entries("", None) if entry["path"] != sysctl_config.UFW_CONF]
    assert sysctl_config.effective(entries, RP_FILTER)["systemd"] == {
        "value": "1",
        "source": "/usr/lib/sysctl.d/60-b.conf",
    }


@pytest.mark.parametrize(
    ("enabled", "default", "reason"),
    [
        ("ENABLED=$(echo yes)", None, "ENABLED is set in a form"),
        ("ENABLED=yes", "IPT_SYSCTL=${X}\n", "cannot follow"),
        ("ENABLED=yes", "IPT_SYSCTL=/etc/other.conf\n", "cannot follow"),
    ],
)
def test_a_ufw_setting_that_the_model_does_not_follow_is_unsupported(
    enabled: str, default: str | None, reason: str
) -> None:
    found = cast(
        "list[str]",
        sysctl_config.effective(ufw_entries(enabled, default), RP_FILTER)["unsupported"],
    )
    assert len(found) == 1
    assert reason in found[0]


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
