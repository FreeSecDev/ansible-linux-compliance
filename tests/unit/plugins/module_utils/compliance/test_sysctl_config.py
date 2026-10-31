"""The model of systemd-sysctl and procps against what the real readers set (FREES-107).

``tests/fixtures/sysctl_reader/verdicts.json`` was recorded by ``make sysctl-reader-verdicts``:
systemd 255 and procps-ng 4.0.4 in the Ubuntu 24.04 Molecule image, procps-ng 3.3.17 in the Rocky
Linux 9 image, each on the cases of ``cases.json``. procps-ng 3.3 reports no value for a dry run on
a read-only ``/proc/sys``, so only the order of its settings is compared.
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
    "dict[str, dict[str, object]]",
    json.loads((FIXTURES / "verdicts.json").read_text(encoding="utf-8")),
)
RP_FILTER = "net.ipv4.conf.all.rp_filter"


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


def test_every_case_has_a_verdict_of_every_reader() -> None:
    assert sorted(VERDICTS) == sorted(CASES)
    for verdict in VERDICTS.values():
        assert sorted(verdict) == ["procps-3", "procps-4", "systemd"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_systemd_sets_what_the_model_decides(name: str) -> None:
    keys = [str(key) for key in cast("list[object]", CASES[name]["keys"])]
    settings = sysctl_config.sequence(case_entries(name), keys, sysctl_config.SYSTEMD)
    found = dict.fromkeys(keys) | {setting[0]: setting[1] for setting in settings}
    assert found == VERDICTS[name]["systemd"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_procps_4_makes_the_settings_of_the_model_in_its_order(name: str) -> None:
    keys = [str(key) for key in cast("list[object]", CASES[name]["keys"])]
    settings = sysctl_config.sequence(case_entries(name), keys, sysctl_config.PROCPS)
    assert [[setting[0], setting[1]] for setting in settings] == VERDICTS[name]["procps-4"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_procps_3_makes_the_settings_of_the_model_in_its_order(name: str) -> None:
    keys = [str(key) for key in cast("list[object]", CASES[name]["keys"])]
    settings = sysctl_config.sequence(case_entries(name), keys, sysctl_config.PROCPS)
    assert [[setting[0], None] for setting in settings] == VERDICTS[name]["procps-3"]


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
    assert {reader: setting["value"] for reader, setting in found.items()} == {
        "systemd": "2",
        "procps": "2",
    }
    assert sysctl_config.effective(entries, RP_FILTER)["systemd"]["value"] == "1"


def test_no_setting_gives_nulls() -> None:
    assert sysctl_config.effective([], RP_FILTER) == {
        "systemd": {"value": None, "source": None},
        "procps": {"value": None, "source": None},
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
    ("key", "path"),
    [
        ("net.ipv4.conf.all.rp_filter", "net/ipv4/conf/all/rp_filter"),
        ("net/ipv4/conf/all/rp_filter", "net/ipv4/conf/all/rp_filter"),
        ("net/ipv4/conf/enp3s0.200/forwarding", "net/ipv4/conf/enp3s0.200/forwarding"),
        ("net.ipv4.conf.enp3s0/200.forwarding", "net/ipv4/conf/enp3s0.200/forwarding"),
        ("kernel", "kernel"),
    ],
)
def test_the_first_separator_decides_the_form_of_a_key(key: str, path: str) -> None:
    assert sysctl_config.normalise(key) == path


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
