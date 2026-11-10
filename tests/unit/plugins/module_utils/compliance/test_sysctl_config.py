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
READERS = sysctl_config.READERS


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
            text = texts.get(target)
            kind = "null" if target == "/dev/null" else "file" if text is not None else "other"
            entries.append({"path": path, "kind": "link", "text": text, "target": kind})
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
        ("ENABLED='yes'", 'IPT_SYSCTL="/etc/ufw/sysctl.conf"\n'),
        ("ENABLED=YES", "IPT_SYSCTL=/etc/ufw/sysctl.conf\n"),
        ("# ENABLED in /etc/default/ufw", "ENABLED=yes\nIPT_SYSCTL=/etc/ufw/sysctl.conf\n"),
        ("IPT_SYSCTL=/etc/ufw/sysctl.conf\nENABLED=yes", "IPT_SYSCTL=\n"),
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
        ("ENABLED=no", "ENABLED=yes\nIPT_SYSCTL=/etc/ufw/sysctl.conf\n"),
        ("IPT_SYSCTL=", "ENABLED=yes\nIPT_SYSCTL=/etc/ufw/sysctl.conf\n"),
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


UBUNTU_UFW_DEFAULT = """# /etc/default/ufw
#

# Set to yes to apply rules to support IPv6 (no means only IPv6 on loopback
# accepted). You will need to 'disable' and then 'enable' the firewall for
# the changes to take affect.
IPV6=yes
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
MANAGE_BUILTINS=no
IPT_SYSCTL=/etc/ufw/sysctl.conf
IPT_MODULES="nf_conntrack_ftp nf_nat_ftp nf_conntrack_netbios_ns"
"""
PLAIN_DEFAULT = "IPT_SYSCTL=/etc/ufw/sysctl.conf\n"
UFW_APPLIED = {
    "systemd": {"value": "2", "source": UFW},
    "procps": {"value": "2", "source": UFW},
}
UFW_IGNORED = {
    "systemd": {"value": "1", "source": "/usr/lib/sysctl.d/60-b.conf"},
    "procps": {"value": "1", "source": "/usr/lib/sysctl.d/60-b.conf"},
}


@pytest.mark.parametrize(
    ("enabled", "default"),
    [
        ("ENABLED=yes\nLOGLEVEL=low", UBUNTU_UFW_DEFAULT),
        ("\tENABLED=yes\n  LOGLEVEL='low  medium'", UBUNTU_UFW_DEFAULT),
        ("ENABLED=yes", "IPT_SYSCTL='/etc/ufw/sysctl.conf'\n"),
        ('ENABLED="yes"', 'IPT_SYSCTL="/etc/ufw/sysctl.conf"\nIPT_MODULES=a,b:c+d@e%f\n'),
    ],
)
def test_plain_assignments_in_ufw_s_files_are_read(enabled: str, default: str) -> None:
    found = sysctl_config.effective(ufw_entries(enabled, default), RP_FILTER)
    assert readers(found) == UFW_APPLIED
    assert found["unsupported"] == []


@pytest.mark.parametrize(
    ("enabled", "default", "path"),
    [
        ("ENABLED=yes;", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=$VAR", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=${E:-yes}", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ('ENABLED="$E"', PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=`echo yes`", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=$(echo yes)", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=y\\es", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ('ENABLED="y\\es"', PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=no \\\n", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=\\\nyes", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        (". /etc/ufw/more", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("source /etc/ufw/more", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("eval ENABLED=yes", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("true && ENABLED=yes", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=no || ENABLED=yes", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=yes # on", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=yes\r", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED='yes", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=~/yes", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=yes", "IPT_SYSCTL=/etc/ufw/sysctl.conf;\n", sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes", ". /etc/ufw/more\n" + PLAIN_DEFAULT, sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes", "IPT_SYSCTL=/etc/ufw/sysctl.conf \\\n", sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes", "ENABLED=$(true)\n" + PLAIN_DEFAULT, sysctl_config.UFW_DEFAULT),
        ("export ENABLED=yes", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=yes", "export IPT_SYSCTL=/etc/ufw/sysctl.conf\n", sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes\nIFS=/", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
        ("ENABLED=yes", "PATH=/tmp\n" + PLAIN_DEFAULT, sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes", "ENV=/tmp/x\n" + PLAIN_DEFAULT, sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes", "BASH_ENV=/tmp/x\n" + PLAIN_DEFAULT, sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes", "LD_PRELOAD=/tmp/x.so\n" + PLAIN_DEFAULT, sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes", "LD_LIBRARY_PATH=/tmp\n" + PLAIN_DEFAULT, sysctl_config.UFW_DEFAULT),
        ("ENABLED=yes\nSITE=x", PLAIN_DEFAULT, sysctl_config.UFW_CONF),
    ],
)
def test_a_line_of_ufw_s_files_other_than_a_plain_assignment_is_unsupported(
    enabled: str, default: str, path: str
) -> None:
    found = sysctl_config.effective(ufw_entries(enabled, default), RP_FILTER)
    assert found["unsupported"] == [
        (
            f"{path}: a line other than a comment or a plain NAME=value assignment of a variable"
            " that ufw defines, which ufw's start script runs and the collection cannot follow"
        )
    ]
    assert readers(found) == UFW_IGNORED


@pytest.mark.parametrize(
    ("enabled", "default"),
    [
        ('ENABLED="yes no"', PLAIN_DEFAULT),
        ("ENABLED='y:es'", PLAIN_DEFAULT),
        ("ENABLED=yes", 'IPT_SYSCTL="/etc/ufw/sysctl conf"\n'),
        ("ENABLED=yes", "IPT_SYSCTL=/etc/ufw/sysctl.conf,x\n"),
    ],
)
def test_a_ufw_value_with_another_character_is_unsupported(enabled: str, default: str) -> None:
    found = sysctl_config.effective(ufw_entries(enabled, default), RP_FILTER)
    assert found["unsupported"] == [
        (
            f"{sysctl_config.UFW_CONF}: ENABLED or IPT_SYSCTL holds a character other than a"
            " letter, a digit or one of _./-, which the collection cannot follow"
        )
    ]


@pytest.mark.parametrize("which", [sysctl_config.UFW_DEFAULT, sysctl_config.UFW_CONF])
@pytest.mark.parametrize(
    ("kind", "target", "text"),
    [
        ("file", None, ""),
        ("file", None, None),
        ("link", "file", ""),
        ("link", "null", None),
        ("link", "other", None),
        ("link", None, None),
        ("directory", None, None),
        ("other", None, None),
    ],
)
def test_ufw_applies_nothing_unless_both_its_files_are_non_empty_regular_files(
    which: str, kind: str, target: str | None, text: str | None
) -> None:
    entries = ufw_entries("ENABLED=yes", PLAIN_DEFAULT)
    entries = [entry for entry in entries if entry["path"] != which]
    entries.append({"path": which, "kind": kind, "target": target, "text": text})
    found = sysctl_config.effective(entries, RP_FILTER)
    assert readers(found) == UFW_IGNORED
    assert found["unsupported"] == []


@pytest.mark.parametrize("which", [sysctl_config.UFW_DEFAULT, sysctl_config.UFW_CONF])
def test_a_link_to_a_regular_ufw_file_is_sourced(which: str) -> None:
    entries = ufw_entries("ENABLED=yes", PLAIN_DEFAULT)
    for entry in entries:
        if entry["path"] == which:
            entry.update({"kind": "link", "target": "file"})
    assert readers(sysctl_config.effective(entries, RP_FILTER)) == UFW_APPLIED


def test_ufw_applies_nothing_without_etc_default_ufw() -> None:
    found = sysctl_config.effective(
        ufw_entries("ENABLED=yes\nIPT_SYSCTL=/etc/ufw/sysctl.conf", None), RP_FILTER
    )
    assert readers(found) == UFW_IGNORED
    assert found["unsupported"] == []


def test_ufw_s_file_is_ignored_without_ufw_conf() -> None:
    entries = [entry for entry in ufw_entries("", None) if entry["path"] != sysctl_config.UFW_CONF]
    assert sysctl_config.effective(entries, RP_FILTER)["systemd"] == {
        "value": "1",
        "source": "/usr/lib/sysctl.d/60-b.conf",
    }


@pytest.mark.parametrize(
    ("enabled", "default", "reason"),
    [
        ("ENABLED=$(echo yes)", "IPT_SYSCTL=/etc/ufw/sysctl.conf\n", "plain NAME=value"),
        ("ENABLED=yes", "IPT_SYSCTL=${X}\n", "cannot follow"),
        ("ENABLED=yes", "IPT_SYSCTL=/etc/other.conf\n", "cannot follow"),
        ("ENABLED=Yes", "IPT_SYSCTL=/etc/ufw/sysctl.conf\n", "a spelling of yes"),
        ("# ufw", "ENABLED=$(echo yes)\n", "plain NAME=value"),
        ("IPT_SYSCTL=${X}", "ENABLED=yes\n", "cannot follow"),
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
        ("net/ipv4/conf/*/rp_filter", "net/ipv4/conf/all/rp_filter/x", False),
    ],
)
def test_a_glob_matches_as_glob_3_does(pattern: str, path: str, *, matches: bool) -> None:
    expression = sysctl_config.glob_pattern(pattern)
    assert expression is not None
    assert bool(re.fullmatch(expression, path)) is matches


@pytest.mark.parametrize(
    ("pattern", "path", "matches"),
    [
        ("conf/[!]x]ll/rp_filter", "conf/all/rp_filter", True),
        ("conf/[!]x]ll/rp_filter", "conf/]ll/rp_filter", False),
        ("conf/[^]x]ll/rp_filter", "conf/xll/rp_filter", False),
        ("conf/[]x]ll/rp_filter", "conf/]ll/rp_filter", True),
        ("conf/[-a]ll/rp_filter", "conf/-ll/rp_filter", True),
        ("conf/[a-]ll/rp_filter", "conf/-ll/rp_filter", True),
        ("conf/*/rp_filter", "conf/.hidden/rp_filter", False),
        ("conf/?all/rp_filter", "conf/.all/rp_filter", False),
        ("conf/[!x]all/rp_filter", "conf/.all/rp_filter", False),
        ("conf/a*/rp_filter", "conf/a.b/rp_filter", True),
        ("conf/all/rp_filte[r]", "conf/all/rp_filter", True),
    ],
)
def test_a_bracket_and_a_leading_period_match_as_glob_3_does(
    pattern: str, path: str, *, matches: bool
) -> None:
    expression = sysctl_config.glob_pattern(pattern)
    assert expression is not None
    assert bool(re.fullmatch(expression, path)) is matches


@pytest.mark.parametrize(
    "pattern",
    [
        "conf/[[:alpha:]]ll/rp_filter",
        "conf/[[.a.]]ll/rp_filter",
        "conf/[[=a=]]ll/rp_filter",
        "conf/\\*/rp_filter",
        "conf/[\\]]ll/rp_filter",
        "conf/{all,default}*/rp_filter",
        "conf/[a-Z]ll/rp_filter",
        "conf/[z-a]ll/rp_filter",
        "conf/[a-c-e]ll/rp_filter",
        "conf/[a--]ll/rp_filter",
        "conf/\u00e9*/rp_filter",
        "net/ipv4/conf/[all/rp_filter",
        "conf/[]/rp_filter",
        "conf/[!/rp_filter",
        "conf/a[b/c]d/rp_filter",
        "conf/all/rp_filte[r",
        "conf/[-a/rp_filter",
        "conf/[[.a/rp_filter",
    ],
)
def test_a_glob_that_does_not_translate_exactly_gives_none(pattern: str) -> None:
    assert sysctl_config.glob_pattern(pattern) is None


DROP_IN: dict[str, object] = {
    "path": "/etc/sysctl.d/999-freesecdev-sysctl-net-ipv4-conf-all-rp-filter.conf",
    "kind": "file",
    "text": f"# Managed by freesecdev.linux_compliance for x.\n{RP_FILTER} = 1\n",
}
LATE = "/usr/lib/sysctl.d/zz-pkg.conf"


def after_drop_in(text: str) -> dict[str, object]:
    """Return what the model decides when a file read after the drop-in holds ``text``."""
    entries: list[dict[str, object]] = [DROP_IN, {"path": LATE, "kind": "file", "text": text}]
    return sysctl_config.effective(entries, RP_FILTER)


@pytest.mark.parametrize(
    "text",
    [
        "--net.ipv4.conf.all.rp_filter = 0\n",
        "--net.ipv4.conf.all.rp_filter=0\n",
        "--net.ipv4.conf.all.rp_filter\n",
        "--net/ipv4/conf/all/rp_filter = 0\n",
    ],
)
def test_a_procps_key_with_a_second_leading_dash_is_unsupported(text: str) -> None:
    assert after_drop_in(text)["unsupported"] == [
        f"{LATE}: a key that starts with a second -, which procps drops from the path it opens"
    ]


def test_a_dash_and_a_space_before_another_dash_is_not_a_second_dash() -> None:
    found = after_drop_in("- -net.ipv4.conf.all.rp_filter = 0\n")
    assert found["unsupported"] == []
    assert readers(found) == {
        "systemd": {"value": "1", "source": DROP_IN["path"]},
        "procps": {"value": "1", "source": DROP_IN["path"]},
    }


@pytest.mark.parametrize(
    "text",
    [
        "net/ipv4//conf/*/rp_filter = 0\n",
        "net.ipv4..conf.*.rp_filter = 0\n",
        "/net/ipv4/conf/*/rp_filter = 0\n",
        "net/ipv4/./conf/*/rp_filter = 0\n",
        "net/ipv4/conf/*/rp_filter/ = 0\n",
        "-net/ipv4//conf/*/rp_filter\n",
    ],
)
def test_a_procps_glob_that_is_not_canonical_is_unsupported(text: str) -> None:
    found = cast("list[str]", after_drop_in(text)["unsupported"])
    assert (
        f"{LATE}: a glob with a repeated slash, a . component or a leading or trailing slash, whose"
        " matches procps compares with the keys as written"
    ) in found


@pytest.mark.parametrize(
    "text",
    ["net/ipv4/.*/conf/all/rp_filter = 0\n", "net/ipv4/conf/.?ll/rp_filter = 0\n"],
)
def test_a_glob_component_that_starts_with_a_period_is_unsupported(text: str) -> None:
    found = cast("list[str]", after_drop_in(text)["unsupported"])
    assert f"{LATE}: a glob with a component that starts with ., which can match . and .." in found


@pytest.mark.parametrize(
    "text",
    [
        "net.ipv4.conf.[[:alpha:]]ll.rp_filter = 0\n",
        "net.ipv4.conf.\\a*.rp_filter = 0\n",
        "net.ipv4.conf.{all,x}*.rp_filter = 0\n",
    ],
)
def test_a_glob_that_does_not_translate_exactly_is_unsupported(text: str) -> None:
    assert after_drop_in(text)["unsupported"] == [
        f"{LATE}: a glob that the collection cannot translate exactly"
    ]


def test_a_bracket_with_a_leading_close_bracket_is_followed() -> None:
    found = after_drop_in("net.ipv4.conf.[!]x]ll.rp_filter = 0\n")
    assert found["unsupported"] == []
    assert readers(found) == {
        "systemd": {"value": "1", "source": DROP_IN["path"]},
        "procps": {"value": "1", "source": DROP_IN["path"]},
    }


@pytest.mark.parametrize(
    ("text", "procps"),
    [
        ("net/ipv4//conf/all/rp_filter = 1\nnet.ipv4.conf.*.rp_filter = 0\n", "0"),
        ("-net/ipv4//conf/all/rp_filter\nnet.ipv4.conf.*.rp_filter = 0\n", "0"),
        ("-/net/ipv4/conf/all/rp_filter\nnet.ipv4.conf.*.rp_filter = 0\n", "0"),
        ("-net.ipv4.conf.all.rp_filter\nnet.ipv4.conf.*.rp_filter = 0\n", None),
        ("net/ipv4/conf/all/rp_filter = 1\nnet.ipv4.conf.*.rp_filter = 0\n", "1"),
    ],
)
def test_procps_excludes_from_a_glob_only_a_key_written_as_its_matches(
    text: str, procps: str | None
) -> None:
    entries: list[dict[str, object]] = [
        {"path": "/etc/sysctl.d/10-a.conf", "kind": "file", "text": text}
    ]
    found = sysctl_config.effective(entries, RP_FILTER)
    assert found["unsupported"] == []
    assert cast("dict[str, object]", found["procps"])["value"] == procps


PATTERN_NAME_REASON = (
    "sysctl --system expands the name of this entry as a pattern, which may read other files a"
    " second time"
)
UNSAFE_ENTRY_REASON = (
    "a FIFO, socket or device, or a link to something other than a regular file or /dev/null, on"
    " which a reader may block or which it may read without end"
)


@pytest.mark.parametrize(
    ("kind", "target"), [("file", None), ("link", "file"), ("link", "null"), ("directory", None)]
)
@pytest.mark.parametrize("directory", sysctl_config.DIRECTORIES)
def test_a_pattern_name_is_unsupported_whatever_the_kind_of_the_entry(
    kind: str, target: str | None, directory: str
) -> None:
    entries: list[dict[str, object]] = [
        DROP_IN,
        {"path": f"{directory}/[1]0-loose.conf", "kind": kind, "text": None, "target": target},
        {"path": "/usr/lib/sysctl.d/10-loose.conf", "kind": "file", "text": f"{RP_FILTER}=0\n"},
    ]
    assert sysctl_config.effective(entries, RP_FILTER)["unsupported"] == [
        f"{directory}/[1]0-loose.conf: {PATTERN_NAME_REASON}"
    ]


@pytest.mark.parametrize(
    ("kind", "target"),
    [("other", None), ("link", "other"), ("link", None), ("link", "directory")],
)
@pytest.mark.parametrize("directory", sysctl_config.DIRECTORIES)
@pytest.mark.parametrize("name", ["70-x.conf", ".70-hidden.conf"])
def test_a_fifo_a_device_or_an_unsafe_link_is_unsupported(
    kind: str, target: str | None, directory: str, name: str
) -> None:
    entries: list[dict[str, object]] = [
        DROP_IN,
        {"path": f"{directory}/{name}", "kind": kind, "text": None, "target": target},
    ]
    assert sysctl_config.effective(entries, RP_FILTER)["unsupported"] == [
        f"{directory}/{name}: {UNSAFE_ENTRY_REASON}"
    ]


@pytest.mark.parametrize(
    ("kind", "target", "text"),
    [
        ("link", "null", None),
        ("link", "file", f"{RP_FILTER} = 1\n"),
        ("directory", None, None),
        ("file", None, ""),
    ],
)
def test_a_file_a_directory_and_a_link_to_a_file_or_dev_null_are_followed(
    kind: str, target: str | None, text: str | None
) -> None:
    entries: list[dict[str, object]] = [
        DROP_IN,
        {"path": "/usr/lib/sysctl.d/70-x.conf", "kind": kind, "text": text, "target": target},
    ]
    assert sysctl_config.effective(entries, RP_FILTER)["unsupported"] == []


def test_an_unsafe_entry_outside_the_conf_files_is_not_listed() -> None:
    entries: list[dict[str, object]] = [
        DROP_IN,
        {"path": "/etc/sysctl.d/70-x.conf.fifo", "kind": "other", "text": None},
        {"path": "/srv/70-x.conf", "kind": "other", "text": None},
    ]
    assert sysctl_config.effective(entries, RP_FILTER)["unsupported"] == []


def test_a_target_that_is_not_a_string_is_refused() -> None:
    with pytest.raises(sysctl_config.ConfigError, match="target"):
        sysctl_config.load_entries(
            [{"path": "/etc/sysctl.d/x.conf", "kind": "link", "text": None, "target": 1}]
        )


@pytest.mark.parametrize(
    ("value", "integer"),
    [
        ("0", 0),
        ("-0", None),
        ("1", 1),
        ("-1", -1),
        ("65536", 65536),
        ("1234567890123456789", 1234567890123456789),
        ("-1234567890123456789", -1234567890123456789),
        ("065536", None),
        ("010", None),
        ("00", None),
        ("+1", None),
        ("0x10", None),
        ("0X10", None),
        ("000000000000000000001", None),
        ("12345678901234567890", None),
        ("1 ", None),
        (" 1", None),
        ("1\n", None),
        ("1.0", None),
        ("", None),
        ("-", None),
        ("\u0661", None),
        (1, None),
        (None, None),
    ],
)
def test_an_integer_counts_only_in_the_form_that_the_kernel_reads_as_written(
    value: object, integer: int | None
) -> None:
    assert sysctl_config.kernel_integer(value) == integer


def test_a_pattern_name_outside_the_conf_files_is_not_read() -> None:
    entries: list[dict[str, object]] = [
        DROP_IN,
        {"path": "/etc/sysctl.d/[1]0-loose.conf.bak", "kind": "directory", "text": None},
        {"path": "/srv/[1]0-loose.conf", "kind": "file", "text": f"{RP_FILTER}=0\n"},
    ]
    assert sysctl_config.effective(entries, RP_FILTER)["unsupported"] == []


@pytest.mark.parametrize(
    ("value", "systemd", "procps"),
    [
        ("1\r\x1f", "1", "1\r\x1f"),
        ("1\x1c", "1\x1c", "1\x1c"),
        ("1\x1d\x1e", "1\x1d\x1e", "1\x1d\x1e"),
        ("1\x85", "1\x85", "1\x85"),
        ("1\u00a0", "1\u00a0", "1\u00a0"),
        ("1\v\f", "1\v\f", "1"),
        ("\v\f1\r", "\v\f1", "1"),
    ],
)
def test_procps_strips_only_the_white_space_of_c(value: str, systemd: str, procps: str) -> None:
    found = after_drop_in(f"{RP_FILTER} = {value}\n")
    assert {reader: cast("dict[str, object]", found[reader])["value"] for reader in READERS} == {
        "systemd": systemd,
        "procps": procps,
    }


def test_procps_keeps_a_key_that_ends_in_a_character_that_is_not_c_white_space() -> None:
    found = after_drop_in(f"{RP_FILTER}\x1f = 0\n\x1c{RP_FILTER} = 0\n")
    assert readers(found) == {
        "systemd": {"value": "1", "source": DROP_IN["path"]},
        "procps": {"value": "1", "source": DROP_IN["path"]},
    }


def test_a_problem_of_ufw_s_file_is_unsupported() -> None:
    entries = ufw_entries("ENABLED=yes", "IPT_SYSCTL=/etc/ufw/sysctl.conf\n")
    entries[-3] = {"path": UFW, "kind": "file", "text": "--net/ipv4/conf/all/rp_filter=0\n"}
    assert sysctl_config.effective(entries, RP_FILTER)["unsupported"] == [
        f"{UFW}: a key that starts with a second -, which procps drops from the path it opens"
    ]


PORT_RANGE = [32768, 65535]


@pytest.mark.parametrize(
    ("value", "vector"),
    [
        ("32768 65535", PORT_RANGE),
        ("32768\t65535", PORT_RANGE),
        ("32768  65535", PORT_RANGE),
        ("32768 \t 65535", PORT_RANGE),
        ("65535 32768", [65535, 32768]),
        ("132768 65535", [132768, 65535]),
        ("32768 655350", [32768, 655350]),
        ("-32768 65535", [-32768, 65535]),
        ("032768 65535", None),
        ("3276865535", None),
        ("+32768 65535", None),
        ("32768\v65535", None),
        ("32768\f65535", None),
        ("32768\r65535", None),
        ("32768 65535x", None),
        ("32768 0x10", None),
        ("32768 65535 1", None),
        (" 32768 65535", None),
        ("32768 65535 ", None),
        ("-0 65535", None),
        ("", None),
        (32768, None),
    ],
)
def test_a_vector_counts_only_as_fields_that_the_kernel_reads_as_written(
    value: object, vector: list[int] | None
) -> None:
    found = sysctl_config.kernel_vector(value, 2)
    assert found == vector
    assert (found == PORT_RANGE) is (vector == PORT_RANGE)


SAMPLE_RATE = "kernel.perf_event_max_sample_rate"
CPU_TIME = "kernel.perf_cpu_time_max_percent"
BLOCKER: dict[str, object] = {"key": CPU_TIME, "refused": [0, 100], "minimum": 0, "maximum": 100}
COMPANION = sysctl_config.load_companion(BLOCKER)
SAMPLE_DROP_IN = "/etc/sysctl.d/999-freesecdev-sysctl-kernel-perf-event-max-sample-rate.conf"
CPU_DROP_IN = "/etc/sysctl.d/999-freesecdev-sysctl-kernel-perf-cpu-time-max-percent.conf"


def perf_entries(files: dict[str, str]) -> list[dict[str, object]]:
    """Return the sample rate's drop-in and ``files``, as the planned entries of the rule."""
    entries: list[dict[str, object]] = [
        {"path": path, "kind": "file", "text": text} for path, text in files.items()
    ]
    entries.append({"path": SAMPLE_DROP_IN, "kind": "file", "text": f"{SAMPLE_RATE} = 1\n"})
    return entries


def refusals(files: dict[str, str]) -> dict[str, dict[str, str] | None]:
    """Return the refusing settings of the companion for ``files`` and the drop-in."""
    return sysctl_config.companion_refusals(perf_entries(files), SAMPLE_RATE, COMPANION)


@pytest.mark.parametrize("value", ["0", "100", "0x0", "00", "+1", "0100"])
def test_a_companion_at_a_refused_value_refuses_the_key_for_both_readers(value: str) -> None:
    found = refusals({"/etc/sysctl.d/50-perf.conf": f"{CPU_TIME} = {value}\n"})
    setting = {"value": value, "source": "/etc/sysctl.d/50-perf.conf"}
    assert found == {"systemd": setting, "procps": setting}


@pytest.mark.parametrize("files", [{}, {"/etc/sysctl.d/50-perf.conf": f"{CPU_TIME} = 1\n"}])
def test_a_companion_at_another_value_or_unset_refuses_nothing(files: dict[str, str]) -> None:
    assert refusals(files) == {"systemd": None, "procps": None}


def test_procps_is_refused_by_a_zero_at_its_write_although_a_later_file_sets_it_back() -> None:
    found = refusals(
        {
            "/etc/sysctl.d/10-a.conf": f"{CPU_TIME} = 0\n",
            "/etc/sysctl.d/9999-z.conf": f"{CPU_TIME} = 25\n",
        }
    )
    assert found == {
        "systemd": None,
        "procps": {"value": "0", "source": "/etc/sysctl.d/10-a.conf"},
    }


def test_procps_is_not_refused_by_a_zero_after_its_last_write_of_the_key() -> None:
    found = refusals({"/etc/sysctl.conf": f"{CPU_TIME} = 0\n"})
    assert found == {"systemd": None, "procps": None}


def test_procps_counts_the_companion_s_value_at_its_last_write_of_the_key() -> None:
    found = refusals(
        {
            "/etc/sysctl.d/10-a.conf": f"{SAMPLE_RATE} = 1\n",
            "/etc/sysctl.d/20-b.conf": f"{CPU_TIME} = 100\n",
            "/etc/sysctl.d/30-c.conf": f"{CPU_TIME} = 25\n",
        }
    )
    assert found == {"systemd": None, "procps": None}


@pytest.mark.parametrize(
    ("values", "refused"),
    [
        (["0", "1"], None),
        (["100", "25"], None),
        (["1", "0"], "0"),
        (["0", "200"], "0"),
        (["0", "-1"], "0"),
        (["1", "200"], None),
        (["1", "0x0"], "0x0"),
        (["0", "0x19"], "0x19"),
        (["1", "+1"], "+1"),
        (["0x0", "1"], None),
    ],
)
def test_procps_tracks_the_companion_through_its_assignments(
    values: list[str], refused: str | None
) -> None:
    files = {
        f"/etc/sysctl.d/{index}0-c.conf": f"{CPU_TIME} = {value}\n"
        for index, value in enumerate(values, start=1)
    }
    found = refusals(files)["procps"]
    source = next(
        (path for path, text in files.items() if text == f"{CPU_TIME} = {refused}\n"), None
    )
    assert found == (None if refused is None else {"value": refused, "source": source})


def test_procps_judges_each_run_of_the_key_by_the_value_at_its_last_write() -> None:
    found = refusals(
        {
            "/etc/sysctl.d/10-a.conf": f"{CPU_TIME} = 0\n{SAMPLE_RATE} = 2\n",
            "/etc/sysctl.d/20-b.conf": f"{CPU_TIME} = 1\n",
        }
    )
    assert found["procps"] is None


@pytest.mark.parametrize(
    "text",
    ["kernel/perf_cpu_time_max_percent/ = 0\n", f"vm.swappiness = 10\r{CPU_TIME} = 0\n"],
)
def test_systemd_s_own_zero_refuses_although_ufw_sets_one_later(text: str) -> None:
    entries: list[dict[str, object]] = [
        *perf_entries({"/etc/sysctl.d/10-a.conf": text}),
        {"path": UFW, "kind": "file", "text": f"{CPU_TIME} = 1\n"},
        {"path": sysctl_config.UFW_CONF, "kind": "file", "text": "ENABLED=yes\n"},
        {"path": sysctl_config.UFW_DEFAULT, "kind": "file", "text": PLAIN_DEFAULT},
    ]
    assert sysctl_config.companion_refusals(entries, SAMPLE_RATE, COMPANION) == {
        "systemd": {"value": "0", "source": "/etc/sysctl.d/10-a.conf"},
        "procps": None,
    }


def test_ufw_s_zero_refuses_for_systemd_after_its_own_one() -> None:
    entries: list[dict[str, object]] = [
        *perf_entries({"/etc/sysctl.d/10-a.conf": f"{CPU_TIME} = 1\n"}),
        {"path": UFW, "kind": "file", "text": f"{CPU_TIME} = 0\n"},
        {"path": sysctl_config.UFW_CONF, "kind": "file", "text": "ENABLED=yes\n"},
        {"path": sysctl_config.UFW_DEFAULT, "kind": "file", "text": PLAIN_DEFAULT},
    ]
    assert sysctl_config.companion_refusals(entries, SAMPLE_RATE, COMPANION) == {
        "systemd": {"value": "0", "source": UFW},
        "procps": None,
    }


@pytest.mark.parametrize("value", ["200", "-1"])
def test_systemd_does_not_refuse_on_a_value_that_the_kernel_refuses(value: str) -> None:
    found = refusals({"/etc/sysctl.d/50-perf.conf": f"{CPU_TIME} = {value}\n"})
    assert found == {"systemd": None, "procps": None}


def test_a_glob_that_sets_the_companion_counts() -> None:
    found = refusals({"/etc/sysctl.d/50-perf.conf": "kernel.perf_cpu_time_max_*= 0\n"})
    setting = {"value": "0", "source": "/etc/sysctl.d/50-perf.conf"}
    assert found == {"systemd": setting, "procps": setting}


def test_procps_is_not_refused_when_it_never_writes_the_key() -> None:
    entries: list[dict[str, object]] = [
        {"path": "/etc/sysctl.d/50-perf.conf", "kind": "file", "text": f"{CPU_TIME} = 0\n"}
    ]
    assert sysctl_config.companion_refusals(entries, SAMPLE_RATE, COMPANION) == {
        "systemd": {"value": "0", "source": "/etc/sysctl.d/50-perf.conf"},
        "procps": None,
    }


def test_ufw_s_file_counts_after_the_boot_files() -> None:
    entries: list[dict[str, object]] = [
        *perf_entries({}),
        {"path": UFW, "kind": "file", "text": f"{CPU_TIME} = 0\n{SAMPLE_RATE} = 2\n"},
        {"path": sysctl_config.UFW_CONF, "kind": "file", "text": "ENABLED=yes\n"},
        {"path": sysctl_config.UFW_DEFAULT, "kind": "file", "text": PLAIN_DEFAULT},
    ]
    setting = {"value": "0", "source": UFW}
    assert sysctl_config.companion_refusals(entries, SAMPLE_RATE, COMPANION) == {
        "systemd": setting,
        "procps": setting,
    }


def companion_rule(status: str | None, *, write: bool = True) -> dict[str, object]:
    """Return the companion's selected rule with a plan of ``status``, or no plan for None."""
    plan: dict[str, object] | None = (
        None if status is None else {"status": status, "write": write, "edits": []}
    )
    return {"plan": plan, "path": CPU_DROP_IN, "content": f"{CPU_TIME} = 1\n"}


CONFLICT = {"/etc/sysctl.d/50-perf.conf": f"{CPU_TIME} = 0\n"}
LATER_100 = {"/etc/sysctl.d/999-freesecdev-sysctl-kernel-perf-d.conf": f"{CPU_TIME} = 100\n"}


@pytest.mark.parametrize(
    "status",
    [
        "conflicting_setting",
        "overridden",
        "not_owned",
        "duplicate_setting",
        "unparsed_configuration",
        "runtime_unavailable",
        "method_changed",
        "prior_unrestorable",
        "prior_too_large",
        "not_regular_file",
        "notapplicable",
    ],
)
@pytest.mark.parametrize("files", [CONFLICT, LATER_100])
def test_a_selected_companion_that_writes_nothing_is_judged_as_the_files_leave_it(
    status: str, files: dict[str, str]
) -> None:
    found = sysctl_config.companion_check(
        perf_entries(files), [], SAMPLE_RATE, BLOCKER, companion_rule(status, write=False)
    )
    planned = cast("dict[str, object]", found["planned"])
    assert found["undecided"] is False
    assert planned["systemd"] is not None
    assert planned["procps"] is not None


@pytest.mark.parametrize("status", ["applied", "compliant"])
def test_an_applied_companion_counts_with_its_drop_in(status: str) -> None:
    found = sysctl_config.companion_check(
        perf_entries({}), [], SAMPLE_RATE, BLOCKER, companion_rule(status)
    )
    assert found == {
        "undecided": False,
        "planned": {"systemd": None, "procps": None},
        "current": {"systemd": None, "procps": None},
    }


def test_an_applied_companion_is_still_judged_on_the_planned_entries() -> None:
    found = sysctl_config.companion_check(
        perf_entries(LATER_100), [], SAMPLE_RATE, BLOCKER, companion_rule("applied")
    )
    planned = cast("dict[str, object]", found["planned"])
    assert planned["systemd"] == {
        "value": "100",
        "source": "/etc/sysctl.d/999-freesecdev-sysctl-kernel-perf-d.conf",
    }


def test_an_applied_companion_s_vendor_edit_counts() -> None:
    vendor = "/etc/sysctl.d/10-kernel-hardening.conf"
    rule = companion_rule("applied", write=False)
    rule["plan"] = {
        "status": "applied",
        "write": False,
        "edits": [{"path": vendor, "original": f"{CPU_TIME}=0", "written": f"{CPU_TIME}=1"}],
    }
    entries = perf_entries({vendor: f"# vendor\n{CPU_TIME}=0\n"})
    assert sysctl_config.companion_check(entries, [], SAMPLE_RATE, BLOCKER, rule)["planned"] == {
        "systemd": None,
        "procps": None,
    }
    assert sysctl_config.companion_check(entries, [], SAMPLE_RATE, BLOCKER)["planned"] == {
        "systemd": {"value": "0", "source": vendor},
        "procps": {"value": "0", "source": vendor},
    }


def test_an_applied_companion_replaces_its_old_drop_in() -> None:
    entries = perf_entries({CPU_DROP_IN: f"# Managed by freesecdev\n{CPU_TIME} = 100\n"})
    found = sysctl_config.companion_check(
        entries, [], SAMPLE_RATE, BLOCKER, companion_rule("applied")
    )
    assert found["planned"] == {"systemd": None, "procps": None}


@pytest.mark.parametrize("files", [{}, CONFLICT])
def test_an_unselected_companion_is_judged_as_the_files_leave_it(files: dict[str, str]) -> None:
    found = sysctl_config.companion_check(
        perf_entries(files), perf_entries(files), SAMPLE_RATE, BLOCKER
    )
    expected = {"value": "0", "source": "/etc/sysctl.d/50-perf.conf"} if files else None
    assert found == {
        "undecided": False,
        "planned": {"systemd": expected, "procps": expected},
        "current": {"systemd": expected, "procps": expected},
    }


def test_a_selected_companion_without_a_plan_entry_is_undecided() -> None:
    found = sysctl_config.companion_check(
        perf_entries({}), [], SAMPLE_RATE, BLOCKER, companion_rule(None)
    )
    assert found["undecided"] is True


@pytest.mark.parametrize(
    "blocker",
    [
        {"key": CPU_TIME},
        {"refused": [0, 100], "minimum": 0, "maximum": 100},
        {"key": CPU_TIME, "refused": "0", "minimum": 0, "maximum": 100},
        {"key": CPU_TIME, "refused": [0, "100"], "minimum": 0, "maximum": 100},
        {"key": CPU_TIME, "refused": [True], "minimum": 0, "maximum": 100},
        {"key": CPU_TIME, "refused": [0, 100]},
        {"key": CPU_TIME, "refused": [0, 100], "minimum": 0, "maximum": "100"},
        {"key": CPU_TIME, "refused": [0, 100], "minimum": False, "maximum": 100},
    ],
)
def test_a_malformed_blocker_is_refused(blocker: dict[str, object]) -> None:
    with pytest.raises(sysctl_config.ConfigError):
        sysctl_config.companion_check([], [], SAMPLE_RATE, blocker)


@pytest.mark.parametrize(
    "plan",
    [
        {"status": "applied", "write": True, "edits": "x"},
        {"status": "applied", "write": True, "edits": [1]},
        {
            "status": "applied",
            "write": True,
            "edits": [{"path": 1, "original": "a", "written": "b"}],
        },
        {"status": "applied", "write": True, "edits": [{"path": "/etc/x", "original": "a"}]},
        {"status": "applied", "write": "yes", "edits": []},
    ],
)
def test_a_malformed_plan_of_an_applied_companion_is_refused(plan: dict[str, object]) -> None:
    rule = {"plan": plan, "path": CPU_DROP_IN, "content": f"{CPU_TIME} = 1\n"}
    with pytest.raises(sysctl_config.ConfigError):
        sysctl_config.companion_check(perf_entries({}), [], SAMPLE_RATE, BLOCKER, rule)


def test_a_plan_without_edits_or_with_null_edits_adds_only_the_drop_in() -> None:
    for plan in ({"status": "applied"}, {"status": "applied", "write": True, "edits": None}):
        rule = {"plan": plan, "path": CPU_DROP_IN, "content": f"{CPU_TIME} = 1\n"}
        found = sysctl_config.companion_check(perf_entries({}), [], SAMPLE_RATE, BLOCKER, rule)
        assert found["planned"] == {"systemd": None, "procps": None}


VENDOR = "/etc/sysctl.d/10-kernel-hardening.conf"


def test_a_cleanup_restore_writes_the_original_line_back() -> None:
    texts: dict[str, object] = {VENDOR: f"kernel.kptr_restrict = 1\n{CPU_TIME} = 1\n", "/x": None}
    restores = [{"path": VENDOR, "written": f"{CPU_TIME} = 1", "original": f"{CPU_TIME} = 0"}]
    assert sysctl_config.restore_lines(texts, restores) == {
        VENDOR: f"kernel.kptr_restrict = 1\n{CPU_TIME} = 0\n",
        "/x": None,
    }


@pytest.mark.parametrize(
    "text",
    [f"{CPU_TIME} = 1\n{CPU_TIME} = 1\n", f"{CPU_TIME} = 2\n", f"{CPU_TIME} = 1\r\n"],
)
def test_a_restore_leaves_a_file_without_exactly_one_written_line_alone(text: str) -> None:
    restores = [{"path": VENDOR, "written": f"{CPU_TIME} = 1", "original": f"{CPU_TIME} = 0"}]
    assert sysctl_config.restore_lines({VENDOR: text}, restores) == {VENDOR: text}


def test_a_restore_of_the_last_line_without_a_line_feed_ends_it_as_lineinfile_does() -> None:
    texts: dict[str, object] = {VENDOR: f"kernel.kptr_restrict = 1\n{CPU_TIME} = 1"}
    restores = [{"path": VENDOR, "written": f"{CPU_TIME} = 1", "original": f"{CPU_TIME} = 0"}]
    assert sysctl_config.restore_lines(texts, restores) == {
        VENDOR: f"kernel.kptr_restrict = 1\n{CPU_TIME} = 0\n"
    }


def test_a_restore_of_an_unknown_file_changes_nothing() -> None:
    restores = [{"path": VENDOR, "written": "a", "original": "b"}]
    assert sysctl_config.restore_lines({}, restores) == {}


@pytest.mark.parametrize(
    "restore",
    [
        {"path": VENDOR, "written": "a"},
        {"path": 1, "written": "a", "original": "b"},
        {"path": VENDOR, "written": None, "original": "b"},
    ],
)
def test_a_malformed_restore_is_refused(restore: dict[str, object]) -> None:
    with pytest.raises(sysctl_config.ConfigError):
        sysctl_config.restore_lines({VENDOR: "a\n"}, [restore])


def test_the_restored_vendor_line_refuses_the_sample_rate() -> None:
    texts = {VENDOR: f"kernel.kptr_restrict = 1\n{CPU_TIME} = 1\n"}
    restores = [{"path": VENDOR, "written": f"{CPU_TIME} = 1", "original": f"{CPU_TIME} = 0"}]
    restored = sysctl_config.restore_lines(texts, restores)
    entries = perf_entries({VENDOR: str(restored[VENDOR])})
    setting = {"value": "0", "source": VENDOR}
    assert sysctl_config.companion_refusals(entries, SAMPLE_RATE, COMPANION) == {
        "systemd": setting,
        "procps": setting,
    }


UFW_REDIRECTS = "net/ipv4/conf/all/send_redirects"


@pytest.mark.parametrize(
    "text",
    [
        f"{UFW_REDIRECTS}=1\nnet/ipv4/tcp_syncookies=1\rkernel/kptr_restrict=0\n",
        f"{UFW_REDIRECTS}=1\r\nnet/ipv4/tcp_syncookies=1\r\n",
        f"{UFW_REDIRECTS}=1\n\r",
    ],
)
def test_a_file_with_a_carriage_return_is_never_edited(text: str) -> None:
    texts: dict[str, object] = {UFW: text, VENDOR: "kernel.kptr_restrict = 1\n"}
    assert sysctl_config.carriage_return_files(texts, [UFW, VENDOR, UFW]) == [UFW]


def test_a_file_without_a_carriage_return_or_unknown_is_not_named() -> None:
    texts: dict[str, object] = {VENDOR: "kernel.kptr_restrict = 1\n", "/x": None}
    assert sysctl_config.carriage_return_files(texts, [VENDOR, "/x", "/unknown"]) == []


@pytest.mark.parametrize(
    ("texts", "paths"),
    [(None, []), ([], []), ({VENDOR: "a\r"}, [1]), ({VENDOR: "a"}, [None])],
)
def test_malformed_input_of_the_carriage_return_check_is_refused(
    texts: object, paths: list[object]
) -> None:
    with pytest.raises(sysctl_config.ConfigError):
        sysctl_config.carriage_return_files(cast("dict[str, object]", texts), paths)


@pytest.mark.parametrize(
    "text",
    [
        f"{UFW_REDIRECTS}=0\nnet/ipv4/tcp_syncookies=1\rkernel/kptr_restrict=0\n",
        f"{UFW_REDIRECTS}=0\r\nnet/ipv4/tcp_syncookies=1\r\n",
    ],
)
def test_a_restore_never_writes_into_a_file_with_a_carriage_return(text: str) -> None:
    restores = [{"path": UFW, "written": f"{UFW_REDIRECTS}=0", "original": f"{UFW_REDIRECTS}=1"}]
    assert sysctl_config.restore_lines({UFW: text}, restores) == {UFW: text}


@pytest.mark.parametrize(
    ("texts", "restores"),
    [({}, ["x"]), ({}, None), ({}, "x"), (None, []), ([], []), ({}, [None])],
)
def test_malformed_input_of_a_restore_is_refused(texts: object, restores: object) -> None:
    with pytest.raises(sysctl_config.ConfigError):
        sysctl_config.restore_lines(
            cast("dict[str, object]", texts), cast("list[object]", restores)
        )
