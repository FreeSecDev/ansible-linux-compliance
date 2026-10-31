"""The generator of the sysctl reader verdicts (FREES-107): cases written, reader output parsed."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from tools.molecule import sysctl_reader

RP_FILTER = "net.ipv4.conf.all.rp_filter"
CASES: dict[str, dict[str, object]] = {
    "mixed": {
        "keys": [RP_FILTER, "kernel.dmesg_restrict"],
        "files": [
            {"path": "etc/sysctl.d/10-a.conf", "text": f"{RP_FILTER} = 1\n"},
            {
                "path": "etc/sysctl.d/20-long.conf",
                "long_key": RP_FILTER,
                "long_value": "2",
                "padding": 3,
            },
            {"path": "etc/sysctl.d/30-mask.conf", "link": "/dev/null"},
            {"path": "etc/sysctl.d/40-dir.conf", "directory": True},
        ],
    }
}
SYSTEMD_LOG = (
    "Setting '/proc/sys/net/ipv4/conf/all/rp_filter' to '1'\n"
    "Couldn't write '1' to 'net/ipv4/conf/all/rp_filter', ignoring: Read-only file system\n"
    "Setting '/proc/sys/net/ipv4/conf/all/rp_filter' to '2\f'\n"
    "Setting '/proc/sys/kernel/printk' to '4 4 1 7'\n"
)
PROCPS_4_LOG = (
    "* Applying /etc/sysctl.d/10-a.conf ...\n"
    'sysctl: setting key "net.ipv4.conf.all.rp_filter", ignoring: Read-only file system\n'
    "net.ipv4.conf.all.rp_filter = 1\n"
    "kernel.printk = 4 4 1 7\n"
    "net.ipv4.conf.all.rp_filter = 2\n"
)
PROCPS_3_LOG = (
    "* Applying /etc/sysctl.d/10-a.conf ...\n"
    'sysctl: permission denied on key "net.ipv4.conf.all.rp_filter"\n'
    'sysctl: permission denied on key "kernel.printk"\n'
    'sysctl: permission denied on key "net.ipv4.conf.all.rp_filter", ignoring\n'
    "net.ipv4.conf.all.rp_filter = 0\n"
)


def write_raw(raw: Path) -> None:
    """Write the reader logs of the case ``mixed`` as the containers would."""
    (raw / "ubuntu").mkdir(parents=True)
    (raw / "rhel_compatible").mkdir(parents=True)
    (raw / "ubuntu" / "mixed.systemd.log").write_text(SYSTEMD_LOG, encoding="utf-8")
    (raw / "ubuntu" / "mixed.procps.log").write_text(PROCPS_4_LOG, encoding="utf-8")
    (raw / "rhel_compatible" / "mixed.procps.log").write_text(PROCPS_3_LOG, encoding="utf-8")


def test_a_case_is_written_with_files_links_and_directories(tmp_path: Path) -> None:
    sysctl_reader.materialise(CASES, tmp_path)
    root = tmp_path / "mixed" / "root" / "etc" / "sysctl.d"
    assert (root / "10-a.conf").read_text(encoding="utf-8") == f"{RP_FILTER} = 1\n"
    assert (root / "20-long.conf").read_text(encoding="utf-8") == f"{RP_FILTER} =    2\n"
    assert (root / "30-mask.conf").readlink() == Path("/dev/null")
    assert (root / "40-dir.conf").is_dir()


def test_an_entry_of_no_kind_is_refused(tmp_path: Path) -> None:
    cases: dict[str, dict[str, object]] = {"bad": {"keys": [], "files": [{"path": "etc/x.conf"}]}}
    with pytest.raises(sysctl_reader.CaseError, match="neither a file"):
        sysctl_reader.materialise(cases, tmp_path)


def test_a_fixture_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "cases.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(sysctl_reader.CaseError, match="object of cases"):
        sysctl_reader.load_cases(path)


def test_the_readers_output_becomes_the_verdicts(tmp_path: Path) -> None:
    write_raw(tmp_path)
    assert sysctl_reader.parse(CASES, tmp_path) == {
        "mixed": {
            "systemd": {RP_FILTER: "2\f", "kernel.dmesg_restrict": None},
            "procps-4": [[RP_FILTER, "1"], [RP_FILTER, "2"]],
            "procps-3": [[RP_FILTER, None], [RP_FILTER, None]],
        }
    }


def test_the_tool_runs_both_commands_as_a_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps(CASES), encoding="utf-8")
    write_raw(tmp_path / "raw")
    verdicts = tmp_path / "verdicts.json"
    assert sysctl_reader.main(["materialise", str(cases), str(tmp_path / "out")]) == 0
    assert (tmp_path / "out" / "mixed" / "root" / "etc" / "sysctl.d" / "10-a.conf").is_file()
    monkeypatch.setattr(
        sys, "argv", ["sysctl_reader", "parse", str(cases), str(tmp_path / "raw"), str(verdicts)]
    )
    sys.modules.pop("tools.molecule.sysctl_reader", None)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("tools.molecule.sysctl_reader", run_name="__main__")
    assert exit_info.value.code == 0
    assert json.loads(verdicts.read_text(encoding="utf-8"))["mixed"]["procps-4"][-1] == [
        RP_FILTER,
        "2",
    ]
