"""The generator of the sysctl reader verdicts (FREES-107): cases written, the tree read back."""

from __future__ import annotations

import base64
import json
import runpy
import sys
from pathlib import Path

import pytest

from tools.molecule import sysctl_reader

RP_FILTER = "net.ipv4.conf.all.rp_filter"
CASES: dict[str, dict[str, object]] = {
    "mixed": {
        "keys": [RP_FILTER, "net.ipv4.conf.eth0.rp_filter", "kernel.dmesg_restrict"],
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


def tree(values: dict[str, bytes]) -> str:
    """Return a record of the tree as the container writes it."""
    return "".join(
        f"{path}\t{base64.b64encode(content).decode()}\n" for path, content in values.items()
    )


def write_raw(raw: Path) -> None:
    """Write what the readers left in the tree for the case ``mixed``."""
    (raw / "ubuntu").mkdir(parents=True)
    (raw / "rhel_compatible").mkdir(parents=True)
    base = {
        "kernel/dmesg_restrict": b"9\n",
        "net/ipv4/conf/eth0/rp_filter": b"9\n",
    }
    (raw / "ubuntu" / "mixed.systemd.values").write_text(
        tree({**base, "net/ipv4/conf/all/rp_filter": b"2\f\n"}), encoding="utf-8"
    )
    (raw / "ubuntu" / "mixed.procps.values").write_text(
        tree({**base, "net/ipv4/conf/all/rp_filter": b"\n\n"}), encoding="utf-8"
    )
    (raw / "rhel_compatible" / "mixed.procps.values").write_text(
        tree({**base, "net/ipv4/conf/all/rp_filter": b"2\n", "kernel/dmesg_restrict": b"1\n"}),
        encoding="utf-8",
    )


def test_a_case_is_written_with_files_links_and_directories(tmp_path: Path) -> None:
    sysctl_reader.materialise(CASES, tmp_path)
    root = tmp_path / "mixed" / "root" / "etc" / "sysctl.d"
    assert (root / "10-a.conf").read_text(encoding="utf-8") == f"{RP_FILTER} = 1\n"
    assert (root / "20-long.conf").read_text(encoding="utf-8") == f"{RP_FILTER} =    2\n"
    assert (root / "30-mask.conf").readlink() == Path("/dev/null")
    assert (root / "40-dir.conf").is_dir()
    assert (tmp_path / "proc.list").read_text(encoding="utf-8").split() == [
        "kernel/dmesg_restrict",
        "net/ipv4/conf/all/rp_filter",
        "net/ipv4/conf/default/rp_filter",
        "net/ipv4/conf/eth0/rp_filter",
        "net/ipv4/conf/lo/rp_filter",
    ]


def test_an_entry_of_no_kind_is_refused(tmp_path: Path) -> None:
    cases: dict[str, dict[str, object]] = {"bad": {"keys": [], "files": [{"path": "etc/x.conf"}]}}
    with pytest.raises(sysctl_reader.CaseError, match="neither a file"):
        sysctl_reader.materialise(cases, tmp_path)


def test_a_fixture_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "cases.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(sysctl_reader.CaseError, match="object of cases"):
        sysctl_reader.load_cases(path)


def test_the_values_left_in_the_tree_become_the_verdicts(tmp_path: Path) -> None:
    write_raw(tmp_path)
    keys = {"net.ipv4.conf.eth0.rp_filter": None}
    assert sysctl_reader.parse(CASES, tmp_path) == {
        "mixed": {
            "systemd": {RP_FILTER: "2\f", "kernel.dmesg_restrict": None, **keys},
            "procps-4": {RP_FILTER: "", "kernel.dmesg_restrict": None, **keys},
            "procps-3": {RP_FILTER: "2", "kernel.dmesg_restrict": "1", **keys},
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
    arguments = ["sysctl_reader", "parse", str(cases), str(tmp_path / "raw"), str(verdicts)]
    monkeypatch.setattr(sys, "argv", arguments)
    sys.modules.pop("tools.molecule.sysctl_reader", None)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("tools.molecule.sysctl_reader", run_name="__main__")
    assert exit_info.value.code == 0
    assert json.loads(verdicts.read_text(encoding="utf-8"))["mixed"]["procps-3"][RP_FILTER] == "2"


def test_a_long_line_entry_holds_a_comment_of_that_many_bytes(tmp_path: Path) -> None:
    entry = {"path": "etc/sysctl.d/x.conf", "text": "a = 1\n@LONG_LINE@\nb = 2\n", "long_line": 5}
    cases: dict[str, dict[str, object]] = {"long": {"keys": [RP_FILTER], "files": [entry]}}
    sysctl_reader.materialise(cases, tmp_path)
    text = (tmp_path / "long" / "root" / "etc" / "sysctl.d" / "x.conf").read_text(encoding="utf-8")
    assert text == "a = 1\n#xxxx\nb = 2\n"


@pytest.mark.parametrize(
    "key",
    ["net.ipv4.conf.all.rp_filter/../../../x", "/net.ipv4", "kernel", "net..ipv4", "Net.ipv4"],
)
def test_a_key_that_the_role_refuses_is_refused(tmp_path: Path, key: str) -> None:
    cases: dict[str, dict[str, object]] = {"bad": {"keys": [key], "files": []}}
    with pytest.raises(sysctl_reader.CaseError, match="not a kernel parameter key"):
        sysctl_reader.materialise(cases, tmp_path)
