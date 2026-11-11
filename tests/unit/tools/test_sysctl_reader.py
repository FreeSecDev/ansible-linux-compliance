"""The generator of the sysctl reader verdicts (FREES-107): cases written, the tree read back."""

from __future__ import annotations

import base64
import json
import runpy
import stat
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
    for image, program in (
        ("ubuntu", "systemd"),
        ("ubuntu", "procps"),
        ("rhel_compatible", "procps"),
    ):
        (raw / image / f"mixed.{program}.status").write_text("done\n", encoding="utf-8")


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
    with pytest.raises(sysctl_reader.CaseError, match="no file, link, directory or FIFO"):
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
            "timed_out": [],
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


RATE = "kernel.perf_event_max_sample_rate"
CPU = "kernel.perf_cpu_time_max_percent"
RATE_PATH = "/proc/sys/kernel/perf_event_max_sample_rate"
CPU_PATH = "/proc/sys/kernel/perf_cpu_time_max_percent"
TRACED: dict[str, dict[str, object]] = {
    "perf": {
        "keys": [RATE, CPU],
        "trace": [RATE, CPU],
        "files": [
            {"path": "etc/sysctl.d/10-a.conf", "text": f"{CPU} = 0\n{RATE} = 1\n{CPU} = 1\n"},
            {"path": "etc/sysctl.d/50-fifo.conf", "fifo": True},
        ],
    }
}
PROGRAMS = (("ubuntu", "systemd"), ("ubuntu", "procps"), ("rhel_compatible", "procps"))


def trace_record(writes: list[tuple[str, bytes]]) -> str:
    """Return a trace as sysctl_trace.py writes it."""
    return "".join(f"{path}\t{base64.b64encode(data).decode()}\n" for path, data in writes)


def write_traced(
    raw: Path, writes: list[tuple[str, bytes]], status: str = "done", rate: bytes = b"1\n"
) -> None:
    """Write the tree, status and trace of every reader for the case ``perf``."""
    for image, program in PROGRAMS:
        (raw / image).mkdir(parents=True, exist_ok=True)
        values = {
            "kernel/perf_event_max_sample_rate": rate,
            "kernel/perf_cpu_time_max_percent": b"1\n",
        }
        (raw / image / f"perf.{program}.values").write_text(tree(values), encoding="utf-8")
        (raw / image / f"perf.{program}.status").write_text(f"{status}\n", encoding="utf-8")
        (raw / image / f"perf.{program}.writes").write_text(trace_record(writes), encoding="utf-8")


def test_a_traced_case_gets_its_trace_list_and_a_fifo(tmp_path: Path) -> None:
    sysctl_reader.materialise(TRACED, tmp_path)
    assert (tmp_path / "perf" / "trace.list").read_text(encoding="utf-8").split() == [
        RATE_PATH,
        CPU_PATH,
    ]
    assert stat.S_ISFIFO(
        (tmp_path / "perf" / "root" / "etc" / "sysctl.d" / "50-fifo.conf").lstat().st_mode
    )
    assert not (tmp_path / "mixed").exists()


def test_a_traced_key_must_be_a_key_of_the_case(tmp_path: Path) -> None:
    cases: dict[str, dict[str, object]] = {"bad": {"keys": [RATE], "trace": [CPU], "files": []}}
    with pytest.raises(sysctl_reader.CaseError, match="not a key of the case"):
        sysctl_reader.materialise(cases, tmp_path)


def test_the_writes_of_a_traced_case_become_part_of_its_verdict(tmp_path: Path) -> None:
    writes = [(CPU_PATH, b"0\n"), (RATE_PATH, b"1\n"), (CPU_PATH, b"1\n")]
    write_traced(tmp_path, writes)
    verdict = sysctl_reader.parse(TRACED, tmp_path)["perf"]
    recorded = [[CPU, "0"], [RATE, "1"], [CPU, "1"]]
    assert verdict == {
        **{reader: {RATE: "1", CPU: "1"} for reader in ("systemd", "procps-4", "procps-3")},
        "timed_out": [],
        "writes": dict.fromkeys(("systemd", "procps-4", "procps-3"), recorded),
    }


def test_a_trace_that_misses_the_value_of_the_tree_is_refused(tmp_path: Path) -> None:
    write_traced(tmp_path, [(CPU_PATH, b"1\n")])
    with pytest.raises(
        sysctl_reader.CaseError, match=r"the trace of kernel\.perf_event_max_sample_rate"
    ):
        sysctl_reader.parse(TRACED, tmp_path)


def test_a_reader_stopped_after_its_time_is_named_and_its_trace_not_checked(tmp_path: Path) -> None:
    write_traced(tmp_path, [(CPU_PATH, b"1\n")], status="timeout", rate=b"9\n")
    verdict = sysctl_reader.parse(TRACED, tmp_path)["perf"]
    assert verdict["timed_out"] == ["procps-3", "procps-4", "systemd"]
    assert verdict["systemd"] == {RATE: None, CPU: "1"}


def test_a_trace_of_a_key_that_the_case_does_not_trace_is_refused(tmp_path: Path) -> None:
    write_traced(tmp_path, [("/proc/sys/kernel/dmesg_restrict", b"1\n")])
    with pytest.raises(sysctl_reader.CaseError, match="which the case does not trace"):
        sysctl_reader.parse(TRACED, tmp_path)


def test_a_status_other_than_done_or_timeout_is_refused(tmp_path: Path) -> None:
    write_traced(tmp_path, [], status="maybe")
    with pytest.raises(sysctl_reader.CaseError, match="holds 'maybe'"):
        sysctl_reader.parse(TRACED, tmp_path)
