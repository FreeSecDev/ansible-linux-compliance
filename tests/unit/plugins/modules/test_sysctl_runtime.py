from __future__ import annotations

import functools
import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import sysctl
from ansible_collections.freesecdev.linux_compliance.plugins.modules import sysctl_runtime

if TYPE_CHECKING:
    from collections.abc import Mapping

MODULE_FILE = Path(__file__).resolve().parents[4] / "plugins" / "modules" / "sysctl_runtime.py"
REAL_READ = sysctl.read
REAL_WRITE = sysctl.write
REAL_WRITABLE = sysctl.writable
REAL_EXPAND = sysctl.expand
IO_ERROR = "io_error"


@pytest.fixture
def proc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "sys"
    values = {
        ("kernel", "dmesg_restrict"): "0\n",
        ("net", "ipv4", "ip_forward"): "1\n",
        ("net", "ipv4", "conf", "all", "forwarding"): "1\n",
        ("net", "ipv4", "conf", "lo", "forwarding"): "1\n",
        ("net", "ipv4", "conf", "eth0", "forwarding"): "0\n",
        ("net", "ipv4", "ip_local_port_range"): "32768\t60999\n",
    }
    for parts, value in values.items():
        path = root.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="ascii")
    monkeypatch.setattr(sysctl, "read", functools.partial(REAL_READ, proc_root=root))
    monkeypatch.setattr(sysctl, "write", functools.partial(REAL_WRITE, proc_root=root))
    monkeypatch.setattr(sysctl, "writable", functools.partial(REAL_WRITABLE, proc_root=root))
    monkeypatch.setattr(sysctl, "expand", functools.partial(REAL_EXPAND, proc_root=root))
    return root


def run(
    capsys: pytest.CaptureFixture[str], arguments: Mapping[str, object]
) -> tuple[int, dict[str, object]]:
    capsys.readouterr()
    with patch_module_args(dict(arguments)), pytest.raises(SystemExit) as raised:
        sysctl_runtime.main()
    output = capsys.readouterr().out
    return int(cast("int", raised.value.code)), cast("dict[str, object]", json.loads(output))


@pytest.mark.usefixtures("proc")
def test_read_expands_wildcards_and_reports_absent_parameters(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, outcome = run(
        capsys,
        {
            "read": ["kernel.dmesg_restrict", "net.ipv4.conf.*.forwarding", "kernel.missing"],
            "probe": ["kernel.dmesg_restrict", "kernel.gone"],
        },
    )
    assert code == 0
    assert outcome["changed"] is False
    assert outcome["running"] == {
        "kernel.dmesg_restrict": "0",
        "net.ipv4.conf.all.forwarding": "1",
        "net.ipv4.conf.eth0.forwarding": "0",
        "net.ipv4.conf.lo.forwarding": "1",
        "kernel.missing": None,
        "kernel.gone": None,
    }
    assert outcome["writable"] == {"kernel.dmesg_restrict": True, "kernel.gone": False}
    assert outcome["set"] == []


def test_set_writes_changed_values_in_order(proc: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, outcome = run(
        capsys,
        {
            "set": [
                {"name": "kernel.dmesg_restrict", "value": "1"},
                {"name": "net.ipv4.ip_local_port_range", "value": "32768 60999"},
                {"name": "net.ipv4.conf.eth0.forwarding", "value": "1"},
            ]
        },
    )
    assert code == 0
    assert outcome["changed"] is True
    assert outcome["set"] == [
        {"name": "kernel.dmesg_restrict", "before": "0", "after": "1", "changed": True},
        {
            "name": "net.ipv4.ip_local_port_range",
            "before": "32768\t60999",
            "after": "32768\t60999",
            "changed": False,
        },
        {"name": "net.ipv4.conf.eth0.forwarding", "before": "0", "after": "1", "changed": True},
    ]
    assert (proc / "kernel" / "dmesg_restrict").read_text() == "1\n"
    assert cast("dict[str, str]", outcome["running"])["kernel.dmesg_restrict"] == "0"


def test_each_value_is_read_just_before_it_is_set(
    proc: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def propagating(name: str, value: str) -> None:
        REAL_WRITE(name, value, proc_root=proc)
        if name == "net.ipv4.ip_forward":
            for interface in ("all", "lo", "eth0"):
                REAL_WRITE(f"net.ipv4.conf.{interface}.forwarding", value, proc_root=proc)

    monkeypatch.setattr(sysctl, "write", propagating)
    code, outcome = run(
        capsys,
        {
            "set": [
                {"name": "net.ipv4.ip_forward", "value": "0"},
                {"name": "net.ipv4.conf.lo.forwarding", "value": "1"},
            ]
        },
    )
    assert code == 0
    entries = cast("list[dict[str, object]]", outcome["set"])
    assert entries[1] == {
        "name": "net.ipv4.conf.lo.forwarding",
        "before": "0",
        "after": "1",
        "changed": True,
    }
    assert (proc / "net" / "ipv4" / "conf" / "lo" / "forwarding").read_text() == "1\n"
    assert (proc / "net" / "ipv4" / "conf" / "eth0" / "forwarding").read_text() == "0\n"


def test_check_mode_reports_and_writes_nothing(
    proc: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, outcome = run(
        capsys,
        {"_ansible_check_mode": True, "set": [{"name": "kernel.dmesg_restrict", "value": "1"}]},
    )
    assert code == 0
    assert outcome["changed"] is True
    assert outcome["set"] == [
        {"name": "kernel.dmesg_restrict", "before": "0", "after": "0", "changed": True}
    ]
    assert (proc / "kernel" / "dmesg_restrict").read_text() == "0\n"


@pytest.mark.usefixtures("proc")
def test_an_absent_parameter_fails_and_names_the_values_already_set(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, outcome = run(
        capsys,
        {
            "set": [
                {"name": "kernel.dmesg_restrict", "value": "1"},
                {"name": "kernel.missing", "value": "1"},
            ]
        },
    )
    assert code == 1
    assert outcome["failed"] is True
    assert outcome["changed"] is True
    assert outcome["changed_names"] == ["kernel.dmesg_restrict"]
    assert "kernel.missing does not exist" in str(outcome["msg"])
    assert "values changed by this run: kernel.dmesg_restrict" in str(outcome["msg"])


def test_a_value_that_the_kernel_does_not_keep_is_written_back(
    proc: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def clamping(name: str, value: str) -> None:
        REAL_WRITE(name, "5" if value == "9" else value, proc_root=proc)

    monkeypatch.setattr(sysctl, "write", clamping)
    code, outcome = run(capsys, {"set": [{"name": "kernel.dmesg_restrict", "value": "9"}]})
    assert code == 1
    assert outcome["changed"] is False
    assert "the kernel kept '5'" in str(outcome["msg"])
    assert "was written back" in str(outcome["msg"])
    assert (proc / "kernel" / "dmesg_restrict").read_text() == "0\n"


def test_a_value_that_cannot_be_written_back_is_reported_as_changed(
    proc: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def one_way(name: str, value: str) -> None:
        if value == "0":
            raise sysctl.SysctlError(IO_ERROR, f"cannot write {name}: Invalid argument")
        REAL_WRITE(name, "5", proc_root=proc)

    monkeypatch.setattr(sysctl, "write", one_way)
    code, outcome = run(capsys, {"set": [{"name": "kernel.dmesg_restrict", "value": "1"}]})
    assert code == 1
    assert outcome["changed"] is True
    assert outcome["changed_names"] == ["kernel.dmesg_restrict"]
    assert "could not be written back" in str(outcome["msg"])


@pytest.mark.usefixtures("proc")
def test_a_refused_write_fails_without_a_change(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(name: str, _value: str) -> None:
        raise sysctl.SysctlError(IO_ERROR, f"cannot write {name}: Read-only file system")

    monkeypatch.setattr(sysctl, "write", refused)
    code, outcome = run(capsys, {"set": [{"name": "kernel.dmesg_restrict", "value": "1"}]})
    assert code == 1
    assert outcome["changed"] is False
    assert outcome["reason"] == "not_set"
    assert "Read-only file system" in str(outcome["msg"])


def test_a_read_error_while_setting_fails(
    proc: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def failing(name: str) -> str | None:
        calls.append(name)
        if len(calls) > 1:
            raise sysctl.SysctlError(IO_ERROR, f"cannot read {name}")
        return REAL_READ(name, proc_root=proc)

    monkeypatch.setattr(sysctl, "read", failing)
    code, outcome = run(capsys, {"set": [{"name": "kernel.dmesg_restrict", "value": "1"}]})
    assert code == 1
    assert "cannot read kernel.dmesg_restrict" in str(outcome["msg"])


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"read": ["kernel..x"]}, "not a kernel parameter name"),
        ({"probe": ["net.ipv4.conf.*.forwarding"]}, "wildcard"),
        ({"set": [{"name": "net.*.x", "value": "1"}]}, "wildcard"),
        ({"set": [{"name": "kernel.dmesg_restrict", "value": "1\n"}]}, "printable"),
        ({"read": ["kernel.x"] * 257}, "at most 256"),
        ({"set": [{"name": "kernel.x", "value": "1"}] * 257}, "at most 256"),
    ],
)
def test_invalid_arguments_fail_before_anything_is_read(
    proc: Path, capsys: pytest.CaptureFixture[str], arguments: dict[str, object], message: str
) -> None:
    code, outcome = run(capsys, arguments)
    assert code == 1
    assert outcome["changed"] is False
    assert message in str(outcome["msg"])
    assert (proc / "kernel" / "dmesg_restrict").read_text() == "0\n"


@pytest.mark.usefixtures("proc")
def test_the_module_runs_as_a_script(capsys: pytest.CaptureFixture[str]) -> None:
    spec = importlib.util.spec_from_file_location("__main__", MODULE_FILE)
    assert spec is not None
    assert spec.loader is not None
    capsys.readouterr()
    with (
        patch_module_args({"read": ["kernel.dmesg_restrict"]}),
        pytest.raises(SystemExit) as raised,
    ):
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    assert raised.value.code == 0
