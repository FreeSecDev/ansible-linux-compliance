from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditrules,
    process,
)
from ansible_collections.freesecdev.linux_compliance.plugins.modules import audit_control

if TYPE_CHECKING:
    from collections.abc import Mapping

MODULE_FILE = Path(__file__).resolve().parents[4] / "plugins" / "modules" / "audit_control.py"

STATUS = b"enabled 1\nfailure 1\npid 726\nbacklog 0\n"
LOCKED = b"enabled 2\nfailure 1\npid 726\n"
STOPPED = b"enabled 1\nfailure 1\npid 0\n"
LISTED = b"-w /etc/localtime -p wa -k time-change\n"


def result(
    returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"", *, timed_out: bool = False
) -> process.CommandResult:
    return process.CommandResult(
        argv=("/usr/sbin/tool",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.01,
        timed_out=timed_out,
    )


class Fake:
    """Answers each command from a queue and records it after checking the shipped policy."""

    def __init__(self, answers: list[process.CommandResult]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def __call__(self, spec: process.CommandSpec) -> process.CommandResult:
        assert process.check_policy(spec).name == spec.executable
        self.calls.append((spec.executable, spec.args))
        return self.answers.pop(0)


def install(
    monkeypatch: pytest.MonkeyPatch,
    answers: list[process.CommandResult],
    files: list[dict[str, object]] | None = None,
    *,
    found: bool = True,
) -> Fake:
    fake = Fake(answers)

    def resolve(name: str) -> str:
        if not found:
            message = f"{name} not found"
            raise process.ProcessExecutionError(message)
        return f"/usr/sbin/{name}"

    monkeypatch.setattr(process, "resolve_executable", resolve)
    monkeypatch.setattr(process, "run", fake)
    monkeypatch.setattr(auditrules, "read_rule_files", lambda: list(files or []))
    return fake


def run(
    capsys: pytest.CaptureFixture[str], arguments: Mapping[str, object]
) -> tuple[int, dict[str, object]]:
    capsys.readouterr()
    with patch_module_args(dict(arguments)), pytest.raises(SystemExit) as raised:
        audit_control.main()
    output = capsys.readouterr().out
    return int(cast("int", raised.value.code)), cast("dict[str, object]", json.loads(output))


def test_status_reads_the_kernel_the_rules_and_the_files(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    files: list[dict[str, object]] = [
        {"path": "/etc/audit/rules.d/a.rules", "regular": True, "lines": ["-w /x -p wa -k x"]}
    ]
    fake = install(monkeypatch, [result(stdout=STATUS), result(stdout=LISTED)], files)
    code, output = run(
        capsys,
        {
            "action": "status",
            "expect": ["-w /etc/localtime -p wa -k time-change", "-w /y -p wa -k y"],
        },
    )
    assert code == 0
    assert output["changed"] is False
    assert output["available"] is True
    assert output["kernel"] is True
    assert output["enabled"] == 1
    assert output["pid"] == 726
    assert output["rules"] == ["-w /etc/localtime -p wa -k time-change"]
    assert output["files"] == files
    assert output["missing"] == ["-w /y -p wa -k y"]
    assert fake.calls == [("auditctl", ("-s",)), ("auditctl", ("-l",))]


def test_status_without_auditctl_reports_it_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(monkeypatch, [], found=False)
    code, output = run(capsys, {"action": "status", "expect": ["-w /x -p wa -k x"]})
    assert code == 0
    assert output["available"] is False
    assert output["kernel"] is False
    assert output["missing"] == ["-w /x -p wa -k x"]
    assert fake.calls == []


@pytest.mark.parametrize(
    "answer",
    [
        result(returncode=1, stderr=b"Error sending status request (Operation not permitted)"),
        result(stdout=b"garbage"),
        result(stdout=STATUS, timed_out=True),
    ],
)
def test_status_in_a_container_reports_no_kernel(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answer: process.CommandResult,
) -> None:
    install(monkeypatch, [answer])
    code, output = run(capsys, {"action": "status"})
    assert code == 0
    assert output["kernel"] is False
    assert output["enabled"] is None
    assert output["rules"] == []


def test_status_fails_when_the_listing_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install(monkeypatch, [result(stdout=STATUS), result(returncode=1, stderr=b"boom")])
    code, output = run(capsys, {"action": "status"})
    assert code == 1
    assert "auditctl -l failed" in str(output["msg"])


def test_status_fails_when_the_rule_files_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install(monkeypatch, [])

    def refuse() -> list[dict[str, object]]:
        message = "/etc/audit/rules.d is not a directory"
        raise auditrules.RulesFileError(message)

    monkeypatch.setattr(auditrules, "read_rule_files", refuse)
    code, output = run(capsys, {"action": "status"})
    assert code == 1
    assert "not a directory" in str(output["msg"])


def test_an_unsafe_auditctl_fails_the_module(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install(monkeypatch, [])

    def unsafe(name: str) -> str:
        message = f"executable is writable by group or others: {name}"
        raise process.ProcessPolicyError(message)

    monkeypatch.setattr(process, "resolve_executable", unsafe)
    code, output = run(capsys, {"action": "status"})
    assert code == 1
    assert "writable by group or others" in str(output["msg"])


def test_a_process_error_fails_the_module(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install(monkeypatch, [])

    def broken(spec: process.CommandSpec) -> process.CommandResult:
        message = f"cannot start {spec.executable}"
        raise process.ProcessExecutionError(message)

    monkeypatch.setattr(process, "run", broken)
    code, output = run(capsys, {"action": "status"})
    assert code == 1
    assert "cannot start" in str(output["msg"])


def test_load_runs_augenrules_and_checks_the_expected_rules(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(
        monkeypatch,
        [
            result(stdout=STATUS),
            result(stdout=b"No rules\n"),
            result(stdout=b"No rules\n" + STATUS),
            result(stdout=STATUS),
            result(stdout=LISTED),
        ],
    )
    code, output = run(
        capsys, {"action": "load", "expect": ["-w /etc/localtime -p wa -k time-change"]}
    )
    assert code == 0
    assert output["changed"] is True
    assert output["ran"] is True
    assert output["loaded"] is True
    assert output["missing"] == []
    assert fake.calls == [
        ("auditctl", ("-s",)),
        ("auditctl", ("-l",)),
        ("augenrules", ("--load",)),
        ("auditctl", ("-s",)),
        ("auditctl", ("-l",)),
    ]


@pytest.mark.parametrize(
    ("loading", "listed", "words"),
    [
        (
            result(returncode=1, stderr=b"Error sending add rule data request (Rule exists)"),
            LISTED,
            "exited with 1",
        ),
        (result(), b"No rules\n", "Not loaded afterwards"),
        (result(timed_out=True, returncode=-9), LISTED, "did not finish in time"),
    ],
)
def test_load_reports_a_failed_load(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    loading: process.CommandResult,
    listed: bytes,
    words: str,
) -> None:
    install(
        monkeypatch,
        [
            result(stdout=STATUS),
            result(stdout=b""),
            loading,
            result(stdout=STATUS),
            result(stdout=listed),
        ],
    )
    code, output = run(
        capsys, {"action": "load", "expect": ["-w /etc/localtime -p wa -k time-change"]}
    )
    assert code == 0
    assert output["changed"] is True
    assert output["loaded"] is False
    assert words in str(output["message"])


def test_load_refuses_a_rule_set_with_a_rule_held_twice(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    files: list[dict[str, object]] = [
        {"path": "/etc/audit/rules.d/a.rules", "lines": ["-w /x -p wa -k x"]},
        {"path": "/etc/audit/rules.d/b.rules", "lines": ["-w /x -p wa -k x"]},
    ]
    fake = install(monkeypatch, [result(stdout=STATUS), result(stdout=LISTED)], files)
    code, output = run(capsys, {"action": "load", "expect": ["-w /x -p wa -k x"]})
    assert code == 0
    assert output["changed"] is False
    assert output["ran"] is False
    assert output["loaded"] is False
    assert output["duplicates"] == [
        {
            "line": "-w /x -p wa -k x",
            "paths": ["/etc/audit/rules.d/a.rules", "/etc/audit/rules.d/b.rules"],
        }
    ]
    assert "a.rules, /etc/audit/rules.d/b.rules" in str(output["message"])
    assert output["missing"] == ["-w /x -p wa -k x"]
    assert ("augenrules", ("--load",)) not in fake.calls


@pytest.mark.parametrize(
    ("answers", "words"),
    [
        ([result(stdout=LOCKED), result(stdout=LISTED)], "locked"),
        ([result(returncode=1, stderr=b"Operation not permitted")], "cannot be read"),
    ],
)
def test_load_refuses_locked_rules_and_a_kernel_it_cannot_read(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answers: list[process.CommandResult],
    words: str,
) -> None:
    fake = install(monkeypatch, answers)
    code, output = run(capsys, {"action": "load"})
    assert code == 0
    assert output["loaded"] is False
    assert output["ran"] is False
    assert words in str(output["message"])
    assert all(call[0] == "auditctl" for call in fake.calls)


def test_load_in_check_mode_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(monkeypatch, [result(stdout=STATUS), result(stdout=LISTED)])
    code, output = run(capsys, {"action": "load", "_ansible_check_mode": True})
    assert code == 0
    assert output["changed"] is False
    assert output["loaded"] is False
    assert "check mode" in str(output["message"])
    assert ("augenrules", ("--load",)) not in fake.calls


def test_load_without_auditctl_loads_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install(monkeypatch, [], found=False)
    code, output = run(capsys, {"action": "load", "expect": ["-w /x -p wa -k x"]})
    assert code == 0
    assert output["available"] is False
    assert output["loaded"] is False
    assert output["missing"] == ["-w /x -p wa -k x"]


def test_load_fails_when_the_rule_files_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install(monkeypatch, [])

    def refuse() -> list[dict[str, object]]:
        message = "too many files"
        raise auditrules.RulesFileError(message)

    monkeypatch.setattr(auditrules, "read_rule_files", refuse)
    code, output = run(capsys, {"action": "load"})
    assert code == 1
    assert "too many files" in str(output["msg"])


def test_reload_signals_a_running_auditd_and_checks_that_it_still_runs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(
        monkeypatch,
        [
            result(stdout=STATUS),
            result(stdout=LISTED),
            result(),
            result(stdout=STATUS),
            result(stdout=LISTED),
        ],
    )
    code, output = run(capsys, {"action": "reload"})
    assert code == 0
    assert output["changed"] is True
    assert output["reloaded"] is True
    assert ("auditctl", ("--signal", "reload")) in fake.calls


def test_reload_reports_an_auditd_that_did_not_survive(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install(
        monkeypatch,
        [
            result(stdout=STATUS),
            result(stdout=LISTED),
            result(),
            result(stdout=STOPPED),
            result(stdout=b""),
        ],
    )
    code, output = run(capsys, {"action": "reload"})
    assert code == 0
    assert output["reloaded"] is False


@pytest.mark.parametrize(
    "answers",
    [
        [result(stdout=STOPPED), result(stdout=b"")],
        [result(returncode=1, stderr=b"Operation not permitted")],
    ],
)
def test_reload_does_nothing_without_a_running_auditd(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answers: list[process.CommandResult],
) -> None:
    fake = install(monkeypatch, answers)
    code, output = run(capsys, {"action": "reload"})
    assert code == 0
    assert output["reloaded"] is False
    assert output["message"] == "auditd is not running"
    assert ("auditctl", ("--signal", "reload")) not in fake.calls


def test_reload_in_check_mode_and_without_auditctl_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = install(monkeypatch, [result(stdout=STATUS), result(stdout=LISTED)])
    code, output = run(capsys, {"action": "reload", "_ansible_check_mode": True})
    assert code == 0
    assert output["reloaded"] is False
    assert output["changed"] is False
    assert ("auditctl", ("--signal", "reload")) not in fake.calls
    install(monkeypatch, [], found=False)
    code, output = run(capsys, {"action": "reload"})
    assert code == 0
    assert output["available"] is False
    assert output["reloaded"] is False


@pytest.mark.parametrize(
    "expect",
    [
        ["w /x"],
        ["-w /x\n-D"],
        ["-" + "x" * 5000],
        ["-w /x\x00"],
        ["-w /x"] * 513,
    ],
)
def test_malformed_expected_rules_fail_the_module(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], expect: list[str]
) -> None:
    fake = install(monkeypatch, [])
    code, output = run(capsys, {"action": "status", "expect": expect})
    assert code == 1
    assert output["changed"] is False
    assert fake.calls == []


def test_expected_rules_of_another_type_are_refused() -> None:
    with pytest.raises(ValueError, match="one line"):
        audit_control.expected([1])
    assert audit_control.expected("not a list") == []


def test_printable_collapses_control_characters_and_bounds_the_text() -> None:
    assert audit_control.printable("a\x00\x01b\nc") == "a b c"
    assert len(audit_control.printable("x" * 5000)) == audit_control.MAX_MESSAGE


def test_the_rule_files_are_read_from_the_real_directory(tmp_path: Path) -> None:
    assert auditrules.read_rule_files(str(tmp_path / "none")) == []


def test_the_module_runs_as_a_script(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, [result(stdout=STATUS), result(stdout=LISTED)])
    spec = importlib.util.spec_from_file_location("__main__", MODULE_FILE)
    assert spec is not None
    assert spec.loader is not None
    capsys.readouterr()
    with patch_module_args({"action": "status"}), pytest.raises(SystemExit) as raised:
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    assert raised.value.code == 0
