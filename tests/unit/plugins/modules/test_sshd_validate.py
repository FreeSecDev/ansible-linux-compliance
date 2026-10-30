from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    process,
)
from ansible_collections.freesecdev.linux_compliance.plugins.modules import sshd_validate

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

MODULE_FILE = Path(__file__).resolve().parents[4] / "plugins" / "modules" / "sshd_validate.py"


def result(
    returncode: int = 0,
    stderr: bytes = b"",
    stdout: bytes = b"",
    *,
    timed_out: bool = False,
) -> process.CommandResult:
    return process.CommandResult(
        argv=("/usr/sbin/sshd",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.01,
        timed_out=timed_out,
    )


class FakeRun:
    """Records each specification, checks it against the shipped policy and answers."""

    def __init__(self, answer: Callable[[], process.CommandResult]) -> None:
        self.answer = answer
        self.specs: list[process.CommandSpec] = []

    def __call__(self, spec: process.CommandSpec) -> process.CommandResult:
        assert process.check_policy(spec).name == "sshd"
        self.specs.append(spec)
        return self.answer()


def found(name: str) -> str:
    assert name == "sshd"
    return "/usr/sbin/sshd"


def install(monkeypatch: pytest.MonkeyPatch, fake: FakeRun) -> FakeRun:
    monkeypatch.setattr(process, "resolve_executable", found)
    monkeypatch.setattr(process, "run", fake)
    return fake


def run(
    capsys: pytest.CaptureFixture[str], arguments: Mapping[str, object]
) -> tuple[int, dict[str, object]]:
    capsys.readouterr()
    with patch_module_args(dict(arguments)), pytest.raises(SystemExit) as raised:
        sshd_validate.main()
    output = capsys.readouterr().out
    return int(cast("int", raised.value.code)), cast("dict[str, object]", json.loads(output))


def test_settings_become_options_in_order() -> None:
    assert sshd_validate.arguments(
        [
            {"keyword": "PermitRootLogin", "value": "no"},
            {"keyword": "Ciphers", "value": "aes256-gcm@openssh.com,aes128-ctr"},
            {"keyword": "MaxStartups", "value": "10:30:60"},
            {"keyword": "Banner", "value": "/etc/issue.net"},
        ]
    ) == [
        "PermitRootLogin=no",
        "Ciphers=aes256-gcm@openssh.com,aes128-ctr",
        "MaxStartups=10:30:60",
        "Banner=/etc/issue.net",
    ]


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ("PermitRootLogin=no", "must be a list"),
        ([{"keyword": "UsePAM", "value": "yes"}] * 31, "at most 30"),
        (["PermitRootLogin=no"], "must be a mapping"),
        ([{"keyword": "Include", "value": "/srv/x"}], "not a keyword of a native ssh rule"),
        ([{"keyword": "AuthorizedKeysCommand", "value": "/bin/x"}], "not a keyword"),
        ([{"keyword": "permitrootlogin", "value": "no"}], "not a keyword"),
        ([{"keyword": 1, "value": "no"}], "not a keyword"),
        ([{"keyword": "PermitRootLogin", "value": "-T"}], "one word"),
        ([{"keyword": "PermitRootLogin", "value": "no yes"}], "one word"),
        ([{"keyword": "PermitRootLogin", "value": "no\n"}], "one word"),
        ([{"keyword": "PermitRootLogin", "value": ""}], "one word"),
        ([{"keyword": "PermitRootLogin", "value": "x" * 1025}], "one word"),
        ([{"keyword": "PermitRootLogin"}], "one word"),
    ],
)
def test_settings_that_are_not_passed_to_sshd(settings: object, message: str) -> None:
    with pytest.raises(sshd_validate.SettingError, match=message):
        sshd_validate.arguments(settings)


def test_every_keyword_of_the_catalogue_is_accepted() -> None:
    root = Path(__file__).resolve().parents[4]
    text = (root / "roles" / "remediate" / "vars" / "rules.yml").read_text(encoding="utf-8")
    keywords = {
        line.split(":", 1)[1].strip().strip('"')
        for line in text.splitlines()
        if line.strip().startswith("keyword:")
    }
    assert len(keywords) == len(sshd_validate.KEYWORDS)
    assert keywords <= sshd_validate.KEYWORDS


def test_a_valid_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = install(monkeypatch, FakeRun(result))
    outcome = sshd_validate.validate(["PermitRootLogin=no", "MaxAuthTries=4"])
    assert outcome == {"available": True, "valid": True, "message": ""}
    assert fake.specs[0].executable == "sshd"
    assert fake.specs[0].args == (
        "-t",
        "-f",
        "/etc/ssh/sshd_config",
        "-o",
        "PermitRootLogin=no",
        "-o",
        "MaxAuthTries=4",
    )
    assert fake.specs[0].timeout_seconds == sshd_validate.TIMEOUT_SECONDS


def test_an_invalid_configuration_keeps_the_message_of_sshd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(
        monkeypatch,
        FakeRun(
            lambda: result(
                255,
                b"/etc/ssh/sshd_config.d/99-site.conf: line 1: Bad configuration option: Foo\n"
                b"\x1b[31mterminating\x00, 1 bad configuration options\n",
            )
        ),
    )
    outcome = sshd_validate.validate([])
    assert outcome["valid"] is False
    assert outcome["available"] is True
    assert outcome["message"] == (
        "/etc/ssh/sshd_config.d/99-site.conf: line 1: Bad configuration option: Foo "
        "[31mterminating , 1 bad configuration options"
    )


def test_the_message_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeRun(lambda: result(1, b"x" * 5000, b"y" * 5000)))
    outcome = sshd_validate.validate([])
    assert len(str(outcome["message"])) == sshd_validate.MAX_MESSAGE


def test_a_timeout_is_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeRun(lambda: result(0, timed_out=True)))
    outcome = sshd_validate.validate([])
    assert outcome["valid"] is False
    assert outcome["available"] is True
    assert "did not finish within 30 s" in str(outcome["message"])


def test_a_missing_sshd_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> str:
        message = f"executable not found in the trusted directories: {name!r}"
        raise process.ProcessExecutionError(message)

    fake = install(monkeypatch, FakeRun(result))
    monkeypatch.setattr(process, "resolve_executable", missing)
    outcome = sshd_validate.validate([])
    assert outcome == {
        "available": False,
        "valid": False,
        "message": "executable not found in the trusted directories: 'sshd'",
    }
    assert fake.specs == []


def test_an_unsafe_sshd_fails_the_module(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unsafe(name: str) -> str:
        message = f"executable is writable by group or others: {name!r}"
        raise process.ProcessPolicyError(message)

    fake = install(monkeypatch, FakeRun(result))
    monkeypatch.setattr(process, "resolve_executable", unsafe)
    code, outcome = run(capsys, {})
    assert code == 1
    assert outcome["failed"] is True
    assert outcome["changed"] is False
    assert "could not be run safely" in str(outcome["msg"])
    assert "writable by group or others" in str(outcome["msg"])
    assert fake.specs == []


def test_an_sshd_that_cannot_start_fails_the_module(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def cannot_start() -> process.CommandResult:
        message = "cannot start 'sshd': Permission denied"
        raise process.ProcessExecutionError(message)

    install(monkeypatch, FakeRun(cannot_start))
    code, outcome = run(capsys, {})
    assert code == 1
    assert outcome["failed"] is True
    assert "cannot start" in str(outcome["msg"])
    assert "available" not in outcome


def test_the_module_reports_without_change(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, FakeRun(result))
    code, outcome = run(capsys, {"settings": [{"keyword": "UsePAM", "value": "yes"}]})
    assert code == 0
    assert outcome["changed"] is False
    assert outcome["valid"] is True
    assert outcome["available"] is True
    assert outcome["arguments"] == ["UsePAM=yes"]


def test_check_mode_runs_the_same_read_only_test(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = install(monkeypatch, FakeRun(lambda: result(255, b"bad")))
    code, outcome = run(capsys, {"_ansible_check_mode": True})
    assert code == 0
    assert outcome["valid"] is False
    assert outcome["message"] == "bad"
    assert fake.specs[0].args == ("-t", "-f", "/etc/ssh/sshd_config")


def test_the_module_refuses_a_setting_before_running_sshd(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = install(monkeypatch, FakeRun(result))
    code, outcome = run(capsys, {"settings": [{"keyword": "Include", "value": "/srv/x"}]})
    assert code == 1
    assert outcome["failed"] is True
    assert outcome["changed"] is False
    assert "not a keyword" in str(outcome["msg"])
    assert fake.specs == []


def test_the_module_runs_as_a_script(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, FakeRun(result))
    spec = importlib.util.spec_from_file_location("__main__", MODULE_FILE)
    assert spec is not None
    assert spec.loader is not None
    capsys.readouterr()
    with patch_module_args({}), pytest.raises(SystemExit) as raised:
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    assert raised.value.code == 0
