from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    model,
    openscap,
    process,
    scanner,
)
from ansible_collections.freesecdev.linux_compliance.plugins.modules import compliance_scan

if TYPE_CHECKING:
    from collections.abc import Mapping

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "catalog"
MODULE_FILE = Path(__file__).resolve().parents[4] / "plugins" / "modules" / "compliance_scan.py"
SYNTHETIC = FIXTURES / "synthetic-ds.xml"
SHA256 = hashlib.sha256(SYNTHETIC.read_bytes()).hexdigest()
BENCHMARK = "xccdf_org.example.synthetic_benchmark_demo"
PROFILE = "xccdf_org.example.synthetic_profile_baseline"
ALPHA = "xccdf_org.example.synthetic_rule_alpha"
BETA = "xccdf_org.example.synthetic_rule_beta"
UID = os.getuid()


def results_xml(profile: str, results: Mapping[str, str]) -> str:
    rules = "".join(
        f'<rule-result idref="{rule}" severity="low"><result>{value}</result></rule-result>'
        for rule, value in results.items()
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{BENCHMARK}">'
        "<version>1.2.3</version>"
        '<TestResult id="xccdf_org.example.synthetic_testresult_demo" '
        'start-time="2026-10-25T10:00:00Z" end-time="2026-10-25T10:00:09Z">'
        f'<benchmark id="{BENCHMARK}"/><profile idref="{profile}"/>{rules}'
        "</TestResult></Benchmark>"
    )


class FakeRunner:
    """Stands in for process.run; never starts a process."""

    def __init__(self) -> None:
        self.results: dict[str, str] = {ALPHA: "pass", BETA: "fail"}
        self.returncode = 2
        self.timed_out = False
        self.calls = 0

    def __call__(self, spec: process.CommandSpec) -> process.CommandResult:
        self.calls += 1
        if spec.args != ("--version",):
            args = spec.args
            profile = args[args.index("--profile") + 1]
            Path(args[args.index("--results") + 1]).write_text(
                results_xml(profile, self.results), encoding="utf-8"
            )
        return process.CommandResult(
            argv=("/usr/bin/oscap",),
            returncode=0 if spec.args == ("--version",) else self.returncode,
            stdout=b"OpenSCAP command line tool (oscap) 1.3.10\n",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=0.1,
            timed_out=self.timed_out and spec.args != ("--version",),
        )


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    fake = FakeRunner()
    registry = scanner.BackendRegistry()
    registry.register("openscap", lambda settings: openscap.OpenScapBackend(settings, runner=fake))
    monkeypatch.setattr(
        audit,
        "Auditor",
        functools.partial(
            audit.Auditor,
            owner_uid=UID,
            registry=registry,
            clock=lambda: datetime.fromisoformat("2026-10-25T09:00:00+00:00"),
        ),
    )
    return fake


@pytest.fixture
def content(tmp_path: Path) -> Path:
    tmp_path.chmod(0o755)
    directory = tmp_path / "content"
    directory.mkdir()
    path = directory / "synthetic-ds.xml"
    shutil.copyfile(SYNTHETIC, path)
    return path


def arguments(content: Path, **overrides: object) -> dict[str, object]:
    return {
        "content_path": str(content),
        "expected_sha256": SHA256,
        "profile_id": PROFILE,
        "host": {
            "hostname": "web01",
            "distribution_id": "ubuntu",
            "distribution_version": "24.04",
            "architecture": "x86_64",
        },
        "output_dir": str(content.parent.parent / "evidence"),
        "run_id": "run-1",
        "scan_timeout": 60,
        **overrides,
    }


def run(
    capsys: pytest.CaptureFixture[str], given: Mapping[str, object]
) -> tuple[int, dict[str, Any]]:
    with patch_module_args(dict(given)), pytest.raises(SystemExit) as raised:
        compliance_scan.main()
    output = capsys.readouterr().out
    return int(cast("int", raised.value.code)), cast("dict[str, Any]", json.loads(output))


def test_a_scan_returns_findings_and_evidence_without_change(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    code, result = run(capsys, arguments(content))
    assert code == 0
    assert result["changed"] is False
    assert result["evidence_written"] is True
    assert result["run_status"] == "completed"
    assert result["summary"]["fail"] == 1
    assert result["summary"]["pass"] == 1
    findings = {item["rule_id"]: item["outcome"] for item in result["scan_run"]["findings"]}
    assert findings == {ALPHA: "pass", BETA: "fail"}
    assert result["scan_run"]["content"]["content_sha256"] == SHA256
    directory = Path(result["evidence"]["directory"])
    assert directory == content.parent.parent / "evidence" / "run-1"
    stored = model.loads((directory / "scan-run.json").read_text(encoding="utf-8"))
    assert stored.to_dict() == result["scan_run"]
    assert runner.calls == 2


def test_disabled_rules_are_reported_with_their_toggle(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    runner.results = {ALPHA: "notselected", BETA: "pass"}
    runner.returncode = 0
    code, result = run(capsys, arguments(content, disabled_rules=[{"rule_id": ALPHA}]))
    assert code == 0
    findings = {item["rule_id"]: item for item in result["scan_run"]["findings"]}
    assert findings[ALPHA]["outcome"] == "disabled"
    assert findings[ALPHA]["disabled_by"] == "linux_compliance_rule_alpha_enabled"
    assert findings[BETA]["outcome"] == "pass"
    assert result["disabled_rules"] == [
        {"rule_id": ALPHA, "disabled_by": "linux_compliance_rule_alpha_enabled"}
    ]


def test_an_incomplete_scan_fails_the_task_but_returns_the_evidence(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    runner.timed_out = True
    code, result = run(capsys, arguments(content))
    assert code == 1
    assert result["failed"] is True
    assert result["error_type"] == "scan_incomplete"
    assert result["changed"] is False
    assert result["run_status"] == "timed_out"
    assert result["evidence_written"] is True
    assert result["summary"]["error"] == 2
    assert result["summary"]["pass"] == 0
    assert {item["outcome"] for item in result["scan_run"]["findings"]} == {"error"}


def test_an_incomplete_scan_can_be_registered_for_a_later_decision(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    runner.returncode = 1
    code, result = run(capsys, arguments(content, fail_on_incomplete=False))
    assert code == 0
    assert result["run_status"] == "failed"
    assert result["summary"]["error"] == 2


def test_check_mode_reports_the_plan_and_runs_nothing(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    code, result = run(capsys, arguments(content, _ansible_check_mode=True))
    assert code == 0
    assert result["changed"] is False
    assert result["evidence_written"] is False
    assert result["run_status"] == "not_run"
    assert result["scan_run"] is None
    assert result["planned"]["expected_rule_count"] == 2
    assert "does not create it" in result["msg"]
    assert runner.calls == 0
    assert not (content.parent.parent / "evidence").exists()


def test_check_mode_with_an_existing_output_dir_returns_real_findings(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    root = content.parent.parent / "evidence"
    root.mkdir(mode=0o700)
    code, result = run(capsys, arguments(content, _ansible_check_mode=True))
    assert code == 0
    assert result["changed"] is False
    assert result["evidence_written"] is False
    assert result["evidence"] == {"directory": None, "files": []}
    assert result["run_status"] == "completed"
    findings = {item["rule_id"]: item["outcome"] for item in result["scan_run"]["findings"]}
    assert findings == {ALPHA: "pass", BETA: "fail"}
    assert "no evidence was kept" in result["msg"]
    assert runner.calls == 2
    assert list(root.iterdir()) == []


def test_an_incomplete_check_mode_scan_fails_and_keeps_nothing(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    root = content.parent.parent / "evidence"
    root.mkdir(mode=0o700)
    runner.timed_out = True
    code, result = run(capsys, arguments(content, _ansible_check_mode=True))
    assert code == 1
    assert result["error_type"] == "scan_incomplete"
    assert result["evidence_written"] is False
    assert list(root.iterdir()) == []


@pytest.mark.usefixtures("runner")
def test_the_default_run_identifier_is_generated(
    capsys: pytest.CaptureFixture[str], content: Path
) -> None:
    given = arguments(content, _ansible_check_mode=True)
    del given["run_id"]
    code, result = run(capsys, given)
    assert code == 0
    assert result["run_id"].endswith("Z")
    assert audit.check_run_id(result["run_id"]) == result["run_id"]


@pytest.mark.parametrize(
    ("overrides", "error_type"),
    [
        ({"expected_sha256": "0" * 64}, "digest_mismatch"),
        ({"profile_id": "xccdf_org.example.synthetic_profile_absent"}, "profile_not_found"),
        ({"profile_id": "--remediate"}, "invalid_argument"),
        ({"output_dir": "relative"}, "unsafe_output_dir"),
        ({"output_dir": "/var/../etc"}, "unsafe_output_dir"),
        ({"run_id": "../escape"}, "invalid_argument"),
        ({"scan_timeout": 7200}, "invalid_argument"),
        (
            {"disabled_rules": [{"rule_id": "xccdf_org.example.synthetic_rule_gamma"}]},
            "invalid_argument",
        ),
        ({"disabled_rules": [{"rule_id": ALPHA}, {"rule_id": BETA}]}, "nothing_to_scan"),
    ],
)
def test_invalid_input_fails_cleanly_without_writing(
    capsys: pytest.CaptureFixture[str],
    runner: FakeRunner,
    content: Path,
    overrides: dict[str, object],
    error_type: str,
) -> None:
    code, result = run(capsys, arguments(content, **overrides))
    assert code == 1
    assert result["error_type"] == error_type
    assert result["changed"] is False
    assert result["evidence_written"] is False
    assert result["evidence_dir"] is None
    assert runner.calls == 0
    assert not (content.parent.parent / "evidence").exists()


def test_a_symlinked_output_directory_is_refused(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    real = content.parent.parent / "real"
    real.mkdir(mode=0o700)
    (content.parent.parent / "evidence").symlink_to(real)
    code, result = run(capsys, arguments(content))
    assert code == 1
    assert result["error_type"] == "unsafe_output_dir"
    assert list(real.iterdir()) == []
    assert runner.calls == 0


def test_an_error_after_the_run_directory_exists_names_it(
    capsys: pytest.CaptureFixture[str], runner: FakeRunner, content: Path
) -> None:
    linked = content.parent.parent / "linked"
    linked.symlink_to(content.parent)
    code, result = run(capsys, arguments(content, content_path=str(linked / content.name)))
    assert code == 1
    assert result["error_type"] == "invalid_request"
    assert result["evidence_written"] is True
    assert result["evidence_dir"] == str(content.parent.parent / "evidence" / "run-1")
    assert runner.calls == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"backend": "other"},
        {"host": {"hostname": "web01"}},
        {"disabled_rules": [{"disabled_by": "linux_compliance_ssh_enabled"}]},
        {"disabled_rules": [{"rule_id": ALPHA, "reason": "x"}]},
    ],
)
def test_argument_spec_violations_are_rejected(
    capsys: pytest.CaptureFixture[str],
    runner: FakeRunner,
    content: Path,
    overrides: dict[str, object],
) -> None:
    code, result = run(capsys, arguments(content, **overrides))
    assert code == 1
    assert result["failed"] is True
    assert runner.calls == 0


@pytest.mark.usefixtures("runner")
@pytest.mark.parametrize("missing", ["content_path", "expected_sha256", "profile_id", "host"])
def test_required_arguments(
    capsys: pytest.CaptureFixture[str], content: Path, missing: str
) -> None:
    given = arguments(content)
    del given[missing]
    code, result = run(capsys, given)
    assert code == 1
    assert "missing required arguments" in str(result["msg"])


def test_the_argument_spec_matches_the_documented_defaults() -> None:
    spec = compliance_scan.argument_spec()
    assert spec["output_dir"] == {"type": "str", "default": audit.DEFAULT_OUTPUT_ROOT}
    assert spec["max_result_bytes"] == {"type": "int", "default": scanner.DEFAULT_MAX_RESULT_BYTES}
    assert spec["scan_timeout"] == {"type": "float", "default": scanner.DEFAULT_TIMEOUT_SECONDS}
    assert spec["fail_on_incomplete"] == {"type": "bool", "default": True}


def test_running_the_file_as_a_script_runs_main(
    capsys: pytest.CaptureFixture[str], content: Path
) -> None:
    given = arguments(content, _ansible_check_mode=True)
    spec = importlib.util.spec_from_file_location("__main__", MODULE_FILE)
    assert spec is not None
    assert spec.loader is not None
    with patch_module_args(given), pytest.raises(SystemExit) as raised:
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    assert raised.value.code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["error_type"] == "unsafe_output_dir"
    assert result["evidence_written"] is False
