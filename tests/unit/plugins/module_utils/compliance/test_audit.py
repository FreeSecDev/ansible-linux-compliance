from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    model,
    openscap,
    process,
    scanner,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

FIXTURES = Path(__file__).resolve().parents[4] / "fixtures"
SYNTHETIC = FIXTURES / "catalog" / "synthetic-ds.xml"
ADVERSARIAL = FIXTURES / "adversarial"
SHA256 = hashlib.sha256(SYNTHETIC.read_bytes()).hexdigest()
BENCHMARK = "xccdf_org.example.synthetic_benchmark_demo"
PROFILE = "xccdf_org.example.synthetic_profile_baseline"
STRICT = "xccdf_org.example.synthetic_profile_strict"
TAILORED = PROFILE + audit.TAILORED_PROFILE_SUFFIX
ALPHA = "xccdf_org.example.synthetic_rule_alpha"
BETA = "xccdf_org.example.synthetic_rule_beta"
GAMMA = "xccdf_org.example.synthetic_rule_gamma"
ALPHA_TOGGLE = "linux_compliance_rule_alpha_enabled"
HOST = model.HostIdentity("host.example", "ubuntu", "24.04", "x86_64", None)
VERSION_OUTPUT = b"OpenSCAP command line tool (oscap) 1.3.10\n"
START = datetime.fromisoformat("2026-10-25T09:00:00+00:00")
UID = os.getuid()


def results_xml(
    profile: str, results: dict[str, str], benchmark: str = BENCHMARK, extra: str = ""
) -> str:
    rules = "".join(
        f'<rule-result idref="{rule}" severity="medium"><result>{value}</result></rule-result>'
        for rule, value in results.items()
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" '
        f'id="{benchmark}"><version>1.2.3</version>'
        '<TestResult id="xccdf_org.example.synthetic_testresult_demo" '
        'start-time="2026-10-25T10:00:00+00:00" end-time="2026-10-25T10:00:09+00:00">'
        f'<benchmark id="{benchmark}"/><profile idref="{profile}"/>{rules}{extra}'
        "</TestResult></Benchmark>"
    )


def command_result(returncode: int = 0, *, timed_out: bool = False) -> process.CommandResult:
    return process.CommandResult(
        argv=("/usr/bin/oscap",),
        returncode=returncode,
        stdout=VERSION_OUTPUT,
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.1,
        timed_out=timed_out,
    )


class FakeRunner:
    """Stands in for process.run; never starts a process."""

    def __init__(self) -> None:
        self.results: dict[str, str] = {ALPHA: "pass", BETA: "fail"}
        self.document: str | bytes | None = None
        self.returncode = 2
        self.timed_out = False
        self.error: Exception | None = None
        self.on_evaluate: Callable[[Path], None] | None = None
        self.specs: list[process.CommandSpec] = []
        self.scanned: list[tuple[str, str]] = []

    def __call__(self, spec: process.CommandSpec) -> process.CommandResult:
        self.specs.append(spec)
        if spec.args == ("--version",):
            if self.error is not None:
                raise self.error
            return command_result(0)
        args = spec.args
        results = Path(args[args.index("--results") + 1])
        arf = Path(args[args.index("--results-arf") + 1])
        profile = args[args.index("--profile") + 1]
        if self.on_evaluate is not None:
            self.on_evaluate(results)
        self.scanned.append((args[-1], hashlib.sha256(Path(args[-1]).read_bytes()).hexdigest()))
        document = self.document
        if document is None:
            document = results_xml(profile, self.results)
        if isinstance(document, bytes):
            results.write_bytes(document)
        else:
            results.write_text(document, encoding="utf-8")
        arf.write_text("<arf/>", encoding="utf-8")
        return command_result(self.returncode, timed_out=self.timed_out)

    @property
    def evaluations(self) -> list[process.CommandSpec]:
        return [spec for spec in self.specs if spec.args != ("--version",)]


def moments() -> Iterator[datetime]:
    return iter(START + timedelta(seconds=n) for n in range(1000))


class Harness:
    """Content, an output root owned by the test user and a fake process layer."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.content_dir = root / "content"
        self.content_dir.mkdir()
        self.content_dir.chmod(0o755)
        self.datastream = self.content_dir / "synthetic-ds.xml"
        shutil.copyfile(SYNTHETIC, self.datastream)
        self.datastream.chmod(0o644)
        self.output_root = root / "evidence"
        self.runner = FakeRunner()
        self.registry = scanner.BackendRegistry()
        clock = moments()
        self.registry.register(
            "openscap",
            lambda settings: openscap.OpenScapBackend(
                settings, runner=self.runner, clock=lambda: next(clock)
            ),
        )

    def job(self, **fields: Any) -> audit.AuditJob:
        values: dict[str, Any] = {
            "backend": "openscap",
            "content_path": str(self.datastream),
            "expected_sha256": SHA256,
            "profile_id": PROFILE,
            "output_root": str(self.output_root),
            "run_id": "run-1",
            "host": HOST,
            "timeout_seconds": 60.0,
            "max_result_bytes": 1024 * 1024,
            "disabled_rules": (),
        }
        values.update(fields)
        return audit.AuditJob(**values)

    def auditor(self, **keywords: Any) -> audit.Auditor:
        values: dict[str, Any] = {
            "owner_uid": UID,
            "registry": self.registry,
            "clock": lambda: START,
        }
        values.update(keywords)
        return audit.Auditor(**values)

    def run(self, *, check_mode: bool = False, **fields: Any) -> dict[str, Any]:
        return self.auditor().run(self.job(**fields), check_mode=check_mode)

    @property
    def run_dir(self) -> Path:
        return self.output_root / "run-1"


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    tmp_path.chmod(0o755)
    return Harness(tmp_path)


def outcomes(result: dict[str, Any]) -> dict[str, str]:
    return {finding["rule_id"]: finding["outcome"] for finding in result["scan_run"]["findings"]}


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_exit_status_two_is_a_completed_scan_with_findings(harness: Harness) -> None:
    result = harness.run()
    assert result["changed"] is False
    assert result["evidence_written"] is True
    assert result["run_status"] == "completed"
    assert outcomes(result) == {ALPHA: "pass", BETA: "fail"}
    summary = result["summary"]
    assert summary["run_status"] == "completed"
    assert summary["pass"] == 1
    assert summary["fail"] == 1
    assert summary["total"] == 2
    assert summary["disabled"] == 0
    run = result["scan_run"]
    assert run["profile_id"] == PROFILE
    assert run["content"]["content_sha256"] == SHA256
    assert run["content"]["source"] == "synthetic-ds.xml"
    assert run["scanner"] == {"name": "openscap", "version": "1.3.10"}
    assert result["disabled_rules"] == []


def test_the_scanner_is_called_with_validated_arguments_only(harness: Harness) -> None:
    harness.run()
    (spec,) = harness.runner.evaluations
    assert spec.executable == "oscap"
    assert spec.args[:4] == ("xccdf", "eval", "--profile", PROFILE)
    assert "--tailoring-file" not in spec.args
    assert "--remediate" not in spec.args
    assert spec.args[-1] == str(harness.run_dir / "content" / "synthetic-ds.xml")
    assert spec.timeout_seconds == 60.0


def test_exit_status_zero_with_passing_rules_completes(harness: Harness) -> None:
    harness.runner.results = {ALPHA: "pass", BETA: "pass"}
    harness.runner.returncode = 0
    result = harness.run()
    assert result["run_status"] == "completed"
    assert result["summary"]["pass"] == 2


def test_evidence_is_restrictive_and_matches_the_reported_run(harness: Harness) -> None:
    result = harness.run()
    run_dir = harness.run_dir
    assert result["evidence"]["directory"] == str(run_dir)
    assert mode(harness.output_root) == 0o700
    assert mode(run_dir) == 0o700
    assert mode(run_dir / "scan") == 0o700
    files = result["evidence"]["files"]
    kinds = {Path(item["path"]).name: item["kind"] for item in files}
    assert kinds == {
        "results-arf.xml": "scanner_output",
        "results.xml": "scanner_output",
        "scan-run.json": "scan_run",
    }
    for item in files:
        path = Path(item["path"])
        assert mode(path) == 0o600
        assert item["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert item["size"] == path.stat().st_size
    stored = model.loads((run_dir / "scan-run.json").read_text(encoding="utf-8"))
    assert stored.to_dict() == result["scan_run"]
    assert not list(run_dir.glob(".*"))


def test_check_mode_never_creates_the_output_root_and_then_runs_nothing(harness: Harness) -> None:
    result = harness.run(check_mode=True)
    assert result["changed"] is False
    assert result["evidence_written"] is False
    assert result["run_status"] == "not_run"
    assert "does not exist and check mode does not create it" in result["msg"]
    assert result["scan_run"] is None
    assert result["summary"] is None
    assert result["evidence"] == {"directory": None, "files": [], "skipped": []}
    assert harness.runner.specs == []
    assert not harness.output_root.exists()
    planned = result["planned"]
    assert planned["output_root_exists"] is False
    assert planned["run_dir"] == str(harness.run_dir)
    assert planned["expected_rule_count"] == 2
    assert planned["tailoring"] is False
    assert planned["evaluated_profile_id"] == PROFILE
    assert planned["content_sha256"] == SHA256


def snapshot(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)) for path in root.rglob("*"))


def test_check_mode_scans_for_real_and_keeps_nothing(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    seen: list[Path] = []

    def observe(results: Path) -> None:
        seen.append(results)
        assert results.parent.parent.name == ".check-run-1"
        assert mode(results.parent.parent) == 0o700

    harness.runner.on_evaluate = observe
    result = harness.run(check_mode=True, expected_sha256=SHA256.upper())
    assert result["changed"] is False
    assert result["evidence_written"] is False
    assert result["evidence"] == {"directory": None, "files": [], "skipped": []}
    assert result["run_status"] == "completed"
    assert outcomes(result) == {ALPHA: "pass", BETA: "fail"}
    assert result["summary"]["fail"] == 1
    assert result["scan_run"]["content"]["content_sha256"] == SHA256
    assert "temporary directory that was removed" in result["msg"]
    assert result["planned"]["output_root_exists"] is True
    assert len(harness.runner.evaluations) == 1
    assert seen
    assert snapshot(harness.output_root) == []


def test_check_mode_with_tailoring_removes_the_tailoring_file(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    harness.runner.results = {ALPHA: "notselected", BETA: "pass"}
    harness.runner.returncode = 0
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    result = harness.run(check_mode=True, disabled_rules=disabled)
    (spec,) = harness.runner.evaluations
    assert spec.args[spec.args.index("--tailoring-file") + 1].endswith(
        "/.check-run-1/tailoring.xml"
    )
    assert outcomes(result) == {ALPHA: "disabled", BETA: "pass"}
    assert snapshot(harness.output_root) == []


@pytest.mark.parametrize("failure", ["exit", "timeout", "missing", "malformed", "planted"])
def test_check_mode_keeps_nothing_when_the_scan_fails(harness: Harness, failure: str) -> None:
    harness.output_root.mkdir(mode=0o700)
    outside = harness.root / "outside"
    outside.write_text("keep", encoding="utf-8")
    if failure == "exit":
        harness.runner.returncode = 1
    elif failure == "timeout":
        harness.runner.timed_out = True
    elif failure == "missing":
        harness.runner.error = process.ProcessExecutionError("executable not found: 'oscap'")
    elif failure == "malformed":
        harness.runner.document = "<Benchmark"
    else:

        def plant(results: Path) -> None:
            (results.parent / "link").symlink_to(outside)
            (results.parent / "nested" / "deeper").mkdir(parents=True)
            (results.parent / "nested" / "deeper" / "file").write_text("x", encoding="utf-8")

        harness.runner.on_evaluate = plant
        harness.runner.returncode = 1
    result = harness.run(check_mode=True)
    assert result["run_status"] in {"failed", "timed_out"}
    assert set(outcomes(result).values()) == {"error"}
    assert result["evidence_written"] is False
    assert snapshot(harness.output_root) == []
    assert outside.read_text(encoding="utf-8") == "keep"


def test_check_mode_keeps_nothing_when_the_backend_refuses(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    with pytest.raises(audit.AuditError) as raised:
        refusing_auditor().run(harness.job(), check_mode=True)
    assert raised.value.error_type == "invalid_request"
    assert raised.value.evidence_dir is None
    assert snapshot(harness.output_root) == []


def test_check_mode_reports_no_evidence_for_an_unregistered_backend(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    planned = audit.plan(harness.job(), UID)
    empty = audit.Auditor(owner_uid=UID, registry=scanner.BackendRegistry())
    with pytest.raises(audit.AuditError) as raised:
        empty.preview(planned)
    assert raised.value.error_type == "unknown_backend"
    assert raised.value.evidence_dir is None
    assert snapshot(harness.output_root) == []


def test_check_mode_scans_a_private_copy_and_removes_it(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)

    def swap(_results: Path) -> None:
        harness.datastream.write_bytes(b"<swapped/>")

    harness.runner.on_evaluate = swap
    result = harness.run(check_mode=True)
    ((scanned_path, scanned_sha256),) = harness.runner.scanned
    expected = harness.output_root / ".check-run-1" / "content" / "synthetic-ds.xml"
    assert scanned_path == str(expected)
    assert scanned_sha256 == SHA256
    assert result["content"]["private_copy"] == scanned_path
    assert result["run_status"] == "completed"
    assert snapshot(harness.output_root) == []


def test_check_mode_keeps_nothing_when_writing_fails(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.output_root.mkdir(mode=0o700)

    def failing_write(path: Path, _text: str) -> None:
        path.write_text("partial", encoding="utf-8")
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(audit, "_write_new_file", failing_write)
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    with pytest.raises(audit.AuditError, match="check-mode scan failed") as raised:
        harness.run(check_mode=True, disabled_rules=disabled)
    assert raised.value.error_type == "evidence_write_failed"
    assert snapshot(harness.output_root) == []
    assert harness.runner.specs == []


def test_a_check_mode_directory_that_already_exists_is_never_reused(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    planted = harness.output_root / ".check-run-1"
    planted.mkdir()
    (planted / "keep").write_text("x", encoding="utf-8")
    with pytest.raises(audit.AuditError) as raised:
        harness.run(check_mode=True)
    assert raised.value.error_type == "output_exists"
    assert (planted / "keep").exists()
    assert harness.runner.specs == []


def test_a_check_mode_directory_that_cannot_be_removed_is_reported(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    locked: list[Path] = []

    def lock(results: Path) -> None:
        directory = results.parent / "locked"
        directory.mkdir()
        (directory / "file").write_text("x", encoding="utf-8")
        directory.chmod(0o500)
        locked.append(directory)

    harness.runner.on_evaluate = lock
    try:
        with pytest.raises(audit.AuditError, match="could not be removed") as raised:
            harness.run(check_mode=True)
        assert raised.value.error_type == "cleanup_failed"
        assert raised.value.evidence_dir == str(harness.output_root / ".check-run-1")
    finally:
        for directory in locked:
            directory.chmod(0o700)


def test_cleanup_refuses_deep_or_crowded_trees(tmp_path: Path) -> None:
    deep = tmp_path / "deep"
    (deep / "a" / "b" / "c" / "d" / "e" / "f").mkdir(parents=True)
    with pytest.raises(audit.AuditError, match="nested too deeply") as nested:
        audit.discard_preview(deep)
    assert nested.value.error_type == "cleanup_failed"
    crowded = tmp_path / "crowded"
    crowded.mkdir()
    for index in range(audit.MAX_EVIDENCE_ENTRIES + 1):
        (crowded / f"f{index}").write_text("x", encoding="utf-8")
    with pytest.raises(audit.AuditError, match="too many entries"):
        audit.discard_preview(crowded)


def test_repeated_runs_never_change_the_host_and_never_reuse_evidence(harness: Harness) -> None:
    first = harness.run(run_id="run-1")
    second = harness.run(run_id="run-2")
    assert first["changed"] is second["changed"] is False
    assert outcomes(first) == outcomes(second)
    assert sorted(path.name for path in harness.output_root.iterdir()) == ["run-1", "run-2"]


def test_a_disabled_rule_is_excluded_through_tailoring_and_reported(harness: Harness) -> None:
    harness.runner.results = {ALPHA: "notselected", BETA: "fail"}
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    result = harness.run(disabled_rules=disabled)
    (spec,) = harness.runner.evaluations
    tailoring = harness.run_dir / "tailoring.xml"
    assert spec.args[3] == TAILORED
    assert spec.args[spec.args.index("--tailoring-file") + 1] == str(tailoring)
    text = tailoring.read_text(encoding="utf-8")
    assert f'<xccdf:Profile id="{TAILORED}" extends="{PROFILE}">' in text
    assert f'<xccdf:select idref="{ALPHA}" selected="false"/>' in text
    assert BETA not in text
    assert mode(tailoring) == 0o600
    assert result["run_status"] == "completed"
    assert outcomes(result) == {ALPHA: "disabled", BETA: "fail"}
    finding = next(item for item in result["scan_run"]["findings"] if item["rule_id"] == ALPHA)
    assert finding["disabled_by"] == ALPHA_TOGGLE
    assert finding["evaluated_outcome"] == "disabled"
    assert finding["severity"] == "high"
    assert ALPHA_TOGGLE in finding["message"]
    assert result["summary"]["disabled"] == 1
    assert result["summary"]["pass"] == 0
    run = result["scan_run"]
    assert run["profile_id"] == PROFILE
    digest = hashlib.sha256(tailoring.read_bytes()).hexdigest()
    assert run["content"]["source"] == (
        f"synthetic-ds.xml tailoring=tailoring.xml tailoring_sha256={digest}"
    )
    assert result["disabled_rules"] == [{"rule_id": ALPHA, "disabled_by": ALPHA_TOGGLE}]
    assert result["planned"]["tailoring"] is True
    assert result["planned"]["expected_rule_count"] == 1
    kinds = sorted(item["kind"] for item in result["evidence"]["files"])
    assert kinds == ["scan_run", "scanner_output", "scanner_output", "tailoring"]


def test_a_disabled_rule_that_the_scanner_still_reports_fails_the_run(harness: Harness) -> None:
    harness.runner.results = {ALPHA: "fail", BETA: "fail"}
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    result = harness.run(disabled_rules=disabled)
    assert result["run_status"] == "failed"
    assert set(outcomes(result).values()) == {"error"}


def test_disabled_rules_become_errors_when_the_scan_does_not_complete(harness: Harness) -> None:
    harness.runner.timed_out = True
    disabled = audit.parse_disabled_rules(
        [{"rule_id": ALPHA, "disabled_by": "linux_compliance_auditd_enabled"}]
    )
    result = harness.run(disabled_rules=disabled)
    assert result["run_status"] == "timed_out"
    assert outcomes(result) == {ALPHA: "error", BETA: "error"}
    finding = next(item for item in result["scan_run"]["findings"] if item["rule_id"] == ALPHA)
    assert "linux_compliance_auditd_enabled" in finding["message"]
    assert finding["disabled_by"] is None
    assert result["summary"]["error"] == 2
    assert result["summary"]["pass"] == 0


def test_a_completed_run_reports_every_profile_rule_exactly_once(harness: Harness) -> None:
    harness.runner.results = {ALPHA: "pass"}
    result = harness.run()
    assert result["run_status"] == "completed"
    assert outcomes(result) == {ALPHA: "pass", BETA: "error"}


@pytest.mark.parametrize(
    ("returncode", "results"),
    [
        (1, {ALPHA: "pass", BETA: "pass"}),
        (-9, {ALPHA: "pass", BETA: "fail"}),
        (137, {ALPHA: "pass", BETA: "fail"}),
        (2, {ALPHA: "pass", BETA: "pass"}),
        (0, {ALPHA: "pass", BETA: "fail"}),
    ],
)
def test_other_exit_statuses_and_contradictions_are_failures(
    harness: Harness, returncode: int, results: dict[str, str]
) -> None:
    harness.runner.returncode = returncode
    harness.runner.results = results
    result = harness.run()
    assert result["run_status"] == "failed"
    assert result["scan_run"]["error_message"]
    assert set(outcomes(result).values()) == {"error"}
    assert result["summary"]["pass"] == 0
    assert result["summary"]["fail"] == 0
    assert result["evidence_written"] is True


def test_a_timeout_is_never_compliant(harness: Harness) -> None:
    harness.runner.timed_out = True
    harness.runner.returncode = 0
    harness.runner.results = {ALPHA: "pass", BETA: "pass"}
    result = harness.run()
    assert result["run_status"] == "timed_out"
    assert result["summary"] == {
        "pass": 0,
        "fail": 0,
        "notapplicable": 0,
        "notchecked": 0,
        "error": 2,
        "waived": 0,
        "disabled": 0,
        "total": 2,
        "run_status": "timed_out",
    }


def test_a_missing_scanner_is_a_failed_run(harness: Harness) -> None:
    harness.runner.error = process.ProcessExecutionError("executable not found: 'oscap'")
    result = harness.run()
    assert result["run_status"] == "failed"
    assert "oscap is not available" in result["scan_run"]["error_message"]
    assert set(outcomes(result).values()) == {"error"}


@pytest.mark.parametrize(
    "document",
    [
        "",
        "<Benchmark",
        "not xml at all",
        (ADVERSARIAL / "billion-laughs.xml").read_text(encoding="utf-8"),
        (ADVERSARIAL / "external-entity.xml").read_text(encoding="utf-8"),
        (ADVERSARIAL / "doctype.xml").read_text(encoding="utf-8"),
        (ADVERSARIAL / "unknown-result-value.xml").read_text(encoding="utf-8"),
        results_xml(STRICT, {ALPHA: "pass", BETA: "fail"}),
        results_xml(PROFILE, {ALPHA: "pass", BETA: "fail"}, "xccdf_org.example.other_benchmark_x"),
        results_xml(PROFILE, {ALPHA: "pass", BETA: "fail", GAMMA: "fail"}),
        results_xml(PROFILE, {ALPHA: "pass", BETA: "fail"}, extra=results_xml(PROFILE, {})),
        b"\xff\xfe<\x00",
    ],
)
def test_malformed_or_hostile_results_fail_the_run(harness: Harness, document: str | bytes) -> None:
    harness.runner.document = document
    result = harness.run()
    assert result["run_status"] == "failed"
    assert set(outcomes(result).values()) == {"error"}


def test_oversized_results_fail_the_run(harness: Harness) -> None:
    harness.runner.document = results_xml(PROFILE, {ALPHA: "pass", BETA: "fail"}) + " " * 2048
    result = harness.run(max_result_bytes=1024)
    assert result["run_status"] == "failed"
    assert "larger than 1024 bytes" in result["scan_run"]["error_message"]


def test_the_scanner_reads_only_the_verified_private_copy(harness: Harness) -> None:
    hostile = b"<attacker-controlled datastream/>"

    def swap(_results: Path) -> None:
        harness.datastream.write_bytes(hostile)

    harness.runner.on_evaluate = swap
    result = harness.run()
    ((scanned_path, scanned_sha256),) = harness.runner.scanned
    assert scanned_path == str(harness.run_dir / "content" / "synthetic-ds.xml")
    assert scanned_sha256 == SHA256
    assert harness.datastream.read_bytes() == hostile
    assert result["run_status"] == "completed"
    assert outcomes(result) == {ALPHA: "pass", BETA: "fail"}
    assert result["content"] == {
        "copy_removed": True,
        "private_copy": scanned_path,
        "sha256": SHA256,
        "size": SYNTHETIC.stat().st_size,
        "source_path": str(harness.datastream),
    }
    assert not (harness.run_dir / "content").exists()
    assert result["scan_run"]["content"]["content_sha256"] == SHA256


def test_a_source_that_changed_after_verification_is_never_scanned(harness: Harness) -> None:
    auditor = harness.auditor()
    planned = audit.plan(harness.job(), UID)
    harness.datastream.write_bytes(SYNTHETIC.read_bytes() + b"\n")
    with pytest.raises(audit.AuditError, match="changed after verification") as raised:
        auditor.execute(planned)
    assert raised.value.error_type == "digest_mismatch"
    assert raised.value.evidence_dir == str(harness.run_dir)
    assert harness.runner.specs == []
    assert not (harness.run_dir / "content").exists()


def test_a_source_replaced_by_a_symlink_after_verification_is_never_scanned(
    harness: Harness,
) -> None:
    auditor = harness.auditor()
    planned = audit.plan(harness.job(), UID)
    harness.datastream.unlink()
    harness.datastream.symlink_to(SYNTHETIC)
    with pytest.raises(audit.AuditError, match="cannot be copied") as raised:
        auditor.execute(planned)
    assert raised.value.error_type == "invalid_content"
    assert harness.runner.specs == []
    assert not (harness.run_dir / "content").exists()


def test_a_copy_that_cannot_be_written_is_reported(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    planned = audit.plan(harness.job(), UID)
    original = Path.open

    def failing_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if args and args[0] == "xb" and self.parent.name == "content":
            raise PermissionError(13, "Permission denied")
        return cast("Any", original(self, *args, **kwargs))

    monkeypatch.setattr(Path, "open", failing_open)
    with pytest.raises(audit.AuditError, match="cannot be copied") as raised:
        harness.auditor().execute(planned)
    assert raised.value.error_type == "evidence_write_failed"
    assert not (harness.run_dir / "content").exists()


def test_a_copy_directory_that_cannot_be_created_is_reported(harness: Harness) -> None:
    directory = harness.root / "copy-target"
    directory.mkdir()
    with pytest.raises(audit.AuditError, match="private copy cannot be created") as raised:
        audit.copy_content(str(harness.datastream), directory, SHA256)
    assert raised.value.error_type == "evidence_write_failed"
    assert directory.exists()


def test_a_copy_that_cannot_be_removed_is_reported(harness: Harness) -> None:
    locked: list[Path] = []

    def lock(results: Path) -> None:
        directory = results.parent.parent / "content"
        directory.chmod(0o500)
        locked.append(directory)

    harness.runner.on_evaluate = lock
    try:
        with pytest.raises(audit.AuditError, match="could not be removed") as raised:
            harness.run()
        assert raised.value.error_type == "cleanup_failed"
        assert raised.value.evidence_dir == str(harness.run_dir)
    finally:
        for directory in locked:
            directory.chmod(0o700)


def test_a_completed_run_with_another_digest_becomes_failed(harness: Harness) -> None:
    run = replace(
        static_run(model.ScanStatus.COMPLETED, finding(ALPHA, model.Outcome.PASS)),
        profile_id=PROFILE,
        content=model.Provenance("synthetic-ds.xml", "1.2.3", "0" * 64),
        findings=(finding(ALPHA, model.Outcome.PASS), finding(BETA, model.Outcome.PASS)),
    )
    auditor, _backend = static_auditor(run)
    result = cast("dict[str, Any]", auditor.run(harness.job(), check_mode=False))
    assert result["run_status"] == "failed"
    assert "not the pinned" in result["scan_run"]["error_message"]
    assert set(outcomes(result).values()) == {"error"}


def test_a_datastream_name_that_cannot_label_the_provenance_is_refused_early(
    harness: Harness,
) -> None:
    odd = harness.content_dir / "synthetic ds.xml"
    harness.datastream.rename(odd)
    with pytest.raises(audit.AuditError, match="file name must match") as raised:
        harness.run(content_path=str(odd))
    assert raised.value.error_type == "invalid_argument"
    assert not harness.output_root.exists()


def test_a_digest_mismatch_stops_before_anything_runs(harness: Harness) -> None:
    with pytest.raises(audit.AuditError) as raised:
        harness.run(expected_sha256="0" * 64)
    assert raised.value.error_type == "digest_mismatch"
    assert harness.runner.specs == []
    assert not harness.output_root.exists()


def test_a_missing_profile_is_never_substituted(harness: Harness) -> None:
    with pytest.raises(audit.AuditError) as raised:
        harness.run(profile_id="xccdf_org.example.synthetic_profile_absent")
    assert raised.value.error_type == "profile_not_found"
    assert harness.runner.specs == []


def test_a_directory_with_one_datastream_is_resolved(harness: Harness) -> None:
    result = harness.run(content_path=str(harness.content_dir))
    assert result["planned"]["content_path"] == str(harness.datastream)


@pytest.mark.parametrize(
    "profile_id",
    [
        "--remediate",
        "cis_level1_server",
        "xccdf_org.example.synthetic_profile_a;rm -rf /",
        "xccdf_org.example.synthetic_profile_../../etc",
        "xccdf_org.example.synthetic_profile_a b",
        "xccdf_org.example.synthetic_profile_\u202ebaseline",
        "xccdf_org.example.synthetic_profile_" + "a" * 300,
        "",
        None,
    ],
)
def test_malicious_profile_identifiers_are_rejected(harness: Harness, profile_id: object) -> None:
    with pytest.raises(audit.AuditError) as raised:
        harness.job(profile_id=profile_id)
    assert raised.value.error_type == "invalid_argument"


def test_a_profile_identifier_too_long_to_tailor_is_rejected(harness: Harness) -> None:
    long_profile = "xccdf_org.example.synthetic_profile_" + "a" * 210
    text = SYNTHETIC.read_text(encoding="utf-8").replace(f'"{PROFILE}"', f'"{long_profile}"')
    harness.datastream.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(harness.datastream.read_bytes()).hexdigest()
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    job = harness.job(profile_id=long_profile, expected_sha256=digest, disabled_rules=disabled)
    with pytest.raises(audit.AuditError, match="too long to be tailored") as raised:
        audit.plan(job, UID)
    assert raised.value.error_type == "invalid_argument"
    plain = audit.plan(harness.job(profile_id=long_profile, expected_sha256=digest), UID)
    assert plain.evaluated_profile_id == long_profile


@pytest.mark.parametrize(
    "rule_id",
    [
        "--remediate",
        "xccdf_org.example.synthetic_rule_a;id",
        "xccdf_org.example.synthetic_rule_../x",
        "xccdf_org.example.synthetic_rule_a\nb",
        "alpha",
        "",
    ],
)
def test_malicious_disabled_rule_identifiers_are_rejected(rule_id: str) -> None:
    with pytest.raises(audit.AuditError) as raised:
        audit.parse_disabled_rules([{"rule_id": rule_id}])
    assert raised.value.error_type == "invalid_argument"


@pytest.mark.parametrize(
    "disabled_by",
    [
        "LINUX_COMPLIANCE_RULE_ALPHA_ENABLED",
        "linux_compliance_rule_alpha",
        "other_variable_enabled",
        "linux_compliance_rule_alpha_enabled; rm",
        "linux_compliance_" + "a" * 101 + "_enabled",
        7,
    ],
)
def test_invalid_toggle_names_are_rejected(disabled_by: object) -> None:
    with pytest.raises(audit.AuditError) as raised:
        audit.parse_disabled_rules([{"rule_id": ALPHA, "disabled_by": disabled_by}])
    assert raised.value.error_type == "invalid_argument"


def test_toggle_names_are_derived_from_the_rule_identifier() -> None:
    assert audit.rule_toggle(ALPHA) == ALPHA_TOGGLE
    rules = audit.parse_disabled_rules(
        [{"rule_id": BETA, "disabled_by": ""}, {"rule_id": ALPHA, "disabled_by": None}]
    )
    assert [rule.rule_id for rule in rules] == [ALPHA, BETA]
    assert rules[1].disabled_by == "linux_compliance_rule_beta_enabled"


@pytest.mark.parametrize(
    "rule_id", ["xccdf_org.example.synthetic_rule_Alpha", "xccdf_org.example.synthetic_rule_a.b"]
)
def test_a_toggle_that_cannot_be_derived_must_be_named(rule_id: str) -> None:
    with pytest.raises(audit.AuditError, match="set disabled_by explicitly"):
        audit.parse_disabled_rules([{"rule_id": rule_id}])
    named = audit.parse_disabled_rules(
        [{"rule_id": rule_id, "disabled_by": "linux_compliance_ssh_enabled"}]
    )
    assert named[0].disabled_by == "linux_compliance_ssh_enabled"


def test_rule_toggle_rejects_an_invalid_identifier() -> None:
    with pytest.raises(audit.AuditError) as raised:
        audit.rule_toggle("--remediate")
    assert raised.value.error_type == "invalid_argument"


@pytest.mark.parametrize(
    ("items", "message"),
    [
        ("xccdf_org.example.synthetic_rule_alpha", "must be a list"),
        ({"rule_id": ALPHA}, "must be a list"),
        ([ALPHA], "must be a mapping"),
        ([{"rule_id": ALPHA, "reason": "x"}], "unknown disabled_rules keys"),
        ([{"disabled_by": ALPHA_TOGGLE}], "needs a rule_id"),
        ([{"rule_id": ALPHA}, {"rule_id": ALPHA}], "more than once"),
        ([{"rule_id": ALPHA}] * (audit.MAX_DISABLED_RULES + 1), "exceeds"),
    ],
)
def test_malformed_disabled_rules_are_rejected(items: object, message: str) -> None:
    with pytest.raises(audit.AuditError, match=message):
        audit.parse_disabled_rules(items)


def test_no_disabled_rules_is_an_empty_tuple() -> None:
    assert audit.parse_disabled_rules(None) == ()
    assert audit.parse_disabled_rules([]) == ()


def test_a_disabled_rule_outside_the_profile_is_rejected(harness: Harness) -> None:
    disabled = audit.parse_disabled_rules([{"rule_id": GAMMA}])
    with pytest.raises(audit.AuditError, match="not selected by the profile") as raised:
        harness.run(disabled_rules=disabled)
    assert raised.value.error_type == "invalid_argument"
    assert harness.runner.specs == []


def test_disabling_every_rule_leaves_nothing_to_scan(harness: Harness) -> None:
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}, {"rule_id": BETA}])
    with pytest.raises(audit.AuditError) as raised:
        harness.run(disabled_rules=disabled)
    assert raised.value.error_type == "nothing_to_scan"
    assert harness.runner.specs == []


@pytest.mark.parametrize(
    "output_root",
    [
        "relative/evidence",
        "evidence",
        "/",
        "",
        "/var/lib/../../etc",
        "/var/lib/./evidence",
        "/var/lib/evidence/",
        "//var/lib/evidence",
        "/var//lib",
        "/var/lib/evi\x00dence",
        "/var/lib/evi\ndence",
        "/var/lib/evi\x7fdence",
        "/" + "a" * 4096,
        None,
    ],
)
def test_unsafe_output_paths_are_rejected(harness: Harness, output_root: object) -> None:
    with pytest.raises(audit.AuditError) as raised:
        harness.job(output_root=output_root)
    assert raised.value.error_type == "unsafe_output_dir"


def test_a_symlinked_output_root_is_rejected(harness: Harness) -> None:
    real = harness.root / "real"
    real.mkdir(mode=0o700)
    harness.output_root.symlink_to(real)
    with pytest.raises(audit.AuditError, match="symlink") as raised:
        harness.run()
    assert raised.value.error_type == "unsafe_output_dir"
    assert list(real.iterdir()) == []
    assert harness.runner.specs == []


def test_a_symlinked_ancestor_is_rejected(harness: Harness) -> None:
    real = harness.root / "real"
    (real / "evidence").mkdir(parents=True, mode=0o700)
    real.chmod(0o755)
    link = harness.root / "link"
    link.symlink_to(real)
    with pytest.raises(audit.AuditError, match="symlink"):
        harness.run(output_root=str(link / "evidence"))
    with pytest.raises(audit.AuditError, match="symlink"):
        harness.run(output_root=str(link / "evidence"), check_mode=True)


def test_a_dangling_symlink_is_not_followed_on_creation(harness: Harness) -> None:
    target = harness.root / "target"
    harness.output_root.symlink_to(target)
    with pytest.raises(audit.AuditError, match="symlink"):
        harness.run()
    assert not target.exists()


def test_an_output_root_that_is_a_file_is_rejected(harness: Harness) -> None:
    harness.output_root.write_text("x", encoding="utf-8")
    with pytest.raises(audit.AuditError, match="not a directory"):
        harness.run()


@pytest.mark.parametrize("permissions", [0o750, 0o705, 0o755, 0o777])
def test_an_output_root_with_open_permissions_is_never_repaired(
    harness: Harness, permissions: int
) -> None:
    harness.output_root.mkdir()
    harness.output_root.chmod(permissions)
    with pytest.raises(audit.AuditError, match="group or other") as raised:
        harness.run()
    assert raised.value.error_type == "unsafe_output_dir"
    assert mode(harness.output_root) == permissions


def test_an_output_root_owned_by_someone_else_is_rejected(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    with pytest.raises(audit.AuditError, match="owner") as raised:
        audit.inspect_output_root(str(harness.output_root), UID + 1, create=False)
    assert raised.value.error_type == "unsafe_output_dir"


def test_production_requires_root_ownership(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    with pytest.raises(audit.AuditError) as raised:
        audit.inspect_output_root(str(harness.output_root), audit.ROOT_UID, create=False)
    assert raised.value.error_type == "unsafe_output_dir"


def test_a_group_writable_ancestor_is_rejected(harness: Harness) -> None:
    parent = harness.root / "shared"
    parent.mkdir()
    parent.chmod(0o775)
    with pytest.raises(audit.AuditError, match="writable by group or others"):
        harness.run(output_root=str(parent / "evidence"))
    assert not (parent / "evidence").exists()


def test_a_sticky_world_writable_ancestor_is_accepted(harness: Harness) -> None:
    parent = harness.root / "sticky"
    parent.mkdir()
    parent.chmod(0o1777)
    result = harness.run(output_root=str(parent / "evidence"))
    assert result["run_status"] == "completed"


def test_missing_ancestors_are_created_with_restrictive_modes(harness: Harness) -> None:
    root = harness.root / "a" / "b" / "evidence"
    result = harness.run(output_root=str(root))
    assert result["run_status"] == "completed"
    assert mode(harness.root / "a") == 0o700
    assert mode(harness.root / "a" / "b") == 0o700
    assert mode(root) == 0o700


def test_an_existing_run_directory_is_never_reused(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    harness.run_dir.mkdir()
    (harness.run_dir / "keep").write_text("old", encoding="utf-8")
    for check_mode in (True, False):
        with pytest.raises(audit.AuditError) as raised:
            harness.run(check_mode=check_mode)
        assert raised.value.error_type == "output_exists"
    assert (harness.run_dir / "keep").read_text(encoding="utf-8") == "old"
    assert harness.runner.specs == []


def test_a_symlink_planted_as_the_run_directory_is_never_followed(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    target = harness.root / "elsewhere"
    target.mkdir()
    harness.run_dir.symlink_to(target)
    with pytest.raises(audit.AuditError) as raised:
        harness.run()
    assert raised.value.error_type == "output_exists"
    assert list(target.iterdir()) == []


def test_a_run_directory_created_after_planning_is_never_reused(harness: Harness) -> None:
    auditor = harness.auditor()
    planned = audit.plan(harness.job(), UID)
    harness.output_root.mkdir(mode=0o700)
    harness.run_dir.mkdir()
    with pytest.raises(audit.AuditError) as raised:
        auditor.execute(planned)
    assert raised.value.error_type == "output_exists"
    assert harness.runner.specs == []


@pytest.mark.parametrize("run_id", ["../escape", ".hidden", "a/b", "-x", "a" * 65, "", "a b", 1])
def test_unsafe_run_identifiers_are_rejected(harness: Harness, run_id: object) -> None:
    with pytest.raises(audit.AuditError) as raised:
        harness.job(run_id=run_id)
    assert raised.value.error_type == "invalid_argument"


def test_the_default_run_identifier_is_a_utc_timestamp() -> None:
    moment = datetime(2026, 10, 25, 11, 0, 0, 123456, tzinfo=timezone(timedelta(hours=1)))
    run_id = audit.default_run_id(moment)
    assert run_id == "20261025T100000.123456Z"
    assert audit.check_run_id(run_id) == run_id


def test_an_unreadable_output_component_is_unsafe(harness: Harness) -> None:
    with pytest.raises(audit.AuditError, match="cannot be inspected"):
        harness.run(output_root=str(harness.root / ("x" * 300)))


def test_an_output_root_that_cannot_be_created_is_unsafe(harness: Harness) -> None:
    locked = harness.root / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        with pytest.raises(audit.AuditError, match="cannot be created"):
            harness.run(output_root=str(locked / "evidence"))
    finally:
        locked.chmod(0o700)


def test_a_run_directory_that_cannot_be_created_is_unsafe(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    harness.output_root.chmod(0o500)
    try:
        with pytest.raises(audit.AuditError, match="run directory cannot be created"):
            harness.run()
    finally:
        harness.output_root.chmod(0o700)


def test_a_directory_created_concurrently_is_vetted(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Path.mkdir

    def racing_mkdir(self: Path, *_args: object, **_kwargs: object) -> None:
        original(self, 0o700)
        raise FileExistsError(str(self))

    monkeypatch.setattr(Path, "mkdir", racing_mkdir)
    assert audit.inspect_output_root(str(harness.output_root), UID, create=True) is True
    assert mode(harness.output_root) == 0o700


def test_a_directory_that_vanishes_after_creation_is_unsafe(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def vanishing_mkdir(_self: Path, *_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(Path, "mkdir", vanishing_mkdir)
    with pytest.raises(audit.AuditError, match="vanished while it was created"):
        audit.inspect_output_root(str(harness.output_root), UID, create=True)


def test_a_run_directory_that_vanishes_is_unsafe(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.output_root.mkdir(mode=0o700)
    planned = audit.plan(harness.job(), UID)
    original = Path.mkdir

    def vanishing_mkdir(self: Path, *args: Any, **kwargs: Any) -> None:
        if self.name != "run-1":
            original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", vanishing_mkdir)
    with pytest.raises(audit.AuditError, match="run directory vanished"):
        harness.auditor().execute(planned)


def test_an_unknown_backend_is_rejected_before_anything_runs(harness: Harness) -> None:
    with pytest.raises(audit.AuditError) as raised:
        harness.run(backend="other")
    assert raised.value.error_type == "unknown_backend"
    assert not harness.output_root.exists()


def test_an_unregistered_backend_at_execution_is_reported(harness: Harness) -> None:
    planned = audit.plan(harness.job(), UID)
    empty = audit.Auditor(owner_uid=UID, registry=scanner.BackendRegistry())
    with pytest.raises(audit.AuditError) as raised:
        empty.execute(planned)
    assert raised.value.error_type == "unknown_backend"
    assert raised.value.evidence_dir == str(harness.run_dir)


def test_the_default_registry_holds_the_openscap_backend(harness: Harness) -> None:
    result = cast(
        "dict[str, Any]", audit.Auditor(owner_uid=UID).run(harness.job(), check_mode=True)
    )
    assert result["planned"]["backend"] == "openscap"


class RefusingBackend:
    """A backend that refuses every request."""

    def audit(self, request: scanner.ScanRequest) -> model.ScanRun:
        message = f"refused {request.run_id}"
        raise scanner.ScanRequestError(message)


def refusing_auditor() -> audit.Auditor:
    registry = scanner.BackendRegistry()
    registry.register("openscap", lambda _settings: RefusingBackend())
    return audit.Auditor(owner_uid=UID, registry=registry)


def test_a_backend_request_error_is_reported_with_the_run_directory(harness: Harness) -> None:
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    with pytest.raises(audit.AuditError) as raised:
        refusing_auditor().run(harness.job(disabled_rules=disabled), check_mode=False)
    assert raised.value.error_type == "invalid_request"
    assert raised.value.evidence_dir == str(harness.run_dir)
    assert not (harness.run_dir / "content").exists()


def test_an_evidence_write_failure_is_reported(harness: Harness) -> None:
    def plant(results: Path) -> None:
        (results.parent.parent / ".scan-run.json.tmp").write_text("x", encoding="utf-8")

    harness.runner.on_evaluate = plant
    with pytest.raises(audit.AuditError) as raised:
        harness.run()
    assert raised.value.error_type == "evidence_write_failed"
    assert raised.value.evidence_dir == str(harness.run_dir)
    assert not (harness.run_dir / "scan-run.json").exists()


def test_scanner_entries_that_are_not_regular_files_are_ignored(harness: Harness) -> None:
    outside = harness.root / "outside"
    outside.write_text("secret", encoding="utf-8")
    outside.chmod(0o644)

    def plant(results: Path) -> None:
        (results.parent / "link").symlink_to(outside)
        (results.parent / "nested").mkdir()

    harness.runner.on_evaluate = plant
    result = harness.run()
    names = {Path(item["path"]).name for item in result["evidence"]["files"]}
    assert names == {"results.xml", "results-arf.xml", "scan-run.json"}
    scan = harness.run_dir / "scan"
    assert result["evidence"]["skipped"] == [
        {"path": str(scan / "link"), "type": "symlink"},
        {"path": str(scan / "nested"), "type": "directory"},
    ]
    assert mode(outside) == 0o644


def test_too_many_scanner_entries_are_refused(harness: Harness) -> None:
    def flood(results: Path) -> None:
        for index in range(audit.MAX_EVIDENCE_ENTRIES):
            (results.parent / f"extra-{index}").write_text("x", encoding="utf-8")

    harness.runner.on_evaluate = flood
    with pytest.raises(audit.AuditError) as raised:
        harness.run()
    assert raised.value.error_type == "evidence_write_failed"


class StaticBackend:
    """A backend that returns a prepared run and writes nothing."""

    def __init__(self, run: model.ScanRun) -> None:
        self.run = run
        self.requests: list[scanner.ScanRequest] = []

    def audit(self, request: scanner.ScanRequest) -> model.ScanRun:
        self.requests.append(request)
        return self.run


def finding(rule_id: str, outcome: model.Outcome) -> model.Finding:
    return model.Finding(
        rule_id=rule_id,
        outcome=outcome,
        evaluated_outcome=outcome,
        severity=model.Severity.LOW,
        message=None if outcome is not model.Outcome.ERROR else "broken",
        evidence=(),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=None,
        flags=(),
    )


def static_run(status: model.ScanStatus, *findings: model.Finding) -> model.ScanRun:
    return model.ScanRun(
        run_id="run-1",
        started_at="2026-10-25T09:00:00Z",
        finished_at="2026-10-25T09:00:05Z",
        host=HOST,
        scanner=model.ScannerInfo("static", "1"),
        content=model.Provenance("synthetic-ds.xml", "1.2.3", SHA256),
        benchmark_id=BENCHMARK,
        profile_id=TAILORED,
        status=status,
        error_message=None if status is model.ScanStatus.COMPLETED else "x" * 4096,
        findings=findings,
    )


def static_auditor(run: model.ScanRun) -> tuple[audit.Auditor, StaticBackend]:
    backend = StaticBackend(run)
    registry = scanner.BackendRegistry()
    registry.register("openscap", lambda _settings: backend)
    return audit.Auditor(owner_uid=UID, registry=registry), backend


def test_a_backend_that_writes_no_output_still_gets_a_recorded_run(harness: Harness) -> None:
    run = static_run(model.ScanStatus.COMPLETED, finding(BETA, model.Outcome.PASS))
    auditor, backend = static_auditor(run)
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    result = cast(
        "dict[str, Any]", auditor.run(harness.job(disabled_rules=disabled), check_mode=False)
    )
    assert len(backend.requests) == 1
    request = backend.requests[0]
    assert request.profile_id == TAILORED
    assert request.expected_rule_ids == (BETA,)
    assert request.output_dir == "scan"
    assert request.tailoring_path == str(harness.run_dir / "tailoring.xml")
    kinds = sorted(item["kind"] for item in result["evidence"]["files"])
    assert kinds == ["scan_run", "tailoring"]
    assert outcomes(result) == {ALPHA: "disabled", BETA: "pass"}
    tailoring = (harness.run_dir / "tailoring.xml").read_text(encoding="utf-8")
    assert '<xccdf:version time="' in tailoring


def test_long_failure_messages_are_bounded(harness: Harness) -> None:
    run = static_run(model.ScanStatus.FAILED, finding(BETA, model.Outcome.ERROR))
    auditor, _backend = static_auditor(run)
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    result = cast(
        "dict[str, Any]", auditor.run(harness.job(disabled_rules=disabled), check_mode=False)
    )
    assert result["run_status"] == "failed"
    messages = [item["message"] for item in result["scan_run"]["findings"]]
    assert all(len(message) <= audit.MAX_MESSAGE_LENGTH for message in messages)


def test_the_planned_scan_is_described_without_side_effects(harness: Harness) -> None:
    disabled = audit.parse_disabled_rules([{"rule_id": BETA}])
    planned = audit.plan(harness.job(disabled_rules=disabled), UID)
    assert planned.tailored is True
    description = planned.to_dict()
    assert description["rule_count"] == 2
    assert description["disabled_rule_count"] == 1
    assert description["evaluated_profile_id"] == TAILORED
    assert description["benchmark_version"] == "1.2.3"
    assert json.dumps(description)
    assert not harness.output_root.exists()


def test_summarize_without_a_run_is_none() -> None:
    assert audit.summarize(None) is None


def host_params(**overrides: object) -> dict[str, object]:
    host: dict[str, object] = {
        "hostname": "web01",
        "distribution_id": "ubuntu",
        "distribution_version": "24.04",
        "architecture": "x86_64",
        "machine_id": None,
    }
    host.update(overrides)
    return host


def params(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "backend": "openscap",
        "content_path": str(SYNTHETIC),
        "expected_sha256": SHA256,
        "profile_id": PROFILE,
        "host": host_params(),
        "output_dir": "/var/lib/freesecdev/linux_compliance/evidence",
        "run_id": None,
        "scan_timeout": 1800.0,
        "max_result_bytes": 1024,
        "disabled_rules": [{"rule_id": ALPHA, "disabled_by": None}],
    }
    values.update(overrides)
    return values


def test_build_job_validates_module_parameters() -> None:
    job = audit.build_job(params(), START)
    assert job.run_id == "20261025T090000.000000Z"
    assert job.host == model.HostIdentity("web01", "ubuntu", "24.04", "x86_64", None)
    assert job.disabled_rules == (audit.DisabledRule(ALPHA, ALPHA_TOGGLE),)
    named = audit.build_job(
        params(run_id="nightly-1", host=host_params(machine_id="a" * 32)), START
    )
    assert named.run_id == "nightly-1"
    assert named.host.machine_id == "a" * 32
    empty = audit.build_job(params(host=host_params(machine_id="")), START)
    assert empty.host.machine_id is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"host": "web01"},
        {"host": host_params(hostname="web 01")},
        {"host": host_params(distribution_id="Ubuntu")},
        {"host": host_params(machine_id="xyz")},
        {"scan_timeout": 0.0},
        {"scan_timeout": -1.0},
        {"scan_timeout": 3601.0},
        {"scan_timeout": True},
        {"scan_timeout": "60"},
        {"max_result_bytes": 0},
        {"max_result_bytes": scanner.MAX_RESULT_BYTES_LIMIT + 1},
        {"max_result_bytes": False},
        {"max_result_bytes": 1.5},
        {"backend": "Open SCAP"},
        {"backend": ""},
        {"backend": None},
    ],
)
def test_build_job_rejects_invalid_parameters(overrides: dict[str, object]) -> None:
    with pytest.raises(audit.AuditError) as raised:
        audit.build_job(params(**overrides), START)
    assert raised.value.error_type == "invalid_argument"


def test_a_job_needs_typed_host_and_disabled_rules(harness: Harness) -> None:
    with pytest.raises(audit.AuditError, match="HostIdentity"):
        harness.job(host={"hostname": "x"})
    with pytest.raises(audit.AuditError, match="tuple of DisabledRule"):
        harness.job(disabled_rules=[audit.DisabledRule(ALPHA, ALPHA_TOGGLE)])
    with pytest.raises(audit.AuditError, match="tuple of DisabledRule"):
        harness.job(disabled_rules=({"rule_id": ALPHA},))


def test_the_tailoring_document_contains_only_validated_identifiers(harness: Harness) -> None:
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}, {"rule_id": BETA}])
    planned = audit.AuditPlan(
        harness.job(disabled_rules=disabled),
        str(harness.datastream),
        audit.plan(harness.job(), UID).benchmark,
        (),
        (),
        TAILORED,
        str(harness.run_dir),
        output_root_exists=False,
    )
    document = audit.tailoring_document(planned, START)
    assert document.splitlines() == [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            '<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" '
            'id="xccdf_org.freesecdev_tailoring_linux_compliance_audit">'
        ),
        '  <xccdf:version time="2026-10-25T09:00:00Z">1</xccdf:version>',
        f'  <xccdf:Profile id="{TAILORED}" extends="{PROFILE}">',
        f"    <xccdf:title>{audit.TAILORING_TITLE}</xccdf:title>",
        f'    <xccdf:select idref="{ALPHA}" selected="false"/>',
        f'    <xccdf:select idref="{BETA}" selected="false"/>',
        "  </xccdf:Profile>",
        "</xccdf:Tailoring>",
    ]
    assert "<!" not in document


def test_a_final_directory_owned_by_another_user_is_rejected() -> None:
    with pytest.raises(audit.AuditError, match="not owned by uid") as raised:
        audit.inspect_output_root("/usr", UID + 1 if UID == 0 else UID, create=False)
    assert raised.value.error_type == "unsafe_output_dir"


@pytest.mark.parametrize("rule_id", ["--remediate", "xccdf_org.example.synthetic_rule_a;id", None])
def test_an_explicitly_toggled_rule_still_needs_a_valid_identifier(rule_id: object) -> None:
    with pytest.raises(audit.AuditError) as raised:
        audit.DisabledRule(cast("str", rule_id), ALPHA_TOGGLE)
    assert raised.value.error_type == "invalid_argument"
    if isinstance(rule_id, str):
        with pytest.raises(audit.AuditError):
            audit.parse_disabled_rules([{"rule_id": rule_id, "disabled_by": ALPHA_TOGGLE}])


@pytest.mark.parametrize(
    ("mode_bits", "expected"),
    [
        (stat.S_IFLNK, "symlink"),
        (stat.S_IFDIR, "directory"),
        (stat.S_IFIFO, "fifo"),
        (stat.S_IFSOCK, "socket"),
        (stat.S_IFCHR, "other"),
    ],
)
def test_skipped_entry_types(mode_bits: int, expected: str) -> None:
    assert audit.entry_type(mode_bits) == expected


def test_xml_escape_covers_every_markup_character() -> None:
    assert audit.xml_escape("a&b<c>d\"e'f") == "a&amp;b&lt;c&gt;d&quot;e&apos;f"
    assert audit.xml_escape(ALPHA) == ALPHA


def test_check_mode_reports_a_copy_that_cannot_be_removed(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    locked: list[Path] = []

    def lock(results: Path) -> None:
        directory = results.parent.parent / "content"
        directory.chmod(0o500)
        locked.append(directory)

    harness.runner.on_evaluate = lock
    try:
        with pytest.raises(audit.AuditError, match="could not be removed") as raised:
            harness.run(check_mode=True)
        assert raised.value.error_type == "cleanup_failed"
        assert raised.value.evidence_dir is not None
    finally:
        for directory in locked:
            directory.chmod(0o700)
