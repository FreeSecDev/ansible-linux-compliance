from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model

if TYPE_CHECKING:
    from collections.abc import Callable

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"
REPORTING = FIXTURES / "reporting"
XCCDF = FIXTURES / "xccdf"
RULE_PREFIX = "xccdf_org.example.synthetic_rule_"
BENCHMARK = "xccdf_org.example.synthetic_benchmark_demo"
PROFILE = "xccdf_org.example.synthetic_profile_baseline"
STARTED = "2026-10-25T10:00:00Z"
FINISHED = "2026-10-25T10:00:09Z"
HOST = model.HostIdentity("host.example", "rhel", "9", "x86_64", None)
SHA = "a" * 64


def finding(
    name: str,
    outcome: model.Outcome = model.Outcome.PASS,
    *,
    severity: model.Severity = model.Severity.MEDIUM,
    exception: model.ExceptionStatus | None = None,
    evaluated: model.Outcome | None = None,
) -> model.Finding:
    return model.Finding(
        rule_id=RULE_PREFIX + name,
        outcome=outcome,
        evaluated_outcome=evaluated or outcome,
        severity=severity,
        message=None,
        evidence=(),
        exception=exception or model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=None,
        flags=(),
    )


def waived(name: str) -> model.Finding:
    exception = model.ExceptionStatus(
        model.ExceptionState.ACTIVE, "EXC-1", "accepted risk", "2026-12-31T00:00:00Z"
    )
    return finding(name, model.Outcome.WAIVED, exception=exception, evaluated=model.Outcome.FAIL)


def expired(name: str) -> model.Finding:
    exception = model.ExceptionStatus(
        model.ExceptionState.EXPIRED, "EXC-2", "old risk", "2026-10-01T00:00:00Z"
    )
    return finding(name, model.Outcome.FAIL, exception=exception)


def scan_run(
    findings: tuple[model.Finding, ...],
    *,
    status: model.ScanStatus = model.ScanStatus.COMPLETED,
    host: model.HostIdentity = HOST,
    content_version: str = "1.0",
    benchmark_id: str = BENCHMARK,
) -> model.ScanRun:
    return model.ScanRun(
        run_id="run-1",
        started_at=STARTED,
        finished_at=FINISHED,
        host=host,
        scanner=model.ScannerInfo("oscap", "1.3.10"),
        content=model.Provenance("synthetic-ds.xml", content_version, SHA),
        benchmark_id=benchmark_id,
        profile_id=PROFILE,
        status=status,
        error_message=None if status is model.ScanStatus.COMPLETED else "scanner did not finish",
        findings=findings,
    )


def xccdf_text(
    target: str | None,
    outcome: str = "pass",
    version: str = "1.0",
    results: list[tuple[str, str]] | None = None,
) -> str:
    host = "" if target is None else f"<target>{target}</target>"
    rules = "".join(
        f'<rule-result idref="{RULE_PREFIX}{name}" severity="medium">'
        f"<result>{state}</result></rule-result>"
        for name, state in (results or [("a", outcome)])
    )
    stamps = 'start-time="2026-10-25T10:00:00+00:00" end-time="2026-10-25T10:00:09+00:00"'
    return (
        f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{BENCHMARK}">'
        f"<version>{version}</version>"
        f'<TestResult id="x" {stamps} version="{version}">'
        f'<benchmark id="{BENCHMARK}"/><profile idref="{PROFILE}"/>{host}{rules}'
        "</TestResult></Benchmark>"
    )


class Kit:
    """Helpers and fixture paths shared by the reporting tests."""

    finding = staticmethod(finding)
    waived = staticmethod(waived)
    expired = staticmethod(expired)
    scan_run = staticmethod(scan_run)
    xccdf_text = staticmethod(xccdf_text)
    RULE_PREFIX = RULE_PREFIX
    HOST = HOST
    REPORTING = REPORTING
    XCCDF = XCCDF
    BENCHMARK = BENCHMARK
    PROFILE = PROFILE


@pytest.fixture
def kit() -> type[Kit]:
    return Kit


@pytest.fixture
def write(tmp_path: Path) -> Callable[[str, str | bytes], Path]:
    def _write(name: str, content: str | bytes) -> Path:
        path = tmp_path / name
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        return path

    return _write


@pytest.fixture
def write_run(write: Callable[[str, str | bytes], Path]) -> Callable[..., Path]:
    def _write_run(name: str, run: model.ScanRun) -> Path:
        return write(name, model.dumps(run))

    return _write_run
