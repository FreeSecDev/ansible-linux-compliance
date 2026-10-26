"""The off-platform opt-in of the audit module (ADR 0019, amendment of FREES-161)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    model,
    scanner,
)
from tests.unit.plugins.module_utils.compliance.test_audit import (
    ALPHA,
    SHA256,
    START,
    UID,
    Harness,
    host_params,
    params,
)

TARGET = model.HostIdentity("host.example", "ubuntu", "26.04", "x86_64", None)
MARKER = model.OffPlatform(model.Platform("ubuntu", "24.04"), model.Platform("ubuntu", "26.04"))


class MarkingBackend:
    """A stand-in for the SCC backend that returns an off-platform run."""

    def __init__(self, digest: str = SHA256) -> None:
        self.requests: list[scanner.ScanRequest] = []
        self.digest = digest

    def audit(self, request: scanner.ScanRequest) -> model.ScanRun:
        self.requests.append(request)
        findings = tuple(
            model.Finding(
                rule_id=rule_id,
                outcome=model.Outcome.PASS,
                evaluated_outcome=model.Outcome.PASS,
                severity=model.Severity.MEDIUM,
                message=None,
                evidence=(),
                exception=model.ExceptionStatus.none(),
                remediation=None,
                disabled_by=None,
                flags=(),
            )
            for rule_id in request.expected_rule_ids
        )
        return model.ScanRun(
            run_id=request.run_id,
            started_at="2026-10-25T09:00:00Z",
            finished_at="2026-10-25T09:00:01Z",
            host=request.host,
            scanner=model.ScannerInfo("scc", "5.15"),
            content=model.Provenance("synthetic-ds.xml", "1.0", self.digest),
            benchmark_id=request.benchmark_id,
            profile_id=request.profile_id,
            status=model.ScanStatus.COMPLETED,
            error_message=None,
            findings=findings,
            off_platform=MARKER,
        )


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    tmp_path.chmod(0o755)
    return Harness(tmp_path)


def auditor(backend: MarkingBackend) -> audit.Auditor:
    registry = scanner.BackendRegistry()
    registry.register("scc", lambda _settings: backend)
    return audit.Auditor(owner_uid=UID, registry=registry, clock=lambda: START)


def test_the_opt_in_is_off_by_default() -> None:
    job = audit.build_job(params(), START)
    assert job.allow_off_platform_benchmark is False
    without = {key: value for key, value in params().items() if key != "disabled_rules"}
    assert audit.build_job(without, START).allow_off_platform_benchmark is False


def test_the_opt_in_is_accepted_for_the_scc_backend() -> None:
    job = audit.build_job(
        params(
            backend="scc",
            allow_off_platform_benchmark=True,
            host=host_params(distribution_version="26.04"),
        ),
        START,
    )
    assert job.allow_off_platform_benchmark is True


def test_the_openscap_backend_refuses_the_opt_in() -> None:
    with pytest.raises(audit.AuditError, match="applies only to the backend scc") as raised:
        audit.build_job(params(allow_off_platform_benchmark=True), START)
    assert raised.value.error_type == "invalid_argument"


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_the_opt_in_is_strictly_a_boolean(harness: Harness, value: object) -> None:
    with pytest.raises(audit.AuditError, match="must be a boolean") as raised:
        harness.job(backend="scc", allow_off_platform_benchmark=value)
    assert raised.value.error_type == "invalid_argument"


def test_the_opt_in_reaches_the_backend_and_the_run_is_reported_marked(harness: Harness) -> None:
    backend = MarkingBackend()
    job = harness.job(backend="scc", host=TARGET, allow_off_platform_benchmark=True)
    result: dict[str, Any] = auditor(backend).run(job, check_mode=False)
    assert [request.allow_off_platform_benchmark for request in backend.requests] == [True]
    assert result["planned"]["allow_off_platform_benchmark"] is True
    run = result["scan_run"]
    assert run["schema_version"] == "1.1"
    assert run["off_platform"] == MARKER.to_dict()
    assert all(item["off_platform"] == MARKER.to_dict() for item in run["findings"])
    record = Path(harness.run_dir / "scan-run.json").read_text(encoding="utf-8")
    assert model.loads(record).off_platform == MARKER
    assert json.loads(record)["schema_version"] == "1.1"


def test_rules_added_to_a_marked_run_carry_the_marker(harness: Harness) -> None:
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    job = harness.job(
        backend="scc", host=TARGET, allow_off_platform_benchmark=True, disabled_rules=disabled
    )
    result: dict[str, Any] = auditor(MarkingBackend()).run(job, check_mode=False)
    findings = {item["rule_id"]: item for item in result["scan_run"]["findings"]}
    assert findings[ALPHA]["outcome"] == "disabled"
    assert {json.dumps(item["off_platform"]) for item in findings.values()} == {
        json.dumps(MARKER.to_dict())
    }


def test_a_marked_run_with_the_wrong_digest_fails_and_keeps_the_marker(harness: Harness) -> None:
    job = harness.job(backend="scc", host=TARGET, allow_off_platform_benchmark=True)
    result: dict[str, Any] = auditor(MarkingBackend(digest="b" * 64)).run(job, check_mode=False)
    assert result["run_status"] == "failed"
    assert result["scan_run"]["off_platform"] == MARKER.to_dict()
    assert {item["outcome"] for item in result["scan_run"]["findings"]} == {"error"}


def test_without_the_opt_in_the_backend_is_told_so(harness: Harness) -> None:
    backend = MarkingBackend()
    auditor(backend).run(harness.job(backend="scc", host=TARGET), check_mode=False)
    assert [request.allow_off_platform_benchmark for request in backend.requests] == [False]
