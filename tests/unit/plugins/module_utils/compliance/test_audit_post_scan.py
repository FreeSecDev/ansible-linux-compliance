"""Disabled rules after the scan and control placements in the audit (ADR 0019, FREES-170)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    model,
    scanner,
)
from tests.unit.plugins.module_utils.compliance.test_audit import (
    ALPHA,
    BETA,
    PROFILE,
    SHA256,
    START,
    UID,
    Harness,
    params,
)

if TYPE_CHECKING:
    from pathlib import Path

TOGGLE = "linux_compliance_ssh_enabled"
PLACEMENT: dict[str, Any] = {
    "rule_id": ALPHA,
    "family": "ssh",
    "topic": "ssh",
    "tags": ["auditd"],
    "stig_id": "UBTU-24-100010",
    "mapped_rules": ["xccdf_org.ssgproject.content_rule_sshd_banner"],
    "partially_disabled_by": [],
}


class ScanningBackend:
    """A stand-in for the SCC backend that evaluates every expected rule."""

    def __init__(
        self,
        outcome: model.Outcome = model.Outcome.PASS,
        status: model.ScanStatus = model.ScanStatus.COMPLETED,
    ) -> None:
        self.requests: list[scanner.ScanRequest] = []
        self.outcome = outcome
        self.status = status

    def audit(self, request: scanner.ScanRequest) -> model.ScanRun:
        self.requests.append(request)
        completed = self.status is model.ScanStatus.COMPLETED
        outcome = self.outcome if completed else model.Outcome.ERROR
        findings = tuple(
            model.Finding(
                rule_id=rule_id,
                outcome=outcome,
                evaluated_outcome=outcome,
                severity=model.Severity.MEDIUM,
                message=None if completed else "SCC failed",
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
            content=model.Provenance("synthetic-ds.xml", "1.0", SHA256),
            benchmark_id=request.benchmark_id,
            profile_id=request.profile_id,
            status=self.status,
            error_message=None if completed else "SCC failed",
            findings=findings,
        )


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    tmp_path.chmod(0o755)
    release = tmp_path / "os-release"
    release.write_text('NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n', encoding="utf-8")
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(release))
    return Harness(tmp_path)


def auditor(backend: ScanningBackend) -> audit.Auditor:
    registry = scanner.BackendRegistry()
    registry.register("scc", lambda _settings: backend)
    return audit.Auditor(owner_uid=UID, registry=registry, clock=lambda: START)


def disabled() -> tuple[audit.DisabledRule, ...]:
    return audit.parse_disabled_rules([{"rule_id": ALPHA, "disabled_by": TOGGLE}])


def findings_of(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["rule_id"]: item for item in result["scan_run"]["findings"]}


def test_scc_scans_the_disabled_rules_without_a_tailoring_file(harness: Harness) -> None:
    backend = ScanningBackend()
    job = harness.job(backend="scc", disabled_rules=disabled())
    planned = audit.plan(job, owner_uid=UID)
    assert planned.disable_method == audit.DISABLE_AFTER_SCAN
    assert planned.tailored is False
    assert planned.evaluated_profile_id == PROFILE
    assert set(planned.expected_rule_ids) == {ALPHA, BETA}
    result: dict[str, Any] = auditor(backend).run(job, check_mode=False)
    assert len(backend.requests) == 1
    request = backend.requests[0]
    assert request.tailoring_path is None
    assert request.profile_id == PROFILE
    assert set(request.expected_rule_ids) == {ALPHA, BETA}
    assert not (harness.run_dir / audit.TAILORING_FILE_NAME).exists()
    assert result["planned"]["disable_method"] == "post_scan"
    assert result["planned"]["tailoring"] is False


def test_a_disabled_rule_that_passed_is_reported_disabled_never_pass(harness: Harness) -> None:
    job = harness.job(backend="scc", disabled_rules=disabled())
    result: dict[str, Any] = auditor(ScanningBackend()).run(job, check_mode=False)
    alpha = findings_of(result)[ALPHA]
    assert alpha["outcome"] == alpha["evaluated_outcome"] == "disabled"
    assert alpha["disabled_by"] == TOGGLE
    assert alpha["evidence"] == [{"content": "pass", "kind": "scanner_result", "source": "scc"}]
    assert "its result 'pass' is kept only in the raw results" in alpha["message"]
    assert findings_of(result)[BETA]["outcome"] == "pass"
    assert result["summary"]["pass"] == 1
    assert result["summary"]["disabled"] == 1
    assert result["summary"]["total"] == 2


def test_a_disabled_rule_of_a_failed_scan_is_an_error_naming_its_toggle(harness: Harness) -> None:
    job = harness.job(backend="scc", disabled_rules=disabled())
    result: dict[str, Any] = auditor(ScanningBackend(status=model.ScanStatus.FAILED)).run(
        job, check_mode=False
    )
    alpha = findings_of(result)[ALPHA]
    assert alpha["outcome"] == "error"
    assert f"the rule was disabled by {TOGGLE}" in alpha["message"]
    assert len(result["scan_run"]["findings"]) == 2


def test_openscap_still_tailors(harness: Harness) -> None:
    planned = audit.plan(harness.job(disabled_rules=disabled()), owner_uid=UID)
    assert planned.disable_method == audit.DISABLE_BY_TAILORING
    assert planned.tailored is True
    assert planned.expected_rule_ids == (BETA,)
    assert audit.plan(harness.job(), owner_uid=UID).disable_method == audit.DISABLE_NOTHING


def test_placements_reach_every_finding_of_their_rule(harness: Harness) -> None:
    placement = audit.parse_control_placement([PLACEMENT])
    job = harness.job(backend="scc", disabled_rules=disabled(), control_placement=placement)
    result: dict[str, Any] = auditor(ScanningBackend()).run(job, check_mode=False)
    run = result["scan_run"]
    assert run["schema_version"] == model.CONTROL_SCHEMA_VERSION
    found = findings_of(result)
    assert found[ALPHA]["control"]["family"] == "ssh"
    assert found[ALPHA]["outcome"] == "disabled"
    assert found[BETA]["control"] is None
    assert result["planned"]["control_placement_count"] == 1
    record = (harness.run_dir / "scan-run.json").read_text(encoding="utf-8")
    assert json.loads(record)["schema_version"] == "1.2"
    assert model.loads(record).findings[0].control is not None


def test_placements_survive_a_failed_scan(harness: Harness) -> None:
    placement = audit.parse_control_placement([PLACEMENT])
    job = harness.job(backend="scc", control_placement=placement)
    result: dict[str, Any] = auditor(ScanningBackend(status=model.ScanStatus.FAILED)).run(
        job, check_mode=False
    )
    assert findings_of(result)[ALPHA]["control"]["stig_id"] == "UBTU-24-100010"


def test_a_placement_for_a_rule_outside_the_profile_is_refused(harness: Harness) -> None:
    other = {**PLACEMENT, "rule_id": "xccdf_org.example.synthetic_rule_other"}
    job = harness.job(backend="scc", control_placement=audit.parse_control_placement([other]))
    with pytest.raises(audit.AuditError, match="not selected by the profile") as raised:
        audit.plan(job, owner_uid=UID)
    assert raised.value.error_type == "invalid_argument"


def test_the_module_parameters_carry_the_placements() -> None:
    job = audit.build_job(params(control_placement=[PLACEMENT]), START)
    (item,) = job.control_placement
    assert item.rule_id == ALPHA
    assert item.control.tags == ("auditd",)
    assert audit.build_job(params(), START).control_placement == ()


@pytest.mark.parametrize(
    ("items", "message"),
    [
        ({}, "control_placement must be a list"),
        ([1], "every control_placement item must be a mapping"),
        ([{**PLACEMENT, "extra": 1}], "unknown control_placement keys"),
        ([{**PLACEMENT, "rule_id": "bad"}], "control_placement rule_id is not a valid XCCDF"),
        ([{**PLACEMENT, "family": "Bad"}], "control.family has an invalid format"),
        ([{**PLACEMENT, "tags": "ssh"}], "tags must be a list of strings"),
        ([{**PLACEMENT, "mapped_rules": [1]}], "mapped_rules must be a list of strings"),
        ([PLACEMENT, PLACEMENT], "names a rule more than once"),
    ],
)
def test_invalid_placements_are_refused(items: object, message: str) -> None:
    with pytest.raises(audit.AuditError, match=message) as raised:
        audit.parse_control_placement(items)
    assert raised.value.error_type == "invalid_argument"


def test_too_many_placements_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "MAX_PLACEMENTS", 1)
    with pytest.raises(audit.AuditError, match="exceeds 1 items"):
        audit.parse_control_placement([PLACEMENT, {**PLACEMENT, "rule_id": BETA}])


def test_a_job_refuses_placements_of_the_wrong_type(harness: Harness) -> None:
    with pytest.raises(audit.AuditError, match="tuple of RulePlacement"):
        harness.job(control_placement=[PLACEMENT])
