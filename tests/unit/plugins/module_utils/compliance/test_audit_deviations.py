"""Operator deviations in the audit (ADR 0032 section 4, decisions A and D; FREES-203)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    audit_result,
    ledger,
    model,
    scanner,
)
from tests.unit.plugins.module_utils.compliance.test_audit import (
    ALPHA,
    BETA,
    GAMMA,
    UID,
    Harness,
)
from tests.unit.plugins.module_utils.compliance.test_audit_post_scan import ScanningBackend

if TYPE_CHECKING:
    from pathlib import Path

MINLEN = model.Deviation("var_password_pam_minlen", "14", "8")
TIMEOUT = model.Deviation("var_sudo_timestamp_timeout", "15", "30")


def record(rule_id: str, deviation: model.Deviation = MINLEN) -> ledger.DeviationRecord:
    return ledger.DeviationRecord(
        rule_id=rule_id,
        value_id=deviation.value_id,
        profile_value=deviation.profile_value,
        effective_value=deviation.effective_value,
        recorded_at="2026-11-11T08:00:00Z",
        collection_version="0.1.0",
    )


def register(harness: Harness, *records: ledger.DeviationRecord) -> None:
    store = ledger.Ledger(state_dir=str(harness.state_dir), owner_uid=UID)
    for item in records:
        store.record_deviation(item)


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    tmp_path.chmod(0o755)
    return Harness(tmp_path)


def findings_of(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["rule_id"]: item for item in result["scan_run"]["findings"]}


def item(rule_id: str, outcome: str | None, deviation: model.Deviation = MINLEN) -> dict[str, Any]:
    return {"outcome": outcome, "rule_id": rule_id, **deviation.to_dict()}


def test_without_a_ledger_nothing_is_flagged_and_the_run_keeps_its_schema(
    harness: Harness,
) -> None:
    result = harness.run()
    assert not harness.state_dir.exists()
    assert result["scan_run"]["schema_version"] == model.SCHEMA_VERSION
    assert result["deviations"] == {"flagged": [], "recorded": 0, "unflagged": []}
    assert result["summary"]["deviation"] == 0
    assert all(item["flags"] == [] for item in result["scan_run"]["findings"])


def test_an_empty_register_flags_nothing(harness: Harness) -> None:
    register(harness, record(ALPHA))
    ledger.Ledger(state_dir=str(harness.state_dir), owner_uid=UID).remove_deviation(ALPHA)
    assert (harness.state_dir / ledger.LEDGER_FILENAME).exists()
    result = harness.run()
    assert result["deviations"] == {"flagged": [], "recorded": 0, "unflagged": []}
    assert result["scan_run"]["schema_version"] == model.SCHEMA_VERSION


def test_a_pass_and_a_fail_of_recorded_rules_carry_the_flag_and_the_deviation(
    harness: Harness,
) -> None:
    register(harness, record(ALPHA), record(BETA, TIMEOUT))
    result = harness.run()
    findings = findings_of(result)
    assert findings[ALPHA]["outcome"] == "pass"
    assert findings[ALPHA]["flags"] == ["operator_deviation"]
    assert findings[ALPHA]["deviation"] == MINLEN.to_dict()
    assert findings[BETA]["outcome"] == "fail"
    assert findings[BETA]["evaluated_outcome"] == "fail"
    assert findings[BETA]["flags"] == ["operator_deviation"]
    assert findings[BETA]["deviation"] == TIMEOUT.to_dict()
    assert result["scan_run"]["schema_version"] == model.DEVIATION_SCHEMA_VERSION
    assert result["summary"]["deviation"] == 2
    assert result["summary"]["pass"] == 1
    assert result["summary"]["fail"] == 1
    assert result["deviations"] == {
        "flagged": [item(ALPHA, "pass"), item(BETA, "fail", TIMEOUT)],
        "recorded": 2,
        "unflagged": [],
    }


def test_the_evidence_holds_the_stamped_run(harness: Harness) -> None:
    register(harness, record(ALPHA))
    result = harness.run()
    written = (harness.run_dir / audit.SCAN_RUN_FILE_NAME).read_text(encoding="utf-8")
    assert json.loads(written) == result["scan_run"]
    reread = model.loads(written)
    flagged = [finding for finding in reread.findings if finding.deviation is not None]
    assert [finding.rule_id for finding in flagged] == [ALPHA]
    assert reread.schema_version == model.DEVIATION_SCHEMA_VERSION


@pytest.mark.parametrize(
    ("scanned", "outcome"),
    [
        ("notapplicable", "notapplicable"),
        ("error", "error"),
        ("notchecked", "notchecked"),
    ],
)
def test_an_outcome_that_cannot_carry_the_flag_is_listed_unflagged(
    harness: Harness, scanned: str, outcome: str
) -> None:
    register(harness, record(ALPHA))
    harness.runner.results = {ALPHA: scanned, BETA: "fail"}
    result = harness.run()
    finding = findings_of(result)[ALPHA]
    assert finding["outcome"] == outcome
    assert finding["flags"] == []
    assert result["scan_run"]["schema_version"] == model.SCHEMA_VERSION
    assert result["summary"]["deviation"] == 0
    assert result["deviations"] == {
        "flagged": [],
        "recorded": 1,
        "unflagged": [item(ALPHA, outcome)],
    }


def test_a_disabled_rule_is_listed_unflagged(harness: Harness) -> None:
    register(harness, record(ALPHA))
    harness.runner.results = {ALPHA: "notselected", BETA: "fail"}
    disabled = audit.parse_disabled_rules([{"rule_id": ALPHA}])
    result = harness.run(disabled_rules=disabled)
    assert findings_of(result)[ALPHA]["outcome"] == "disabled"
    assert result["deviations"]["unflagged"] == [item(ALPHA, "disabled")]


def test_a_rule_the_profile_does_not_select_is_listed_without_an_outcome(
    harness: Harness,
) -> None:
    register(harness, record(BETA), record(GAMMA, TIMEOUT))
    result = harness.run()
    assert GAMMA not in findings_of(result)
    assert result["deviations"] == {
        "flagged": [item(BETA, "fail")],
        "recorded": 2,
        "unflagged": [item(GAMMA, None, TIMEOUT)],
    }


def test_a_scan_that_did_not_complete_flags_nothing(harness: Harness) -> None:
    register(harness, record(ALPHA))
    harness.runner.timed_out = True
    harness.runner.returncode = 0
    result = harness.run()
    assert result["run_status"] == "timed_out"
    assert result["summary"]["deviation"] == 0
    assert result["deviations"]["unflagged"] == [item(ALPHA, "error")]


def test_check_mode_stamps_the_preview_and_keeps_nothing(harness: Harness) -> None:
    harness.output_root.mkdir(mode=0o700)
    register(harness, record(ALPHA))
    result = harness.run(check_mode=True)
    assert result["evidence_written"] is False
    assert findings_of(result)[ALPHA]["flags"] == ["operator_deviation"]
    assert result["deviations"]["flagged"] == [item(ALPHA, "pass")]
    assert list(harness.output_root.iterdir()) == []


def test_check_mode_without_an_output_root_lists_the_register(harness: Harness) -> None:
    register(harness, record(ALPHA))
    result = harness.run(check_mode=True)
    assert result["run_status"] == audit.RUN_STATUS_NOT_RUN
    assert result["summary"] is None
    assert result["deviations"] == {
        "flagged": [],
        "recorded": 1,
        "unflagged": [item(ALPHA, None)],
    }


def test_the_plan_reads_the_register(harness: Harness) -> None:
    register(harness, record(ALPHA))
    planned = audit.plan(harness.job(), owner_uid=UID, state_dir=str(harness.state_dir))
    assert planned.deviations == (audit_result.RecordedDeviation(ALPHA, MINLEN),)


def assert_refused_before_the_scan(
    harness: Harness, error_type: str, *, check_mode: bool = False
) -> audit.AuditError:
    with pytest.raises(audit.AuditError) as raised:
        harness.run(check_mode=check_mode)
    assert raised.value.error_type == error_type
    assert raised.value.evidence_dir is None
    assert harness.runner.evaluations == []
    assert not harness.output_root.exists()
    return raised.value


def test_a_corrupt_ledger_stops_the_audit_before_anything_is_created(harness: Harness) -> None:
    register(harness, record(ALPHA))
    (harness.state_dir / ledger.LEDGER_FILENAME).write_bytes(b'{"schema_version": 2,')
    error = assert_refused_before_the_scan(harness, audit.ERROR_DEVIATIONS)
    assert "control_state" in str(error)
    assert "nothing was scanned" in str(error)
    assert str(harness.state_dir) in str(error)


def test_an_unsupported_ledger_version_stops_the_audit(harness: Harness) -> None:
    register(harness, record(ALPHA))
    (harness.state_dir / ledger.LEDGER_FILENAME).write_bytes(
        b'{"deviations": [], "entries": [], "schema_version": 3}'
    )
    assert_refused_before_the_scan(harness, audit.ERROR_DEVIATIONS)


def test_an_unsafe_ledger_directory_stops_the_audit_in_check_mode_too(harness: Harness) -> None:
    register(harness, record(ALPHA))
    harness.state_dir.chmod(0o770)
    assert_refused_before_the_scan(harness, audit.ERROR_DEVIATIONS, check_mode=True)


def test_a_ledger_of_another_owner_stops_the_audit(harness: Harness) -> None:
    register(harness, record(ALPHA))
    planned = harness.job()
    with pytest.raises(audit.AuditError) as raised:
        audit.plan(planned, owner_uid=UID + 1, state_dir=str(harness.state_dir))
    assert raised.value.error_type == audit.ERROR_DEVIATIONS


def test_a_record_the_model_refuses_stops_the_audit(harness: Harness) -> None:
    same = ledger.DeviationRecord(
        rule_id=ALPHA,
        value_id="var_password_pam_minlen",
        profile_value="14",
        effective_value="14",
        recorded_at="2026-11-11T08:00:00Z",
        collection_version="0.1.0",
    )
    register(harness, same)
    error = assert_refused_before_the_scan(harness, audit.ERROR_DEVIATIONS)
    assert ALPHA in str(error)


def scc_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    tmp_path.chmod(0o755)
    release = tmp_path / "os-release"
    release.write_text('NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n', encoding="utf-8")
    monkeypatch.setattr(audit, "OS_RELEASE_PATH", str(release))
    return Harness(tmp_path)


def scc_auditor(harness: Harness, backend: ScanningBackend) -> audit.Auditor:
    registry = scanner.BackendRegistry()
    registry.register("scc", lambda _settings: backend)
    return harness.auditor(registry=registry)


def test_scc_is_refused_while_the_register_holds_a_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = scc_harness(tmp_path, monkeypatch)
    register(harness, record(ALPHA))
    backend = ScanningBackend()
    with pytest.raises(audit.AuditError) as raised:
        scc_auditor(harness, backend).run(harness.job(backend="scc"), check_mode=False)
    assert raised.value.error_type == audit.ERROR_DEVIATION_BACKEND
    assert "scc" in str(raised.value)
    assert backend.requests == []
    assert not harness.output_root.exists()


def test_scc_scans_with_an_empty_register(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = scc_harness(tmp_path, monkeypatch)
    register(harness)
    backend = ScanningBackend()
    result = scc_auditor(harness, backend).run(harness.job(backend="scc"), check_mode=False)
    assert result["deviations"] == {"flagged": [], "recorded": 0, "unflagged": []}
    assert len(backend.requests) == 1


def finding(outcome: model.Outcome) -> model.Finding:
    waived = outcome is model.Outcome.WAIVED
    return model.Finding(
        rule_id=ALPHA,
        outcome=outcome,
        evaluated_outcome=model.Outcome.FAIL if waived else outcome,
        severity=model.Severity.MEDIUM,
        message=None,
        evidence=(),
        exception=(
            model.ExceptionStatus(
                model.ExceptionState.ACTIVE, "EXC-1", "accepted risk", "2027-01-01T00:00:00Z"
            )
            if waived
            else model.ExceptionStatus.none()
        ),
        remediation=None,
        disabled_by="linux_compliance_rule_alpha_enabled"
        if outcome is model.Outcome.DISABLED
        else None,
        flags=(),
    )


@pytest.mark.parametrize("outcome", list(model.Outcome))
def test_stamp_follows_the_outcomes_the_model_allows(outcome: model.Outcome) -> None:
    recorded = (audit_result.RecordedDeviation(ALPHA, MINLEN),)
    (stamped,) = audit_result.stamp((finding(outcome),), recorded)
    allowed = outcome in {model.Outcome.PASS, model.Outcome.FAIL, model.Outcome.WAIVED}
    assert (stamped.deviation is not None) is allowed
    assert (model.ResultFlag.OPERATOR_DEVIATION in stamped.flags) is allowed
    assert stamped.outcome is outcome


def test_stamp_leaves_other_rules_alone() -> None:
    recorded = (audit_result.RecordedDeviation(BETA, MINLEN),)
    original = finding(model.Outcome.PASS)
    assert audit_result.stamp((original,), recorded) == (original,)


def test_registered_refuses_scc_only_with_records() -> None:
    assert audit_result.registered(lambda: (), "scc", "/state") == ()
    with pytest.raises(audit_result.RegisterError) as raised:
        audit_result.registered(lambda: (record(ALPHA),), "scc", "/state")
    assert raised.value.error_type == audit_result.ERROR_DEVIATION_BACKEND
    assert audit_result.registered(lambda: (record(ALPHA),), "openscap", "/state") == (
        audit_result.RecordedDeviation(ALPHA, MINLEN),
    )


def test_registered_turns_a_ledger_error_into_an_untrusted_source() -> None:
    def broken() -> tuple[ledger.DeviationRecord, ...]:
        kind, message = "corrupt", "the ledger is not valid JSON"
        raise ledger.LedgerError(kind, message)

    with pytest.raises(audit_result.RegisterError) as raised:
        audit_result.registered(broken, "openscap", "/state")
    assert raised.value.error_type == audit_result.ERROR_DEVIATIONS
    assert "the ledger is not valid JSON" in str(raised.value)


def test_describe_and_summarize_without_a_run() -> None:
    recorded = (audit_result.RecordedDeviation(ALPHA, MINLEN),)
    assert audit_result.describe(recorded, None) == {
        "flagged": [],
        "recorded": 1,
        "unflagged": [item(ALPHA, None)],
    }
    assert audit_result.summarize(None) is None
