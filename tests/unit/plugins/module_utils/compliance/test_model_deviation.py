"""Operator deviations in the findings model and schema version 1.3 (FREES-203, ADR 0032)."""

from __future__ import annotations

import itertools
import json
from dataclasses import replace
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    deviations,
    model,
)
from tests.unit.plugins.module_utils.compliance.test_model import (
    RULE,
    exception_status,
    finding,
    remediation,
    scan_run,
)
from tests.unit.plugins.module_utils.compliance.test_model_control import placed
from tests.unit.plugins.module_utils.compliance.test_model_off_platform import MARKER, marked_run

VALUE_ID = "var_password_pam_minlen"
DEVIATION = model.Deviation(VALUE_ID, "14", "12")
FLAG = model.ResultFlag.OPERATOR_DEVIATION
ALLOWED_OUTCOMES = frozenset({model.Outcome.PASS, model.Outcome.FAIL, model.Outcome.WAIVED})


def deviated(**overrides: Any) -> model.Finding:
    values: dict[str, Any] = {"flags": (FLAG,), "deviation": DEVIATION}
    return finding(**{**values, **overrides})


def deviated_run(**overrides: Any) -> model.ScanRun:
    return scan_run(findings=(deviated(),), **overrides)


def valued(**overrides: Any) -> model.RemediationResult:
    values: dict[str, Any] = {
        "status": model.RemediationStatus.DEVIATION,
        "value_source": model.ValueSource.OVERRIDE,
        "profile_value": "14",
        "effective_value": "12",
        "deviation": DEVIATION,
    }
    return remediation(**{**values, **overrides})


def findings_of(document: dict[str, object]) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", document["findings"])


def test_a_deviation_serializes_every_field_and_round_trips() -> None:
    assert DEVIATION.to_dict() == {
        "effective_value": "12",
        "profile_value": "14",
        "value_id": VALUE_ID,
    }
    assert model.Deviation.from_dict(DEVIATION.to_dict()) == DEVIATION
    longest = model.Deviation("a" * 128, "x" * deviations.MAX_VALUE_LENGTH, "4096 87380 6291456")
    assert model.Deviation.from_dict(longest.to_dict()) == longest


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"value_id": 7}, "value_id must be of type str"),
        ({"value_id": "Var_minlen"}, "value_id has an invalid format"),
        ({"value_id": "_var"}, "value_id has an invalid format"),
        ({"value_id": "a" * 129}, "value_id has an invalid format"),
        ({"value_id": "var-minlen"}, "value_id has an invalid format"),
        ({"profile_value": 14}, "profile_value must be a string"),
        ({"profile_value": ""}, "profile_value must not be empty"),
        ({"profile_value": " \t"}, "profile_value must not be empty"),
        ({"effective_value": " 12"}, "effective_value must not have surrounding whitespace"),
        ({"effective_value": "1\n2"}, "effective_value contains control or formatting"),
        ({"effective_value": "1\x002"}, "effective_value contains control or formatting"),
        ({"effective_value": "12\u202e"}, "effective_value contains control or formatting"),
        ({"effective_value": "1\u20282"}, "effective_value contains control or formatting"),
        ({"effective_value": "x" * 4097}, "effective_value exceeds 4096 characters"),
        ({"effective_value": "14"}, "effective_value must differ from the profile value"),
    ],
)
def test_a_deviation_rejects_invalid_fields(overrides: dict[str, object], message: str) -> None:
    values: dict[str, Any] = {**DEVIATION.to_dict(), **overrides}
    with pytest.raises(deviations.DeviationError, match=message):
        model.Deviation(**values)


def test_a_deviation_document_rejects_unknown_missing_and_non_mapping() -> None:
    with pytest.raises(deviations.DeviationError, match="deviation must be an object"):
        model.Deviation.from_dict(["var", "14", "12"])
    with pytest.raises(deviations.DeviationError, match="unknown keys: 'reason'"):
        model.Deviation.from_dict({**DEVIATION.to_dict(), "reason": "operator_override"})
    document = DEVIATION.to_dict()
    del document["value_id"]
    with pytest.raises(deviations.DeviationError, match="missing keys: value_id"):
        model.Deviation.from_dict(document)
    with pytest.raises(deviations.DeviationError, match="profile_value must be a string"):
        model.Deviation.from_dict({**DEVIATION.to_dict(), "profile_value": None})


@pytest.mark.parametrize("outcome", list(model.Outcome), ids=str)
def test_the_flag_is_allowed_on_pass_fail_and_waived_only(outcome: model.Outcome) -> None:
    extra: dict[str, object] = {}
    if outcome is model.Outcome.WAIVED:
        extra["exception"] = exception_status()
    if outcome is model.Outcome.DISABLED:
        extra["disabled_by"] = "linux_compliance_ssh_enabled"
    if outcome in ALLOWED_OUTCOMES:
        item = deviated(outcome=outcome, **extra)
        assert item.flags == (FLAG,)
        assert item.deviation == DEVIATION
        return
    with pytest.raises(model.ModelError, match="operator_deviation does not match outcome"):
        deviated(outcome=outcome, **extra)


def test_the_flag_and_the_deviation_go_together() -> None:
    with pytest.raises(model.ModelError, match=r"requires exactly finding\.deviation"):
        finding(flags=(FLAG,))
    with pytest.raises(model.ModelError, match=r"requires exactly finding\.deviation"):
        finding(deviation=DEVIATION)
    with pytest.raises(model.ModelError, match=r"finding\.deviation must be of type Deviation"):
        finding(flags=(FLAG,), deviation=DEVIATION.to_dict())


def test_a_fixed_pass_may_also_be_a_deviation_and_flags_stay_sorted() -> None:
    item = deviated(outcome=model.Outcome.PASS, flags=(FLAG, model.ResultFlag.FIXED))
    assert item.flags == (model.ResultFlag.FIXED, FLAG)
    assert item.to_dict()["flags"] == ["fixed", "operator_deviation"]


def test_a_waived_deviation_keeps_its_flag_and_object() -> None:
    failed = deviated()
    waived = replace(failed, outcome=model.Outcome.WAIVED, exception=exception_status())
    assert waived.flags == (FLAG,)
    assert waived.deviation == DEVIATION
    assert waived.evaluated_outcome is model.Outcome.FAIL
    run = scan_run(findings=(waived,))
    assert model.loads(model.dumps(run)).findings[0] == waived


def expected_version(*, marker: bool, control: bool, deviation: bool) -> str:
    if deviation:
        return model.DEVIATION_SCHEMA_VERSION
    if control:
        return model.CONTROL_SCHEMA_VERSION
    return model.OFF_PLATFORM_SCHEMA_VERSION if marker else model.SCHEMA_VERSION


MATRIX = list(itertools.product((False, True), repeat=3))


@pytest.mark.parametrize(
    ("marker", "control", "deviation"),
    MATRIX,
    ids=[f"marker={m}-control={c}-deviation={d}" for m, c, d in MATRIX],
)
def test_the_schema_version_follows_the_content(
    *, marker: bool, control: bool, deviation: bool
) -> None:
    first = finding(control=placed() if control else None)
    if deviation:
        first = replace(first, flags=(FLAG,), deviation=DEVIATION)
    other = finding(rule_id="xccdf_org.ssgproject.content_rule_other_rule")
    run = (marked_run if marker else scan_run)(findings=(first, other))
    version = expected_version(marker=marker, control=control, deviation=deviation)
    assert run.schema_version == version
    text = model.dumps(run)
    document = json.loads(text)
    assert document["schema_version"] == version
    assert (model.OFF_PLATFORM_KEY in document) is marker
    with_control = version in {model.CONTROL_SCHEMA_VERSION, model.DEVIATION_SCHEMA_VERSION}
    for item in findings_of(document):
        assert ("control" in item) is with_control
        assert ("deviation" in item) is (version == model.DEVIATION_SCHEMA_VERSION)
        assert (model.OFF_PLATFORM_KEY in item) is marker
    by_rule = {item["rule_id"]: item for item in findings_of(document)}
    if deviation:
        assert by_rule[RULE]["deviation"] == DEVIATION.to_dict()
        assert by_rule["xccdf_org.ssgproject.content_rule_other_rule"]["deviation"] is None
    assert model.loads(text) == run
    assert model.dumps(model.loads(text)) == text


def test_a_one_three_document_needs_a_deviation_somewhere() -> None:
    document = deviated_run().to_dict()
    findings: list[dict[str, object]] = [
        {**item, "flags": [], "deviation": None, "outcome": "fail"}
        for item in findings_of(document)
    ]
    with pytest.raises(model.ModelError, match="does not match the content"):
        model.ScanRun.from_dict({**document, "findings": findings})


def test_a_one_three_document_holds_control_and_deviation_on_every_finding() -> None:
    document = deviated_run().to_dict()
    for key in ("control", "deviation"):
        findings = [dict(item) for item in findings_of(document)]
        del findings[0][key]
        with pytest.raises(model.ModelError, match=f"missing keys: {key}"):
            model.ScanRun.from_dict({**document, "findings": findings})


@pytest.mark.parametrize("version", ["1.0", "1.1", "1.2"])
def test_older_documents_may_not_carry_a_deviation(version: str) -> None:
    run = marked_run(findings=(deviated(),)) if version == "1.1" else deviated_run()
    document = run.to_dict()
    with pytest.raises(model.ModelError, match=r"unknown keys: .*'deviation'"):
        model.ScanRun.from_dict({**document, "schema_version": version})


def test_a_one_two_document_cannot_hide_a_deviation_without_its_object() -> None:
    document = scan_run(findings=(finding(control=placed()),)).to_dict()
    findings = [{**item, "flags": ["operator_deviation"]} for item in findings_of(document)]
    with pytest.raises(model.ModelError, match=r"requires exactly finding\.deviation"):
        model.ScanRun.from_dict({**document, "findings": findings})


def test_a_one_three_document_refuses_a_flag_without_its_object_and_the_reverse() -> None:
    document = deviated_run().to_dict()
    without_object = [{**item, "deviation": None} for item in findings_of(document)]
    with pytest.raises(model.ModelError, match=r"requires exactly finding\.deviation"):
        model.ScanRun.from_dict({**document, "findings": without_object})
    without_flag: list[dict[str, object]] = [
        {**item, "flags": []} for item in findings_of(document)
    ]
    with pytest.raises(model.ModelError, match=r"requires exactly finding\.deviation"):
        model.ScanRun.from_dict({**document, "findings": without_flag})


def test_an_invalid_deviation_in_a_document_is_a_model_error() -> None:
    document = deviated_run().to_dict()
    for bad, message in (
        ({**DEVIATION.to_dict(), "value_id": "Bad"}, "value_id has an invalid format"),
        ({**DEVIATION.to_dict(), "effective_value": "14"}, "must differ from the profile"),
        ("12", "deviation must be an object"),
    ):
        findings = [{**item, "deviation": bad} for item in findings_of(document)]
        with pytest.raises(model.ModelError, match=message):
            model.ScanRun.from_dict({**document, "findings": findings})


def test_a_marked_run_stamps_its_marker_and_keeps_the_deviation() -> None:
    run = marked_run(findings=(deviated(),))
    assert run.findings[0].off_platform == MARKER
    assert run.findings[0].deviation == DEVIATION
    assert run.schema_version == model.DEVIATION_SCHEMA_VERSION
    assert model.loads(model.dumps(run)) == run


def test_a_remediation_result_without_a_value_keeps_its_four_keys() -> None:
    result = remediation()
    assert result.value_source is None
    assert sorted(result.to_dict()) == ["changed", "message", "rule_id", "status"]
    assert model.RemediationResult.from_dict(result.to_dict()) == result


@pytest.mark.parametrize(
    "result",
    [
        valued(),
        valued(changed=False),
        valued(
            status=model.RemediationStatus.APPLIED,
            value_source=model.ValueSource.PROFILE,
            profile_value="14",
            effective_value="14",
            deviation=None,
        ),
        valued(
            status=model.RemediationStatus.ALREADY_COMPLIANT,
            changed=False,
            value_source=model.ValueSource.OVERRIDE,
            profile_value="14",
            effective_value="16",
            deviation=None,
        ),
        valued(
            status=model.RemediationStatus.FAILED,
            value_source=model.ValueSource.PROFILE,
            effective_value=None,
            deviation=None,
        ),
    ],
    ids=["deviation", "deviation-unchanged", "profile", "stricter-override", "failed"],
)
def test_a_remediation_result_with_a_value_round_trips_with_eight_keys(
    result: model.RemediationResult,
) -> None:
    document = result.to_dict()
    assert sorted(document) == sorted(
        ("changed", "message", "rule_id", "status", *deviations.RESULT_KEYS)
    )
    assert model.RemediationResult.from_dict(document) == result
    assert model.RemediationResult.from_dict(json.loads(json.dumps(document))) == result


def test_the_deviation_status_lists_the_deviation_of_the_result() -> None:
    document = valued().to_dict()
    assert document["status"] == "deviation"
    assert document["value_source"] == "override"
    assert document["deviation"] == DEVIATION.to_dict()
    assert model.RemediationStatus.DEVIATION.value == "deviation"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {
                "value_source": None,
                "profile_value": None,
                "effective_value": None,
                "deviation": None,
            },
            "status deviation requires remediation.deviation",
        ),
        (
            {"status": model.RemediationStatus.APPLIED, "value_source": None},
            "value fields require remediation.value_source",
        ),
        (
            {
                "status": model.RemediationStatus.APPLIED,
                "value_source": None,
                "profile_value": None,
                "effective_value": None,
            },
            "value fields require remediation.value_source",
        ),
        ({"value_source": "override"}, "value_source must be of type ValueSource"),
        ({"profile_value": None}, "profile_value must be a string"),
        ({"effective_value": "1\n2"}, "effective_value contains control"),
        ({"deviation": DEVIATION.to_dict()}, "remediation.deviation must be of type Deviation"),
        ({"deviation": None}, "requires exactly remediation.deviation"),
        ({"status": model.RemediationStatus.APPLIED}, "requires exactly remediation.deviation"),
        (
            {"value_source": model.ValueSource.PROFILE},
            "requires remediation.value_source override",
        ),
        ({"effective_value": "13"}, "must repeat the profile value and the value in force"),
        ({"profile_value": "15"}, "must repeat the profile value and the value in force"),
        ({"effective_value": None}, "must repeat the profile value and the value in force"),
    ],
)
def test_a_remediation_result_rejects_inconsistent_value_fields(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(model.ModelError, match=message):
        valued(**overrides)


def test_a_remediation_document_has_four_or_eight_keys() -> None:
    document = valued().to_dict()
    partial = {key: value for key, value in document.items() if key != "value_source"}
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.RemediationResult.from_dict(partial)
    for key in ("profile_value", "effective_value", "deviation"):
        missing = {name: value for name, value in document.items() if name != key}
        with pytest.raises(model.ModelError, match=f"missing keys: {key}"):
            model.RemediationResult.from_dict(missing)
    with pytest.raises(model.ModelError, match="must contain only strings"):
        model.RemediationResult.from_dict({**document, "value_source": None})
    with pytest.raises(model.ModelError, match="unknown value 'tailoring'"):
        model.RemediationResult.from_dict({**document, "value_source": "tailoring"})
    with pytest.raises(model.ModelError, match="value_id has an invalid format"):
        model.RemediationResult.from_dict(
            {**document, "deviation": {**DEVIATION.to_dict(), "value_id": "X"}}
        )


def test_a_finding_with_a_valued_remediation_needs_schema_one_three() -> None:
    plain = valued(
        status=model.RemediationStatus.APPLIED,
        value_source=model.ValueSource.PROFILE,
        effective_value="14",
        deviation=None,
    )
    run = scan_run(findings=(finding(outcome=model.Outcome.PASS, remediation=plain),))
    assert run.schema_version == model.DEVIATION_SCHEMA_VERSION
    text = model.dumps(run)
    assert json.loads(text)["findings"][0]["deviation"] is None
    assert model.loads(text) == run
    document = json.loads(text)
    older = [
        {key: value for key, value in item.items() if key != "deviation"}
        for item in findings_of(document)
    ]
    with pytest.raises(model.ModelError, match="does not match the content"):
        model.ScanRun.from_dict({**document, "schema_version": "1.2", "findings": older})


def test_a_deviation_in_the_remediation_of_a_finding_round_trips() -> None:
    run = scan_run(findings=(deviated(outcome=model.Outcome.PASS, remediation=valued()),))
    text = model.dumps(run)
    assert model.loads(text) == run
    assert model.loads(text).findings[0].remediation == valued()


def test_runs_without_deviations_never_name_the_new_keys() -> None:
    for run in (scan_run(), marked_run(), scan_run(findings=(finding(control=placed()),))):
        text = model.dumps(run)
        assert "deviation" not in text
        assert "value_source" not in text


def test_the_new_versions_and_names_are_pinned() -> None:
    assert model.DEVIATION_SCHEMA_VERSION == "1.3"
    assert frozenset({"1.0", "1.1", "1.2", "1.3"}) == model.SUPPORTED_SCHEMA_VERSIONS
    assert FLAG.value == "operator_deviation"
    assert deviations.DEVIATION_KEY == "deviation"
    assert [item.value for item in model.ValueSource] == ["profile", "override"]
    assert model.RemediationStatus.DEVIATION not in {
        model.RemediationStatus.ALREADY_COMPLIANT,
        model.RemediationStatus.SKIPPED,
        model.RemediationStatus.NOT_REMEDIATED,
    }
    assert valued(changed=True).changed is True
