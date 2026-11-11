"""Operator deviations in the verify comparison (ADR 0032 section 4, FREES-203)."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import compare_scans
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tests.unit.plugins.filter.test_compare_scans import (
    PROFILE,
    SHA_A,
    Outcome,
    audited,
    categories,
    finding,
    not_run,
    rule,
    scan_run,
)

DEVIATION = model.Deviation("var_password_pam_minlen", "14", "8")


def flagged(run: model.ScanRun, *names: str) -> model.ScanRun:
    chosen = {rule(name) for name in names}
    return replace(
        run,
        findings=tuple(
            replace(
                item,
                flags=(*item.flags, model.ResultFlag.OPERATOR_DEVIATION),
                deviation=DEVIATION,
            )
            if item.rule_id in chosen
            else item
            for item in run.findings
        ),
    )


def deviated_pair(
    before: dict[str, Outcome], after: dict[str, Outcome], *names: str
) -> tuple[dict[str, object], dict[str, object]]:
    return (
        audited(scan_run(before, run_id="baseline-1")),
        audited(flagged(scan_run(after, run_id="post-1", offset=10), *names)),
    )


@pytest.mark.parametrize(
    "before", [Outcome.FAIL, Outcome.PASS, Outcome.NOTAPPLICABLE, Outcome.ERROR]
)
def test_a_flagged_pass_is_deviated_whatever_the_baseline(before: Outcome) -> None:
    baseline, post = deviated_pair({"minlen": before}, {"minlen": Outcome.PASS}, "minlen")
    result = compare_scans.compare_scans(baseline, post, "raw", PROFILE)
    assert categories(result) == {rule("minlen"): "deviated"}
    counts = cast("dict[str, int]", result["counts"])
    assert counts["deviated"] == 1
    assert counts["improved"] == 0
    assert result["deviation_detected"] is True
    assert result["regression_detected"] is False
    (record,) = cast("list[dict[str, object]]", result["deviations"])
    assert record["rule_id"] == rule("minlen")
    assert record["post"] == {
        "deviation": DEVIATION.to_dict(),
        "evaluated_outcome": "pass",
        "operator_deviation": True,
        "outcome": "pass",
    }
    message = cast("str", result["message"])
    assert message.startswith(
        "DEVIATION: 1 rule(s) pass only under a value that an operator override made looser "
        f"than the profile's: {rule('minlen')}. No regression and no new failure"
    )
    assert "1 deviated" in message
    post_summary = cast("dict[str, object]", cast("dict[str, object]", result["post"])["summary"])
    assert post_summary["deviation"] == 1
    assert post_summary["pass"] == 1


def test_a_flagged_pass_missing_from_the_baseline_is_deviated() -> None:
    baseline, post = deviated_pair(
        {"other": Outcome.PASS}, {"other": Outcome.PASS, "minlen": Outcome.PASS}, "minlen"
    )
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {rule("minlen"): "deviated", rule("other"): "unchanged"}


@pytest.mark.parametrize(
    ("before", "expected"),
    [
        (Outcome.PASS, "regressed"),
        (Outcome.FAIL, "unchanged"),
        (Outcome.NOTAPPLICABLE, "newly_failing"),
    ],
)
def test_a_flagged_fail_is_classified_as_any_fail(before: Outcome, expected: str) -> None:
    baseline, post = deviated_pair({"minlen": before}, {"minlen": Outcome.FAIL}, "minlen")
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {rule("minlen"): expected}
    assert result["deviation_detected"] is False
    assert result["deviations"] == []
    rules = cast("list[dict[str, object]]", result["rules"])
    post_record = cast("dict[str, object]", rules[0]["post"])
    assert post_record["operator_deviation"] is True
    assert post_record["deviation"] == DEVIATION.to_dict()


def test_a_flag_in_the_baseline_only_is_not_a_deviation_now() -> None:
    baseline = audited(flagged(scan_run({"minlen": Outcome.PASS}, run_id="baseline-1"), "minlen"))
    post = audited(scan_run({"minlen": Outcome.PASS}, run_id="post-1", offset=10))
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {rule("minlen"): "unchanged"}
    rules = cast("list[dict[str, object]]", result["rules"])
    assert cast("dict[str, object]", rules[0]["baseline"])["operator_deviation"] is True
    assert result["deviation_detected"] is False
    message = cast("str", result["message"])
    assert message.startswith("No regression and no new failure")


def test_a_regression_leads_the_message_before_a_deviation() -> None:
    baseline, post = deviated_pair(
        {"minlen": Outcome.FAIL, "other": Outcome.PASS},
        {"minlen": Outcome.PASS, "other": Outcome.FAIL},
        "minlen",
    )
    result = compare_scans.compare_scans(baseline, post)
    message = cast("str", result["message"])
    assert message.startswith("REGRESSION: 1 rule(s)")
    assert "DEVIATION: 1 rule(s)" in message
    assert "No regression and no new failure" not in message


def test_a_waived_flagged_failure_keeps_the_flag_in_waived_mode() -> None:
    raw = flagged(scan_run({"minlen": Outcome.FAIL}, run_id="post-1", offset=10), "minlen")
    waived = replace(
        raw,
        findings=tuple(
            replace(
                item,
                outcome=Outcome.WAIVED,
                exception=finding(item.rule_id, Outcome.WAIVED).exception,
            )
            for item in raw.findings
        ),
    )
    base_raw = scan_run({"minlen": Outcome.FAIL}, run_id="baseline-1")
    baseline = audited(base_raw, waived_run=base_raw, digest=SHA_A)
    post = audited(raw, waived_run=waived, digest=SHA_A)
    result = compare_scans.compare_scans(baseline, post, "waived")
    assert categories(result) == {rule("minlen"): "unchanged"}
    rules = cast("list[dict[str, object]]", result["rules"])
    assert rules[0]["post"] == {
        "deviation": DEVIATION.to_dict(),
        "evaluated_outcome": "fail",
        "operator_deviation": True,
        "outcome": "waived",
    }
    post_summary = cast("dict[str, object]", cast("dict[str, object]", result["post"])["summary"])
    assert post_summary["deviation"] == 1


def test_an_incomplete_comparison_reports_no_deviation() -> None:
    baseline = audited(scan_run({"minlen": Outcome.FAIL}, run_id="baseline-1"))
    result = compare_scans.compare_scans(baseline, not_run("post-1"))
    assert result["deviation_detected"] is None
    assert result["deviations"] is None
