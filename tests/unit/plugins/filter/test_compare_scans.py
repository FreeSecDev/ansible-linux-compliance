from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import compare_scans
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model

RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"
BENCHMARK = "xccdf_org.ssgproject.content_benchmark_UBUNTU2404"
SHA_A = "a" * 64
SHA_B = "b" * 64
BASE_TIME = datetime(2026, 10, 26, 8, 0, 0, tzinfo=timezone.utc)
VARIABLE = "linux_compliance_rule_example_enabled"
IDENTITY = {
    "hostname": "web01",
    "benchmark_id": BENCHMARK,
    "profile_id": PROFILE,
    "content_version": "0.1.82",
    "scanner_version": "1.3.9",
}

Outcome = model.Outcome


def rule(name: str) -> str:
    return f"{RULE_PREFIX}{name}"


def finding(rule_id: str, outcome: Outcome) -> model.Finding:
    """Build a finding; ``waived`` stands for an evaluated failure under an active exception."""
    exception = model.ExceptionStatus.none()
    evaluated = outcome
    if outcome is Outcome.WAIVED:
        exception = model.ExceptionStatus(
            model.ExceptionState.ACTIVE, "EXC-1", "Accepted risk.", "2027-01-01T00:00:00Z"
        )
        evaluated = Outcome.FAIL
    return model.Finding(
        rule_id=rule_id,
        outcome=outcome,
        evaluated_outcome=evaluated,
        severity=model.Severity.MEDIUM,
        message=None,
        evidence=(),
        exception=exception,
        remediation=None,
        disabled_by=VARIABLE if outcome is Outcome.DISABLED else None,
        flags=(),
    )


def scan_run(
    outcomes: dict[str, Outcome],
    *,
    run_id: str,
    offset: int = 0,
    status: model.ScanStatus = model.ScanStatus.COMPLETED,
    identity: dict[str, str] | None = None,
) -> model.ScanRun:
    fields = {**IDENTITY, **(identity or {})}
    started = (BASE_TIME + timedelta(minutes=offset)).strftime(model.TIMESTAMP_FORMAT)
    finished = (BASE_TIME + timedelta(minutes=offset + 1)).strftime(model.TIMESTAMP_FORMAT)
    completed = status is model.ScanStatus.COMPLETED
    findings = tuple(
        finding(rule(name), outcome if completed else Outcome.ERROR)
        for name, outcome in outcomes.items()
    )
    return model.ScanRun(
        run_id=run_id,
        started_at=started,
        finished_at=finished,
        host=model.HostIdentity(fields["hostname"], "ubuntu", "24.04", "x86_64", None),
        scanner=model.ScannerInfo("openscap", fields["scanner_version"]),
        content=model.Provenance("ssg-ubuntu2404-ds.xml", fields["content_version"], "0" * 64),
        benchmark_id=fields["benchmark_id"],
        profile_id=fields["profile_id"],
        status=status,
        error_message=None if completed else "oscap exited with status 1",
        findings=findings,
    )


def audited(
    run: model.ScanRun,
    *,
    waived_run: model.ScanRun | None = None,
    digest: str | None = None,
) -> dict[str, object]:
    exceptions: dict[str, object] = {
        "applied": waived_run is not None,
        "evaluation": None
        if waived_run is None
        else {"scan_run": waived_run.to_dict(), "source_sha256": digest},
        "source_sha256": digest,
    }
    return {
        "exceptions": exceptions,
        "run_id": run.run_id,
        "run_status": run.status.value,
        "scan_run": run.to_dict(),
        "summary": None,
    }


def not_run(run_id: str) -> dict[str, object]:
    return {"run_id": run_id, "run_status": "not_run", "scan_run": None, "summary": None}


def pair(
    before: dict[str, Outcome], after: dict[str, Outcome]
) -> tuple[dict[str, object], dict[str, object]]:
    return (
        audited(scan_run(before, run_id="baseline-1")),
        audited(scan_run(after, run_id="post-1", offset=10)),
    )


def categories(result: dict[str, object]) -> dict[str, str]:
    rules = cast("list[dict[str, object]]", result["rules"])
    return {cast("str", record["rule_id"]): cast("str", record["category"]) for record in rules}


def test_the_filter_is_registered() -> None:
    filters = compare_scans.FilterModule().filters()
    assert filters == {"compare_scans": compare_scans.compare_scans}


TRANSITIONS = [
    (Outcome.FAIL, Outcome.PASS, "improved"),
    (Outcome.PASS, Outcome.FAIL, "regressed"),
    (Outcome.PASS, Outcome.ERROR, "regressed"),
    (Outcome.PASS, Outcome.NOTCHECKED, "regressed"),
    (Outcome.PASS, Outcome.DISABLED, "regressed"),
    (Outcome.PASS, Outcome.PASS, "unchanged"),
    (Outcome.FAIL, Outcome.FAIL, "unchanged"),
    (Outcome.NOTAPPLICABLE, Outcome.NOTAPPLICABLE, "unchanged"),
    (Outcome.NOTCHECKED, Outcome.NOTCHECKED, "unchanged"),
    (Outcome.DISABLED, Outcome.DISABLED, "unchanged"),
    (Outcome.NOTAPPLICABLE, Outcome.PASS, "newly_applicable"),
    (Outcome.NOTAPPLICABLE, Outcome.FAIL, "newly_failing"),
    (Outcome.PASS, Outcome.NOTAPPLICABLE, "newly_not_applicable"),
    (Outcome.FAIL, Outcome.NOTAPPLICABLE, "newly_not_applicable"),
    (Outcome.DISABLED, Outcome.NOTAPPLICABLE, "newly_not_applicable"),
    (Outcome.NOTCHECKED, Outcome.NOTAPPLICABLE, "newly_not_applicable"),
    (Outcome.ERROR, Outcome.PASS, "error"),
    (Outcome.ERROR, Outcome.FAIL, "error"),
    (Outcome.ERROR, Outcome.ERROR, "error"),
    (Outcome.FAIL, Outcome.ERROR, "error"),
    (Outcome.NOTAPPLICABLE, Outcome.ERROR, "error"),
    (Outcome.ERROR, Outcome.NOTAPPLICABLE, "error"),
    (Outcome.FAIL, Outcome.NOTCHECKED, "not_comparable"),
    (Outcome.FAIL, Outcome.DISABLED, "not_comparable"),
    (Outcome.NOTCHECKED, Outcome.PASS, "not_comparable"),
    (Outcome.NOTCHECKED, Outcome.FAIL, "not_comparable"),
    (Outcome.DISABLED, Outcome.PASS, "not_comparable"),
    (Outcome.DISABLED, Outcome.FAIL, "not_comparable"),
    (Outcome.NOTAPPLICABLE, Outcome.NOTCHECKED, "not_comparable"),
    (Outcome.NOTAPPLICABLE, Outcome.DISABLED, "not_comparable"),
]


@pytest.mark.parametrize(("before", "after", "expected"), TRANSITIONS)
def test_every_transition_has_its_category(before: Outcome, after: Outcome, expected: str) -> None:
    baseline, post = pair({"example": before}, {"example": after})
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {rule("example"): expected}
    counts = cast("dict[str, int]", result["counts"])
    assert counts[expected] == 1
    assert sum(counts.values()) == 1
    assert result["regression_detected"] is (expected == "regressed")
    assert result["new_failure_detected"] is (expected == "newly_failing")


def test_every_pair_of_scanner_outcomes_is_classified() -> None:
    scanner_outcomes = [outcome for outcome in Outcome if outcome is not Outcome.WAIVED]
    covered = {(transition[0], transition[1]) for transition in TRANSITIONS}
    for before in scanner_outcomes:
        for after in scanner_outcomes:
            category = compare_scans.classify(
                finding(rule("example"), before), finding(rule("example"), after)
            )
            assert category in compare_scans.CATEGORIES
            if category == "improved":
                assert (before, after) == (Outcome.FAIL, Outcome.PASS)
            if before is Outcome.PASS and after not in (Outcome.PASS, Outcome.NOTAPPLICABLE):
                assert category == "regressed"
    assert len(covered) == len(TRANSITIONS)


def test_an_error_that_becomes_a_pass_is_not_an_improvement() -> None:
    baseline, post = pair({"broken": Outcome.ERROR}, {"broken": Outcome.PASS})
    result = compare_scans.compare_scans(baseline, post)
    counts = cast("dict[str, int]", result["counts"])
    assert counts["improved"] == 0
    assert counts["error"] == 1
    assert categories(result) == {rule("broken"): "error"}


def test_a_complete_comparison_reports_counts_rules_and_a_message() -> None:
    baseline, post = pair(
        {"a": Outcome.FAIL, "b": Outcome.PASS, "c": Outcome.PASS, "d": Outcome.NOTAPPLICABLE},
        {"a": Outcome.PASS, "b": Outcome.FAIL, "c": Outcome.PASS, "d": Outcome.NOTAPPLICABLE},
    )
    result = compare_scans.compare_scans(baseline, post, "raw", PROFILE)
    assert result["status"] == "complete"
    assert result["complete"] is True
    assert result["incomplete_reasons"] == []
    assert result["mode"] == "raw"
    assert result["exceptions_sha256"] is None
    assert result["counts"] == {
        "improved": 1,
        "regressed": 1,
        "unchanged": 2,
        "newly_applicable": 0,
        "newly_failing": 0,
        "newly_not_applicable": 0,
        "error": 0,
        "not_comparable": 0,
    }
    assert result["regressions"] == [
        {
            "baseline": {"evaluated_outcome": "pass", "outcome": "pass"},
            "category": "regressed",
            "post": {"evaluated_outcome": "fail", "outcome": "fail"},
            "rule_id": rule("b"),
        }
    ]
    message = cast("str", result["message"])
    assert message.startswith(
        f"REGRESSION: 1 rule(s) passed in the baseline and no longer pass: {rule('b')}."
    )
    assert "not a claim of compliance" in message
    assert "1 improved, 1 regressed, 2 unchanged" in message
    identity = cast("dict[str, object]", result["identity"])
    assert identity["profile_id"] == PROFILE
    assert identity["benchmark_id"] == BENCHMARK
    baseline_report = cast("dict[str, object]", result["baseline"])
    assert baseline_report["run_id"] == "baseline-1"
    assert baseline_report["started_at"] == "2026-10-26T08:00:00Z"
    assert baseline_report["finished_at"] == "2026-10-26T08:01:00Z"
    summary = cast("dict[str, object]", baseline_report["summary"])
    assert summary["fail"] == 1
    assert summary["pass"] == 2
    assert summary["total"] == 4
    assert summary["run_status"] == "completed"


def test_no_regression_is_stated_explicitly() -> None:
    baseline, post = pair({"a": Outcome.FAIL}, {"a": Outcome.PASS})
    result = compare_scans.compare_scans(baseline, post)
    assert result["regression_detected"] is False
    assert result["regressions"] == []
    assert cast("str", result["message"]).startswith("No regression and no new failure:")
    assert result["new_failure_detected"] is False
    assert result["new_failures"] == []
    assert result["passed_now_not_applicable"] == []


def test_long_regression_lists_are_shortened_in_the_message() -> None:
    names = [f"rule_{index:02d}" for index in range(25)]
    baseline, post = pair(dict.fromkeys(names, Outcome.PASS), dict.fromkeys(names, Outcome.FAIL))
    result = compare_scans.compare_scans(baseline, post)
    assert len(cast("list[object]", result["regressions"])) == 25
    assert "and 5 more" in cast("str", result["message"])


def test_a_rule_missing_from_either_run_is_classified_fail_closed() -> None:
    baseline, post = pair(
        {
            "kept": Outcome.PASS,
            "dropped_pass": Outcome.PASS,
            "dropped_fail": Outcome.FAIL,
        },
        {"kept": Outcome.PASS, "added_pass": Outcome.PASS, "added_fail": Outcome.FAIL},
    )
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {
        rule("added_fail"): "newly_failing",
        rule("added_pass"): "error",
        rule("dropped_fail"): "error",
        rule("dropped_pass"): "regressed",
        rule("kept"): "unchanged",
    }
    records = {
        cast("str", record["rule_id"]): record
        for record in cast("list[dict[str, object]]", result["rules"])
    }
    assert records[rule("added_pass")]["baseline"] is None
    assert records[rule("dropped_pass")]["post"] is None
    assert result["regression_detected"] is True
    assert result["new_failure_detected"] is True


def test_a_rule_that_passed_and_disappears_is_a_regression() -> None:
    baseline, post = pair({"kept": Outcome.FAIL, "gone": Outcome.PASS}, {"kept": Outcome.FAIL})
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {rule("gone"): "regressed", rule("kept"): "unchanged"}
    message = cast("str", result["message"])
    assert message.startswith("REGRESSION: 1 rule(s)")
    assert "No regression" not in message


def test_applicability_changes_are_listed_and_new_failures_named() -> None:
    baseline, post = pair(
        {"passing": Outcome.PASS, "failing": Outcome.FAIL, "absent": Outcome.NOTAPPLICABLE},
        {
            "passing": Outcome.NOTAPPLICABLE,
            "failing": Outcome.NOTAPPLICABLE,
            "absent": Outcome.FAIL,
        },
    )
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {
        rule("absent"): "newly_failing",
        rule("failing"): "newly_not_applicable",
        rule("passing"): "newly_not_applicable",
    }
    assert result["regression_detected"] is False
    assert result["new_failure_detected"] is True
    new_failures = cast("list[dict[str, object]]", result["new_failures"])
    assert [record["rule_id"] for record in new_failures] == [rule("absent")]
    lost = cast("list[dict[str, object]]", result["passed_now_not_applicable"])
    assert [record["rule_id"] for record in lost] == [rule("passing")]
    message = cast("str", result["message"])
    assert message.startswith(
        f"NEW FAILURE: 1 rule(s) were not applicable or missing in the baseline and fail now: "
        f"{rule('absent')}."
    )
    assert "No regression" not in message
    assert "1 newly_failing" in message


def test_regressions_and_new_failures_are_both_named() -> None:
    baseline, post = pair(
        {"a": Outcome.PASS, "b": Outcome.NOTAPPLICABLE},
        {"a": Outcome.FAIL, "b": Outcome.FAIL},
    )
    message = cast("str", compare_scans.compare_scans(baseline, post)["message"])
    assert message.startswith("REGRESSION: 1 rule(s)")
    assert "NEW FAILURE: 1 rule(s)" in message


@pytest.mark.parametrize(
    ("changes", "label"),
    [
        ({"hostname": "db01"}, "host"),
        ({"benchmark_id": "xccdf_org.ssgproject.content_benchmark_RHEL-9"}, "benchmark"),
        ({"profile_id": "xccdf_org.ssgproject.content_profile_stig"}, "profile"),
        ({"content_version": "0.1.83"}, "content version or digest"),
        ({"scanner_version": "1.3.10"}, "scanner name or version"),
    ],
)
def test_scans_of_a_different_kind_are_refused(changes: dict[str, str], label: str) -> None:
    baseline = audited(scan_run({"a": Outcome.PASS}, run_id="baseline-1"))
    post = audited(
        scan_run(
            {"a": Outcome.PASS},
            run_id="post-1",
            offset=10,
            identity=changes,
        )
    )
    with pytest.raises(compare_scans.ComparisonError, match=f"differ in {label};"):
        compare_scans.compare_scans(baseline, post)


def test_a_different_content_digest_is_refused() -> None:
    baseline = audited(scan_run({"a": Outcome.PASS}, run_id="baseline-1"))
    document = scan_run({"a": Outcome.PASS}, run_id="post-1", offset=10).to_dict()
    content = cast("dict[str, object]", document["content"])
    content["content_sha256"] = "1" * 64
    post = {
        **audited(scan_run({"a": Outcome.PASS}, run_id="post-1", offset=10)),
        "scan_run": document,
    }
    with pytest.raises(compare_scans.ComparisonError, match="content version or digest"):
        compare_scans.compare_scans(baseline, post)


def test_both_runs_must_report_the_requested_profile() -> None:
    baseline, post = pair({"a": Outcome.PASS}, {"a": Outcome.PASS})
    with pytest.raises(
        compare_scans.ComparisonError, match=r"not xccdf_org\.ssgproject\.content_profile_stig"
    ):
        compare_scans.compare_scans(
            baseline, post, "raw", "xccdf_org.ssgproject.content_profile_stig"
        )


def test_an_invalid_profile_identifier_is_refused() -> None:
    baseline, post = pair({"a": Outcome.PASS}, {"a": Outcome.PASS})
    with pytest.raises(compare_scans.ComparisonError, match="invalid profile_id"):
        compare_scans.compare_scans(baseline, post, "raw", "cis_level1_server")


def test_the_same_run_is_not_compared_with_itself() -> None:
    baseline = audited(scan_run({"a": Outcome.PASS}, run_id="run-1"))
    with pytest.raises(compare_scans.ComparisonError, match="same run 'run-1'"):
        compare_scans.compare_scans(baseline, baseline)


def test_a_post_scan_that_started_before_the_baseline_finished_is_refused() -> None:
    baseline = audited(scan_run({"a": Outcome.PASS}, run_id="baseline-1", offset=10))
    post = audited(scan_run({"a": Outcome.FAIL}, run_id="post-1"))
    with pytest.raises(compare_scans.ComparisonError, match="check the argument order"):
        compare_scans.compare_scans(baseline, post)


@pytest.mark.parametrize("failed_side", ["baseline", "post"])
@pytest.mark.parametrize("status", [model.ScanStatus.FAILED, model.ScanStatus.TIMED_OUT])
def test_a_scan_that_did_not_complete_makes_the_comparison_incomplete(
    failed_side: str, status: model.ScanStatus
) -> None:
    outcomes = {"a": Outcome.FAIL, "b": Outcome.PASS}
    improved = {"a": Outcome.PASS, "b": Outcome.PASS}
    baseline_status = status if failed_side == "baseline" else model.ScanStatus.COMPLETED
    post_status = status if failed_side == "post" else model.ScanStatus.COMPLETED
    baseline = audited(scan_run(outcomes, run_id="baseline-1", status=baseline_status))
    post = audited(scan_run(improved, run_id="post-1", offset=10, status=post_status))
    result = compare_scans.compare_scans(baseline, post)
    assert result["status"] == "incomplete"
    assert result["complete"] is False
    assert result["incomplete_reasons"] == [
        f"the {failed_side} scan did not complete (run_status {status.value})"
    ]
    for key in (
        "counts",
        "regressions",
        "rules",
        "regression_detected",
        "new_failures",
        "new_failure_detected",
        "passed_now_not_applicable",
    ):
        assert result[key] is None
    assert result["identity"] is not None
    message = cast("str", result["message"])
    assert message.startswith("Verification incomplete:")
    assert "improved" not in message


def test_check_mode_without_a_scan_is_incomplete() -> None:
    baseline = audited(scan_run({"a": Outcome.FAIL}, run_id="baseline-1"))
    result = compare_scans.compare_scans(baseline, not_run("post-1"))
    assert result["status"] == "incomplete"
    assert result["identity"] is None
    post_report = cast("dict[str, object]", result["post"])
    assert post_report == {
        "finished_at": None,
        "run_id": "post-1",
        "run_status": "not_run",
        "started_at": None,
        "summary": None,
    }
    assert result["incomplete_reasons"] == ["the post scan did not complete (run_status not_run)"]


def test_both_sides_incomplete_list_both_reasons() -> None:
    result = compare_scans.compare_scans(not_run("baseline-1"), not_run("post-1"))
    assert result["incomplete_reasons"] == [
        "the baseline scan did not complete (run_status not_run)",
        "the post scan did not complete (run_status not_run)",
    ]


def test_the_profile_is_still_checked_on_an_incomplete_comparison() -> None:
    baseline = audited(scan_run({"a": Outcome.FAIL}, run_id="baseline-1"))
    with pytest.raises(compare_scans.ComparisonError, match="reports profile"):
        compare_scans.compare_scans(
            baseline, not_run("post-1"), "raw", "xccdf_org.ssgproject.content_profile_stig"
        )


def waive(outcomes: dict[str, Outcome], names: frozenset[str]) -> dict[str, Outcome]:
    return {
        name: Outcome.WAIVED if name in names else outcome for name, outcome in outcomes.items()
    }


def waived_pair(
    before: dict[str, Outcome],
    after: dict[str, Outcome],
    *,
    waived_before: frozenset[str],
    waived_after: frozenset[str],
    digest_after: str = SHA_A,
) -> tuple[dict[str, object], dict[str, object]]:
    raw_before = scan_run(before, run_id="baseline-1")
    raw_after = scan_run(after, run_id="post-1", offset=10)
    return (
        audited(
            raw_before,
            waived_run=scan_run(waive(before, waived_before), run_id="baseline-1"),
            digest=SHA_A,
        ),
        audited(
            raw_after,
            waived_run=scan_run(waive(after, waived_after), run_id="post-1", offset=10),
            digest=digest_after,
        ),
    )


def test_waived_mode_with_the_same_file_compares_evaluated_outcomes() -> None:
    baseline, post = waived_pair(
        {"waived_now": Outcome.FAIL, "still_waived": Outcome.FAIL, "fixed": Outcome.FAIL},
        {"waived_now": Outcome.FAIL, "still_waived": Outcome.FAIL, "fixed": Outcome.PASS},
        waived_before=frozenset({"still_waived", "fixed"}),
        waived_after=frozenset({"waived_now", "still_waived"}),
    )
    result = compare_scans.compare_scans(baseline, post, "waived", PROFILE)
    assert result["mode"] == "waived"
    assert result["exceptions_sha256"] == SHA_A
    assert categories(result) == {
        rule("fixed"): "improved",
        rule("still_waived"): "unchanged",
        rule("waived_now"): "unchanged",
    }
    counts = cast("dict[str, int]", result["counts"])
    assert counts["improved"] == 1
    records = {
        cast("str", record["rule_id"]): record
        for record in cast("list[dict[str, object]]", result["rules"])
    }
    assert records[rule("waived_now")]["baseline"] == {
        "evaluated_outcome": "fail",
        "outcome": "fail",
    }
    assert records[rule("waived_now")]["post"] == {"evaluated_outcome": "fail", "outcome": "waived"}
    post_summary = cast("dict[str, object]", cast("dict[str, object]", result["post"])["summary"])
    assert post_summary["waived"] == 2
    assert post_summary["pass"] == 1


def test_a_waiver_never_counts_as_an_improvement_in_raw_mode() -> None:
    baseline, post = waived_pair(
        {"a": Outcome.FAIL},
        {"a": Outcome.FAIL},
        waived_before=frozenset(),
        waived_after=frozenset({"a"}),
    )
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {rule("a"): "unchanged"}
    assert cast("dict[str, int]", result["counts"])["improved"] == 0


def test_a_rule_that_passed_and_is_waived_later_is_a_regression() -> None:
    baseline, post = waived_pair(
        {"a": Outcome.PASS},
        {"a": Outcome.FAIL},
        waived_before=frozenset(),
        waived_after=frozenset({"a"}),
    )
    result = compare_scans.compare_scans(baseline, post, "waived")
    assert categories(result) == {rule("a"): "regressed"}


def test_waived_mode_with_a_different_file_is_refused() -> None:
    baseline, post = waived_pair(
        {"a": Outcome.FAIL},
        {"a": Outcome.FAIL},
        waived_before=frozenset({"a"}),
        waived_after=frozenset({"a"}),
        digest_after=SHA_B,
    )
    with pytest.raises(compare_scans.ComparisonError, match="same exceptions file"):
        compare_scans.compare_scans(baseline, post, "waived")


def test_waived_mode_without_an_exceptions_file_is_refused() -> None:
    baseline, post = pair({"a": Outcome.FAIL}, {"a": Outcome.FAIL})
    with pytest.raises(compare_scans.ComparisonError, match="applied an exceptions file"):
        compare_scans.compare_scans(baseline, post, "waived")


def test_waived_mode_without_the_exceptions_result_is_refused() -> None:
    baseline, post = pair({"a": Outcome.FAIL}, {"a": Outcome.FAIL})
    del baseline["exceptions"]
    with pytest.raises(compare_scans.ComparisonError, match="needs the exceptions result"):
        compare_scans.compare_scans(baseline, post, "waived")


def test_waived_mode_with_an_incomplete_scan_is_incomplete() -> None:
    raw_before = scan_run({"a": Outcome.FAIL}, run_id="baseline-1")
    baseline = audited(
        raw_before,
        waived_run=scan_run({"a": Outcome.WAIVED}, run_id="baseline-1"),
        digest=SHA_A,
    )
    post = audited(
        scan_run({"a": Outcome.PASS}, run_id="post-1", offset=10, status=model.ScanStatus.FAILED),
        digest=SHA_A,
    )
    result = compare_scans.compare_scans(baseline, post, "waived")
    assert result["status"] == "incomplete"
    assert result["exceptions_sha256"] == SHA_A
    assert result["counts"] is None


def test_waived_mode_with_check_mode_without_a_scan_is_incomplete() -> None:
    raw_before = scan_run({"a": Outcome.FAIL}, run_id="baseline-1")
    baseline = audited(
        raw_before,
        waived_run=scan_run({"a": Outcome.WAIVED}, run_id="baseline-1"),
        digest=SHA_A,
    )
    post = {
        **not_run("post-1"),
        "exceptions": {"applied": False, "evaluation": None, "source_sha256": SHA_A},
    }
    result = compare_scans.compare_scans(baseline, post, "waived")
    assert result["status"] == "incomplete"


def waived_baseline(**changes: object) -> dict[str, object]:
    raw = scan_run({"a": Outcome.FAIL, "b": Outcome.PASS}, run_id="baseline-1")
    waived = scan_run({"a": Outcome.WAIVED, "b": Outcome.PASS}, run_id="baseline-1")
    result = audited(raw, waived_run=waived, digest=SHA_A)
    exceptions = cast("dict[str, object]", result["exceptions"])
    evaluation = cast("dict[str, object]", exceptions["evaluation"])
    for key, value in changes.items():
        if key in ("evaluation_source_sha256", "evaluation_scan_run"):
            evaluation[key.removeprefix("evaluation_")] = value
        else:
            exceptions[key] = value
    return result


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"applied": "yes"}, "exceptions.applied must be a boolean"),
        ({"applied": False}, "applied exactly when the scan completed"),
        ({"evaluation": None}, "exceptions.evaluation must be the evaluation document"),
        ({"evaluation_source_sha256": SHA_B}, "not made from the recorded exceptions file"),
        ({"evaluation_scan_run": "{}"}, "baseline waived scan run: invalid scan run"),
        (
            {
                "evaluation_scan_run": scan_run(
                    {"a": Outcome.FAIL, "b": Outcome.PASS}, run_id="other-1"
                ).to_dict()
            },
            "not derived from the raw scan run",
        ),
        (
            {
                "evaluation_scan_run": scan_run(
                    {"a": Outcome.FAIL, "b": Outcome.FAIL}, run_id="baseline-1"
                ).to_dict()
            },
            "does not have the evaluated outcomes of the raw run",
        ),
    ],
)
def test_an_inconsistent_waived_result_is_refused(changes: dict[str, object], message: str) -> None:
    post = audited(scan_run({"a": Outcome.FAIL, "b": Outcome.PASS}, run_id="post-1", offset=10))
    with pytest.raises(compare_scans.ComparisonError, match=message):
        compare_scans.compare_scans(waived_baseline(**changes), post, "waived")


def test_raw_mode_refuses_a_scan_run_that_carries_waivers() -> None:
    waived = scan_run({"a": Outcome.WAIVED}, run_id="baseline-1")
    baseline = audited(waived)
    post = audited(scan_run({"a": Outcome.FAIL}, run_id="post-1", offset=10))
    with pytest.raises(compare_scans.ComparisonError, match="carries exception data"):
        compare_scans.compare_scans(baseline, post)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("text", "must be a mapping like linux_compliance_audited"),
        ({"run_id": "bad id", "run_status": "completed"}, "run_id is missing or invalid: 'bad id'"),
        ({"run_status": "completed"}, "run_id is missing or invalid: 'None'"),
        ({"run_id": "r1", "run_status": "running"}, "run_status must be one of"),
        ({"run_id": "r1", "run_status": "completed", "scan_run": None}, "null exactly when"),
        ({"run_id": "r1", "run_status": "not_run", "scan_run": {}}, "null exactly when"),
        ({"run_id": "r1", "run_status": "completed", "scan_run": []}, "baseline scan run: "),
    ],
)
def test_a_malformed_audit_result_is_refused(value: object, message: str) -> None:
    post = audited(scan_run({"a": Outcome.PASS}, run_id="post-1", offset=10))
    with pytest.raises(compare_scans.ComparisonError, match=message):
        compare_scans.compare_scans(value, post)


def test_a_run_status_that_contradicts_the_scan_run_is_refused() -> None:
    baseline = {
        **audited(scan_run({"a": Outcome.PASS}, run_id="baseline-1")),
        "run_status": "failed",
    }
    post = audited(scan_run({"a": Outcome.PASS}, run_id="post-1", offset=10))
    with pytest.raises(compare_scans.ComparisonError, match="run_status does not match"):
        compare_scans.compare_scans(baseline, post)


def test_a_run_id_that_contradicts_the_scan_run_is_refused() -> None:
    baseline = {**audited(scan_run({"a": Outcome.PASS}, run_id="baseline-1")), "run_id": "other"}
    post = audited(scan_run({"a": Outcome.PASS}, run_id="post-1", offset=10))
    with pytest.raises(compare_scans.ComparisonError, match="run_id does not match"):
        compare_scans.compare_scans(baseline, post)


def test_an_unknown_mode_is_refused() -> None:
    baseline, post = pair({"a": Outcome.PASS}, {"a": Outcome.PASS})
    with pytest.raises(compare_scans.ComparisonError, match="mode must be raw or waived: 'both'"):
        compare_scans.compare_scans(baseline, post, "both")


def test_scan_runs_given_as_json_text_are_accepted() -> None:
    before = scan_run({"a": Outcome.FAIL}, run_id="baseline-1")
    after = scan_run({"a": Outcome.PASS}, run_id="post-1", offset=10)
    baseline = {**audited(before), "scan_run": model.dumps(before)}
    post = {**audited(after), "scan_run": model.dumps(after)}
    result = compare_scans.compare_scans(baseline, post)
    assert categories(result) == {rule("a"): "improved"}
