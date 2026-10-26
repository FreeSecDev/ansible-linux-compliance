from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    apply_exceptions,
    exception_removal_candidates,
    scan_summary,
    stale_exceptions,
    validate_exceptions,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
)

RULE = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
OTHER_RULE = "xccdf_org.ssgproject.content_rule_audit_rules_login_events"
BENCHMARK = "xccdf_org.ssgproject.content_benchmark_UBUNTU2404"
TODAY = datetime.now(timezone.utc).date()


def exceptions_text() -> str:
    created = (TODAY - timedelta(days=10)).isoformat()
    approved = (TODAY - timedelta(days=9)).isoformat()
    expires = (TODAY + timedelta(days=30)).isoformat()
    lines = ["---", "schema_version: '1.0'", "exceptions:"]
    for identifier, rule, host in (("EXC-1", RULE, "web01"), ("EXC-2", OTHER_RULE, "db01")):
        lines.extend(
            [
                f"  - id: {identifier}",
                f"    rule: {rule}",
                "    framework: cis",
                "    scope:",
                f"      hosts: [{host}]",
                "    justification: Accepted until the replacement ships.",
                "    owner: platform-team",
                "    approval:",
                "      approver: security-lead",
                f"      date: {approved}",
                f"    created: {created}",
                f"    expires: {expires}",
                "    risk: low",
            ]
        )
    return "\n".join(lines) + "\n"


def scan_run(age: timedelta = timedelta(hours=1)) -> model.ScanRun:
    started = (datetime.now(timezone.utc) - age).strftime(model.TIMESTAMP_FORMAT)
    findings = tuple(
        model.Finding(
            rule_id=rule_id,
            outcome=model.Outcome.FAIL,
            evaluated_outcome=model.Outcome.FAIL,
            severity=model.Severity.HIGH,
            message=None,
            evidence=(),
            exception=model.ExceptionStatus.none(),
            remediation=None,
            disabled_by=None,
            flags=(),
        )
        for rule_id in (RULE, OTHER_RULE)
    )
    return model.ScanRun(
        run_id="run-1",
        started_at=started,
        finished_at=started,
        host=model.HostIdentity("web01", "ubuntu", "24.04", "x86_64", None),
        scanner=model.ScannerInfo("openscap", "1.3.10"),
        content=model.Provenance("ssg-ubuntu2404-ds.xml", "0.1.82", "b" * 64),
        benchmark_id=BENCHMARK,
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        status=model.ScanStatus.COMPLETED,
        error_message=None,
        findings=findings,
    )


def outcomes(result: dict[str, object]) -> dict[str, str]:
    run = cast("dict[str, list[dict[str, str]]]", result["scan_run"])
    return {item["rule_id"]: item["outcome"] for item in run["findings"]}


def test_filter_plugins_expose_their_filters() -> None:
    applied = apply_exceptions.FilterModule().filters()
    stale = stale_exceptions.FilterModule().filters()
    assert applied == {"apply_exceptions": apply_exceptions.apply_exceptions}
    assert stale == {"stale_exceptions": stale_exceptions.stale_exceptions}
    removal = exception_removal_candidates.FilterModule().filters()
    assert removal == {
        "exception_removal_candidates": exception_removal_candidates.exception_removal_candidates
    }


@pytest.mark.parametrize("form", ["mapping", "json"])
def test_apply_exceptions_waives_matching_failures(form: str) -> None:
    run = scan_run()
    value: object = run.to_dict() if form == "mapping" else model.dumps(run)
    result = apply_exceptions.apply_exceptions(value, exceptions_text(), "web01", ["web"])
    assert outcomes(result) == {RULE: "waived", OTHER_RULE: "fail"}
    assert result["summary"] == {
        "expired": 0,
        "not_failing": 0,
        "not_yet_effective": 0,
        "superseded": 0,
        "unmatched": 1,
        "waived": 1,
    }
    assert result["target"] == {"groups": ["web"], "host": "web01"}


def test_stale_exceptions_across_hosts() -> None:
    first = apply_exceptions.apply_exceptions(scan_run().to_dict(), exceptions_text(), "web01", [])
    second = apply_exceptions.apply_exceptions(scan_run().to_dict(), exceptions_text(), "web02", [])
    assert stale_exceptions.stale_exceptions([first, second]) == ["EXC-2"]


@pytest.mark.parametrize(
    ("scan_run_value", "message"),
    [
        (42, "the scan run must be a mapping or JSON text"),
        ("run", "invalid scan run"),
        (None, "the scan run must be a mapping"),
    ],
)
def test_apply_exceptions_rejects_invalid_scan_runs(scan_run_value: object, message: str) -> None:
    with pytest.raises(exceptions.ExceptionsError, match=message):
        apply_exceptions.apply_exceptions(scan_run_value, "x", "web01", ["web"])


@pytest.mark.parametrize(
    ("text", "host", "groups", "message"),
    [
        (None, "web01", [], "the exceptions file must be text"),
        ("---\nschema_version: '1.0'\n", "web01", [], "missing keys: exceptions"),
        ("", "web01", "web", "groups must be a list"),
        ("", "", [], "target.host must not be empty"),
    ],
)
def test_apply_exceptions_rejects_invalid_arguments(
    text: object, host: object, groups: object, message: str
) -> None:
    with pytest.raises(exceptions.ExceptionsError, match=message):
        apply_exceptions.apply_exceptions(scan_run().to_dict(), text, host, groups)


def test_stale_exceptions_rejects_invalid_input() -> None:
    with pytest.raises(exceptions.ExceptionsError, match="at least one evaluation"):
        stale_exceptions.stale_exceptions([])


def test_removal_candidates_across_hosts() -> None:
    first = apply_exceptions.apply_exceptions(scan_run().to_dict(), exceptions_text(), "web01", [])
    second = apply_exceptions.apply_exceptions(scan_run().to_dict(), exceptions_text(), "web02", [])
    removal = exception_removal_candidates.exception_removal_candidates
    assert removal([first, second]) == ["EXC-2"]
    passing = scan_run().to_dict()
    for item in cast("list[dict[str, object]]", passing["findings"]):
        item["outcome"] = item["evaluated_outcome"] = "pass"
    third = apply_exceptions.apply_exceptions(passing, exceptions_text(), "db01", [])
    assert removal([first, third]) == ["EXC-2"]
    assert stale_exceptions.stale_exceptions([first, third]) == []
    newer = {**first, "schema_version": "1.1"}
    with pytest.raises(exceptions.ExceptionsError, match=r"unsupported schema_version '1\.1'"):
        removal([first, newer])
    with pytest.raises(exceptions.ExceptionsError, match=r"unsupported schema_version '1\.1'"):
        stale_exceptions.stale_exceptions([newer])


def test_the_evaluation_of_the_filter_loads_back_unchanged() -> None:
    result = apply_exceptions.apply_exceptions(scan_run().to_dict(), exceptions_text(), "web01", [])
    assert exceptions.verify_evaluation(result, exceptions_text()).to_dict() == result


def test_the_filter_uses_the_controller_clock() -> None:
    result = apply_exceptions.apply_exceptions(
        scan_run(timedelta(hours=2)).to_dict(), exceptions_text(), "web01", [], 1
    )
    assert result["scan_lag_exceeded"] is True
    assert result["max_scan_lag_seconds"] == 3600
    assert result["evaluated_at"] == result["controller_time"]
    default = apply_exceptions.apply_exceptions(
        scan_run().to_dict(), exceptions_text(), "web01", []
    )
    assert default["scan_lag_exceeded"] is False
    assert default["max_scan_lag_seconds"] == 86400


def test_the_filter_refuses_a_scan_from_the_future() -> None:
    future = scan_run(-timedelta(minutes=10)).to_dict()
    with pytest.raises(exceptions.ExceptionsError, match="later than the controller time"):
        apply_exceptions.apply_exceptions(future, exceptions_text(), "web01", [])


@pytest.mark.parametrize("hours", [0, -1, 8761, True, "24", 1.5])
def test_the_filter_validates_the_scan_lag_limit(hours: object) -> None:
    with pytest.raises(exceptions.ExceptionsError, match="max_scan_lag_hours must be an integer"):
        apply_exceptions.apply_exceptions(
            scan_run().to_dict(), exceptions_text(), "web01", [], hours
        )


PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"


def profiled_text() -> str:
    created = (TODAY - timedelta(days=3)).isoformat()
    expires = (TODAY + timedelta(days=3)).isoformat()
    return "\n".join(
        [
            "---",
            "schema_version: '1.0'",
            "exceptions:",
            "  - id: EXC-STIG",
            f"    rule: {RULE}",
            "    framework: stig",
            "    scope:",
            f"      profiles: [{PROFILE}]",
            "    justification: Limited to one profile.",
            "    owner: platform-team",
            "    approval:",
            "      approver: security-lead",
            f"      date: {created}",
            f"    created: {created}",
            f"    expires: {expires}",
            "    risk: high",
            "",
        ]
    )


def test_new_filter_plugins_expose_their_filters() -> None:
    validate = validate_exceptions.FilterModule().filters()
    summary = scan_summary.FilterModule().filters()
    assert validate == {"validate_exceptions": validate_exceptions.validate_exceptions}
    assert summary == {"scan_summary": scan_summary.scan_summary}


def test_validate_exceptions_describes_a_valid_file() -> None:
    text = exceptions_text()
    overview = validate_exceptions.validate_exceptions(text)
    assert overview["schema_version"] == "1.0"
    assert overview["count"] == 2
    assert overview["ids"] == ["EXC-1", "EXC-2"]
    assert overview["source_sha256"] == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert overview["framework_without_profiles"] == [
        {"framework": "cis", "id": "EXC-1"},
        {"framework": "cis", "id": "EXC-2"},
    ]
    stamp = str(overview["validated_at"]).replace("Z", "+0000")
    validated_at = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S%z")
    assert abs(validated_at - datetime.now(timezone.utc)) < timedelta(minutes=1)


def test_validate_exceptions_does_not_warn_about_profiled_exceptions() -> None:
    overview = validate_exceptions.validate_exceptions(profiled_text())
    assert overview["ids"] == ["EXC-STIG"]
    assert overview["framework_without_profiles"] == []


def test_validate_exceptions_matches_the_digest_of_the_evaluation() -> None:
    text = exceptions_text()
    evaluation = apply_exceptions.apply_exceptions(scan_run().to_dict(), text, "web01", [])
    overview = validate_exceptions.validate_exceptions(text)
    assert overview["source_sha256"] == evaluation["source_sha256"]


def test_validate_exceptions_accepts_an_empty_list() -> None:
    overview = validate_exceptions.validate_exceptions(
        "---\nschema_version: '1.0'\nexceptions: []\n"
    )
    assert overview["count"] == 0
    assert overview["ids"] == []
    assert overview["framework_without_profiles"] == []


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (None, "the exceptions file must be text"),
        (42, "the exceptions file must be text"),
        ("---\nschema_version: '1.0'\n", "missing keys: exceptions"),
        ("schema_version: '1.0'\n", "exceptions file"),
        ("---\nschema_version: '2.0'\nexceptions: []\n", "unsupported schema_version"),
    ],
)
def test_validate_exceptions_rejects_invalid_files(text: object, message: str) -> None:
    with pytest.raises(exceptions.ExceptionsError, match=message):
        validate_exceptions.validate_exceptions(text)


def test_validate_exceptions_rejects_the_whole_file_for_one_bad_entry() -> None:
    text = exceptions_text().replace("    risk: low\n", "    risk: none\n", 1)
    with pytest.raises(exceptions.ExceptionsError, match=r"exceptions\[0\]\.risk"):
        validate_exceptions.validate_exceptions(text)


@pytest.mark.parametrize("form", ["mapping", "json"])
def test_scan_summary_counts_every_outcome(form: str) -> None:
    run = scan_run()
    value: object = run.to_dict() if form == "mapping" else model.dumps(run)
    assert scan_summary.scan_summary(value) == {
        "disabled": 0,
        "error": 0,
        "fail": 2,
        "notapplicable": 0,
        "notchecked": 0,
        "pass": 0,
        "run_status": "completed",
        "total": 2,
        "waived": 0,
    }


def test_scan_summary_counts_the_waived_run() -> None:
    evaluation = apply_exceptions.apply_exceptions(
        scan_run().to_dict(), exceptions_text(), "web01", []
    )
    summary = scan_summary.scan_summary(evaluation["scan_run"])
    assert summary["waived"] == 1
    assert summary["fail"] == 1
    assert summary["total"] == 2


def test_scan_summary_of_a_run_without_findings() -> None:
    run = replace(scan_run(), findings=())
    summary = scan_summary.scan_summary(run.to_dict())
    assert summary["total"] == 0
    assert summary["fail"] == 0


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, "the scan run must be a mapping or JSON text"),
        ("{", "invalid scan run"),
        ({"schema_version": "1.0"}, "invalid scan run"),
    ],
)
def test_scan_summary_rejects_invalid_scan_runs(value: object, message: str) -> None:
    with pytest.raises(exceptions.ExceptionsError, match=message):
        scan_summary.scan_summary(value)
