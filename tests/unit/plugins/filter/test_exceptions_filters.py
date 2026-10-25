from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    apply_exceptions,
    stale_exceptions,
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


def scan_run() -> model.ScanRun:
    started = f"{TODAY.isoformat()}T00:00:01Z"
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
