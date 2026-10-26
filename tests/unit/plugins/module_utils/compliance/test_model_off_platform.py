"""The off-platform marker of the findings model and schema version 1.1 (FREES-161)."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tests.unit.plugins.module_utils.compliance.test_model import finding, host, scan_run

BENCHMARK_PLATFORM = model.Platform("ubuntu", "24.04")
TARGET_PLATFORM = model.Platform("ubuntu", "26.04")
MARKER = model.OffPlatform(BENCHMARK_PLATFORM, TARGET_PLATFORM)


def marked_run(**overrides: Any) -> model.ScanRun:
    values: dict[str, Any] = {
        "host": host(distribution_version="26.04"),
        "off_platform": MARKER,
    }
    return scan_run(**{**values, **overrides})


def findings_of(document: dict[str, object]) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", document["findings"])


def test_a_marked_run_gives_every_finding_its_marker() -> None:
    run = marked_run()
    assert run.off_platform == MARKER
    assert run.findings
    assert all(item.off_platform == MARKER for item in run.findings)
    assert run.schema_version == model.OFF_PLATFORM_SCHEMA_VERSION


def test_an_unmarked_run_stays_schema_one_zero_byte_for_byte() -> None:
    run = scan_run()
    document = json.loads(model.dumps(run))
    assert document["schema_version"] == "1.0"
    assert model.OFF_PLATFORM_KEY not in document
    assert all(model.OFF_PLATFORM_KEY not in item for item in document["findings"])
    assert model.loads(model.dumps(run)) == run


def test_a_marked_run_round_trips_as_schema_one_one() -> None:
    run = marked_run()
    document = json.loads(model.dumps(run))
    assert document["schema_version"] == "1.1"
    assert document["off_platform"] == {
        "benchmark_platform": {"distribution_id": "ubuntu", "distribution_version": "24.04"},
        "target_platform": {"distribution_id": "ubuntu", "distribution_version": "26.04"},
    }
    assert all(item["off_platform"] == document["off_platform"] for item in document["findings"])
    assert model.loads(model.dumps(run)) == run


def test_a_one_one_document_must_mark_the_run_and_every_finding() -> None:
    document = marked_run().to_dict()
    without_run = {key: value for key, value in document.items() if key != "off_platform"}
    with pytest.raises(model.ModelError, match="missing keys: off_platform"):
        model.ScanRun.from_dict(without_run)
    findings = [dict(item) for item in findings_of(document)]
    del findings[0]["off_platform"]
    with pytest.raises(model.ModelError, match="missing keys: off_platform"):
        model.ScanRun.from_dict({**document, "findings": findings})
    with pytest.raises(model.ModelError, match="off_platform must be an object"):
        model.ScanRun.from_dict({**document, "off_platform": None})


def test_a_one_zero_document_may_not_carry_a_marker() -> None:
    document = marked_run().to_dict()
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.ScanRun.from_dict({**document, "schema_version": "1.0"})
    plain = scan_run().to_dict()
    findings = [dict(item) for item in findings_of(plain)]
    findings[0]["off_platform"] = MARKER.to_dict()
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.ScanRun.from_dict({**plain, "findings": findings})


def test_a_finding_with_another_marker_is_refused() -> None:
    other = model.OffPlatform(model.Platform("ubuntu", "22.04"), TARGET_PLATFORM)
    with pytest.raises(model.ModelError, match="another off-platform marker"):
        marked_run(findings=(finding(off_platform=other),))
    with pytest.raises(model.ModelError, match="another off-platform marker"):
        scan_run(findings=(finding(off_platform=MARKER),))


def test_a_one_one_document_with_a_mismatching_finding_marker_is_refused() -> None:
    document = marked_run().to_dict()
    findings = [dict(item) for item in findings_of(document)]
    findings[0]["off_platform"] = model.OffPlatform(
        model.Platform("debian", "12"), TARGET_PLATFORM
    ).to_dict()
    with pytest.raises(model.ModelError, match="another off-platform marker"):
        model.ScanRun.from_dict({**document, "findings": findings})


def test_the_marker_must_name_the_platform_of_the_host() -> None:
    with pytest.raises(model.ModelError, match=r"platform of scan_run\.host"):
        marked_run(host=host())
    with pytest.raises(model.ModelError, match=r"platform of scan_run\.host"):
        marked_run(host=host(distribution_id="debian", distribution_version="26.04"))


def test_the_marker_needs_two_different_platforms() -> None:
    with pytest.raises(model.ModelError, match="differs from the target"):
        model.OffPlatform(TARGET_PLATFORM, TARGET_PLATFORM)
    text: Any = "ubuntu 26.04"
    with pytest.raises(model.ModelError, match="must be of type Platform"):
        model.OffPlatform(BENCHMARK_PLATFORM, text)
    with pytest.raises(model.ModelError, match="must be of type Platform"):
        model.OffPlatform(text, TARGET_PLATFORM)


@pytest.mark.parametrize(
    ("distribution", "version"),
    [("Ubuntu", "26.04"), ("ubuntu", " 26.04"), ("ubuntu", ""), ("ubuntu", "26.04" + chr(0x202E))],
)
def test_a_platform_is_validated_like_a_host(distribution: str, version: str) -> None:
    with pytest.raises(model.ModelError):
        model.Platform(distribution, version)


def test_the_marker_types_are_checked_on_findings_and_runs() -> None:
    with pytest.raises(
        model.ModelError, match=r"finding\.off_platform must be of type OffPlatform"
    ):
        finding(off_platform="ubuntu 24.04")
    with pytest.raises(
        model.ModelError, match=r"scan_run\.off_platform must be of type OffPlatform"
    ):
        marked_run(off_platform="ubuntu 24.04")


def test_a_failed_marked_run_keeps_the_marker_on_its_error_findings() -> None:
    errors = (
        finding(outcome=model.Outcome.ERROR, evidence=(), message="SCC wrote no results"),
        finding(
            rule_id="xccdf_org.ssgproject.content_rule_audit_rules_login_events",
            outcome=model.Outcome.ERROR,
            message="SCC wrote no results",
        ),
    )
    run = marked_run(
        status=model.ScanStatus.FAILED, error_message="SCC wrote no results", findings=errors
    )
    assert all(item.off_platform == MARKER for item in run.findings)
    assert model.loads(model.dumps(run)) == run


def test_replacing_findings_keeps_the_marker() -> None:
    run = marked_run()
    added = finding(
        rule_id="xccdf_org.ssgproject.content_rule_extra_rule", outcome=model.Outcome.PASS
    )
    updated = replace(run, findings=(*run.findings, added))
    assert all(item.off_platform == MARKER for item in updated.findings)


def test_a_marker_round_trips_and_rejects_unknown_keys() -> None:
    assert model.OffPlatform.from_dict(MARKER.to_dict()) == MARKER
    assert model.Platform.of_host(host()) == BENCHMARK_PLATFORM
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.OffPlatform.from_dict({**MARKER.to_dict(), "threshold": 50})
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.Platform.from_dict({**TARGET_PLATFORM.to_dict(), "codename": "resolute"})


def test_a_document_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(model.ModelError, match="scan_run must be an object"):
        model.ScanRun.from_dict(["schema_version", "1.1"])
