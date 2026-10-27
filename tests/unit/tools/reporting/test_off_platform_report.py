"""Off-platform scan runs in the report, schema 2.2 (ADR 0016 amendment of FREES-161)."""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import compliance, dashboard, report
from tools.reporting.common import dumps
from tools.reporting.report import ReportInputs, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA = json.loads(
    (Path(report.__file__).parent / "schema" / "report-v2.json").read_text(encoding="utf-8")
)
VALIDATOR: Any = Draft202012Validator(SCHEMA)
TARGET = model.HostIdentity("lab2604", "ubuntu", "26.04", "x86_64", "f" * 32)
MARKER = model.OffPlatform(model.Platform("ubuntu", "24.04"), model.Platform("ubuntu", "26.04"))


def build(**inputs: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(report.build_report(ReportInputs(**inputs))))
    assert VALIDATOR.is_valid(document), [e.message[:200] for e in VALIDATOR.iter_errors(document)]
    return document


def off_platform_run(kit: Any, status: model.ScanStatus = model.ScanStatus.COMPLETED) -> Any:
    outcome = model.Outcome.PASS if status is model.ScanStatus.COMPLETED else model.Outcome.ERROR
    run = kit.scan_run(
        (kit.finding("a", outcome), kit.finding("b", outcome)), status=status, host=TARGET
    )
    return dataclasses.replace(run, off_platform=MARKER)


def test_an_off_platform_run_is_listed_and_never_figured(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    on_platform = write_run(
        "on.json", kit.scan_run((kit.finding("a"), kit.finding("b", model.Outcome.FAIL)))
    )
    marked = write_run("off.json", off_platform_run(kit))
    document = build(scope=Scope.MULTI_HOST, scan_run=(on_platform, marked))
    section = document["sections"]["compliance"]
    assert section["status"] == "available"
    assert document["schema_version"] == "2.3"
    assert document["overview"]["off_platform"] == 1
    assert [group["host"]["hostname"] for group in section["groups"]] == ["host.example"]
    assert {rule["host"]["hostname"] for rule in section["rules"]} == {"host.example"}
    assert [aggregate["host_count"] for aggregate in section["aggregates"]] == [1]
    assert section["summary"]["compliance_percent"] == 50.0
    assert section["off_platform"] == [
        {
            "artifact": str(marked),
            "benchmark_id": kit.BENCHMARK,
            "benchmark_platform": {"distribution_id": "ubuntu", "distribution_version": "24.04"},
            "content_version": "1.0",
            "counts": {
                "disabled": 0,
                "error": 0,
                "fail": 0,
                "notapplicable": 0,
                "notchecked": 0,
                "pass": 2,
                "waived": 0,
            },
            "host": {"hostname": "lab2604", "input_sha256": None, "machine_id": "f" * 32},
            "input_sha256": section["off_platform"][0]["input_sha256"],
            "kind": "scan_run",
            "profile_id": kit.PROFILE,
            "run_status": "completed",
            "target_platform": {"distribution_id": "ubuntu", "distribution_version": "26.04"},
        }
    ]
    data = next(item["data"] for item in section["items"] if item["data"]["off_platform"])
    assert data["summary"]["assessment"] == "off_platform_benchmark"
    assert data["summary"]["compliance_percent"] is None
    assert data["scan_run"]["schema_version"] == "1.1"


def test_a_report_of_only_off_platform_runs_has_no_figure(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    marked = write_run("off.json", off_platform_run(kit))
    document = build(scope=Scope.SINGLE_HOST, scan_run=(marked,))
    section = document["sections"]["compliance"]
    assert section["status"] == "available"
    assert section["summary"] is None
    assert section["groups"] == []
    assert section["rules"] == []
    assert section["aggregates"] == []
    assert len(section["off_platform"]) == 1


def test_a_failed_off_platform_run_is_listed_as_not_completed(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    marked = write_run("off.json", off_platform_run(kit, model.ScanStatus.FAILED))
    document = build(scope=Scope.SINGLE_HOST, scan_run=(marked,))
    section = document["sections"]["compliance"]
    [entry] = section["off_platform"]
    assert entry["run_status"] == "failed"
    assert entry["counts"]["error"] == 2
    assert section["items"][0]["data"]["summary"]["assessment"] == "run_not_completed"


def test_an_off_platform_input_is_listed_even_when_the_section_is_partial(
    kit: Any, write_run: Callable[..., Path], tmp_path: Path
) -> None:
    marked = write_run("off.json", off_platform_run(kit))
    document = build(scope=Scope.MULTI_HOST, scan_run=(marked, tmp_path / "absent.json"))
    section = document["sections"]["compliance"]
    assert section["status"] == "partial"
    assert len(section["off_platform"]) == 1
    assert document["overview"]["off_platform"] == 1


def test_an_off_platform_evaluation_is_verified_and_listed(kit: Any, tmp_path: Path) -> None:
    run = dataclasses.replace(
        kit.evaluation_run(host=dataclasses.replace(kit.EVALUATION_HOST, distribution_id="ubuntu")),
        host=dataclasses.replace(
            kit.EVALUATION_HOST, distribution_id="ubuntu", distribution_version="26.04"
        ),
        off_platform=MARKER,
    )
    path = tmp_path / "evaluation.json"
    path.write_text(kit.evaluation_json(kit.evaluate(run)), encoding="utf-8")
    document = build(
        scope=Scope.SINGLE_HOST,
        exceptions_evaluation=(path,),
        exceptions_file=kit.EXCEPTIONS_FILE,
    )
    section = document["sections"]["compliance"]
    assert section["status"] == "available", section["reason"]
    [entry] = section["off_platform"]
    assert entry["kind"] == "exceptions_evaluation"
    assert section["summary"] is None
    assert document["sections"]["exceptions"]["status"] == "available"


def test_the_withheld_summary_keeps_counts_and_drops_the_percentage(kit: Any) -> None:
    tallies = compliance.tally_findings((kit.finding("a"),))
    completed = compliance.summarize(tallies, "completed", 1, 0)
    assert compliance.scan_run_summary(completed, None) == completed
    withheld = compliance.scan_run_summary(completed, MARKER)
    assert withheld.assessment == "off_platform_benchmark"
    assert withheld.compliance_percent is None
    assert withheld.counts == completed.counts
    failed = compliance.summarize(tallies, "failed", 1, 1)
    assert compliance.scan_run_summary(failed, MARKER) == failed


@pytest.fixture
def marked_document(kit: Any, write_run: Callable[..., Path]) -> dict[str, Any]:
    on_platform = write_run("on.json", kit.scan_run((kit.finding("a"),)))
    marked = write_run("off.json", off_platform_run(kit))
    return build(scope=Scope.MULTI_HOST, scan_run=(on_platform, marked))


def _marked_item(document: dict[str, Any]) -> dict[str, Any]:
    items = document["sections"]["compliance"]["items"]
    item: dict[str, Any] = next(entry for entry in items if entry["data"]["off_platform"])
    return item


def test_the_schema_never_lets_an_off_platform_input_carry_a_figure(
    marked_document: dict[str, Any],
) -> None:
    forged = copy.deepcopy(marked_document)
    summary = _marked_item(forged)["data"]["summary"]
    summary["compliance_percent"] = 100.0
    summary["assessment"] = "all_evaluated_passed"
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(marked_document)
    _marked_item(forged)["data"]["off_platform"] = None
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(marked_document)
    forged["sections"]["compliance"]["groups"][0]["summary"]["assessment"] = (
        "off_platform_benchmark"
    )
    forged["sections"]["compliance"]["groups"][0]["summary"]["compliance_percent"] = None
    assert not VALIDATOR.is_valid(forged)


def test_the_schema_couples_the_scan_run_marker_with_its_version(
    marked_document: dict[str, Any],
) -> None:
    forged = copy.deepcopy(marked_document)
    del _marked_item(forged)["data"]["scan_run"]["off_platform"]
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(marked_document)
    del _marked_item(forged)["data"]["scan_run"]["findings"][0]["off_platform"]
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(marked_document)
    _marked_item(forged)["data"]["scan_run"]["schema_version"] = "1.0"
    assert not VALIDATOR.is_valid(forged)


def test_the_schema_couples_the_off_platform_keys_with_the_report_version(
    marked_document: dict[str, Any],
) -> None:
    forged = copy.deepcopy(marked_document)
    del forged["sections"]["compliance"]["off_platform"]
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(marked_document)
    del forged["overview"]["off_platform"]
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(marked_document)
    del _marked_item(forged)["data"]["off_platform"]
    assert not VALIDATOR.is_valid(forged)
    older = copy.deepcopy(marked_document)
    older["schema_version"] = "2.1"
    assert not VALIDATOR.is_valid(older)


def test_the_dashboard_embeds_a_2_2_report(marked_document: dict[str, Any]) -> None:
    page = dashboard.render_dashboard(marked_document)
    assert page.startswith("<!DOCTYPE html>")
    assert "off_platform_benchmark" in page


def _compliance_reasons(document: dict[str, Any]) -> list[str | None]:
    return [item["reason"] for item in document["sections"]["compliance"]["items"]]


def test_raw_off_platform_copies_are_refused(kit: Any, tmp_path: Path) -> None:
    xccdf = tmp_path / "results.off-platform.xml"
    xccdf.write_text(kit.xccdf_text("lab2604.example"), encoding="utf-8")
    arf = tmp_path / "results-arf.off-platform.xml"
    arf.write_bytes((kit.REPORTING / "arf.xml").read_bytes())
    document = build(scope=Scope.MULTI_HOST, xccdf=(xccdf,), arf=(arf,))
    assert document["sections"]["compliance"]["status"] == "error"
    reasons = _compliance_reasons(document)
    assert len(reasons) == 2
    assert all(reason is not None and "off-platform scan run" in reason for reason in reasons)


def test_results_next_to_a_marked_scan_run_are_refused(kit: Any, tmp_path: Path) -> None:
    run_directory = tmp_path / "run-1"
    (run_directory / "scan").mkdir(parents=True)
    (run_directory / "scan-run.json").write_text(
        model.dumps(off_platform_run(kit)), encoding="utf-8"
    )
    beside = run_directory / "scan" / "results.xml"
    beside.write_text(kit.xccdf_text("lab2604.example"), encoding="utf-8")
    same = run_directory / "results.xml"
    same.write_text(kit.xccdf_text("lab2604.example"), encoding="utf-8")
    document = build(scope=Scope.MULTI_HOST, xccdf=(beside, same))
    reasons = _compliance_reasons(document)
    assert all(reason is not None and "off-platform scan run" in reason for reason in reasons)


def test_results_next_to_an_unmarked_scan_run_are_read(kit: Any, tmp_path: Path) -> None:
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan-run.json").write_text(
        model.dumps(kit.scan_run((kit.finding("a"),))), encoding="utf-8"
    )
    results = tmp_path / "scan" / "results.xml"
    results.write_text(kit.xccdf_text("host.example"), encoding="utf-8")
    document = build(scope=Scope.MULTI_HOST, xccdf=(results,))
    assert document["sections"]["compliance"]["status"] == "available"


def test_an_unreadable_or_invalid_neighbour_refuses_the_results(kit: Any, tmp_path: Path) -> None:
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "scan-run.json").write_text("{}", encoding="utf-8")
    first = broken / "results.xml"
    first.write_text(kit.xccdf_text("host.example"), encoding="utf-8")
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "scan-run.json").symlink_to(broken / "scan-run.json")
    second = linked / "results.xml"
    second.write_text(kit.xccdf_text("host.example"), encoding="utf-8")
    document = build(scope=Scope.MULTI_HOST, xccdf=(first, second))
    reasons = _compliance_reasons(document)
    assert any(reason is not None and "is not a valid scan run" in reason for reason in reasons)
    assert any(reason is not None and "cannot be read" in reason for reason in reasons)
