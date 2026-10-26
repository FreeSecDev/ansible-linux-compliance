from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
)
from tools.reporting import common, report
from tools.reporting.common import dumps
from tools.reporting.report import ReportError, ReportInputs, RunMetadata, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA_PATH = Path(report.__file__).parent / "schema" / "report-v2.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR: Any = Draft202012Validator(SCHEMA)
SECTIONS = set(report.SECTION_NAMES)
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def build(inputs: ReportInputs) -> Any:
    return json.loads(dumps(report.build_report(inputs)))


def errors(document: Any) -> list[str]:
    return [] if VALIDATOR.is_valid(document) else ["invalid"]


def full_inputs(kit: Any, **changes: Any) -> ReportInputs:
    fixtures = kit.REPORTING
    base: dict[str, Any] = {
        "scope": Scope.FLEET,
        "metadata": RunMetadata(
            commit=COMMIT,
            pull_request="42",
            workflow_run="12345/attempt/1",
            started_at="2026-10-25T10:00:00Z",
            finished_at="2026-10-25T10:10:00Z",
            generated_at="2026-10-25T10:11:00Z",
        ),
        "xccdf": (kit.XCCDF / "mixed-results.xml",),
        "arf": (fixtures / "arf.xml",),
        "junit": (fixtures / "junit.xml",),
        "pytest_json": (fixtures / "pytest.json",),
        "cobertura": (fixtures / "cobertura.xml",),
        "lint": (fixtures / "ansible-lint.sarif", fixtures / "ansible-lint.json"),
        "grype": (fixtures / "grype.json",),
        "sbom": (fixtures / "spdx.json", fixtures / "cyclonedx.json"),
        "packer": (fixtures / "packer-manifest.json",),
        "codebuild": (fixtures / "codebuild.json",),
        "molecule": (fixtures / "molecule-summary.json",),
        "exceptions_evaluation": (kit.EVALUATION_FILE,),
    }
    base.update(changes)
    return ReportInputs(**base)


def test_the_schema_is_a_valid_2020_12_schema() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_full_report_validates_against_the_schema(kit: Any) -> None:
    document = build(full_inputs(kit))
    assert errors(document) == []
    assert document["schema_version"] == "2.0"
    exceptions_summary = document["sections"]["exceptions"]["summary"]
    assert document["overview"] == {
        "available": sorted(SECTIONS),
        "error": [],
        "exceptions": exceptions_summary,
        "partial": [],
        "unavailable": [],
    }
    assert exceptions_summary["by_status"]["stale"] == 1
    assert not report.has_error(document)


def test_empty_report_marks_every_section_unavailable_never_pass() -> None:
    document = build(ReportInputs(scope=Scope.FLEET))
    assert errors(document) == []
    assert document["overview"] == {
        "available": [],
        "error": [],
        "exceptions": None,
        "partial": [],
        "unavailable": sorted(SECTIONS),
    }
    sections: dict[str, Any] = document["sections"]
    for section in sections.values():
        assert section["status"] == "unavailable"
        assert section["reason"] == "no input was supplied"
        assert section["items"] == []
        assert section["gaps"] == []
        assert section["summary"] is None
    assert sections["compliance"]["rules"] == []
    assert sections["compliance"]["groups"] == []
    assert sections["compliance"]["aggregates"] == []
    assert document["raw_artifacts"] == []
    assert document["metadata"] == dict.fromkeys(
        ("commit", "finished_at", "generated_at", "pull_request", "started_at", "workflow_run")
    )


def test_output_is_byte_identical_for_identical_inputs(kit: Any) -> None:
    first = dumps(report.build_report(full_inputs(kit)))
    second = dumps(report.build_report(full_inputs(kit)))
    assert first == second
    assert first.endswith("\n")
    assert first == dumps(json.loads(first))


def test_no_timestamp_is_generated_when_none_is_supplied(kit: Any) -> None:
    document = build(full_inputs(kit, metadata=RunMetadata()))
    assert document["metadata"] == dict.fromkeys(
        ("commit", "finished_at", "generated_at", "pull_request", "started_at", "workflow_run")
    )


def test_raw_artifact_references_keep_path_and_checksum(kit: Any) -> None:
    document = build(full_inputs(kit))
    references: list[dict[str, Any]] = document["raw_artifacts"]
    assert len(references) == 14
    assert [ref["format"] for ref in references].count("exceptions_evaluation") == 1
    paths = [reference["path"] for reference in references]
    assert paths == sorted(paths)
    junit = next(ref for ref in references if ref["format"] == "junit")
    content = (kit.REPORTING / "junit.xml").read_bytes()
    assert junit["path"] == str(kit.REPORTING / "junit.xml")
    assert junit["sha256"] == hashlib.sha256(content).hexdigest()
    assert junit["size"] == len(content)
    assert junit["status"] == "available"


def test_missing_and_corrupt_inputs_are_never_available(
    kit: Any, write: Callable[..., Path], tmp_path: Path
) -> None:
    corrupt = write("junit.xml", "<testsuite><testcase")
    inputs = ReportInputs(
        scope=Scope.MULTI_HOST,
        junit=(corrupt,),
        cobertura=(tmp_path / "absent.xml",),
        lint=(kit.REPORTING / "ansible-lint.json",),
    )
    document = build(inputs)
    assert errors(document) == []
    assert document["overview"] == {
        "available": ["lint"],
        "error": ["tests"],
        "exceptions": None,
        "partial": [],
        "unavailable": sorted(SECTIONS - {"lint", "tests"}),
    }
    assert report.has_error(document)
    assert report.has_gap(document)
    sections: dict[str, Any] = document["sections"]
    assert sections["tests"]["summary"] is None
    assert sections["tests"]["items"][0]["data"] is None
    assert sections["coverage"]["items"][0]["status"] == "unavailable"
    assert sections["coverage"]["reason"] == "1 of 1 input(s) are missing and 0 are invalid"
    assert sections["coverage"]["gaps"] == [
        {
            "artifact": str(tmp_path / "absent.xml"),
            "reason": "input file does not exist",
            "status": "unavailable",
        }
    ]
    assert sections["tests"]["gaps"][0]["status"] == "error"


def test_a_missing_input_among_good_ones_makes_the_section_partial(
    kit: Any, tmp_path: Path
) -> None:
    inputs = ReportInputs(
        scope=Scope.BENCHMARK,
        junit=(kit.REPORTING / "junit.xml", tmp_path / "absent.xml"),
    )
    document = build(inputs)
    assert errors(document) == []
    section: dict[str, Any] = document["sections"]["tests"]
    assert section["status"] == "partial"
    assert section["summary"] is None
    assert section["items"][0]["status"] == "available"
    assert section["items"][0]["data"]["total"] == 5
    assert [gap["status"] for gap in section["gaps"]] == ["unavailable"]
    assert document["overview"]["partial"] == ["tests"]
    assert document["overview"]["available"] == []
    assert report.has_gap(document)
    assert not report.has_error(document)


def test_error_outweighs_unavailable(write: Callable[..., Path], tmp_path: Path) -> None:
    inputs = ReportInputs(
        scope=Scope.BENCHMARK,
        junit=(tmp_path / "absent.xml", write("bad.xml", "<x/>")),
    )
    assert build(inputs)["overview"]["error"] == ["tests"]


def test_oversized_inputs_are_errors(kit: Any) -> None:
    document = build(full_inputs(kit, max_bytes=50))
    assert errors(document) == []
    assert document["overview"]["available"] == []
    assert document["overview"]["error"] == sorted(SECTIONS)


def test_section_summaries(kit: Any) -> None:
    document = build(full_inputs(kit))
    sections: dict[str, Any] = document["sections"]
    assert sections["tests"]["summary"] == {
        "errors": 2,
        "failed": 3,
        "passed": 5,
        "skipped": 3,
        "total": 13,
    }
    assert sections["molecule"]["summary"]["total"] == 4
    assert sections["lint"]["summary"]["total"] == 6
    assert sections["lint"]["summary"]["by_severity"]["critical"] == 1
    assert sections["vulnerabilities"]["summary"]["total"] == 4
    for name in ("coverage", "sbom", "packer"):
        assert sections[name]["summary"] is None


def write_runs(
    write_run: Callable[..., Path], scenarios: dict[str, model.ScanRun]
) -> tuple[Path, ...]:
    return tuple(write_run(f"{name}.json", run) for name, run in scenarios.items())


def test_compliance_summary_with_waived_expired_and_dedup(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    out = model.Outcome
    cis = kit.scan_run(
        (
            kit.finding("a"),
            kit.finding("b", out.FAIL),
            kit.waived("c"),
            kit.expired("d"),
            kit.finding("e", out.NOTAPPLICABLE),
            kit.finding("f", out.NOTCHECKED),
        ),
        benchmark_id=kit.BENCHMARK + "_cis",
    )
    stig = kit.scan_run(
        (kit.finding("a", out.FAIL), kit.finding("g", out.ERROR)),
        benchmark_id=kit.BENCHMARK + "_stig",
    )
    paths = write_runs(write_run, {"cis": cis, "stig": stig})
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=paths))
    assert errors(document) == []
    section: dict[str, Any] = document["sections"]["compliance"]
    assert section["summary"] is None
    assert section["aggregates"] == []
    groups = {group["benchmark_id"][-3:]: group["summary"] for group in section["groups"]}
    assert groups["cis"]["counts"] == {
        "pass": 1,
        "fail": 2,
        "notapplicable": 1,
        "notchecked": 1,
        "error": 0,
        "waived": 1,
        "disabled": 0,
    }
    assert groups["cis"]["evaluated"] == 5
    assert groups["cis"]["compliance_percent"] == 20.0
    assert groups["cis"]["expired_waivers"] == 1
    assert groups["tig"]["compliance_percent"] == 0.0
    rules = {rule["rule_id"].rsplit("_", 1)[-1]: rule for rule in section["rules"]}
    assert len(section["rules"]) == 7
    assert rules["a"]["outcome"] == "fail"
    assert [source["outcome"] for source in rules["a"]["sources"]] == ["pass", "fail"]
    assert section["items"][0]["data"]["findings"] == []
    assert section["items"][0]["data"]["scan_run"]["run_id"] == "run-1"


def test_non_completed_scan_run_is_never_summarised_as_compliant(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    good = kit.scan_run((kit.finding("a"), kit.finding("b")))
    failed = kit.scan_run(
        (),
        status=model.ScanStatus.FAILED,
        host=model.HostIdentity("b.example", "rhel", "9", "x86_64", None),
    )
    paths = write_runs(write_run, {"good": good, "failed": failed})
    document = build(ReportInputs(scope=Scope.MULTI_HOST, scan_run=paths))
    assert errors(document) == []
    section: dict[str, Any] = document["sections"]["compliance"]
    summary: dict[str, Any] = section["summary"]
    assert section["aggregates"][0]["host_count"] == 2
    assert section["aggregates"][0]["scope"] == "multi_host"
    by_host = {group["host"]["hostname"]: group["summary"] for group in section["groups"]}
    assert by_host["b.example"]["run_status"] == "failed"
    assert by_host["b.example"]["compliance_percent"] is None
    assert by_host["host.example"]["compliance_percent"] == 100.0
    assert summary["run_status"] == "not_completed"
    assert summary["assessment"] == "run_not_completed"
    assert summary["compliance_percent"] is None
    assert (summary["runs_total"], summary["runs_not_completed"]) == (2, 1)


def test_xccdf_results_without_a_target_have_no_host_and_validate(kit: Any) -> None:
    document = build(ReportInputs(scope=Scope.BENCHMARK, xccdf=(kit.XCCDF / "mixed-results.xml",)))
    assert errors(document) == []
    item = document["sections"]["compliance"]["items"][0]
    assert item["data"]["host"] is None
    assert item["data"]["scan_run"] is None
    assert len(item["data"]["findings"]) == 8


INVALID_METADATA = [
    ("commit", ""),
    ("commit", "ZZZ"),
    ("commit", "abc"),
    ("pull_request", "0"),
    ("pull_request", "٣"),
    ("pull_request", "12345678901"),
    ("workflow_run", ""),
    ("workflow_run", "has space"),
    ("workflow_run", "x" * 257),
    *[
        (name, value)
        for name in ("started_at", "finished_at", "generated_at")
        for value in (
            "",
            "yesterday",
            "2026-13-45T25:61:61Z",
            "2026-10-25 10:00:00",
            "2026-10-25T10:00:00+00:00",
        )
    ],
]


@pytest.mark.parametrize(("field", "value"), INVALID_METADATA)
def test_invalid_metadata_is_rejected(field: str, value: str) -> None:
    with pytest.raises(ReportError):
        RunMetadata(**{field: value})


def test_valid_metadata_is_accepted() -> None:
    metadata = RunMetadata(
        commit=COMMIT,
        pull_request="7",
        workflow_run="https_run-1",
        started_at="2026-10-25T10:00:00Z",
    )
    assert metadata.pull_request == "7"


def test_scope_values() -> None:
    assert [scope.value for scope in Scope] == ["single_host", "multi_host", "benchmark", "fleet"]


@pytest.fixture
def valid_report(kit: Any) -> dict[str, Any]:
    document: dict[str, Any] = build(full_inputs(kit))
    return document


DELETE = object()
type PathSteps = tuple[str | int, ...]
SCHEMA_VIOLATIONS: list[tuple[PathSteps, str, Any]] = [
    ((), "schema_version", "1.0"),
    ((), "schema_version", "3.0"),
    ((), "scope", "global"),
    ((), "extra", 1),
    ((), "sections", DELETE),
    (("sections",), "tests", DELETE),
    (("sections", "tests"), "status", "pass"),
    (("sections", "tests"), "reason", "stale"),
    (("sections", "tests"), "items", []),
    (("sections", "tests"), "summary", None),
    (("sections", "tests"), "gaps", [{"artifact": "x", "reason": "r", "status": "error"}]),
    (("sections", "tests"), "status", "partial"),
    (("sections", "tests", "items", 0, "artifact"), "sha256", None),
    (("sections", "tests", "items", 0, "artifact"), "size", None),
    (("sections", "compliance"), "rules", "x"),
    (("sections", "compliance", "summary"), "run_status", "failed"),
    (("sections", "compliance", "summary"), "evaluated", 0),
    (("sections", "compliance", "summary"), "compliance_percent", 100),
    (("sections", "compliance", "summary"), "assessment", "all_evaluated_passed"),
    (("sections", "compliance", "summary"), "assessment", "run_not_completed"),
    (("sections", "compliance", "items", 0, "data"), "scan_status", "failed"),
    (("sections", "compliance", "aggregates", 0), "host_count", 0),
    (("raw_artifacts", 0), "format", "x" * 100000),
    (("overview",), "error", ["tests"]),
    (("overview",), "partial", ["lint"]),
    (("overview",), "available", []),
    (("sections", "lint", "items", 0, "data"), "issues", [{}] * 2000),
    (("sections", "coverage"), "summary", {"total": 1}),
    (("sections", "tests", "items", 0), "data", None),
    (("sections", "tests", "items", 0), "status", "error"),
    (("sections", "tests", "items", 0), "reason", "should be null"),
    (("sections", "tests", "items", 0, "data"), "total", -1),
    (("sections", "tests", "items", 0, "data"), "extra", 1),
    (("sections", "compliance", "summary"), "compliance_percent", 101),
    (("sections", "compliance", "summary"), "assessment", "compliant"),
    (("sections", "compliance", "items", 0, "data", "findings", 0), "outcome", "ok"),
    (("sections", "compliance", "items", 0, "data"), "kind", "scan_run"),
    (("metadata",), "commit", "not-a-sha"),
    (("metadata",), "started_at", "yesterday"),
    (("raw_artifacts", 0), "sha256", "abc"),
    (("raw_artifacts", 0), "status", "pass"),
    (("overview",), "available", ["nonsense"]),
]


def mutate(document: dict[str, Any], path: PathSteps, key: str, value: Any) -> list[str]:
    candidate = copy.deepcopy(document)
    target: Any = candidate
    for step in path:
        target = target[step]
    if value is DELETE:
        del target[key]
    else:
        target[key] = value
    return errors(candidate)


@pytest.mark.parametrize(("path", "key", "value"), SCHEMA_VIOLATIONS)
def test_schema_rejects_invalid_reports(
    valid_report: dict[str, Any], path: PathSteps, key: str, value: Any
) -> None:
    assert mutate(valid_report, path, key, value)


def test_schema_requires_a_reason_when_a_section_is_not_available() -> None:
    document = build(ReportInputs(scope=Scope.FLEET))
    assert errors(document) == []
    assert mutate(document, ("sections", "lint"), "reason", None)
    assert mutate(document, ("sections", "lint"), "summary", {"total": 0})
    assert mutate(document, ("sections", "lint"), "status", "available")


def run_with(write_run: Callable[..., Path], *runs: model.ScanRun) -> tuple[Path, ...]:
    return tuple(write_run(f"run{index}.json", run) for index, run in enumerate(runs))


def test_scope_single_host_rejects_data_from_several_hosts(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    other = model.HostIdentity("other.example", "rhel", "9", "x86_64", None)
    paths = run_with(
        write_run,
        kit.scan_run((kit.finding("a"),)),
        kit.scan_run((kit.finding("a"),), host=other),
    )
    with pytest.raises(ReportError, match="2 hosts"):
        report.build_report(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=paths))
    for scope in (Scope.MULTI_HOST, Scope.FLEET, Scope.BENCHMARK):
        assert errors(build(ReportInputs(scope=scope, scan_run=paths))) == []


def test_scope_benchmark_rejects_several_benchmark_versions(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    paths = run_with(
        write_run,
        kit.scan_run((kit.finding("a"),)),
        kit.scan_run((kit.finding("a"),), content_version="2.0"),
    )
    with pytest.raises(ReportError, match="2 benchmark versions"):
        report.build_report(ReportInputs(scope=Scope.BENCHMARK, scan_run=paths))
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=paths))
    assert errors(document) == []


def test_scope_single_host_accepts_one_host_in_several_files(
    kit: Any, write: Callable[..., Path]
) -> None:
    first = write("one.xml", kit.xccdf_text("Web01"))
    second = write("two.xml", kit.xccdf_text("web01"))
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, xccdf=(first, second)))
    assert errors(document) == []
    groups = document["sections"]["compliance"]["groups"]
    assert [group["host"]["hostname"] for group in groups] == ["web01"]
    anonymous = write("three.xml", kit.xccdf_text(None))
    with pytest.raises(ReportError):
        report.build_report(ReportInputs(scope=Scope.SINGLE_HOST, xccdf=(first, anonymous)))


def test_figures_are_never_pooled_across_benchmark_versions_or_hosts(
    kit: Any, write: Callable[..., Path]
) -> None:
    rhel = write("rhel.xml", kit.xccdf_text("rhel9", "pass", "0.1.75"))
    debian = write("debian.xml", kit.xccdf_text("debian12", "fail", "0.1.70"))
    document = build(ReportInputs(scope=Scope.FLEET, xccdf=(rhel, debian)))
    assert errors(document) == []
    section = document["sections"]["compliance"]
    assert section["summary"] is None
    assert {
        (g["content_version"], g["host"]["hostname"], g["summary"]["compliance_percent"])
        for g in section["groups"]
    } == {
        ("0.1.75", "rhel9", 100.0),
        ("0.1.70", "debian12", 0.0),
    }
    assert [
        (a["content_version"], a["host_count"], a["summary"]["compliance_percent"])
        for a in section["aggregates"]
    ] == [
        ("0.1.70", 1, 0.0),
        ("0.1.75", 1, 100.0),
    ]


def test_aggregate_over_hosts_of_one_benchmark_version_is_labelled(
    kit: Any, write: Callable[..., Path]
) -> None:
    paths = tuple(
        write(f"{name}.xml", kit.xccdf_text(name, outcome))
        for name, outcome in (("h1", "pass"), ("h2", "pass"), ("h3", "fail"))
    )
    document = build(ReportInputs(scope=Scope.MULTI_HOST, xccdf=paths))
    section = document["sections"]["compliance"]
    assert section["aggregates"][0]["scope"] == "multi_host"
    assert section["aggregates"][0]["host_count"] == 3
    assert section["summary"]["compliance_percent"] == 66.6


def test_reviewers_notselected_case_reports_100_percent_end_to_end(
    kit: Any, write: Callable[..., Path]
) -> None:
    results = [(f"s{i}", "pass") for i in range(10)]
    results += [(f"n{i}", "notselected") for i in range(90)]
    text = kit.xccdf_text("h", results=results)
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, xccdf=(write("x.xml", text),)))
    assert errors(document) == []
    summary = document["sections"]["compliance"]["summary"]
    assert summary["compliance_percent"] == 100.0
    assert summary["assessment"] == "all_evaluated_passed"
    assert summary["not_selected"] == 90
    assert summary["counts"]["notchecked"] == 0
    assert summary["evaluated"] == 10


def test_scan_run_notselected_expected_rule_is_notchecked(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    flagged = model.Finding(
        rule_id=kit.RULE_PREFIX + "ns",
        outcome=model.Outcome.NOTCHECKED,
        evaluated_outcome=model.Outcome.NOTCHECKED,
        severity=model.Severity.MEDIUM,
        message=None,
        evidence=(),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=None,
        flags=(model.ResultFlag.NOTSELECTED,),
    )
    path = write_run("run.json", kit.scan_run((kit.finding("a"), flagged)))
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(path,)))
    summary = document["sections"]["compliance"]["summary"]
    assert summary["counts"]["notchecked"] == 1
    assert summary["compliance_percent"] == 50.0
    assert summary["not_selected"] == 0


def test_the_same_file_twice_is_counted_once(kit: Any, write_run: Callable[..., Path]) -> None:
    path = write_run("run.json", kit.scan_run((kit.finding("a"),)))
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(path, path)))
    assert document["sections"]["compliance"]["summary"]["runs_total"] == 1
    assert len(document["sections"]["compliance"]["items"]) == 2


def test_codebuild_summary_counts_failed_and_in_progress_builds(kit: Any) -> None:
    document = build(ReportInputs(scope=Scope.FLEET, codebuild=(kit.REPORTING / "codebuild.json",)))
    assert errors(document) == []
    assert document["sections"]["codebuild"]["summary"] == {
        "failed": 1,
        "in_progress": 0,
        "succeeded": 1,
        "total": 2,
    }


def test_crashed_tools_make_their_sections_errors(write: Callable[..., Path]) -> None:
    pytest_report = write(
        "pytest.json", json.dumps({"exitcode": 2, "summary": {"passed": 5, "total": 5}})
    )
    sarif_report = write(
        "lint.sarif",
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ansible-lint"}},
                        "invocations": [{"executionSuccessful": False}],
                        "results": [],
                    }
                ],
            }
        ),
    )
    document = build(
        ReportInputs(scope=Scope.FLEET, pytest_json=(pytest_report,), lint=(sarif_report,))
    )
    assert errors(document) == []
    assert document["overview"]["error"] == ["lint", "tests"]
    assert document["sections"]["tests"]["summary"] is None


def test_limits_are_enforced(
    kit: Any, monkeypatch: pytest.MonkeyPatch, write_run: Callable[..., Path]
) -> None:
    monkeypatch.setattr(report, "MAX_INPUTS", 1)
    twice = ReportInputs(scope=Scope.FLEET, junit=(kit.REPORTING / "junit.xml",) * 2)
    with pytest.raises(ReportError, match="more than 1 inputs"):
        report.build_report(twice)
    monkeypatch.setattr(report, "MAX_INPUTS", 1000)
    monkeypatch.setattr(report, "MAX_RULES", 0)
    path = write_run("run.json", kit.scan_run((kit.finding("a"),)))
    with pytest.raises(ReportError, match="size limits"):
        report.build_report(ReportInputs(scope=Scope.FLEET, scan_run=(path,)))


def test_failed_runs_cannot_carry_a_percentage_in_the_schema(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    failed = kit.scan_run((), status=model.ScanStatus.FAILED)
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(write_run("f.json", failed),)))
    assert errors(document) == []
    summary = document["sections"]["compliance"]["summary"]
    assert (summary["run_status"], summary["compliance_percent"]) == ("failed", None)
    for change in (
        {"compliance_percent": 100.0, "assessment": "all_evaluated_passed"},
        {"compliance_percent": 55.0},
        {"assessment": "all_evaluated_passed"},
    ):
        assert mutate_many(document, ("sections", "compliance", "summary"), change)
    item_summary = ("sections", "compliance", "items", 0, "data", "summary")
    assert mutate_many(document, item_summary, {"compliance_percent": 100.0})


def mutate_many(document: dict[str, Any], path: PathSteps, changes: dict[str, Any]) -> list[str]:
    candidate = copy.deepcopy(document)
    target: Any = candidate
    for step in path:
        target = target[step]
    target.update(changes)
    return errors(candidate)


def test_inconsistent_documents_fail_validation(kit: Any, tmp_path: Path) -> None:
    ok = build(full_inputs(kit))
    partial = build(
        ReportInputs(
            scope=Scope.FLEET, junit=(kit.REPORTING / "junit.xml", tmp_path / "absent.xml")
        )
    )
    assert errors(partial) == []
    tests = ("sections", "tests")
    assert mutate_many(partial, tests, {"status": "available"})
    assert mutate_many(partial, tests, {"status": "error"})
    assert mutate_many(partial, tests, {"status": "unavailable"})
    assert mutate_many(partial, tests, {"gaps": []})
    assert mutate_many(ok, tests, {"status": "error"})
    assert mutate_many(ok, tests, {"summary": None})
    first_item = (*tests, "items", 0)
    assert mutate_many(ok, first_item, {"status": "error"})
    assert mutate_many(ok, first_item, {"status": "unavailable"})
    assert mutate_many(ok, ("overview",), {"available": [], "unavailable": sorted(SECTIONS)})


def test_files_claiming_the_same_host_are_merged_with_a_note(
    kit: Any, write: Callable[..., Path]
) -> None:
    paths = (
        write("one.xml", kit.xccdf_text("Web01")),
        write("two.xml", kit.xccdf_text("web01", "fail")),
        write("three.xml", kit.xccdf_text("other")),
    )
    document = build(ReportInputs(scope=Scope.FLEET, xccdf=paths))
    assert errors(document) == []
    section = document["sections"]["compliance"]
    digests = sorted(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths[:2])
    host = {"hostname": "web01", "input_sha256": None, "machine_id": None}
    assert section["notes"] == [
        {
            "group": {"benchmark_id": kit.BENCHMARK, "content_version": "1.0", "host": host},
            "kind": "merged_inputs",
            "repeated_profile": True,
            "sources": digests,
        }
    ]
    single = build(ReportInputs(scope=Scope.FLEET, xccdf=paths[2:]))
    assert single["sections"]["compliance"]["notes"] == []
    assert mutate_many(document, ("sections", "compliance"), {"status": "partial"})


SHA_PATTERN = "^[0-9a-f]{64}$"
HOST_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._:+-]*$"
MACHINE_PATTERN = "^[0-9a-f]{32}$"
BEHAVIOURAL = "checked by the timestamp agreement test"
MAX_HOST = 253
STRUCTURAL = {0, 1}


def anchored(pattern: re.Pattern[str]) -> str:
    return "^" + pattern.pattern + "$"


def anchored_text(pattern: str) -> str:
    return "^" + pattern + "$"


LIMIT_RULES: list[tuple[str, Any]] = [
    (r"/(then|else)/.*/maxItems$", STRUCTURAL),
    (r"/\$defs/sameHostNote/properties/groups/maxItems$", report.MAX_INPUTS),
    (r"/\$defs/exceptionScope/properties/\w+/maxItems$", exceptions.MAX_SCOPE_ITEMS),
    (r"/properties/findings/maxItems$", model.MAX_FINDINGS),
    (r"/properties/evidence/maxItems$", model.MAX_EVIDENCE_ITEMS),
    (r"/properties/flags/maxItems$", len(model.ResultFlag)),
    (r"/properties/rules/maxItems$", report.MAX_RULES),
    (r"/properties/(groups|aggregates)/maxItems$", report.MAX_GROUPS),
    (r"/properties/(builds|scenarios)/maxItems$", common.MAX_ENTRIES),
    (r"/properties/(items|gaps|sources|notes|matched_hosts)/maxItems$", report.MAX_INPUTS),
    (
        r"/properties/(issues|vulnerabilities|components|packages|failed_cases)/maxItems$",
        common.MAX_DETAIL_ITEMS,
    ),
    (r"/properties/(files|fixed_versions)/maxItems$", common.MAX_SUBENTRIES),
    (r"/properties/raw_artifacts/maxItems$", report.MAX_RAW_ARTIFACTS),
    (r"/properties/overview/properties/\w+/maxItems$", len(report.SECTION_NAMES)),
    (r"/properties/(exceptions|lapsed_waivers)/maxItems$", exceptions.MAX_EXCEPTIONS),
    (r"/properties/custom_data/maxProperties$", common.MAX_SUBENTRIES),
    (r"/\$defs/counts/maxProperties$", common.MAX_ENTRIES),
    (r"/\$defs/(host|inventoryHost)/maxLength$", MAX_HOST),
    (r"/properties/(path|artifact)/maxLength$", common.MAX_PATH_LENGTH),
    (r"/properties/content/maxLength$", model.MAX_EVIDENCE_LENGTH),
    (
        r"/properties/custom_data/(propertyNames|additionalProperties)/maxLength$",
        common.MAX_TEXT_LENGTH,
    ),
    (
        r"/\$defs/exceptionEntry/properties/justification/maxLength$",
        exceptions.MAX_JUSTIFICATION_LENGTH,
    ),
    (r"/\$defs/exceptionId/maxLength$", exceptions.MAX_ID_LENGTH),
    (r"/\$defs/person/maxLength$", exceptions.MAX_PERSON_LENGTH),
    (r"/\$defs/exceptionScope/properties/hosts/items/maxLength$", exceptions.MAX_HOST_LENGTH),
    (r"/\$defs/exceptionScope/properties/groups/items/maxLength$", exceptions.MAX_GROUP_LENGTH),
    (
        r"/\$defs/exceptionScope/properties/benchmark/.*/version/maxLength$",
        exceptions.MAX_VERSION_LENGTH,
    ),
    (
        (
            r"/(\$defs/exceptionScope/properties/(profiles/items|benchmark/.*/id)"
            r"|\$defs/complianceData/properties/lapsed_waivers/items)/maxLength$"
        ),
        model.MAX_ID_LENGTH,
    ),
    (r"/maxLength$", model.MAX_TEXT_LENGTH),
    (r"/\$defs/timestamp/pattern$", BEHAVIOURAL),
    (r"/\$defs/sha256/pattern$", SHA_PATTERN),
    (r"/\$defs/host/pattern$", HOST_PATTERN),
    (r"/\$defs/machineId/pattern$", MACHINE_PATTERN),
    (
        r"/\$defs/(inventoryHost|exceptionScope/properties/hosts/items)/pattern$",
        anchored_text(exceptions.HOST_PATTERN),
    ),
    (
        r"/\$defs/exceptionScope/properties/groups/items/pattern$",
        anchored_text(exceptions.GROUP_PATTERN),
    ),
    (r"/\$defs/exceptionId/pattern$", anchored_text(exceptions.ID_PATTERN)),
    (r"/\$defs/person/pattern$", anchored_text(f"(?:{exceptions.PERSON_PATTERN})")),
    (r"/\$defs/date/pattern$", anchored_text(exceptions.DATE_PATTERN)),
    (
        r"/\$defs/exceptionScope/properties/benchmark/.*/version/pattern$",
        anchored_text(exceptions.TRIMMED_PATTERN),
    ),
    (
        r"/\$defs/exceptionScope/properties/benchmark/.*/id/pattern$",
        anchored_text(model.XCCDF_ID_PATTERNS["benchmark"]),
    ),
    (
        r"/\$defs/exceptionScope/properties/profiles/items/pattern$",
        anchored_text(model.XCCDF_ID_PATTERNS["profile"]),
    ),
    (
        r"/\$defs/complianceData/properties/lapsed_waivers/items/pattern$",
        anchored_text(model.XCCDF_ID_PATTERNS["rule"]),
    ),
    (r"/properties/commit/oneOf/\d+/pattern$", anchored(report.COMMIT_PATTERN)),
    (
        r"/properties/pull_request/oneOf/\d+/pattern$",
        "^" + report.PULL_REQUEST_PATTERN.pattern + "$",
    ),
    (
        r"/properties/workflow_run/oneOf/\d+/pattern$",
        "^" + report.WORKFLOW_RUN_PATTERN.pattern + "$",
    ),
]
LIMIT_KEYWORDS = {"maxItems", "maxProperties", "maxLength", "pattern"}


def schema_limits(node: object, path: str = "") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for key, value in cast("dict[str, object]", node).items():
            if key in LIMIT_KEYWORDS and not common.is_object(value):
                found.append((f"{path}/{key}", value))
            else:
                found.extend(schema_limits(value, f"{path}/{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(cast("list[object]", node)):
            found.extend(schema_limits(value, f"{path}/{index}"))
    return found


def test_every_schema_limit_equals_a_python_constant() -> None:
    limits = schema_limits(SCHEMA)
    assert len(limits) > 100
    used: set[int] = set()
    for path, value in limits:
        matches = [
            (index, expected)
            for index, (rule, expected) in enumerate(LIMIT_RULES)
            if re.search(rule, path)
        ]
        assert matches, f"no mapped constant for {path}"
        index, expected = matches[0]
        used.add(index)
        if isinstance(expected, set):
            assert value in expected, path
        elif expected != BEHAVIOURAL:
            assert value == expected, path
    unused = [LIMIT_RULES[i][0] for i in range(len(LIMIT_RULES)) if i not in used]
    assert unused == []


def test_the_drift_walker_sees_every_copy_of_a_property() -> None:
    paths = [path for path, _ in schema_limits(SCHEMA)]
    assert "/$defs/packerData/properties/builds/maxItems" in paths
    assert "/$defs/scanRun/properties/findings/maxItems" in paths
    assert "/$defs/vulnerabilitiesSection/properties/items/maxItems" in paths
    mutated: Any = copy.deepcopy(SCHEMA)
    mutated["$defs"]["packerData"]["properties"]["builds"]["maxItems"] = 99
    assert ("/$defs/packerData/properties/builds/maxItems", 99) in schema_limits(mutated)


def test_the_schema_timestamp_pattern_agrees_with_the_metadata_validator() -> None:
    pattern = re.compile(SCHEMA["$defs"]["timestamp"]["pattern"])
    candidates = [
        "2026-10-25T10:00:00Z",
        "2026-12-31T23:59:59Z",
        "2026-02-28T00:00:00Z",
        "2024-02-29T12:00:00Z",
        "2026-13-45T99:99:99Z",
        "0000-10-25T10:00:00Z",
        "2026-02-30T10:00:00Z",
        "2026-04-31T10:00:00Z",
        "2026-00-10T10:00:00Z",
        "2026-10-00T10:00:00Z",
        "2026-10-32T10:00:00Z",
        "2026-10-25T24:00:00Z",
        "2026-10-25T10:60:00Z",
        "2026-10-25T10:00:60Z",
        "2026-10-25 10:00:00Z",
        "2026-10-25T10:00:00",
    ]
    for value in candidates:
        try:
            RunMetadata(generated_at=value)
            accepted = True
        except ReportError:
            accepted = False
        if accepted:
            assert pattern.fullmatch(value), value
        if not pattern.fullmatch(value):
            assert not accepted, value
    assert not pattern.fullmatch("2026-13-45T99:99:99Z")
    assert not pattern.fullmatch("2026-02-30T10:00:00Z")
    assert not pattern.fullmatch("0000-01-01T00:00:00Z")


HOSTILE_HOST = "web01.example \u2014 all controls compliant (100%)"


def test_a_hostile_host_name_is_an_input_error_not_prose(
    kit: Any, write: Callable[..., Path]
) -> None:
    for hostile in (HOSTILE_HOST, "web 01", "-web", "::1", "x" * 254):
        document = build(
            ReportInputs(scope=Scope.FLEET, xccdf=(write("h.xml", kit.xccdf_text(hostile)),))
        )
        assert errors(document) == []
        assert document["sections"]["compliance"]["status"] == "error"
        assert HOSTILE_HOST not in json.dumps(document)
    valid = build(
        ReportInputs(scope=Scope.FLEET, xccdf=(write("v.xml", kit.xccdf_text("Web-01.Example")),))
    )
    assert valid["sections"]["compliance"]["groups"][0]["host"]["hostname"] == "web-01.example"


def test_the_schema_rejects_prose_in_host_fields_and_notes(
    kit: Any, write: Callable[..., Path]
) -> None:
    paths = (
        write("one.xml", kit.xccdf_text("web01")),
        write("two.xml", kit.xccdf_text("web01", "fail")),
    )
    document = build(ReportInputs(scope=Scope.FLEET, xccdf=paths))
    assert errors(document) == []
    section = ("sections", "compliance")
    assert mutate_many(
        document, (*section, "notes", 0, "group", "host"), {"hostname": HOSTILE_HOST}
    )
    assert mutate_many(document, (*section, "notes", 0, "group"), {"benchmark_id": 5})
    assert mutate_many(document, (*section, "notes", 0), {"host": HOSTILE_HOST})
    assert mutate_many(document, (*section, "notes", 0), {"kind": "free text"})
    assert mutate_many(document, (*section, "notes", 0), {"kind": "same_host_across_groups"})
    assert mutate_many(document, (*section, "notes", 0), {"repeated_profile": "yes"})
    assert mutate_many(document, (*section, "notes", 0), {"sources": ["a" * 64]})
    assert mutate_many(document, (*section, "notes", 0), {"extra": "x"})
    assert mutate_many(document, (*section, "groups", 0), {"host": HOSTILE_HOST})
    assert mutate_many(document, (*section, "rules", 0), {"host": HOSTILE_HOST})
    assert mutate_many(document, (*section, "items", 0, "data"), {"reported_host": HOSTILE_HOST})


def test_host_and_sha_patterns_agree_with_the_model() -> None:
    hosts = ["web01", "a.b-c_d:e+f", "-web", "web 01", "", "x" * 253, "x" * 254, "::1", "é"]
    for name in hosts:
        try:
            model.HostIdentity(name, "rhel", "9", "x86_64", None)
            accepted = True
        except model.ModelError:
            accepted = False
        matches = re.fullmatch(HOST_PATTERN, name) is not None and len(name) <= MAX_HOST
        assert accepted == matches, name
    for digest in ("a" * 64, "A" * 64, "a" * 63, "g" * 64):
        try:
            model.Provenance("s", "1", digest)
            accepted = True
        except model.ModelError:
            accepted = False
        assert accepted == (re.fullmatch(SHA_PATTERN, digest) is not None), digest


def test_host_patterns_agree_for_machine_ids() -> None:
    for machine in ("a" * 32, "A" * 32, "a" * 31, "g" * 32, ""):
        try:
            model.HostIdentity("web01", "rhel", "9", "x86_64", machine)
            accepted = True
        except model.ModelError:
            accepted = False
        assert accepted == (re.fullmatch(MACHINE_PATTERN, machine) is not None), machine


def machine_run(kit: Any, name: str, machine: str | None, outcome: model.Outcome) -> model.ScanRun:
    host = model.HostIdentity(name, "rhel", "9", "x86_64", machine)
    run: model.ScanRun = kit.scan_run((kit.finding("a", outcome),), host=host)
    return run


def groups_of(document: dict[str, Any]) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = document["sections"]["compliance"]["groups"]
    return groups


def test_xccdf_target_cannot_borrow_a_scan_runs_machine_key(
    kit: Any, write: Callable[..., Path], write_run: Callable[..., Path]
) -> None:
    machine = "a" * 32
    victim = write_run("victim.json", machine_run(kit, "web01", machine, model.Outcome.FAIL))
    attacker = write("attacker.xml", kit.xccdf_text("web01:" + machine, "pass"))
    document = build(ReportInputs(scope=Scope.FLEET, scan_run=(victim,), xccdf=(attacker,)))
    assert errors(document) == []
    keys = [group["host"] for group in groups_of(document)]
    assert {"hostname": "web01", "input_sha256": None, "machine_id": machine} in keys
    assert {"hostname": "web01:" + machine, "input_sha256": None, "machine_id": None} in keys
    with pytest.raises(ReportError, match="2 hosts"):
        report.build_report(
            ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(victim,), xccdf=(attacker,))
        )


def test_scan_run_hostname_cannot_borrow_a_scan_runs_machine_key(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    machine = "a" * 32
    victim = write_run("victim.json", machine_run(kit, "web01", machine, model.Outcome.FAIL))
    spoof = write_run("spoof.json", machine_run(kit, "web01:" + machine, None, model.Outcome.PASS))
    with pytest.raises(ReportError, match="2 hosts"):
        report.build_report(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(victim, spoof)))
    document = build(ReportInputs(scope=Scope.FLEET, scan_run=(victim, spoof)))
    percents = sorted(g["summary"]["compliance_percent"] for g in groups_of(document))
    assert percents == [0.0, 100.0]


def test_a_predictable_unnamed_key_cannot_be_claimed_by_a_name(
    kit: Any, write: Callable[..., Path]
) -> None:
    unnamed = write("unnamed.xml", kit.xccdf_text(None, "fail"))
    digest = hashlib.sha256(unnamed.read_bytes()).hexdigest()
    path_hash = "unnamed:" + hashlib.sha256(str(unnamed).encode()).hexdigest()[:16]
    claimant = write("claimant.xml", kit.xccdf_text(path_hash, "pass"))
    document = build(ReportInputs(scope=Scope.FLEET, xccdf=(unnamed, claimant)))
    keys = [group["host"] for group in groups_of(document)]
    assert {"hostname": None, "input_sha256": digest, "machine_id": None} in keys
    assert {"hostname": path_hash, "input_sha256": None, "machine_id": None} in keys
    assert document["sections"]["compliance"]["notes"] == []


def test_two_unnamed_inputs_stay_separate(kit: Any, write: Callable[..., Path]) -> None:
    first = write("one.xml", kit.xccdf_text(None, "pass"))
    second = write("two.xml", kit.xccdf_text(None, "fail"))
    document = build(ReportInputs(scope=Scope.FLEET, xccdf=(first, second)))
    assert errors(document) == []
    groups = groups_of(document)
    assert len({group["host"]["input_sha256"] for group in groups}) == 2
    assert all(group["host"]["hostname"] is None for group in groups)
    assert document["sections"]["compliance"]["notes"] == []
    with pytest.raises(ReportError, match="2 hosts"):
        report.build_report(ReportInputs(scope=Scope.SINGLE_HOST, xccdf=(first, second)))


def test_host_case_does_not_split_or_merge_groups_inconsistently(
    kit: Any, write: Callable[..., Path], write_run: Callable[..., Path]
) -> None:
    scan = write_run("scan.json", machine_run(kit, "WEB01", None, model.Outcome.PASS))
    xccdf = write("x.xml", kit.xccdf_text("Web01", "fail"))
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(scan,), xccdf=(xccdf,)))
    assert errors(document) == []
    assert [group["host"]["hostname"] for group in groups_of(document)] == ["web01"]
    notes = document["sections"]["compliance"]["notes"]
    assert [
        (note["kind"], note["group"]["host"]["hostname"], len(note["sources"])) for note in notes
    ] == [("merged_inputs", "web01", 2)]


def test_the_schema_rejects_mixed_host_key_shapes(kit: Any, write: Callable[..., Path]) -> None:
    document = build(
        ReportInputs(scope=Scope.FLEET, xccdf=(write("x.xml", kit.xccdf_text("web01")),))
    )
    group = ("sections", "compliance", "groups", 0, "host")
    assert mutate_many(document, group, {"input_sha256": "a" * 64})
    assert mutate_many(document, group, {"hostname": None})
    assert mutate_many(document, group, {"machine_id": "short"})
    assert mutate_many(document, group, {"extra": 1})
    assert mutate_many(
        document, ("sections", "compliance", "rules", 0, "host"), {"hostname": "a b"}
    )
