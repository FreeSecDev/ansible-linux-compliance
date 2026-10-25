from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import report
from tools.reporting.common import dumps
from tools.reporting.report import ReportError, ReportInputs, RunMetadata, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA_PATH = Path(report.__file__).parent / "schema" / "report-v1.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SECTIONS = set(report.SECTION_NAMES)
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def build(inputs: ReportInputs) -> Any:
    return json.loads(dumps(report.build_report(inputs)))


def errors(document: Any) -> list[str]:
    try:
        validate(document, SCHEMA, cls=Draft202012Validator)
    except ValidationError as error:
        return [error.message]
    return []


def full_inputs(kit: Any, **changes: Any) -> ReportInputs:
    fixtures = kit.REPORTING
    base: dict[str, Any] = {
        "scope": Scope.SINGLE_HOST,
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
    }
    base.update(changes)
    return ReportInputs(**base)


def test_the_schema_is_a_valid_2020_12_schema() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_full_report_validates_against_the_schema(kit: Any) -> None:
    document = build(full_inputs(kit))
    assert errors(document) == []
    assert document["schema_version"] == "1.0"
    assert document["overview"] == {
        "available": sorted(SECTIONS),
        "error": [],
        "unavailable": [],
    }
    assert not report.has_error(document)


def test_empty_report_marks_every_section_unavailable_never_pass() -> None:
    document = build(ReportInputs(scope=Scope.FLEET))
    assert errors(document) == []
    assert document["overview"] == {
        "available": [],
        "error": [],
        "unavailable": sorted(SECTIONS),
    }
    sections: dict[str, Any] = document["sections"]
    for section in sections.values():
        assert section["status"] == "unavailable"
        assert section["reason"] == "no input was supplied"
        assert section["items"] == []
        assert section["summary"] is None
    assert sections["compliance"]["rules"] == []
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
    assert len(references) == 13
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
        "unavailable": sorted(SECTIONS - {"lint", "tests", "coverage"} | {"coverage"}),
    }
    assert report.has_error(document)
    sections: dict[str, Any] = document["sections"]
    assert sections["tests"]["summary"] is None
    assert sections["tests"]["items"][0]["data"] is None
    assert sections["coverage"]["items"][0]["status"] == "unavailable"
    assert sections["coverage"]["reason"] == "1 of 1 input(s) are unavailable or invalid"


def test_one_bad_input_makes_the_section_non_available_but_keeps_the_good_item(
    kit: Any, tmp_path: Path
) -> None:
    inputs = ReportInputs(
        scope=Scope.BENCHMARK,
        junit=(kit.REPORTING / "junit.xml", tmp_path / "absent.xml"),
    )
    document = build(inputs)
    assert errors(document) == []
    section: dict[str, Any] = document["sections"]["tests"]
    assert section["status"] == "unavailable"
    assert section["summary"] is None
    assert section["items"][0]["status"] == "available"
    assert section["items"][0]["data"]["total"] == 5


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
    for name in ("coverage", "sbom", "packer", "codebuild"):
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
    summary = section["summary"]
    assert summary["run_status"] == "completed"
    assert summary["counts"] == {
        "pass": 0,
        "fail": 3,
        "notapplicable": 1,
        "notchecked": 1,
        "error": 1,
        "waived": 1,
        "disabled": 0,
    }
    assert summary["evaluated"] == 6
    assert summary["compliance_percent"] == 0.0
    assert summary["expired_waivers"] == 1
    assert summary["assessment"] == "findings_open"
    rules = {rule["rule_id"].rsplit("_", 1)[-1]: rule for rule in section["rules"]}
    assert len(section["rules"]) == 7
    assert rules["a"]["outcome"] == "fail"
    assert len(rules["a"]["sources"]) == 2
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
    summary: dict[str, Any] = document["sections"]["compliance"]["summary"]
    assert summary["run_status"] == "not_completed"
    assert summary["assessment"] == "run_not_completed"
    assert summary["compliance_percent"] is None
    assert (summary["runs_total"], summary["runs_not_completed"]) == (2, 1)


def test_xccdf_results_have_no_host_and_validate(kit: Any) -> None:
    document = build(ReportInputs(scope=Scope.BENCHMARK, xccdf=(kit.XCCDF / "mixed-results.xml",)))
    assert errors(document) == []
    item = document["sections"]["compliance"]["items"][0]
    assert item["data"]["host"] is None
    assert item["data"]["scan_run"] is None
    assert len(item["data"]["findings"]) == 9


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
    ((), "schema_version", "2.0"),
    ((), "scope", "global"),
    ((), "extra", 1),
    ((), "sections", DELETE),
    (("sections",), "tests", DELETE),
    (("sections", "tests"), "status", "pass"),
    (("sections", "tests"), "reason", "stale"),
    (("sections", "tests"), "items", []),
    (("sections", "tests"), "summary", None),
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
