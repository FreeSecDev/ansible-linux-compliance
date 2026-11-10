"""Report schema 2.3 refuses findings model schema 1.3 (FREES-203, ADR 0032).

A scan run with an operator deviation must never count as a pass. Until the report
reads the flag (report schema 2.4), such a run is an input error on every path that
feeds the compliance section: a ScanRun JSON file, an exceptions evaluation and an
evidence bundle. Raw XCCDF and ARF results next to such a run carry no flag at all,
so they are refused too.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tests.unit.tools.reporting.test_bundle import write_bundle
from tools.reporting import report
from tools.reporting.common import InvalidInputError, SectionStatus, dumps
from tools.reporting.compliance import UNREADABLE_FINDINGS_VERSIONS, check_findings_version
from tools.reporting.parsers import evaluation as evaluation_parser
from tools.reporting.parsers import scanrun, xccdf
from tools.reporting.report import ReportInputs, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA_PATH = Path(report.__file__).parent / "schema" / "report-v2.json"
SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR: Any = Draft202012Validator(SCHEMA)
DEVIATION = model.Deviation("var_password_pam_minlen", "14", "12")
REASON = "findings schema 1.3 (operator deviations) is not supported"
RAW_REASON = "raw results of a scan run of findings schema 1.3 (operator deviations)"


def flagged(item: model.Finding) -> model.Finding:
    return replace(item, flags=(model.ResultFlag.OPERATOR_DEVIATION,), deviation=DEVIATION)


def valued(item: model.Finding) -> model.Finding:
    result = model.RemediationResult(
        item.rule_id,
        model.RemediationStatus.APPLIED,
        changed=True,
        message=None,
        value_source=model.ValueSource.PROFILE,
        profile_value="14",
        effective_value="14",
    )
    return replace(item, remediation=result)


@pytest.mark.parametrize("change", [flagged, valued], ids=["deviation", "value-fields"])
def test_a_scan_run_of_schema_one_three_is_an_input_error(
    kit: Any, write_run: Callable[..., Path], change: Callable[[model.Finding], model.Finding]
) -> None:
    run = kit.scan_run((change(kit.finding("a")), kit.finding("b", model.Outcome.FAIL)))
    assert run.schema_version in UNREADABLE_FINDINGS_VERSIONS
    result = scanrun.parse_scan_run(write_run("run.json", run))
    assert result.status is SectionStatus.ERROR
    assert result.data is None
    assert REASON in (result.reason or "")


def test_the_report_counts_no_pass_of_a_deviated_run(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    run = kit.scan_run((flagged(kit.finding("a")),))
    inputs = ReportInputs(scope=Scope.FLEET, scan_run=(write_run("run.json", run),))
    document: dict[str, Any] = json.loads(dumps(report.build_report(inputs)))
    assert VALIDATOR.is_valid(document)
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "error"
    assert compliance["summary"] is None
    assert compliance["rules"] == []
    assert [item["data"] for item in compliance["items"]] == [None]
    assert REASON in compliance["gaps"][0]["reason"]


def test_an_evaluation_of_a_deviated_run_is_an_input_error(
    kit: Any, write: Callable[..., Path]
) -> None:
    base = kit.evaluation_run()
    run = replace(
        base,
        findings=tuple(
            flagged(item) if item.outcome is model.Outcome.PASS else item for item in base.findings
        ),
    )
    evaluation = kit.evaluate(run)
    assert evaluation.run.schema_version == model.DEVIATION_SCHEMA_VERSION
    with pytest.raises(InvalidInputError, match=r"findings schema 1\.3"):
        evaluation_parser.evaluation_data(b"{}", evaluation)
    path = write("evaluation.json", kit.evaluation_json(evaluation))
    inputs = ReportInputs(
        scope=Scope.FLEET, exceptions_evaluation=(path,), exceptions_file=kit.EXCEPTIONS_FILE
    )
    document: dict[str, Any] = json.loads(dumps(report.build_report(inputs)))
    assert VALIDATOR.is_valid(document)
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "error"
    assert compliance["summary"] is None
    assert REASON in compliance["gaps"][0]["reason"]


def test_runs_of_earlier_schema_versions_are_read(kit: Any) -> None:
    check_findings_version(kit.scan_run((kit.finding("a"),)))
    assert frozenset({model.DEVIATION_SCHEMA_VERSION}) == UNREADABLE_FINDINGS_VERSIONS


def flag_passes(run: model.ScanRun) -> model.ScanRun:
    return replace(
        run,
        findings=tuple(
            flagged(item) if item.outcome is model.Outcome.PASS else item for item in run.findings
        ),
    )


def deviated_kit(kit: Any) -> Any:
    def evaluation_run(*args: Any, **kwargs: Any) -> model.ScanRun:
        return flag_passes(kit.evaluation_run(*args, **kwargs))

    return type("DeviatedKit", (kit,), {"evaluation_run": staticmethod(evaluation_run)})


def build(inputs: ReportInputs) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(report.build_report(inputs)))
    assert VALIDATOR.is_valid(document)
    return document


@pytest.mark.parametrize("applied", [False, True], ids=["scan-run", "evaluation"])
def test_an_evidence_bundle_of_a_deviated_run_is_an_input_error(
    kit: Any, tmp_path: Path, *, applied: bool
) -> None:
    target = write_bundle(deviated_kit(kit), tmp_path, applied=applied)
    supplied = kit.EXCEPTIONS_FILE if applied else None
    inputs = ReportInputs(
        scope=Scope.SINGLE_HOST, evidence_bundle=(target,), exceptions_file=supplied
    )
    document = build(inputs)
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "error"
    assert compliance["summary"] is None
    assert compliance["rules"] == []
    assert [item["data"] for item in compliance["items"]] == [None]
    assert REASON in compliance["gaps"][0]["reason"]


def raw_inputs(kit: Any, directory: Path) -> tuple[Path, Path]:
    results = directory / "results.xml"
    results.write_text(kit.xccdf_text("host.example"), encoding="utf-8")
    arf = directory / "results-arf.xml"
    arf.write_bytes((kit.REPORTING / "arf.xml").read_bytes())
    return results, arf


@pytest.mark.parametrize("change", [flagged, valued], ids=["deviation", "value-fields"])
@pytest.mark.parametrize("depth", [0, 1], ids=["same-directory", "directory-above"])
def test_raw_results_next_to_a_run_of_schema_one_three_are_refused(
    kit: Any, tmp_path: Path, change: Callable[[model.Finding], model.Finding], depth: int
) -> None:
    run = kit.scan_run((change(kit.finding("a")),))
    (tmp_path / "scan-run.json").write_text(model.dumps(run), encoding="utf-8")
    directory = tmp_path / "scan" if depth else tmp_path
    directory.mkdir(exist_ok=True)
    results, arf = raw_inputs(kit, directory)
    for parsed in (xccdf.parse_xccdf(results), xccdf.parse_arf(arf)):
        assert parsed.status is SectionStatus.ERROR
        assert parsed.data is None
        assert RAW_REASON in (parsed.reason or "")
    document = build(ReportInputs(scope=Scope.MULTI_HOST, xccdf=(results,), arf=(arf,)))
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "error"
    assert compliance["summary"] is None
    assert compliance["rules"] == []
    reasons = [item["reason"] for item in compliance["items"]]
    assert len(reasons) == 2
    assert all(RAW_REASON in (reason or "") for reason in reasons)


def test_raw_results_without_a_deviated_neighbour_are_read(kit: Any, tmp_path: Path) -> None:
    (tmp_path / "scan-run.json").write_text(
        model.dumps(kit.scan_run((kit.finding("a"),))), encoding="utf-8"
    )
    (tmp_path / "scan").mkdir()
    for directory in (tmp_path, tmp_path / "scan"):
        results, arf = raw_inputs(kit, directory)
        for parsed in (xccdf.parse_xccdf(results), xccdf.parse_arf(arf)):
            assert parsed.status is SectionStatus.AVAILABLE
            assert parsed.data is not None
