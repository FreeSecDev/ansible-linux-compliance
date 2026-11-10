"""Report schema 2.3 refuses findings model schema 1.3 (FREES-203, ADR 0032).

A scan run with an operator deviation must never count as a pass. Until the report
reads the flag (report schema 2.4), such a run is an input error on every path that
feeds the compliance section: a ScanRun JSON file and an exceptions evaluation.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import report
from tools.reporting.common import InvalidInputError, SectionStatus, dumps
from tools.reporting.compliance import UNREADABLE_FINDINGS_VERSIONS, check_findings_version
from tools.reporting.parsers import evaluation as evaluation_parser
from tools.reporting.parsers import scanrun
from tools.reporting.report import ReportInputs, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA_PATH = Path(report.__file__).parent / "schema" / "report-v2.json"
SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR: Any = Draft202012Validator(SCHEMA)
DEVIATION = model.Deviation("var_password_pam_minlen", "14", "12")
REASON = "findings schema 1.3 (operator deviations) is not supported"


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
