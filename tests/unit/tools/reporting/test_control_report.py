"""Control placements in the report, schema 2.3 (ADR 0016 amendment of FREES-170)."""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    placement,
)
from tools.reporting import dashboard, report
from tools.reporting.common import dumps
from tools.reporting.report import ReportInputs, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA = json.loads(
    (Path(report.__file__).parent / "schema" / "report-v2.json").read_text(encoding="utf-8")
)
VALIDATOR: Any = Draft202012Validator(SCHEMA)
SSH = placement.ControlPlacement(
    family="ssh",
    topic="ssh",
    tags=("auditd",),
    stig_id="UBTU-24-100010",
    mapped_rules=("xccdf_org.ssgproject.content_rule_sshd_banner",),
    partially_disabled_by=("linux_compliance_auditd_enabled",),
)
UNMAPPED = placement.ControlPlacement(
    placement.UNMAPPED_FAMILY, placement.UNMAPPED_FAMILY, (), None, (), ()
)


def build(**inputs: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(report.build_report(ReportInputs(**inputs))))
    assert VALIDATOR.is_valid(document), [e.message[:200] for e in VALIDATOR.iter_errors(document)]
    return document


def placed_run(kit: Any) -> Any:
    run = kit.scan_run((kit.finding("a"), kit.finding("b", model.Outcome.FAIL), kit.finding("c")))
    first, second, third = run.findings
    return dataclasses.replace(
        run,
        findings=(
            dataclasses.replace(first, control=SSH),
            dataclasses.replace(second, control=UNMAPPED),
            third,
        ),
    )


def test_rules_carry_the_placement_of_their_findings(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    document = build(scope=Scope.SINGLE_HOST, scan_run=(write_run("run.json", placed_run(kit)),))
    assert document["schema_version"] == "2.3"
    rules = {rule["rule_id"]: rule for rule in document["sections"]["compliance"]["rules"]}
    controls = [rule["control"] for rule in rules.values()]
    assert SSH.to_dict() in controls
    assert UNMAPPED.to_dict() in controls
    assert None in controls
    item = document["sections"]["compliance"]["items"][0]
    assert item["data"]["scan_run"]["schema_version"] == "1.2"


def test_the_first_placed_source_by_artifact_places_a_rule(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    plain = write_run("a-plain.json", kit.scan_run((kit.finding("a"),)))
    placed = write_run("b-placed.json", placed_run(kit))
    document = build(scope=Scope.SINGLE_HOST, scan_run=(plain, placed), allow_repeated_scans=True)
    rules = document["sections"]["compliance"]["rules"]
    merged = [rule for rule in rules if len(rule["sources"]) == 2]
    assert len(merged) == 1
    assert merged[0]["control"] == SSH.to_dict()


def test_the_schema_requires_a_placement_key_on_every_rule_of_a_2_3_report(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    document = build(scope=Scope.SINGLE_HOST, scan_run=(write_run("run.json", placed_run(kit)),))
    forged = copy.deepcopy(document)
    del forged["sections"]["compliance"]["rules"][0]["control"]
    assert not VALIDATOR.is_valid(forged)
    older = copy.deepcopy(document)
    older["schema_version"] = "2.2"
    errors = [error.message for error in VALIDATOR.iter_errors(older)]
    assert any("'control'" in message for message in errors), errors


def test_the_schema_checks_the_findings_of_a_one_two_scan_run(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    document = build(scope=Scope.SINGLE_HOST, scan_run=(write_run("run.json", placed_run(kit)),))
    without = copy.deepcopy(document)
    del without["sections"]["compliance"]["items"][0]["data"]["scan_run"]["findings"][0]["control"]
    assert not VALIDATOR.is_valid(without)
    unplaced = copy.deepcopy(document)
    for finding in unplaced["sections"]["compliance"]["items"][0]["data"]["scan_run"]["findings"]:
        finding["control"] = None
    assert not VALIDATOR.is_valid(unplaced)
    older = copy.deepcopy(document)
    older["sections"]["compliance"]["items"][0]["data"]["scan_run"]["schema_version"] = "1.0"
    assert not VALIDATOR.is_valid(older)


def test_the_dashboard_reads_a_2_3_report(kit: Any, write_run: Callable[..., Path]) -> None:
    document = build(scope=Scope.SINGLE_HOST, scan_run=(write_run("run.json", placed_run(kit)),))
    html = dashboard.render_dashboard(document)
    assert html.startswith("<!DOCTYPE html>")
    assert "UBTU-24-100010" in html
