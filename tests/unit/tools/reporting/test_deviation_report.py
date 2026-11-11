"""Operator deviations in the report, schema 2.4 (ADR 0016 amendment of FREES-203, ADR 0032).

A finding flagged ``operator_deviation`` ran under a value looser than the profile. It is
never counted as a pass: a flagged pass leaves ``counts`` but stays in ``evaluated``, a
flagged fail or waived finding stays in its count, and every flagged rule is counted in
``deviation`` and ``deviation_by_outcome``. Raw XCCDF and ARF results next to a scan run of
findings schema 1.3 carry no flag and stay refused.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tests.unit.tools.reporting.test_bundle import write_bundle
from tools.reporting import checklist_export, cli, compliance, dashboard, report
from tools.reporting.checklist import ChecklistError
from tools.reporting.common import SectionStatus, dumps
from tools.reporting.compliance import Tally, summarize
from tools.reporting.dashboard import DashboardError
from tools.reporting.parsers import scanrun, xccdf
from tools.reporting.report import ReportInputs, RunMetadata, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA_PATH = Path(report.__file__).parent / "schema" / "report-v2.json"
SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR: Any = Draft202012Validator(SCHEMA)
REPOSITORY = Path(__file__).resolve().parents[4]
FIXTURE = REPOSITORY / "tests" / "fixtures" / "reporting" / "scan-run-deviation.json"
RAW_REASON = "raw results of a scan run of findings schema 1.3 (operator deviations)"
OC = model.Outcome
SEVERITY = model.Severity.MEDIUM
LOOSER = model.Deviation("var_password_pam_minlen", "14", "8")
OTHER = model.Deviation("var_accounts_tmout", "900", "1800")
ZERO = {outcome.value: 0 for outcome in model.Outcome}
COMMIT = "0123456789abcdef0123456789abcdef01234567"
MAIN_2_3_DIGEST = "ef9586f64d7e754f02f97b12bca7a7ecff6b91c3aaebafa1b8d28fcb28fca267"


def build(inputs: ReportInputs) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(report.build_report(inputs)))
    assert VALIDATOR.is_valid(document), [e.message[:200] for e in VALIDATOR.iter_errors(document)]
    return document


def invalid(document: dict[str, Any]) -> bool:
    return not VALIDATOR.is_valid(document)


def tally(outcome: model.Outcome, *, deviation: bool = False) -> Tally:
    return Tally(outcome, SEVERITY, expired_waiver=False, deviation=deviation)


def counts(**values: int) -> dict[str, int]:
    return {**ZERO, **values}


def flag_outcomes(run: model.ScanRun, outcomes: frozenset[model.Outcome]) -> model.ScanRun:
    return dataclasses.replace(
        run,
        findings=tuple(_flag(item) if item.outcome in outcomes else item for item in run.findings),
    )


def _flag(item: model.Finding) -> model.Finding:
    return dataclasses.replace(
        item, flags=(*item.flags, model.ResultFlag.OPERATOR_DEVIATION), deviation=LOOSER
    )


def deviated_run(kit: Any) -> model.ScanRun:
    run: model.ScanRun = kit.scan_run(
        (
            kit.flagged(kit.finding("a")),
            kit.flagged(kit.finding("b", OC.FAIL), OTHER),
            kit.finding("c"),
            kit.finding("d", OC.NOTAPPLICABLE),
        )
    )
    return run


@pytest.mark.parametrize(
    ("tallies", "expected", "deviated", "figure"),
    [
        (
            [tally(OC.PASS, deviation=True), tally(OC.PASS)],
            counts(**{"pass": 1}),
            counts(**{"pass": 1}),
            (2, 50.0, compliance.ASSESSMENT_FINDINGS_OPEN),
        ),
        (
            [tally(OC.PASS, deviation=True)],
            counts(),
            counts(**{"pass": 1}),
            (1, 0.0, compliance.ASSESSMENT_FINDINGS_OPEN),
        ),
        (
            [tally(OC.FAIL, deviation=True), tally(OC.PASS)],
            counts(**{"pass": 1, "fail": 1}),
            counts(fail=1),
            (2, 50.0, compliance.ASSESSMENT_FINDINGS_OPEN),
        ),
        (
            [tally(OC.WAIVED, deviation=True), tally(OC.NOTAPPLICABLE)],
            counts(waived=1, notapplicable=1),
            counts(waived=1),
            (1, 0.0, compliance.ASSESSMENT_FINDINGS_OPEN),
        ),
        (
            [tally(OC.ERROR, deviation=True), tally(OC.PASS)],
            counts(**{"pass": 1, "error": 1}),
            counts(error=1),
            (2, 50.0, compliance.ASSESSMENT_FINDINGS_OPEN),
        ),
        (
            [tally(OC.PASS), tally(OC.PASS)],
            counts(**{"pass": 2}),
            counts(),
            (2, 100.0, compliance.ASSESSMENT_ALL_PASSED),
        ),
    ],
    ids=[
        "pass-and-flagged-pass",
        "only-flagged",
        "flagged-fail",
        "flagged-waived",
        "merged-error",
        "none",
    ],
)
def test_a_flagged_pass_is_never_counted_as_a_pass(
    tallies: list[Tally],
    expected: dict[str, int],
    deviated: dict[str, int],
    figure: tuple[int, float, str],
) -> None:
    summary = summarize(tallies, compliance.COMPLETED, 1, 0)
    assert summary.counts == expected
    assert summary.deviation_by_outcome == deviated
    assert summary.deviation == sum(deviated.values())
    assert (summary.evaluated, summary.compliance_percent, summary.assessment) == figure
    assert sum(summary.counts.values()) + deviated["pass"] == len(tallies)


def test_a_run_that_did_not_complete_still_counts_its_deviations() -> None:
    summary = summarize([tally(OC.PASS, deviation=True)], "failed", 1, 1)
    assert summary.assessment == compliance.ASSESSMENT_RUN_NOT_COMPLETED
    assert summary.compliance_percent is None
    assert summary.deviation == 1


def test_tallies_carry_the_flag_of_their_findings(kit: Any) -> None:
    run = deviated_run(kit)
    flags = [item.deviation for item in compliance.tally_findings(run.findings)]
    assert flags == [True, True, False, False]


def entry(artifact: str, run: model.ScanRun) -> compliance.Entry:
    return artifact, scanrun.scan_run_data(model.dumps(run).encode("utf-8"))


def test_a_rule_merged_from_several_scans_is_flagged_when_any_of_them_is(kit: Any) -> None:
    plain = kit.scan_run((kit.finding("a", OC.FAIL), kit.finding("b"), kit.finding("c")))
    marked = kit.scan_run(
        (
            kit.flagged(kit.finding("a")),
            kit.flagged(kit.finding("b"), OTHER),
            kit.flagged(kit.finding("c")),
        )
    )
    other = kit.scan_run((kit.flagged(kit.finding("b")), kit.finding("c", OC.ERROR)))
    rules = {
        rule.rule_id.removeprefix(kit.RULE_PREFIX): rule
        for rule in compliance.rollup(
            [entry("a-plain.json", plain), entry("b-marked.json", marked), entry("c.json", other)]
        )
    }
    assert (rules["a"].outcome, rules["a"].deviation) == (OC.FAIL, LOOSER)
    assert [source.deviation for source in rules["a"].sources] == [None, LOOSER]
    assert rules["b"].deviation == OTHER
    assert (rules["c"].outcome, rules["c"].deviation) == (OC.ERROR, LOOSER)
    summary = compliance.figure(
        [entry("a-plain.json", plain), entry("b-marked.json", marked), entry("c.json", other)]
    )
    assert summary.deviation_by_outcome == counts(**{"pass": 1, "fail": 1, "error": 1})
    assert summary.counts == counts(fail=1, error=1)
    assert summary.evaluated == 3
    assert summary.compliance_percent == 0.0


def run_path(write_run: Callable[..., Path], run: model.ScanRun, name: str = "run.json") -> Path:
    return write_run(name, run)


def test_a_scan_run_of_schema_one_three_is_figured_with_its_deviations(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    run = deviated_run(kit)
    assert run.schema_version == model.DEVIATION_SCHEMA_VERSION
    path = run_path(write_run, run)
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(path,)))
    assert document["schema_version"] == "2.4"
    section = document["sections"]["compliance"]
    assert section["status"] == "available"
    summary = section["summary"]
    assert summary["counts"] == counts(**{"pass": 1, "fail": 1, "notapplicable": 1})
    assert summary["deviation_by_outcome"] == counts(**{"pass": 1, "fail": 1})
    assert summary["deviation"] == 2
    assert summary["evaluated"] == 3
    assert summary["compliance_percent"] == 33.3
    assert summary["assessment"] == "findings_open"
    assert section["groups"][0]["summary"] == summary
    assert section["items"][0]["data"]["summary"] == summary
    assert section["items"][0]["data"]["scan_run"]["schema_version"] == "1.3"
    rules = {rule["rule_id"]: rule for rule in section["rules"]}
    first = rules[kit.RULE_PREFIX + "a"]
    assert first["outcome"] == "pass"
    assert first["deviation"] == LOOSER.to_dict()
    assert [source["deviation"] for source in first["sources"]] == [LOOSER.to_dict()]
    assert rules[kit.RULE_PREFIX + "c"]["deviation"] is None
    host = {"hostname": "host.example", "input_sha256": None, "machine_id": None}
    assert section["deviations"] == [
        {
            "artifact": str(path),
            "benchmark_id": kit.BENCHMARK,
            "content_version": "1.0",
            "effective_value": "8",
            "host": host,
            "off_platform": False,
            "outcome": "pass",
            "profile_id": kit.PROFILE,
            "profile_value": "14",
            "rule_id": kit.RULE_PREFIX + "a",
            "value_id": "var_password_pam_minlen",
        },
        {
            "artifact": str(path),
            "benchmark_id": kit.BENCHMARK,
            "content_version": "1.0",
            "effective_value": "1800",
            "host": host,
            "off_platform": False,
            "outcome": "fail",
            "profile_id": kit.PROFILE,
            "profile_value": "900",
            "rule_id": kit.RULE_PREFIX + "b",
            "value_id": "var_accounts_tmout",
        },
    ]
    assert document["overview"]["deviation"] == 2


def test_the_committed_one_three_fixture_reads_and_dumps_byte_identically() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    run = model.loads(text)
    assert run.schema_version == model.DEVIATION_SCHEMA_VERSION
    assert model.dumps(run) + "\n" == text
    remediated = [item.remediation for item in run.findings if item.remediation is not None]
    assert {result.status for result in remediated} == {
        model.RemediationStatus.DEVIATION,
        model.RemediationStatus.APPLIED,
    }
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(FIXTURE,)))
    section = document["sections"]["compliance"]
    assert section["summary"]["deviation_by_outcome"] == counts(**{"pass": 1, "waived": 1})
    assert section["summary"]["counts"] == counts(**{"pass": 1, "waived": 1, "fail": 1})
    assert [item["outcome"] for item in section["deviations"]] == ["pass", "waived"]
    assert document["overview"]["deviation"] == 2


def test_a_waived_finding_keeps_its_flag_through_an_exceptions_evaluation(
    kit: Any, write: Callable[..., Path]
) -> None:
    run = flag_outcomes(kit.evaluation_run(), frozenset({OC.PASS, OC.FAIL}))
    evaluation = kit.evaluate(run)
    assert evaluation.run.schema_version == model.DEVIATION_SCHEMA_VERSION
    path = write("evaluation.json", kit.evaluation_json(evaluation))
    inputs = ReportInputs(
        scope=Scope.FLEET, exceptions_evaluation=(path,), exceptions_file=kit.EXCEPTIONS_FILE
    )
    document = build(inputs)
    section = document["sections"]["compliance"]
    assert section["status"] == "available"
    outcomes = sorted(item["outcome"] for item in section["deviations"])
    assert outcomes == ["fail", "fail", "fail", "pass", "waived"]
    summary = section["summary"]
    assert summary["deviation_by_outcome"] == counts(**{"pass": 1, "fail": 3, "waived": 1})
    assert summary["counts"]["pass"] == 0
    assert summary["counts"]["waived"] == 1
    assert summary["compliance_percent"] == 0.0


def deviated_kit(kit: Any) -> Any:
    def evaluation_run(*args: Any, **kwargs: Any) -> model.ScanRun:
        return flag_outcomes(kit.evaluation_run(*args, **kwargs), frozenset({OC.PASS}))

    return type("DeviatedKit", (kit,), {"evaluation_run": staticmethod(evaluation_run)})


@pytest.mark.parametrize("applied", [False, True], ids=["scan-run", "evaluation"])
def test_an_evidence_bundle_of_a_deviated_run_is_figured(
    kit: Any, tmp_path: Path, *, applied: bool
) -> None:
    target = write_bundle(deviated_kit(kit), tmp_path, applied=applied)
    supplied = kit.EXCEPTIONS_FILE if applied else None
    inputs = ReportInputs(
        scope=Scope.SINGLE_HOST, evidence_bundle=(target,), exceptions_file=supplied
    )
    section = build(inputs)["sections"]["compliance"]
    assert section["status"] == "available"
    assert section["summary"]["counts"]["pass"] == 0
    assert section["summary"]["deviation_by_outcome"]["pass"] == 1
    assert [item["outcome"] for item in section["deviations"]] == ["pass"]


def test_deviations_are_listed_whatever_the_section_status(
    kit: Any, write_run: Callable[..., Path], tmp_path: Path
) -> None:
    path = run_path(write_run, deviated_run(kit))
    inputs = ReportInputs(scope=Scope.FLEET, scan_run=(path, tmp_path / "absent.json"))
    document = build(inputs)
    section = document["sections"]["compliance"]
    assert section["status"] == "partial"
    assert section["summary"] is None
    assert section["rules"] == []
    assert len(section["deviations"]) == 2
    assert document["overview"]["deviation"] == 2


def test_an_off_platform_run_lists_its_deviations_but_is_never_figured(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    target = model.HostIdentity("lab2604", "ubuntu", "26.04", "x86_64", "f" * 32)
    marker = model.OffPlatform(model.Platform("ubuntu", "24.04"), model.Platform("ubuntu", "26.04"))
    run = dataclasses.replace(
        kit.scan_run((kit.flagged(kit.finding("a")),), host=target), off_platform=marker
    )
    document = build(ReportInputs(scope=Scope.FLEET, scan_run=(write_run("off.json", run),)))
    section = document["sections"]["compliance"]
    assert section["rules"] == []
    assert section["summary"] is None
    assert [item["off_platform"] for item in section["deviations"]] == [True]
    assert section["off_platform"][0]["counts"] == ZERO
    assert section["items"][0]["data"]["summary"]["deviation_by_outcome"]["pass"] == 1


def test_more_deviations_than_rules_a_report_can_hold_are_refused(
    kit: Any, write_run: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report, "MAX_RULES", 1)
    path = run_path(write_run, deviated_run(kit))
    with pytest.raises(report.ReportError, match="size limits"):
        report.build_report(ReportInputs(scope=Scope.FLEET, scan_run=(path,)))


def raw_inputs(kit: Any, directory: Path) -> tuple[Path, Path]:
    results = directory / "results.xml"
    results.write_text(kit.xccdf_text("host.example"), encoding="utf-8")
    arf = directory / "results-arf.xml"
    arf.write_bytes((kit.REPORTING / "arf.xml").read_bytes())
    return results, arf


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
    return dataclasses.replace(item, remediation=result)


@pytest.mark.parametrize("change", [_flag, valued], ids=["deviation", "value-fields"])
@pytest.mark.parametrize("depth", [0, 1], ids=["same-directory", "directory-above"])
def test_raw_results_next_to_a_run_of_schema_one_three_stay_refused(
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
    section = document["sections"]["compliance"]
    assert section["status"] == "error"
    assert section["summary"] is None
    assert section["deviations"] == []


def test_raw_results_without_a_deviated_neighbour_are_read(kit: Any, tmp_path: Path) -> None:
    (tmp_path / "scan-run.json").write_text(
        model.dumps(kit.scan_run((kit.finding("a"),))), encoding="utf-8"
    )
    (tmp_path / "scan").mkdir()
    for directory in (tmp_path, tmp_path / "scan"):
        results, arf = raw_inputs(kit, directory)
        for parsed in (xccdf.parse_xccdf(results), xccdf.parse_arf(arf)):
            assert parsed.status is SectionStatus.AVAILABLE


@pytest.fixture
def deviated_document(kit: Any, write_run: Callable[..., Path]) -> dict[str, Any]:
    run = dataclasses.replace(
        deviated_run(kit),
        findings=(*deviated_run(kit).findings, valued(kit.finding("e"))),
    )
    return build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(run_path(write_run, run),)))


def _rule(document: dict[str, Any], kit: Any, name: str) -> dict[str, Any]:
    rules = document["sections"]["compliance"]["rules"]
    return next(rule for rule in rules if rule["rule_id"] == kit.RULE_PREFIX + name)


def _findings(document: dict[str, Any]) -> list[dict[str, Any]]:
    item = document["sections"]["compliance"]["items"][0]
    findings: list[dict[str, Any]] = item["data"]["scan_run"]["findings"]
    return findings


def test_a_report_without_deviations_validates_as_2_3_and_2_4(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    path = run_path(write_run, kit.scan_run((kit.finding("a"), kit.finding("b", OC.FAIL))))
    document = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(path,)))
    assert document["overview"]["deviation"] == 0
    assert document["sections"]["compliance"]["summary"]["deviation"] == 0
    older = copy.deepcopy(document)
    older["schema_version"] = "2.3"
    assert invalid(older)
    kit.without_deviations(older)
    assert VALIDATOR.is_valid(older)
    missing = copy.deepcopy(older)
    missing["schema_version"] = "2.4"
    assert invalid(missing)


COMPLIANCE = ("sections", "compliance")


@pytest.mark.parametrize(
    "path",
    [
        ("overview", "deviation"),
        (*COMPLIANCE, "deviations"),
        (*COMPLIANCE, "summary", "deviation"),
        (*COMPLIANCE, "summary", "deviation_by_outcome"),
        (*COMPLIANCE, "groups", 0, "summary", "deviation"),
        (*COMPLIANCE, "items", 0, "data", "summary", "deviation"),
        (*COMPLIANCE, "rules", 0, "deviation"),
        (*COMPLIANCE, "rules", 0, "sources", 0, "deviation"),
    ],
    ids=["overview", "list", "summary", "by-outcome", "group", "item", "rule", "source"],
)
def test_a_2_4_report_requires_every_deviation_key(
    deviated_document: dict[str, Any], path: tuple[str | int, ...]
) -> None:
    forged = copy.deepcopy(deviated_document)
    parent: Any = forged
    for step in path[:-1]:
        parent = parent[step]
    del parent[path[-1]]
    assert invalid(forged)


def test_a_2_3_report_may_not_embed_a_one_three_scan_run(
    kit: Any, deviated_document: dict[str, Any]
) -> None:
    older = copy.deepcopy(deviated_document)
    older["schema_version"] = "2.3"
    kit.without_deviations(older)
    assert invalid(older)
    errors = [error.message for error in VALIDATOR.iter_errors(older)]
    assert any("'1.3'" in message for message in errors), errors


def test_the_schema_ties_a_summary_to_its_deviations(deviated_document: dict[str, Any]) -> None:
    summary = deviated_document["sections"]["compliance"]["summary"]
    forged = copy.deepcopy(deviated_document)
    forged["sections"]["compliance"]["summary"] = {
        **summary,
        "assessment": "all_evaluated_passed",
        "compliance_percent": 100,
    }
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    forged["sections"]["compliance"]["summary"]["deviation"] = 0
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    forged["sections"]["compliance"]["summary"]["deviation_by_outcome"]["notapplicable"] = 1
    assert invalid(forged)


def test_the_schema_ties_a_rule_to_the_deviations_of_its_sources(
    kit: Any, deviated_document: dict[str, Any]
) -> None:
    forged = copy.deepcopy(deviated_document)
    _rule(forged, kit, "a")["deviation"] = None
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    _rule(forged, kit, "c")["deviation"] = LOOSER.to_dict()
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    rule = _rule(forged, kit, "d")
    rule["sources"][0]["deviation"] = LOOSER.to_dict()
    rule["deviation"] = LOOSER.to_dict()
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    forged["sections"]["compliance"]["deviations"][0]["outcome"] = "notapplicable"
    assert invalid(forged)


def test_the_schema_checks_the_findings_of_a_one_three_scan_run(
    deviated_document: dict[str, Any],
) -> None:
    forged = copy.deepcopy(deviated_document)
    _findings(forged)[0]["deviation"] = None
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    _findings(forged)[2]["deviation"] = LOOSER.to_dict()
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    del _findings(forged)[2]["deviation"]
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    first = _findings(forged)[0]
    first["outcome"] = first["evaluated_outcome"] = "notapplicable"
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    for item in _findings(forged):
        item.update({"deviation": None, "flags": [], "remediation": None})
    assert invalid(forged)
    forged = copy.deepcopy(deviated_document)
    _findings(forged)[0]["deviation"]["value_id"] = "Not An Id"
    assert invalid(forged)


def test_the_schema_checks_the_value_fields_of_a_remediation(
    deviated_document: dict[str, Any],
) -> None:
    valued_finding = _findings(deviated_document)[4]
    assert valued_finding["remediation"]["value_source"] == "profile"
    for change in (
        {"status": "deviation"},
        {"deviation": LOOSER.to_dict()},
        {"value_source": "operator"},
        {"profile_value": ""},
    ):
        forged = copy.deepcopy(deviated_document)
        _findings(forged)[4]["remediation"].update(change)
        assert invalid(forged), change
    forged = copy.deepcopy(deviated_document)
    del _findings(forged)[4]["remediation"]["value_source"]
    assert invalid(forged)


def test_the_schema_refuses_deviation_keys_in_an_earlier_scan_run(
    deviated_document: dict[str, Any],
) -> None:
    for version in ("1.0", "1.1", "1.2"):
        forged = copy.deepcopy(deviated_document)
        forged["sections"]["compliance"]["items"][0]["data"]["scan_run"]["schema_version"] = version
        assert invalid(forged), version


def test_the_dashboard_refuses_a_report_with_deviations(
    deviated_document: dict[str, Any], kit: Any, write_run: Callable[..., Path]
) -> None:
    with pytest.raises(DashboardError, match="operator deviations"):
        dashboard.render_dashboard(deviated_document)
    path = run_path(write_run, kit.scan_run((kit.finding("a"),)), "plain.json")
    plain = build(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(path,)))
    assert dashboard.render_dashboard(plain).startswith("<!DOCTYPE html>")


def test_the_cli_writes_the_json_but_no_dashboard_of_a_report_with_deviations(
    kit: Any, write_run: Callable[..., Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = run_path(write_run, deviated_run(kit))
    output = tmp_path / "report.json"
    html = tmp_path / "report.html"
    argv = ["--scope", "single_host", "--output", str(output), "--html", str(html)]
    assert cli.main([*argv, "--scan-run", str(path)]) == cli.EXIT_DASHBOARD_SKIPPED
    assert "operator deviations, which the dashboard does not show yet" in capsys.readouterr().err
    assert json.loads(output.read_text(encoding="utf-8"))["overview"]["deviation"] == 2
    assert not html.exists()


def test_the_checklist_export_refuses_a_run_with_deviations(kit: Any) -> None:
    with pytest.raises(ChecklistError, match=r"2 finding\(s\) of scan run run-1 carry an operator"):
        checklist_export.refuse_deviations(deviated_run(kit), "run.json")
    checklist_export.refuse_deviations(kit.scan_run((kit.finding("a"),)), "run.json")


def normalized_digest(document: dict[str, Any], *directories: Path) -> str:
    text = dumps(document)
    for index, directory in enumerate(directories):
        text = text.replace(str(directory), f"<directory-{index}>")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_inputs(kit: Any, directory: Path) -> ReportInputs:
    runs = {
        "web.json": kit.scan_run(
            (
                kit.finding("a"),
                kit.finding("b", OC.FAIL, severity=model.Severity.HIGH),
                kit.finding("c", OC.NOTAPPLICABLE),
                kit.finding("d", OC.ERROR),
                kit.finding("e", OC.NOTCHECKED),
                kit.waived("f"),
                kit.expired("g"),
            )
        ),
        "db.json": kit.scan_run(
            (kit.finding("a", OC.FAIL), kit.finding("b")),
            host=model.HostIdentity("db.example", "rhel", "9", "x86_64", None),
        ),
    }
    paths: list[Path] = []
    for name, run in runs.items():
        path = directory / name
        path.write_text(model.dumps(run), encoding="utf-8")
        paths.append(path)
    fixtures = kit.REPORTING
    return ReportInputs(
        scope=Scope.FLEET,
        metadata=RunMetadata(commit=COMMIT, generated_at="2026-10-25T10:11:00Z"),
        xccdf=(kit.XCCDF / "mixed-results.xml",),
        arf=(fixtures / "arf.xml",),
        scan_run=tuple(paths),
        exceptions_evaluation=(kit.EVALUATION_FILE,),
        exceptions_file=kit.EXCEPTIONS_FILE,
        junit=(fixtures / "junit.xml",),
    )


def test_a_report_without_deviations_keeps_the_bytes_of_report_schema_2_3(
    kit: Any, tmp_path: Path
) -> None:
    """Without deviations, the 2.4 document is the 2.3 document plus the new keys.

    ``MAIN_2_3_DIGEST`` was computed with :func:`digest_inputs` and :func:`normalized_digest`
    by the report code of ``main`` at commit 0550445, before report schema 2.4. It is never
    regenerated from the code under test.
    """
    document = json.loads(dumps(report.build_report(digest_inputs(kit, tmp_path))))
    assert document["overview"]["deviation"] == 0
    kit.without_deviations(document)
    document["schema_version"] = "2.3"
    assert VALIDATOR.is_valid(document)
    assert normalized_digest(document, tmp_path, REPOSITORY) == MAIN_2_3_DIGEST
