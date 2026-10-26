from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from defusedxml.ElementTree import fromstring
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import checklist, checklist_formats, stig_content
from tools.reporting.checklist import (
    NOT_A_FINDING,
    NOT_APPLICABLE,
    NOT_REVIEWED,
    OPEN,
    ChecklistError,
    Source,
)

SCHEMA_PATH = Path(checklist_formats.__file__).parent / "schema" / "cklb-export.json"
VALIDATOR: Any = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))

EXPECTED = {
    1: NOT_A_FINDING,
    2: OPEN,
    3: NOT_APPLICABLE,
    4: NOT_REVIEWED,
    5: NOT_REVIEWED,
    6: OPEN,
    7: OPEN,
    8: NOT_REVIEWED,
    9: NOT_REVIEWED,
    10: NOT_REVIEWED,
}


def content(stig: Any, **options: Any) -> stig_content.StigBenchmark:
    xml = stig.benchmark_xml(test_result=stig.result_xml(), **options)
    return stig_content.read_benchmarks(xml.encode("utf-8"))[0]


def source(stig: Any, run: model.ScanRun | None = None, **options: Any) -> Source:
    lapsed = frozenset(options.pop("lapsed", ()))
    own = bool(options.pop("own", True))
    return Source(
        "bundles/web01/run-web01",
        stig.scan_run() if run is None else run,
        lapsed,
        content(stig, **options),
        own,
    )


def statuses(made: checklist.Checklist) -> dict[str, checklist.Status]:
    return {entry.rule.rule_ref: entry.verdict.status for entry in made.entries}


def rule_ref(number: int) -> str:
    return f"SV-90{number:04d}r1_rule"


def test_the_status_strings_are_the_published_ones() -> None:
    assert [(item.ckl, item.cklb) for item in checklist.STATUSES] == [
        ("NotAFinding", "not_a_finding"),
        ("Open", "open"),
        ("Not_Applicable", "not_applicable"),
        ("Not_Reviewed", "not_reviewed"),
    ]
    assert set(checklist.OUTCOME_STATUSES) == set(model.Outcome)


def test_every_outcome_maps_by_the_adr_table(stig: Any) -> None:
    made = checklist.build(source(stig))
    assert statuses(made) == {rule_ref(number): status for number, status in EXPECTED.items()}


@pytest.mark.parametrize("status", list(model.ScanStatus))
@pytest.mark.parametrize("outcome", list(model.Outcome))
def test_only_a_plain_pass_of_a_completed_on_platform_run_is_not_a_finding(
    stig: Any, outcome: model.Outcome, status: model.ScanStatus
) -> None:
    run = stig.scan_run((), status=status)
    waived = outcome is model.Outcome.WAIVED
    finding = stig.finding(
        1,
        outcome,
        evaluated=model.Outcome.FAIL if waived else None,
        exception=stig.WAIVER if waived else None,
        disabled_by="linux_compliance_x" if outcome is model.Outcome.DISABLED else None,
    )
    result = checklist.verdict(run, finding)
    plain = outcome is model.Outcome.PASS and status is model.ScanStatus.COMPLETED
    assert (result.status is NOT_A_FINDING) == plain
    marked = replace(finding, off_platform=stig.OFF_PLATFORM)
    assert checklist.verdict(run, marked).status is not NOT_A_FINDING


def test_a_waived_finding_stays_open_and_names_its_exception(stig: Any) -> None:
    made = checklist.build(source(stig))
    entry = next(item for item in made.entries if item.rule.rule_ref == rule_ref(6))
    assert entry.verdict.status is OPEN
    assert "Waiver: exception EXC-STIG-1 was in effect" in entry.verdict.comments
    assert "expires 2026-12-31T00:00:00Z" in entry.verdict.comments
    assert "Exception reason: Accepted risk" in entry.verdict.comments
    assert "Scanner result: fail\nReported outcome: waived" in entry.verdict.details


def test_an_expired_exception_and_a_lapsed_waiver_are_named(stig: Any) -> None:
    made = checklist.build(source(stig, lapsed={stig.rule_id(2)}))
    entries = {item.rule.rule_ref: item for item in made.entries}
    assert entries[rule_ref(7)].verdict.status is OPEN
    assert "EXC-STIG-2 expired at 2026-10-01T00:00:00Z" in entries[rule_ref(7)].verdict.comments
    assert entries[rule_ref(2)].verdict.status is OPEN
    assert "lapsed after the scan started" in entries[rule_ref(2)].verdict.comments


def test_the_details_explain_every_not_reviewed_entry(stig: Any) -> None:
    made = checklist.build(source(stig))
    details = {item.rule.rule_ref: item.verdict.details for item in made.entries}
    assert "Flags: informational" in details[rule_ref(4)]
    assert "Message: SCC reported 'unknown'" in details[rule_ref(5)]
    assert "Disabled by: linux_compliance_rule_synthetic" in details[rule_ref(8)]
    assert "the scanner reported fixed" in details[rule_ref(9)]
    assert "has no result for this rule" in details[rule_ref(10)]
    assert details[rule_ref(1)].startswith("Scanner result: pass\nScan run run-web01: scc 5.15")


def test_every_finding_of_an_off_platform_run_is_not_reviewed(stig: Any) -> None:
    run = stig.scan_run(host=stig.OFF_PLATFORM_HOST, off_platform=stig.OFF_PLATFORM)
    made = checklist.build(source(stig, run))
    assert set(statuses(made).values()) == {NOT_REVIEWED}
    label = "off-platform: the ubuntu 24.04 benchmark on an ubuntu 26.04 host"
    assert all(label in entry.verdict.details for entry in made.entries)
    waived = next(item for item in made.entries if item.rule.rule_ref == rule_ref(6))
    assert "Waiver: exception EXC-STIG-1" in waived.verdict.comments


def test_a_marked_finding_is_not_reviewed_even_without_the_run(stig: Any) -> None:
    run = stig.scan_run(host=stig.OFF_PLATFORM_HOST, off_platform=stig.OFF_PLATFORM)
    bare = replace(run, findings=())
    marked = run.findings[0]
    assert marked.outcome is model.Outcome.PASS
    assert checklist.verdict(bare, marked).status is NOT_REVIEWED


def test_a_run_that_did_not_complete_is_not_reviewed(stig: Any) -> None:
    findings = tuple(stig.finding(n, model.Outcome.ERROR) for n in (1, 2))
    run = stig.scan_run(findings, status=model.ScanStatus.TIMED_OUT)
    made = checklist.build(source(stig, run))
    assert set(statuses(made).values()) == {NOT_REVIEWED}
    assert "did not complete (run status timed_out): the scanner timed out" in (
        made.entries[0].verdict.details
    )


def test_findings_of_other_rules_than_the_content_are_refused(stig: Any) -> None:
    with pytest.raises(ChecklistError, match="not rules of the content"):
        checklist.build(source(stig, rules=3))


def test_compliance_as_code_findings_are_refused_with_the_mapping_issue(stig: Any) -> None:
    foreign = replace(
        stig.finding(1, model.Outcome.PASS), rule_id="xccdf_org.ssgproject.content_rule_x"
    )
    run = stig.scan_run((foreign,))
    with pytest.raises(ChecklistError, match="FREES-146, which is not built yet"):
        checklist.refuse_unmapped(run, "scan-run.json")
    checklist.refuse_unmapped(stig.scan_run(), "scan-run.json")


def test_asset_fields_come_from_the_runs_own_results_only(stig: Any) -> None:
    made = checklist.build(source(stig))
    assert made.asset.host_name == "web01.example"
    assert made.asset.host_ip == "192.0.2.10, 2001:db8::10"
    assert made.asset.host_fqdn == "web01.example"
    assert made.asset.target_key == "9999"
    assert "self-asserted by the scanned host" in made.asset.comment
    supplied = checklist.build(source(stig, own=False))
    assert (supplied.asset.host_ip, supplied.asset.host_fqdn) == ("", "")


def test_target_facts_that_name_another_host_are_not_used(stig: Any) -> None:
    xml = stig.benchmark_xml(test_result=stig.result_xml(target="EE205EA5504A", fqdn="x."))
    other = stig_content.read_benchmarks(xml.encode("utf-8"))[0]
    made = checklist.build(Source("b", stig.scan_run(), frozenset(), other, own_results=True))
    assert (made.asset.host_ip, made.asset.host_fqdn) == ("", "")
    assert "name another host and are not used" in made.asset.comment


def test_two_checklists_of_one_host_and_benchmark_are_refused(stig: Any) -> None:
    first = source(stig)
    second = replace(first, display="other", run=stig.scan_run(run_id="run-again"))
    assert len(checklist.build_all([first])) == 1
    with pytest.raises(ChecklistError, match="one checklist is written per host and benchmark"):
        checklist.build_all([first, second])


def test_file_names_are_safe_on_every_file_system(stig: Any) -> None:
    host = model.HostIdentity("web:01+a.example", "ubuntu", "24.04", "x86_64", None)
    made = checklist.build(source(stig, stig.scan_run(host=host)))
    assert made.file_stem == "web_01_a.example_Synthetic_Linux_STIG"
    assert checklist.safe_name("a/b\\c..d \u00e9") == "a_b_c..d__"


def test_the_output_is_deterministic_and_matches_the_golden_files(stig: Any) -> None:
    made = checklist.build(source(stig))
    again = checklist.build(source(stig))
    ckl = checklist_formats.render_ckl(made)
    cklb = checklist_formats.render_cklb(made)
    assert ckl == checklist_formats.render_ckl(again)
    assert cklb == checklist_formats.render_cklb(again)
    assert ckl == (stig.GOLDEN / "synthetic-ckl.xml").read_text(encoding="utf-8")
    assert cklb == (stig.GOLDEN / "synthetic-cklb.json").read_text(encoding="utf-8")


def test_both_formats_read_back_with_the_mapped_statuses(stig: Any) -> None:
    made = checklist.build(source(stig))
    ckl = checklist_formats.read_ckl(checklist_formats.render_ckl(made).encode("utf-8"))
    cklb = checklist_formats.read_cklb(checklist_formats.render_cklb(made).encode("utf-8"))
    assert ckl == {ref: status.ckl for ref, status in statuses(made).items()}
    assert cklb == {ref: status.cklb for ref, status in statuses(made).items()}


def test_the_cklb_output_matches_its_structural_schema(stig: Any) -> None:
    made = checklist.build(source(stig))
    document = json.loads(checklist_formats.render_cklb(made))
    assert VALIDATOR.is_valid(document), [e.message for e in VALIDATOR.iter_errors(document)]
    document["stigs"][0]["rules"][0]["status"] = "passed"
    assert not VALIDATOR.is_valid(document)


def test_the_ckl_carries_every_published_element(stig: Any) -> None:
    made = checklist.build(source(stig))
    root = fromstring(checklist_formats.render_ckl(made))
    assert root.tag == "CHECKLIST"
    asset = root.find("ASSET")
    assert asset is not None
    assert [child.tag for child in asset] == list(checklist_formats.ASSET_FIELDS)
    assert asset.findtext("ROLE") == "None"
    assert asset.findtext("ASSET_TYPE") == "Computing"
    vuln = root.find("STIGS/iSTIG/VULN")
    assert vuln is not None
    data = {item.findtext("VULN_ATTRIBUTE"): item.findtext("ATTRIBUTE_DATA") for item in vuln}
    assert data["Vuln_Num"] == "V-900001"
    assert data["Rule_ID"] == "SV-900001r1_rule"
    assert data["Rule_Ver"] == "SYN-00-000001"
    assert data["Severity"] == "high"
    assert data["Group_Title"] == "SRG-SYN-000001"
    assert data["Rule_Title"] == "Synthetic requirement 1 must hold"
    assert data["Vuln_Discuss"] == "Synthetic discussion 1 & notes"
    assert data["CCI_REF"] == "CCI-000001"
    assert data["LEGACY_ID"] == "SV-1"
    info = {
        item.findtext("SID_NAME"): item.findtext("SID_DATA")
        for item in root.findall("STIGS/iSTIG/STIG_INFO/SI_DATA")
    }
    assert info["stigid"] == "Synthetic_Linux_STIG"
    assert info["filename"] == stig.CONTENT_FILE
    assert info["classification"] is None
