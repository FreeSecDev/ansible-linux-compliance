from __future__ import annotations

import json
import stat
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import checklist, checklist_formats, cli, stig_content, stig_mapping
from tools.reporting.checklist import NOT_A_FINDING, NOT_APPLICABLE, NOT_REVIEWED, OPEN

if TYPE_CHECKING:
    from pathlib import Path

CAC = "xccdf_org.ssgproject.content_rule_"
CAC_BENCHMARK = "xccdf_org.ssgproject.content_benchmark_SYNTHETIC"
CAC_PROFILE = "xccdf_org.ssgproject.content_profile_stig"
CAC_SHA = "c" * 64
HOST = model.HostIdentity("web01.example", "ubuntu", "24.04", "x86_64", "e" * 32)
CHECKS: dict[str, list[str]] = {
    "SYN-00-000001": ["one"],
    "SYN-00-000002": ["many_fail", "many_pass"],
    "SYN-00-000003": ["both_a", "both_b"],
    "SYN-00-000004": ["mixed_na", "mixed_pass"],
    "SYN-00-000005": ["shared"],
    "SYN-00-000006": ["shared"],
    "SYN-00-000007": ["missing"],
    "SYN-00-000008": ["waived"],
    "SYN-00-000009": ["fixed"],
    "SYN-00-000099": ["elsewhere"],
}
EXPECTED: dict[int, str] = {
    1: "NotAFinding",
    2: "Open",
    3: "NotAFinding",
    4: "Not_Reviewed",
    5: "NotAFinding",
    6: "NotAFinding",
    7: "Not_Reviewed",
    8: "Open",
    9: "Not_Reviewed",
    10: "Not_Reviewed",
}
WAIVER = model.ExceptionStatus(
    model.ExceptionState.ACTIVE,
    "EXC-CAC-1",
    "Accepted risk of a synthetic check",
    "2027-01-31T00:00:00Z",
)


DISA_BENCHMARK = "xccdf_mil.disa.stig_benchmark_Synthetic_Linux_STIG"
PAIRS: dict[str, str] = {
    f"SV-90{number:04d}r1_rule": f"SYN-00-{number:06d}" for number in range(1, 10)
}


def mapping_document(
    checks: dict[str, list[str]] | None = None,
    *,
    release: str = "V1R2",
    sha: str = CAC_SHA,
    benchmark: str = DISA_BENCHMARK,
    pairs: dict[str, str] | None = None,
) -> dict[str, object]:
    table = CHECKS if checks is None else checks
    return {
        "schema_version": 1,
        "generator": "tools/content/generate_stig_mapping.py",
        "source": "ComplianceAsCode/content v0.1.82",
        "join_key": "STIG ID",
        "datastreams": [
            {
                "name": "synthetic",
                "file_name": "ssg-synthetic-ds.xml",
                "sha256": sha,
                "benchmark_id": CAC_BENCHMARK,
                "benchmark_version": "0.1.82",
                "profiles": [
                    {
                        "profile_id": CAC_PROFILE,
                        "stig_release": release,
                        "disa_benchmark_id": benchmark,
                        "stig_ids": {key: [CAC + rule for rule in table[key]] for key in table},
                        "disa_rules": PAIRS if pairs is None else pairs,
                        "rules_without_stig_id": [CAC + "unmapped"],
                    }
                ],
            }
        ],
    }


def cac(name: str, outcome: model.Outcome, **options: Any) -> model.Finding:
    return model.Finding(
        rule_id=CAC + name,
        outcome=outcome,
        evaluated_outcome=options.get("evaluated") or outcome,
        severity=model.Severity.MEDIUM,
        message=options.get("message"),
        evidence=(),
        exception=options.get("exception") or model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=options.get("disabled_by"),
        flags=options.get("flags", ()),
    )


def cac_findings() -> tuple[model.Finding, ...]:
    return (
        cac("one", model.Outcome.PASS),
        cac("many_fail", model.Outcome.FAIL, message="value is 0; expected 1"),
        cac("many_pass", model.Outcome.PASS),
        cac("both_a", model.Outcome.PASS),
        cac("both_b", model.Outcome.PASS),
        cac("mixed_na", model.Outcome.NOTAPPLICABLE),
        cac("mixed_pass", model.Outcome.PASS),
        cac("shared", model.Outcome.PASS),
        cac("waived", model.Outcome.WAIVED, evaluated=model.Outcome.FAIL, exception=WAIVER),
        cac("fixed", model.Outcome.PASS, flags=(model.ResultFlag.FIXED,)),
        cac("elsewhere", model.Outcome.FAIL),
        cac("unmapped", model.Outcome.FAIL),
    )


def cac_run(findings: tuple[model.Finding, ...] | None = None, **options: Any) -> model.ScanRun:
    status = options.get("status", model.ScanStatus.COMPLETED)
    return model.ScanRun(
        run_id=options.get("run_id", "run-oscap"),
        started_at="2026-10-26T10:00:00Z",
        finished_at="2026-10-26T10:05:00Z",
        host=options.get("host", HOST),
        scanner=model.ScannerInfo("oscap", "1.3.9"),
        content=model.Provenance("ssg-synthetic-ds.xml", "0.1.82", options.get("sha", CAC_SHA)),
        benchmark_id=CAC_BENCHMARK,
        profile_id=CAC_PROFILE,
        status=status,
        error_message=None if status is model.ScanStatus.COMPLETED else "oscap timed out",
        findings=cac_findings() if findings is None else findings,
        off_platform=options.get("off_platform"),
    )


def files(tmp_path: Path, stig: Any, run: model.ScanRun, **options: Any) -> list[str]:
    run_path = tmp_path / f"{run.run_id}.json"
    run_path.write_text(model.dumps(run), encoding="utf-8")
    content = tmp_path / "disa-content.xml"
    content.write_text(
        stig.data_stream(stig.benchmark_xml(version=options.get("version", stig.VERSION))),
        encoding="utf-8",
    )
    mapping = tmp_path / "stig-mapping.json"
    document = options.get("mapping") or mapping_document()
    mapping.write_text(json.dumps(document), encoding="utf-8")
    return [
        "--scan-run",
        str(run_path),
        "--checklist-content",
        str(content),
        "--stig-mapping",
        str(mapping),
    ]


def export(tmp_path: Path, *arguments: str) -> int:
    return cli.main(
        [
            "--scope",
            "multi_host",
            "--output",
            str(tmp_path / "report.json"),
            "--export-ckl",
            str(tmp_path / "out"),
            "--export-cklb",
            str(tmp_path / "out"),
            *arguments,
        ]
    )


def cklb(tmp_path: Path, host: str = "web01.example") -> dict[str, Any]:
    path = tmp_path / "out" / f"{host}_Synthetic_Linux_STIG.cklb"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    return cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))


def rules(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {rule["rule_version"]: rule for rule in document["stigs"][0]["rules"]}


def test_compliance_as_code_findings_export_through_the_mapping(stig: Any, tmp_path: Path) -> None:
    assert export(tmp_path, *files(tmp_path, stig, cac_run())) == 0
    ckl = checklist_formats.read_ckl(
        (tmp_path / "out" / "web01.example_Synthetic_Linux_STIG.ckl").read_bytes()
    )
    assert ckl == {f"SV-90{number:04d}r1_rule": status for number, status in EXPECTED.items()}
    document = cklb(tmp_path)
    by_id = rules(document)
    assert by_id["SYN-00-000002"]["group_id"] == "V-900002"
    assert (
        "Mapped by STIG ID SYN-00-000002 to 2 ComplianceAsCode check(s)"
        in by_id["SYN-00-000002"]["finding_details"]
    )
    assert (
        f"ComplianceAsCode check {CAC}many_fail: Open" in by_id["SYN-00-000002"]["finding_details"]
    )
    assert by_id["SYN-00-000004"]["finding_details"].startswith(
        "Not reviewed: the 2 ComplianceAsCode checks of this STIG rule disagree "
        "(Not a Finding: 1, Not Applicable: 1)"
    )
    assert by_id["SYN-00-000007"]["finding_details"].startswith(
        "Not reviewed: the scan run has no result for this rule"
    )
    assert by_id["SYN-00-000009"]["finding_details"].startswith(
        "Not reviewed: the scanner reported fixed"
    )
    assert by_id["SYN-00-000010"]["finding_details"].startswith(
        "Not reviewed: no ComplianceAsCode check: profile"
    )
    assert "Waiver: exception EXC-CAC-1 was in effect" in by_id["SYN-00-000008"]["comments"]
    assert document["target_data"]["ip_address"] == ""
    assert "2 finding(s) check no rule of this STIG" in document["target_data"]["comments"]
    assert "9 DISA rule(s) of the content were checked" in document["target_data"]["comments"]
    assert "for DISA release V1R2 (disa-content.xml)" in document["target_data"]["comments"]
    assert document["stigs"][0]["stig_name"] == "Synthetic Linux STIG SCAP Benchmark"


def test_an_off_platform_or_incomplete_mapped_run_is_never_reviewed(
    stig: Any, tmp_path: Path
) -> None:
    marked = tuple(replace(item, off_platform=stig.OFF_PLATFORM) for item in cac_findings())
    run = cac_run(marked, off_platform=stig.OFF_PLATFORM, host=stig.OFF_PLATFORM_HOST)
    assert export(tmp_path, *files(tmp_path, stig, run)) == 0
    entries = rules(cklb(tmp_path, "web26.example"))
    assert {entry["status"] for entry in entries.values()} == {"not_reviewed"}
    assert entries["SYN-00-000001"]["finding_details"].startswith(
        "Not reviewed: off-platform: the ubuntu 24.04"
    )
    assert entries["SYN-00-000010"]["finding_details"].startswith("Not reviewed: off-platform")
    failed = cac_run((), status=model.ScanStatus.FAILED, run_id="run-failed")
    assert export(tmp_path, *files(tmp_path, stig, failed)) == 0
    entries = rules(cklb(tmp_path))
    assert {entry["status"] for entry in entries.values()} == {"not_reviewed"}
    assert entries["SYN-00-000003"]["finding_details"].startswith(
        "Not reviewed: the scan run did not complete (run status failed)"
    )


def refused(tmp_path: Path, capsys: pytest.CaptureFixture[str], *arguments: str) -> str:
    assert export(tmp_path, *arguments) == 2
    assert not (tmp_path / "out").exists()
    return capsys.readouterr().err


def test_another_compliance_as_code_version_is_a_version_mismatch(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    error = refused(tmp_path, capsys, *files(tmp_path, stig, cac_run(sha="d" * 64)))
    assert "version mismatch: scan run run-oscap evaluated ComplianceAsCode content" in error
    assert "regenerate the mapping" in error


@pytest.mark.parametrize(
    ("version", "message"),
    [
        ("001.003.000", "disa-content.xml is DISA release V1R3"),
        ("draft", "is DISA release unknown (version draft)"),
    ],
)
def test_disa_content_of_another_release_is_a_version_mismatch(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str], version: str, message: str
) -> None:
    error = refused(tmp_path, capsys, *files(tmp_path, stig, cac_run(), version=version))
    assert message in error
    assert "implements release V1R2" in error


def test_the_disa_content_must_be_exactly_one_benchmark_with_the_stig_ids(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = files(tmp_path, stig, cac_run())
    other = tmp_path / "other.xml"
    other.write_text(
        stig.benchmark_xml(benchmark="xccdf_mil.disa.stig_benchmark_Other"), encoding="utf-8"
    )
    error = refused(tmp_path, capsys, *arguments, "--checklist-content", str(other))
    assert "exactly one DISA benchmark with its STIG IDs (found: " in error
    assert "other.xml" in error
    without = [item for item in arguments if not item.endswith("disa-content.xml")]
    without.remove("--checklist-content")
    assert "(found: none)" in refused(tmp_path, capsys, *without)


def test_another_disa_benchmark_than_the_pinned_one_is_refused(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pinned = mapping_document(benchmark="xccdf_mil.disa.stig_benchmark_Pinned_STIG")
    error = refused(tmp_path, capsys, *files(tmp_path, stig, cac_run(), mapping=pinned))
    assert "is the benchmark xccdf_mil.disa.stig_benchmark_Synthetic_Linux_STIG" in error
    assert "implements the DISA benchmark xccdf_mil.disa.stig_benchmark_Pinned_STIG" in error


def test_content_that_contradicts_the_pinned_pairs_is_refused(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    swapped = {**PAIRS, "SV-900001r1_rule": "SYN-00-000002", "SV-900002r1_rule": "SYN-00-000001"}
    document = mapping_document(pairs=swapped)
    error = refused(tmp_path, capsys, *files(tmp_path, stig, cac_run(), mapping=document))
    assert "contradicts the pinned STIG mapping in 2 rule(s)" in error
    assert (
        "SV-900001r1_rule has the STIG ID SYN-00-000001, but the STIG mapping pairs it with "
        "SYN-00-000002"
    ) in error


def test_content_of_a_run_that_is_not_mapped_is_checked_against_the_pinned_benchmark(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    scc_path = tmp_path / "scc.json"
    scc_path.write_text(model.dumps(stig.scan_run()), encoding="utf-8")
    content = tmp_path / "content.xml"
    content.write_text(stig.benchmark_xml(), encoding="utf-8")
    mapping_path = tmp_path / "stig-mapping.json"
    arguments = ["--scan-run", str(scc_path), "--checklist-content", str(content)]
    mapping_path.write_text(json.dumps(mapping_document()), encoding="utf-8")
    assert export(tmp_path, *arguments, "--stig-mapping", str(mapping_path)) == 0
    capsys.readouterr()
    contradicting = mapping_document(pairs={**PAIRS, "SV-900001r1_rule": "SYN-00-000002"})
    mapping_path.write_text(json.dumps(contradicting), encoding="utf-8")
    assert export(tmp_path, *arguments, "--stig-mapping", str(mapping_path)) == 2
    assert "contradicts the pinned STIG mapping in 1 rule(s)" in capsys.readouterr().err


def test_an_invalid_mapping_file_is_refused(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    document = mapping_document()
    document["schema_version"] = 2
    error = refused(tmp_path, capsys, *files(tmp_path, stig, cac_run(), mapping=document))
    assert "the STIG mapping" in error
    assert "must have schema_version 1" in error


def test_a_stig_rule_without_mapped_checks_is_not_reviewed_with_the_reason() -> None:
    made = checklist.mapped_verdict(cac_run(), "SYN-00-000010", [])
    assert made.status is NOT_REVIEWED
    assert made.details.splitlines()[0] == (
        f"Not reviewed: no ComplianceAsCode check: profile {CAC_PROFILE} maps no rule to the "
        "STIG ID SYN-00-000010."
    )
    assert made.comments == ""


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], NOT_REVIEWED),
        ([NOT_A_FINDING], NOT_A_FINDING),
        ([NOT_A_FINDING, NOT_A_FINDING], NOT_A_FINDING),
        ([NOT_A_FINDING, OPEN], OPEN),
        ([NOT_REVIEWED, OPEN], OPEN),
        ([NOT_APPLICABLE, NOT_APPLICABLE], NOT_APPLICABLE),
        ([NOT_A_FINDING, NOT_APPLICABLE], NOT_REVIEWED),
        ([NOT_A_FINDING, NOT_REVIEWED], NOT_REVIEWED),
        ([NOT_REVIEWED, NOT_REVIEWED], NOT_REVIEWED),
    ],
)
def test_aggregation_is_conservative(
    statuses: list[checklist.Status], expected: checklist.Status
) -> None:
    assert checklist.aggregate(statuses) is expected


def outcome_finding(name: str, outcome: model.Outcome) -> model.Finding:
    if outcome is model.Outcome.WAIVED:
        return cac(name, outcome, evaluated=model.Outcome.FAIL, exception=WAIVER)
    if outcome is model.Outcome.DISABLED:
        return cac(name, outcome, disabled_by="linux_compliance_rule_synthetic_enabled")
    return cac(name, outcome)


def test_not_a_finding_needs_every_mapped_check_to_pass() -> None:
    run = cac_run()
    outcomes = list(model.Outcome)
    for left in outcomes:
        for right in outcomes:
            checks = [
                (CAC + "a", outcome_finding("a", left)),
                (CAC + "b", outcome_finding("b", right)),
            ]
            made = checklist.mapped_verdict(run, "SYN-00-000001", checks)
            both_pass = left is right is model.Outcome.PASS
            assert (made.status is NOT_A_FINDING) is both_pass
    missing = checklist.mapped_verdict(
        run, "SYN-00-000001", [(CAC + "a", cac("a", model.Outcome.PASS)), (CAC + "b", None)]
    )
    assert missing.status is NOT_REVIEWED


def test_uniformly_unreviewed_checks_and_their_comments_are_explained() -> None:
    run = cac_run()
    expired = model.ExceptionStatus(
        model.ExceptionState.EXPIRED, "EXC-OLD", "old", "2026-10-01T00:00:00Z"
    )
    checks = [
        (CAC + "a", cac("a", model.Outcome.ERROR, exception=expired)),
        (CAC + "b", cac("b", model.Outcome.NOTCHECKED)),
    ]
    made = checklist.mapped_verdict(run, "SYN-00-000003", checks, frozenset({CAC + "b"}))
    assert made.details.startswith(
        "Not reviewed: none of the 2 ComplianceAsCode checks of this STIG rule"
    )
    assert made.comments.startswith(f"ComplianceAsCode check {CAC}a:\nException EXC-OLD expired")
    assert f"ComplianceAsCode check {CAC}b:\nThe waiver of this rule lapsed" in made.comments
    single = checklist.mapped_verdict(run, "SYN-00-000003", checks[1:])
    assert single.details.startswith("Mapped by STIG ID SYN-00-000003 to 1")


def test_the_mapped_checklist_is_deterministic_and_matches_the_golden_file(stig: Any) -> None:
    benchmark = stig_content.read_benchmarks(stig.benchmark_xml().encode("utf-8"))[0]
    mapping = checklist_mapping()
    source = checklist.Source(
        "scan-run.json",
        cac_run(),
        frozenset(),
        benchmark,
        own_results=False,
        mapping=mapping,
        content_name="disa.xml",
    )
    first = checklist.build(source)
    assert first == checklist.build(replace(source))
    rendered = checklist_formats.render_cklb(first)
    golden = stig.GOLDEN / "synthetic-mapped-cklb.json"
    assert rendered == golden.read_text(encoding="utf-8")


def checklist_mapping() -> stig_mapping.ProfileMapping:
    parsed = stig_mapping.parse_mapping(json.dumps(mapping_document()).encode("utf-8"), "map.json")
    return parsed.profiles[0]


def test_the_comparison_lists_the_rules_where_scc_and_openscap_disagree(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = files(tmp_path, stig, cac_run())
    scc_path = tmp_path / "scc.json"
    scc_path.write_text(model.dumps(stig.scan_run()), encoding="utf-8")
    comparison = tmp_path / "private" / "comparison.json"
    common = ["--scope", "single_host", "--output", str(tmp_path / "r.json")]
    assert (
        cli.main(
            [*common, *arguments, "--scan-run", str(scc_path), "--compare-stig", str(comparison)]
        )
        == 0
    )
    assert "STIG comparison written to" in capsys.readouterr().out
    assert stat.S_IMODE(comparison.stat().st_mode) == 0o600
    assert stat.S_IMODE(comparison.parent.stat().st_mode) == 0o700
    document = json.loads(comparison.read_text(encoding="utf-8"))
    assert document["kind"] == "stig_comparison"
    pair = document["comparisons"][0]
    assert (pair["rules"], pair["agree"] + pair["disagree"]) == (10, 10)
    assert pair["disa_run"]["scanner"] == "scc"
    assert pair["compliance_as_code_run"]["stig_release"] == "V1R2"
    differing = {item["stig_id"]: item for item in pair["disagreements"]}
    assert differing["SYN-00-000003"] == {
        "group_id": "V-900003",
        "rule_id": "SV-900003r1_rule",
        "stig_id": "SYN-00-000003",
        "disa": "Not_Applicable",
        "compliance_as_code": "NotAFinding",
        "compliance_as_code_rules": [CAC + "both_a", CAC + "both_b"],
    }
    assert "SYN-00-000001" not in differing
    assert pair["statuses"]["compliance_as_code"]["NotAFinding"] == 4


def test_a_comparison_needs_one_run_of_each_kind_per_host(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = files(tmp_path, stig, cac_run())
    common = ["--scope", "single_host", "--output", str(tmp_path / "r.json")]
    assert cli.main([*common, *arguments, "--compare-stig", str(tmp_path / "c.json")]) == 2
    error = capsys.readouterr().err
    assert "--compare-stig needs exactly one SCC run and one mapped ComplianceAsCode run" in error
    assert "found 0 and 1" in error
    assert not (tmp_path / "c.json").exists()
