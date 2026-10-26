from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import compliance
from tools.reporting.compliance import (
    ASSESSMENT_ALL_PASSED,
    ASSESSMENT_FINDINGS_OPEN,
    ASSESSMENT_NOTHING_EVALUATED,
    ASSESSMENT_RUN_NOT_COMPLETED,
    Tally,
)

OC = model.Outcome
SV = model.Severity


def tallies(*outcomes: model.Outcome) -> list[Tally]:
    return [Tally(outcome, SV.MEDIUM, expired_waiver=False) for outcome in outcomes]


def summary_of(*outcomes: model.Outcome, status: str = "completed") -> compliance.Summary:
    return compliance.summarize(tallies(*outcomes), status, 1, 0 if status == "completed" else 1)


@pytest.mark.parametrize(
    ("passed", "evaluated", "expected"),
    [
        (0, 0, None),
        (1, 3, 33.3),
        (2, 3, 66.6),
        (1, 8, 12.5),
        (1, 200, 0.5),
        (1, 1, 100.0),
        (0, 5, 0.0),
    ],
)
def test_percent_rounds_down_and_withholds_empty_denominators(
    passed: int, evaluated: int, expected: float | None
) -> None:
    assert compliance.percent(passed, evaluated) == expected


def test_rounding_is_downwards_so_100_means_everything_passed() -> None:
    assert compliance.percent(99999, 100000) == 99.9
    assert compliance.percent(999, 1000) == 99.9
    assert compliance.percent(5, 8000) == 0.0
    assert compliance.percent(1, 16) == 6.2
    assert compliance.percent(100000, 100000) == 100.0


def test_a_single_open_finding_never_reaches_100_percent() -> None:
    summary = summary_of(*([OC.PASS] * 99999 + [OC.FAIL]))
    assert summary.compliance_percent == 99.9
    assert summary.assessment == ASSESSMENT_FINDINGS_OPEN


def test_mixed_outcomes() -> None:
    summary = summary_of(
        OC.PASS, OC.PASS, OC.FAIL, OC.NOTCHECKED, OC.ERROR, OC.WAIVED, OC.NOTAPPLICABLE, OC.DISABLED
    )
    assert summary.evaluated == 6
    assert summary.compliance_percent == 33.3
    assert summary.assessment == ASSESSMENT_FINDINGS_OPEN
    assert summary.counts == {
        "pass": 2,
        "fail": 1,
        "notapplicable": 1,
        "notchecked": 1,
        "error": 1,
        "waived": 1,
        "disabled": 1,
    }


def test_only_pass_counts_as_pass() -> None:
    for outcome in (OC.FAIL, OC.NOTCHECKED, OC.ERROR, OC.WAIVED, OC.NOTAPPLICABLE, OC.DISABLED):
        summary = summary_of(OC.PASS, outcome)
        assert summary.counts["pass"] == 1
        excluded = outcome in compliance.EXCLUDED_FROM_DENOMINATOR
        assert (summary.assessment == ASSESSMENT_ALL_PASSED) is excluded


def test_notchecked_error_and_waived_lower_compliance_but_stay_visible() -> None:
    for outcome in (OC.NOTCHECKED, OC.ERROR, OC.WAIVED):
        summary = summary_of(OC.PASS, outcome)
        assert summary.compliance_percent == 50.0
        assert summary.counts[outcome.value] == 1


def test_not_applicable_and_disabled_are_shown_but_not_in_the_denominator() -> None:
    summary = summary_of(OC.PASS, OC.NOTAPPLICABLE, OC.DISABLED)
    assert summary.evaluated == 1
    assert summary.compliance_percent == 100.0
    assert summary.assessment == ASSESSMENT_ALL_PASSED
    assert (summary.counts["notapplicable"], summary.counts["disabled"]) == (1, 1)


def test_all_error_is_zero_percent_never_a_pass() -> None:
    summary = summary_of(OC.ERROR, OC.ERROR, OC.ERROR)
    assert summary.compliance_percent == 0.0
    assert summary.assessment == ASSESSMENT_FINDINGS_OPEN
    assert summary.counts["pass"] == 0


def test_all_not_applicable_evaluates_nothing() -> None:
    summary = summary_of(OC.NOTAPPLICABLE, OC.NOTAPPLICABLE)
    assert summary.evaluated == 0
    assert summary.compliance_percent is None
    assert summary.assessment == ASSESSMENT_NOTHING_EVALUATED


def test_empty_run_evaluates_nothing() -> None:
    summary = summary_of()
    assert summary.compliance_percent is None
    assert summary.assessment == ASSESSMENT_NOTHING_EVALUATED


@pytest.mark.parametrize("status", ["failed", "timed_out", "not_completed"])
def test_a_run_that_did_not_complete_is_never_compliant(status: str) -> None:
    summary = summary_of(OC.PASS, OC.PASS, status=status)
    assert summary.run_status == status
    assert summary.assessment == ASSESSMENT_RUN_NOT_COMPLETED
    assert summary.compliance_percent is None
    assert summary.runs_not_completed == 1


def test_waived_and_expired_waivers() -> None:
    items = [
        Tally(OC.WAIVED, SV.HIGH, expired_waiver=False),
        Tally(OC.FAIL, SV.HIGH, expired_waiver=True),
        Tally(OC.PASS, SV.HIGH, expired_waiver=False),
    ]
    summary = compliance.summarize(items, "completed", 1, 0)
    assert summary.counts["waived"] == 1
    assert summary.counts["fail"] == 1
    assert summary.counts["pass"] == 1
    assert summary.expired_waivers == 1
    assert summary.compliance_percent == 33.3
    assert summary.open_by_severity["high"] == 1


def test_open_severities_count_fail_error_and_notchecked_only() -> None:
    items = [
        Tally(OC.FAIL, SV.HIGH, expired_waiver=False),
        Tally(OC.ERROR, SV.UNKNOWN, expired_waiver=False),
        Tally(OC.NOTCHECKED, SV.INFO, expired_waiver=False),
        Tally(OC.WAIVED, SV.HIGH, expired_waiver=False),
        Tally(OC.PASS, SV.HIGH, expired_waiver=False),
    ]
    summary = compliance.summarize(items, "completed", 1, 0)
    assert summary.open_by_severity == {"unknown": 1, "info": 1, "low": 0, "medium": 0, "high": 1}


def test_tally_findings_marks_only_expired_exceptions(kit: Any) -> None:
    findings = (kit.expired("a"), kit.waived("b"), kit.finding("c"))
    result = compliance.tally_findings(findings)
    assert [item.expired_waiver for item in result] == [True, False, False]
    assert [item.outcome for item in result] == [OC.FAIL, OC.WAIVED, OC.PASS]


def test_worse_and_higher() -> None:
    assert compliance.worse(OC.PASS, OC.FAIL) is OC.FAIL
    assert compliance.worse(OC.FAIL, OC.PASS) is OC.FAIL
    assert compliance.worse(OC.ERROR, OC.FAIL) is OC.ERROR
    assert compliance.worse(OC.NOTCHECKED, OC.WAIVED) is OC.NOTCHECKED
    assert compliance.worse(OC.NOTAPPLICABLE, OC.DISABLED) is OC.NOTAPPLICABLE
    assert compliance.higher(SV.LOW, SV.HIGH) is SV.HIGH
    assert compliance.higher(SV.HIGH, SV.LOW) is SV.HIGH
    assert compliance.higher(SV.UNKNOWN, SV.INFO) is SV.INFO


def data_for(
    run: model.ScanRun, *, scan_run: bool = True, reported_host: str | None = None
) -> compliance.ComplianceData:
    return compliance.ComplianceData(
        kind="scan_run" if scan_run else "xccdf",
        scan_status=run.status.value,
        error_message=run.error_message,
        benchmark_id=run.benchmark_id,
        benchmark_version=None,
        profile_id=run.profile_id,
        started_at=run.started_at,
        finished_at=run.finished_at,
        host=run.host if scan_run else None,
        reported_host=reported_host,
        input_sha256=hashlib.sha256(model.dumps(run).encode()).hexdigest(),
        content_version=run.content.content_version,
        findings=run.findings,
        not_selected=0,
        scan_run=run if scan_run else None,
        summary=compliance.summarize(compliance.tally_findings(run.findings), "completed", 1, 0),
    )


def test_rollup_deduplicates_by_rule_id_within_one_profile_and_keeps_every_source(
    kit: Any,
) -> None:
    first = kit.scan_run((kit.finding("a"), kit.finding("b", OC.FAIL)))
    second = kit.scan_run((kit.finding("a", OC.FAIL, severity=SV.HIGH), kit.finding("c")))
    rules = compliance.rollup([("one.json", data_for(first)), ("two.json", data_for(second))])
    assert [rule.rule_id.rsplit("_", 1)[-1] for rule in rules] == ["a", "b", "c"]
    merged = rules[0]
    assert merged.outcome is OC.FAIL
    assert merged.severity is SV.HIGH
    assert (merged.benchmark_id, merged.profile_id) == (kit.BENCHMARK, kit.PROFILE)
    assert [source.artifact for source in merged.sources] == ["one.json", "two.json"]
    assert len(rules[1].sources) == 1


def test_rollup_never_pools_benchmarks_or_profiles(kit: Any) -> None:
    cis = kit.scan_run(
        (kit.finding("a"), kit.finding("b", OC.FAIL)), benchmark_id=kit.BENCHMARK + "_cis"
    )
    stig = kit.scan_run(
        (kit.finding("a", OC.FAIL, severity=SV.HIGH), kit.finding("c")),
        benchmark_id=kit.BENCHMARK + "_stig",
    )
    other_profile = dataclasses.replace(cis, profile_id=kit.PROFILE + "_stig")
    entries = [
        ("cis.json", data_for(cis)),
        ("stig.json", data_for(stig)),
        ("profile.json", data_for(other_profile)),
    ]
    rules = compliance.rollup(entries)
    assert len(rules) == 6
    for rule in rules:
        assert len(rule.sources) == 1
        assert rule.sources[0].benchmark_id == rule.benchmark_id
        assert rule.sources[0].profile_id == rule.profile_id


def test_rollup_keeps_different_hosts_and_content_versions_apart(kit: Any) -> None:
    other_host = model.HostIdentity("other.example", "rhel", "9", "x86_64", None)
    runs = [
        kit.scan_run((kit.finding("a"),)),
        kit.scan_run((kit.finding("a", OC.FAIL),), host=other_host),
        kit.scan_run((kit.finding("a", OC.ERROR),), content_version="2.0"),
    ]
    entries = [(f"{index}.json", data_for(run)) for index, run in enumerate(runs)]
    rules = compliance.rollup(entries)
    assert len(rules) == 3
    assert {(rule.host.hostname, rule.content_version, rule.outcome) for rule in rules} == {
        ("host.example", "1.0", OC.PASS),
        ("other.example", "1.0", OC.FAIL),
        ("host.example", "2.0", OC.ERROR),
    }


def test_rollup_never_merges_hostless_inputs(kit: Any) -> None:
    run = kit.scan_run((kit.finding("a"),))
    failing = kit.scan_run((kit.finding("a", OC.FAIL),))
    rules = compliance.rollup(
        [("one.xml", data_for(run, scan_run=False)), ("two.xml", data_for(failing, scan_run=False))]
    )
    assert {(rule.host.hostname, rule.host.input_sha256 != "", rule.outcome) for rule in rules} == {
        ("", True, OC.PASS),
        ("", True, OC.FAIL),
    }
    assert len({rule.host for rule in rules}) == 2


def test_rollup_reports_any_expired_waiver_in_the_group(kit: Any) -> None:
    first = kit.scan_run((kit.expired("a"),))
    second = kit.scan_run((kit.finding("a"),))
    rules = compliance.rollup([("1.json", data_for(first)), ("2.json", data_for(second))])
    assert len(rules) == 1
    assert rules[0].expired_waiver
    assert rules[0].outcome is OC.FAIL


def test_figure_status(kit: Any) -> None:
    run = kit.scan_run((kit.finding("a"), kit.finding("b", OC.FAIL)))
    entry = ("1.json", data_for(run))
    completed = compliance.figure([entry, ("2.json", data_for(run))])
    assert (completed.run_status, completed.compliance_percent) == ("completed", 50.0)
    failed = kit.scan_run((), status=model.ScanStatus.FAILED)
    mixed = compliance.figure([entry, ("2.json", data_for(failed))])
    assert (mixed.run_status, mixed.compliance_percent, mixed.runs_not_completed) == (
        "not_completed",
        None,
        1,
    )
    assert mixed.assessment == ASSESSMENT_RUN_NOT_COMPLETED


def test_a_single_failed_run_keeps_its_own_status(kit: Any) -> None:
    timed_out = kit.scan_run((), status=model.ScanStatus.TIMED_OUT)
    single = compliance.figure([("1.json", data_for(timed_out))])
    assert single.run_status == "timed_out"
    assert single.compliance_percent is None


def test_host_key_uses_fields_not_joined_text(kit: Any) -> None:
    run = kit.scan_run((kit.finding("a"),))
    with_machine = model.HostIdentity("h.example", "rhel", "9", "x86_64", "a" * 32)
    machine_run = kit.scan_run((kit.finding("a"),), host=with_machine)
    key = compliance.HostKey
    assert compliance.host_key(data_for(run)) == key("host.example")
    assert compliance.host_key(data_for(machine_run)) == key("h.example", "a" * 32)
    named = data_for(run, scan_run=False, reported_host="web01")
    assert compliance.host_key(named) == key("web01")
    unnamed = data_for(run, scan_run=False)
    assert compliance.host_key(unnamed) == key(input_sha256=unnamed.input_sha256)
    assert compliance.host_key(unnamed).to_dict() == {
        "hostname": None,
        "input_sha256": unnamed.input_sha256,
        "machine_id": None,
    }
    assert compliance.host_key(machine_run).to_dict()["machine_id"] == "a" * 32


def test_host_names_are_lower_cased_for_scan_runs_and_xccdf_alike(kit: Any) -> None:
    def named(name: str) -> model.ScanRun:
        host = model.HostIdentity(name, "rhel", "9", "x", None)
        run: model.ScanRun = kit.scan_run((kit.finding("a"),), host=host)
        return run

    upper, lower = named("WEB01"), named("web01")
    assert compliance.host_key(data_for(upper)) == compliance.host_key(data_for(lower))
    xccdf_upper = data_for(lower, scan_run=False, reported_host="WEB01")
    assert compliance.host_key(xccdf_upper) == compliance.host_key(data_for(lower))


def test_a_crafted_name_cannot_take_over_another_hosts_key(kit: Any) -> None:
    machine = "a" * 32
    run = kit.scan_run((kit.finding("a"),))

    def scan_key(name: str, machine_id: str | None) -> compliance.HostKey:
        host = model.HostIdentity(name, "rhel", "9", "x", machine_id)
        return compliance.host_key(data_for(kit.scan_run((kit.finding("a"),), host=host)))

    def xccdf_key(name: str | None) -> compliance.HostKey:
        return compliance.host_key(data_for(run, scan_run=False, reported_host=name))

    victim = scan_key("web01", machine)
    predictable = "unnamed:" + hashlib.sha256(b"path.xml").hexdigest()[:16]
    others = [
        scan_key("web01:" + machine, None),
        xccdf_key("web01:" + machine),
        xccdf_key(None),
        xccdf_key(predictable),
    ]
    assert victim.hostname == "web01"
    assert victim.machine_id == machine
    assert victim not in others
    assert xccdf_key(None).hostname == ""
    assert xccdf_key(predictable).input_sha256 == ""


def test_same_hostname_with_different_machine_ids_is_not_merged(kit: Any) -> None:
    first = kit.scan_run(
        (kit.finding("a"),), host=model.HostIdentity("h", "rhel", "9", "x", "1" * 32)
    )
    second = kit.scan_run(
        (kit.finding("a", OC.FAIL),), host=model.HostIdentity("h", "rhel", "9", "x", "2" * 32)
    )
    rules = compliance.rollup([("1", data_for(first)), ("2", data_for(second))])
    assert len(rules) == 2


def test_rollup_records_the_outcome_of_every_source(kit: Any) -> None:
    first = kit.scan_run((kit.finding("a", OC.ERROR),))
    second = kit.scan_run((kit.expired("a"),))
    rule = compliance.rollup([("1.json", data_for(first)), ("2.json", data_for(second))])[0]
    assert rule.outcome is OC.ERROR
    assert not rule.expired_waiver
    assert [
        (source.artifact, source.outcome, source.expired_waiver) for source in rule.sources
    ] == [
        ("1.json", OC.ERROR, False),
        ("2.json", OC.FAIL, True),
    ]


def test_group_figures_are_per_benchmark_version_and_host(kit: Any) -> None:
    other = model.HostIdentity("other.example", "rhel", "9", "x86_64", None)
    entries = [
        ("1", data_for(kit.scan_run((kit.finding("a"),)))),
        ("2", data_for(kit.scan_run((kit.finding("a", OC.FAIL),), host=other))),
        ("3", data_for(kit.scan_run((kit.finding("a", OC.FAIL),), content_version="2.0"))),
        ("4", data_for(kit.scan_run((kit.finding("a"),), benchmark_id=kit.BENCHMARK + "_z"))),
    ]
    groups = compliance.group_figures(entries)
    assert len(groups) == 4
    assert {
        (g.content_version, g.host, g.summary.compliance_percent)
        for g in groups
        if g.benchmark_id == kit.BENCHMARK
    } == {
        ("1.0", compliance.HostKey("host.example"), 100.0),
        ("1.0", compliance.HostKey("other.example"), 0.0),
        ("2.0", compliance.HostKey("host.example"), 0.0),
    }


def test_aggregates_never_pool_benchmarks_or_versions(kit: Any) -> None:
    other = model.HostIdentity("other.example", "rhel", "9", "x86_64", None)
    entries = [
        ("1", data_for(kit.scan_run((kit.finding("a"), kit.finding("b"))))),
        ("2", data_for(kit.scan_run((kit.finding("a", OC.FAIL), kit.finding("b")), host=other))),
        ("3", data_for(kit.scan_run((kit.finding("a", OC.FAIL),), content_version="2.0"))),
    ]
    aggregates = compliance.aggregate_figures(entries, "fleet")
    assert [
        (a.content_version, a.host_count, a.scope, a.summary.compliance_percent) for a in aggregates
    ] == [
        ("1.0", 2, "fleet", 75.0),
        ("2.0", 1, "fleet", 0.0),
    ]
    assert set(compliance.figured(entries)) == {
        (kit.BENCHMARK, "1.0", kit.PROFILE),
        (kit.BENCHMARK, "2.0", kit.PROFILE),
    }
    stig = dataclasses.replace(
        kit.scan_run((kit.finding("a", OC.FAIL),)), profile_id=kit.PROFILE + "_stig"
    )
    pooled = compliance.aggregate_figures([*entries[:1], ("4", data_for(stig))], "fleet")
    assert [(a.profile_id, a.summary.compliance_percent) for a in pooled] == [
        (kit.PROFILE, 100.0),
        (kit.PROFILE + "_stig", 0.0),
    ]


def test_compliance_data_serializes_scan_runs_without_duplicating_findings(kit: Any) -> None:
    run = kit.scan_run((kit.finding("a"),))
    embedded = data_for(run).to_dict()
    assert embedded["findings"] == []
    assert embedded["scan_run"] == run.to_dict()
    flat = data_for(run, scan_run=False).to_dict()
    assert flat["findings"] == [finding.to_dict() for finding in run.findings]
    assert flat["scan_run"] is None
    assert flat["host"] is None
    assert flat["reported_host"] is None
    assert flat["not_selected"] == 0
