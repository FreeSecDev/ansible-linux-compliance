from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model

GOLDEN = Path(__file__).resolve().parents[4] / "fixtures" / "checklist"
NS = "http://checklists.nist.gov/xccdf/1.2"
DS = "http://scap.nist.gov/schema/scap/source/1.2"
DC = "http://purl.org/dc/elements/1.1/"
BENCHMARK = "xccdf_mil.disa.stig_benchmark_Synthetic_Linux_STIG"
PROFILE = "xccdf_mil.disa.stig_profile_MAC-1_Classified"
VERSION = "001.002.003"
STARTED = "2026-10-26T09:00:00Z"
FINISHED = "2026-10-26T09:00:30Z"
HOST = model.HostIdentity("web01.example", "ubuntu", "24.04", "x86_64", "e" * 32)
SEVERITIES = ("high", "medium", "low", "medium", "medium", "low", "high", "medium", "low", "low")
CONTENT_FILE = "synthetic-linux-stig-ds.xml"


def rule_id(number: int) -> str:
    return f"xccdf_mil.disa.stig_rule_SV-90{number:04d}r1_rule"


def group(number: int, severity: str, title: str | None = None) -> str:
    shown = title or f"Synthetic requirement {number} must hold"
    return (
        f'<Group id="xccdf_mil.disa.stig_group_V-90{number:04d}">'
        f"<title>SRG-SYN-{number:06d}</title>"
        "<description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>"
        f'<Rule id="{rule_id(number)}" severity="{severity}" weight="10.0">'
        f"<version>SYN-00-{number:06d}</version><title>{shown}</title>"
        f"<description>&lt;VulnDiscussion&gt;Synthetic discussion {number} &amp;amp; "
        "notes&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;"
        "&lt;Documentable&gt;false&lt;/Documentable&gt;</description>"
        f'<reference><dc:type xmlns:dc="{DC}">DPMS Target</dc:type>'
        f'<dc:identifier xmlns:dc="{DC}">9999</dc:identifier></reference>'
        f'<ident system="http://cyber.mil/cci">CCI-{number:06d}</ident>'
        '<ident system="http://cyber.mil/legacy">SV-1</ident>'
        f'<fixtext fixref="F-{number}r1_fix">Synthetic fix {number}.</fixtext>'
        '<check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">'
        f'<check-content-ref href="synthetic-oval.xml" name="oval:syn:def:{number}"/></check>'
        '<check system="http://scap.nist.gov/schema/ocil/2"><check-content>Synthetic check '
        f"{number}.</check-content></check></Rule></Group>"
    )


def benchmark_xml(
    *,
    rules: int = 10,
    test_result: str = "",
    benchmark: str = BENCHMARK,
    version: str = VERSION,
    titles: dict[int, str] | None = None,
) -> str:
    groups = "".join(
        group(number, SEVERITIES[(number - 1) % len(SEVERITIES)], (titles or {}).get(number))
        for number in range(1, rules + 1)
    )
    return (
        f'<Benchmark xmlns="{NS}" id="{benchmark}"><status>accepted</status>'
        "<title>Synthetic Linux STIG SCAP Benchmark</title>"
        "<description>A synthetic benchmark for the exporter tests.</description>"
        '<notice id="terms-of-use"/>'
        '<plain-text id="generator">synthetic</plain-text>'
        '<plain-text id="release-info">Release: 2 Benchmark Date: 01 Oct 2026</plain-text>'
        f"<version>{version}</version>{groups}{test_result}</Benchmark>"
    )


RAW_RESULTS: dict[model.Outcome, str] = {
    model.Outcome.PASS: "pass",
    model.Outcome.FAIL: "fail",
    model.Outcome.WAIVED: "fail",
    model.Outcome.NOTAPPLICABLE: "notapplicable",
    model.Outcome.NOTCHECKED: "notchecked",
    model.Outcome.ERROR: "error",
    model.Outcome.DISABLED: "notselected",
}


def raw_result(finding: model.Finding) -> str:
    if model.ResultFlag.FIXED in finding.flags:
        return "fixed"
    if model.ResultFlag.INFORMATIONAL in finding.flags:
        return "informational"
    return RAW_RESULTS[finding.outcome]


def rule_results(findings: tuple[model.Finding, ...]) -> str:
    return "".join(
        f'<rule-result idref="{item.rule_id}"><result>{raw_result(item)}</result></rule-result>'
        for item in findings
    )


def result_xml(
    *, findings: tuple[model.Finding, ...] | None = None, **facts: str | tuple[str, ...]
) -> str:
    target = str(facts.get("target", "web01"))
    fqdn = str(facts.get("fqdn", "web01.example"))
    profile = str(facts.get("profile", PROFILE))
    benchmark = str(facts.get("benchmark", BENCHMARK))
    addresses = facts.get("addresses", ("127.0.0.1", "192.0.2.10", "fe80::1", "2001:db8::10"))
    address = "".join(f"<target-address>{item}</target-address>" for item in addresses)
    return (
        '<TestResult id="xccdf_mil.disa.stig_testresult_1" start-time="2026-10-26T09:00:00" '
        f'end-time="2026-10-26T09:00:30" version="{VERSION}">'
        f'<benchmark id="{benchmark}"/><profile idref="{profile}"/>'
        f"<target>{target}</target>{address}<target-facts>"
        f'<fact name="urn:scap:fact:asset:identifier:host_name" type="string">{target}</fact>'
        f'<fact name="urn:scap:fact:asset:identifier:fqdn" type="string">{fqdn}</fact>'
        "</target-facts>"
        f"{rule_results(mixed_findings() if findings is None else findings)}</TestResult>"
    )


def data_stream(*benchmarks: str) -> str:
    components = "".join(
        f'<ds:component id="scap_syn_comp_{index}">{body}</ds:component>'
        for index, body in enumerate(benchmarks)
    )
    return f'<ds:data-stream-collection xmlns:ds="{DS}">{components}</ds:data-stream-collection>'


def finding(number: int, outcome: model.Outcome, **options: Any) -> model.Finding:
    return model.Finding(
        rule_id=rule_id(number),
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


WAIVER = model.ExceptionStatus(
    model.ExceptionState.ACTIVE,
    "EXC-STIG-1",
    "Accepted risk: the synthetic service needs it",
    "2026-12-31T00:00:00Z",
)
EXPIRED = model.ExceptionStatus(
    model.ExceptionState.EXPIRED, "EXC-STIG-2", "Old risk acceptance", "2026-10-01T00:00:00Z"
)


def mixed_findings() -> tuple[model.Finding, ...]:
    return (
        finding(1, model.Outcome.PASS),
        finding(2, model.Outcome.FAIL, message="value is 0; expected 1"),
        finding(3, model.Outcome.NOTAPPLICABLE),
        finding(4, model.Outcome.NOTCHECKED, flags=(model.ResultFlag.INFORMATIONAL,)),
        finding(5, model.Outcome.ERROR, message="SCC reported 'unknown' for this rule"),
        finding(6, model.Outcome.WAIVED, evaluated=model.Outcome.FAIL, exception=WAIVER),
        finding(7, model.Outcome.FAIL, exception=EXPIRED),
        finding(8, model.Outcome.DISABLED, disabled_by="linux_compliance_rule_synthetic"),
        finding(9, model.Outcome.PASS, flags=(model.ResultFlag.FIXED,)),
    )


def scan_run(findings: tuple[model.Finding, ...] | None = None, **options: Any) -> model.ScanRun:
    status = options.get("status", model.ScanStatus.COMPLETED)
    return model.ScanRun(
        run_id=options.get("run_id", "run-web01"),
        started_at=STARTED,
        finished_at=FINISHED,
        host=options.get("host", HOST),
        scanner=model.ScannerInfo("scc", "5.15"),
        content=model.Provenance(CONTENT_FILE, options.get("version", VERSION), "b" * 64),
        benchmark_id=options.get("benchmark", BENCHMARK),
        profile_id=PROFILE,
        status=status,
        error_message=None if status is model.ScanStatus.COMPLETED else "the scanner timed out",
        findings=mixed_findings() if findings is None else findings,
        off_platform=options.get("off_platform"),
    )


OFF_PLATFORM = model.OffPlatform(
    model.Platform("ubuntu", "24.04"), model.Platform("ubuntu", "26.04")
)
OFF_PLATFORM_HOST = model.HostIdentity("web26.example", "ubuntu", "26.04", "x86_64", None)


class StigKit:
    """Synthetic DISA-shaped content and scan runs; no DISA benchmark text."""

    BENCHMARK = BENCHMARK
    PROFILE = PROFILE
    VERSION = VERSION
    HOST = HOST
    GOLDEN = GOLDEN
    WAIVER = WAIVER
    EXPIRED = EXPIRED
    OFF_PLATFORM = OFF_PLATFORM
    OFF_PLATFORM_HOST = OFF_PLATFORM_HOST
    CONTENT_FILE = CONTENT_FILE
    rule_id = staticmethod(rule_id)
    group = staticmethod(group)
    benchmark_xml = staticmethod(benchmark_xml)
    result_xml = staticmethod(result_xml)
    data_stream = staticmethod(data_stream)
    finding = staticmethod(finding)
    rule_results = staticmethod(rule_results)
    mixed_findings = staticmethod(mixed_findings)
    scan_run = staticmethod(scan_run)


@pytest.fixture
def stig() -> type[StigKit]:
    return StigKit
