from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import xmlsafe
from tools.reporting.common import InvalidInputError, SectionStatus
from tools.reporting.parsers import cobertura, junit, xccdf

if TYPE_CHECKING:
    from collections.abc import Callable

ADVERSARIAL = Path(__file__).resolve().parents[3] / "fixtures" / "adversarial"
BILLION_LAUGHS = (
    b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>'
    b"<testsuite><testcase name='&b;'/></testsuite>"
)
EXTERNAL_ENTITY = (
    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]>'
    b"<testsuite><testcase name='&e;'/></testsuite>"
)
DOCTYPE_ONLY = (
    b'<!DOCTYPE testsuite SYSTEM "http://127.0.0.1:9/x.dtd">'
    b'<testsuite><testcase name="a"/></testsuite>'
)


BAD_PACKAGE_RATE = (
    '<coverage line-rate="1" branch-rate="1"><package line-rate="2" branch-rate="1"/></coverage>'
)


def test_parse_xml_builds_a_tree() -> None:
    root = xmlsafe.parse_xml(b'<a xmlns="urn:x" k="v"><b>text</b><c/></a>')
    assert root.local == "a"
    assert root.attributes == {"k": "v"}
    assert [node.local for node in root.descendants()] == ["a", "b", "c"]
    assert root.children[0].text == "text"
    assert root.children[1].text == ""


@pytest.mark.parametrize(
    "payload",
    [
        BILLION_LAUGHS,
        EXTERNAL_ENTITY,
        DOCTYPE_ONLY,
        b"<a>",
        b"<a></b>",
        b"",
        b"   ",
        b"\xff\xfe<a/>",
    ],
)
def test_parse_xml_rejects_unsafe_or_malformed(payload: bytes) -> None:
    with pytest.raises(InvalidInputError):
        xmlsafe.parse_xml(payload)


def test_parse_xml_rejects_deep_nesting() -> None:
    depth = xmlsafe.MAX_DEPTH + 1
    with pytest.raises(InvalidInputError, match="nesting or element limit"):
        xmlsafe.parse_xml(b"<a>" * depth + b"</a>" * depth)


def test_parse_xml_rejects_too_many_elements(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xmlsafe, "MAX_ELEMENTS", 3)
    with pytest.raises(InvalidInputError, match="nesting or element limit"):
        xmlsafe.parse_xml(b"<a><b/><b/><b/></a>")


@pytest.mark.parametrize(
    "name", ["billion-laughs.xml", "doctype.xml", "external-entity.xml", "parameter-entity.xml"]
)
def test_every_adversarial_fixture_is_an_error_for_every_xml_parser(name: str) -> None:
    path = ADVERSARIAL / name
    for parse in (junit.parse_junit, cobertura.parse_cobertura, xccdf.parse_arf):
        assert parse(path).status is SectionStatus.ERROR


def test_junit_counts_cases_not_attributes(kit: Any) -> None:
    result = junit.parse_junit(kit.REPORTING / "junit.xml")
    assert result.status is SectionStatus.AVAILABLE
    data = result.data
    assert data is not None
    assert (data.total, data.passed, data.failed, data.errors, data.skipped) == (5, 2, 1, 1, 1)
    assert [case.name for case in data.failed_cases] == ["test_fail", "test_error"]
    assert not data.truncated


def test_junit_truncates_the_failure_list(write: Callable[..., Path]) -> None:
    cases = "".join(f'<testcase name="t{i}"><failure/></testcase>' for i in range(1001))
    result = junit.parse_junit(write("j.xml", f"<testsuite>{cases}</testsuite>"))
    assert result.data is not None
    assert result.data.failed == 1001
    assert len(result.data.failed_cases) == 1000
    assert result.data.truncated


@pytest.mark.parametrize(
    "document",
    ["<other/>", "<testsuite/>", "<testsuites><testsuite/></testsuites>", "<testsuite><testcase"],
)
def test_junit_rejects_unexpected_documents(write: Callable[..., Path], document: str) -> None:
    assert junit.parse_junit(write("j.xml", document)).status is SectionStatus.ERROR


def test_junit_names_default_and_markup_stays_data(write: Callable[..., Path]) -> None:
    document = (
        '<testsuite><testcase><failure message="&lt;/script&gt;&amp;"/></testcase></testsuite>'
    )
    result = junit.parse_junit(write("j.xml", document))
    assert result.data is not None
    case = result.data.failed_cases[0]
    assert (case.name, case.classname, case.message) == ("unnamed", None, "</script>&")


def test_junit_large_valid_report_parses_within_bounds(write: Callable[..., Path]) -> None:
    cases = "".join(f'<testcase classname="c" name="t{i}"/>' for i in range(20000))
    result = junit.parse_junit(write("j.xml", f"<testsuite>{cases}</testsuite>"))
    assert result.data is not None
    assert result.data.total == 20000


def test_junit_huge_input_is_rejected_by_the_size_limit(write: Callable[..., Path]) -> None:
    path = write("j.xml", "<testsuite>" + "<testcase name='a'/>" * 100 + "</testsuite>")
    assert junit.parse_junit(path, 100).status is SectionStatus.ERROR


def test_cobertura_rates_counts_and_packages(kit: Any) -> None:
    result = cobertura.parse_cobertura(kit.REPORTING / "cobertura.xml")
    data = result.data
    assert data is not None
    assert (data.line_rate, data.branch_rate) == (0.9, 0.8)
    assert (data.lines_valid, data.lines_covered) == (100, 90)
    assert (data.branches_valid, data.branches_covered) == (10, 8)
    assert [package.name for package in data.packages] == ["tools.alpha", "tools.beta"]
    assert not data.truncated


def test_cobertura_counts_are_optional_and_package_names_default(
    write: Callable[..., Path],
) -> None:
    package = '<package line-rate="0" branch-rate="0"/>'
    document = f'<coverage line-rate="1" branch-rate="0">{package}</coverage>'
    data = cobertura.parse_cobertura(write("c.xml", document)).data
    assert data is not None
    assert data.lines_valid is None
    assert data.packages[0].name == "."


def test_cobertura_truncates_packages(write: Callable[..., Path]) -> None:
    packages = "".join(
        f'<package name="p{i:04d}" line-rate="1" branch-rate="1"/>' for i in range(1001)
    )
    data = cobertura.parse_cobertura(
        write("c.xml", f'<coverage line-rate="1" branch-rate="1">{packages}</coverage>')
    ).data
    assert data is not None
    assert len(data.packages) == 1000
    assert data.truncated


@pytest.mark.parametrize(
    "document",
    [
        "<other/>",
        '<coverage branch-rate="1"/>',
        '<coverage line-rate="1"/>',
        '<coverage line-rate="abc" branch-rate="1"/>',
        '<coverage line-rate="1.5" branch-rate="1"/>',
        '<coverage line-rate="nan" branch-rate="1"/>',
        '<coverage line-rate="1" branch-rate="1" lines-valid="-3"/>',
        '<coverage line-rate="1" branch-rate="1" lines-valid="x"/>',
        BAD_PACKAGE_RATE,
    ],
)
def test_cobertura_rejects_bad_values(write: Callable[..., Path], document: str) -> None:
    assert cobertura.parse_cobertura(write("c.xml", document)).status is SectionStatus.ERROR


def test_xccdf_maps_results_with_the_plugin_parser(kit: Any) -> None:
    result = xccdf.parse_xccdf(kit.XCCDF / "mixed-results.xml")
    data = result.data
    assert data is not None
    assert (data.kind, data.scan_status, data.host) == ("xccdf", "completed", None)
    assert data.benchmark_id == kit.BENCHMARK
    assert data.content_version == "1.0"
    counts = data.summary.counts
    assert (counts["pass"], counts["fail"], counts["notchecked"], counts["error"]) == (2, 1, 2, 2)
    assert data.summary.evaluated == 7
    assert data.summary.compliance_percent == 28.5
    assert data.not_selected == 1
    assert data.summary.not_selected == 1
    assert len(data.findings) == 8
    assert data.reported_host is None


def test_notselected_rules_never_enter_the_compliance_maths(
    kit: Any, write: Callable[..., Path]
) -> None:
    results = [(f"selected_{i}", "pass") for i in range(10)]
    results += [(f"other_{i}", "notselected") for i in range(90)]
    data = xccdf.parse_xccdf(write("x.xml", kit.xccdf_text("web01.example", results=results))).data
    assert data is not None
    assert data.summary.compliance_percent == 100.0
    assert data.summary.evaluated == 10
    assert data.summary.counts["notchecked"] == 0
    assert data.summary.not_selected == 90
    assert data.not_selected == 90
    assert len(data.findings) == 10
    assert data.summary.open_by_severity["medium"] == 0


def test_reported_host_comes_from_target_or_fqdn_fact(kit: Any, write: Callable[..., Path]) -> None:
    named = xccdf.parse_xccdf(write("a.xml", kit.xccdf_text(" Web01.Example "))).data
    assert named is not None
    assert named.reported_host == "web01.example"
    anonymous = xccdf.parse_xccdf(write("b.xml", kit.xccdf_text(None))).data
    assert anonymous is not None
    assert anonymous.reported_host is None
    blank = xccdf.parse_xccdf(write("c.xml", kit.xccdf_text("   "))).data
    assert blank is not None
    assert blank.reported_host is None
    fact = (
        '<target-facts><fact name="urn:xccdf:fact:asset:identifier:fqdn">fact.example</fact>'
        '<fact name="other">x</fact></target-facts>'
    )
    document = kit.xccdf_text("target.example").replace("</TestResult>", f"{fact}</TestResult>")
    both = xccdf.parse_xccdf(write("d.xml", document)).data
    assert both is not None
    assert both.reported_host == "fact.example"


def test_xccdf_rejects_what_the_plugin_parser_rejects(kit: Any) -> None:
    result = xccdf.parse_xccdf(kit.XCCDF.parent / "adversarial" / "no-test-result.xml")
    assert result.status is SectionStatus.ERROR
    assert result.reason is not None
    assert result.reason.startswith("XCCDF results rejected")


def test_xccdf_rejects_non_utf8(write: Callable[..., Path]) -> None:
    assert xccdf.parse_xccdf(write("x.xml", b"\xff\xfe<a/>")).status is SectionStatus.ERROR


def test_arf_extracts_the_embedded_test_result(kit: Any) -> None:
    data = xccdf.parse_arf(kit.REPORTING / "arf.xml").data
    assert data is not None
    assert data.kind == "arf"
    assert [finding.rule_id.rsplit("_", 1)[-1] for finding in data.findings] == ["alpha", "beta"]
    assert data.reported_host == "host.example"


def test_arf_rejects_wrong_root_and_wrong_result_counts(
    kit: Any, write: Callable[..., Path]
) -> None:
    assert xccdf.parse_arf(kit.XCCDF / "mixed-results.xml").status is SectionStatus.ERROR
    arf = (kit.REPORTING / "arf.xml").read_text(encoding="utf-8")
    block = arf[arf.index("<TestResult") : arf.index("</TestResult>") + len("</TestResult>")]
    empty = arf.replace(block, "")
    doubled = arf.replace(block, block + block)
    for text in (empty, doubled):
        result = xccdf.parse_arf(write("a.xml", text))
        assert result.status is SectionStatus.ERROR
        assert result.reason is not None
        assert "exactly one" in result.reason


def test_arf_notselected_rules_are_counted_separately(kit: Any, write: Callable[..., Path]) -> None:
    arf = (kit.REPORTING / "arf.xml").read_text(encoding="utf-8")
    extra = "".join(
        f'<rule-result idref="xccdf_org.example.synthetic_rule_n{i}"><result>notselected</result>'
        "</rule-result>"
        for i in range(5)
    )
    data = xccdf.parse_arf(
        write("a.xml", arf.replace("</TestResult>", f"{extra}</TestResult>"))
    ).data
    assert data is not None
    assert data.not_selected == 5
    assert data.summary.compliance_percent == 50.0
    assert len(data.findings) == 2


def test_arf_asset_must_match_the_target(kit: Any, write: Callable[..., Path]) -> None:
    arf = (kit.REPORTING / "arf.xml").read_text(encoding="utf-8")
    result = xccdf.parse_arf(
        write("a.xml", arf.replace("<target>host.example", "<target>other.example"))
    )
    assert result.status is SectionStatus.ERROR
    assert result.reason is not None
    assert "different host" in result.reason


def test_arf_asset_with_other_children_and_no_names_is_accepted(
    kit: Any, write: Callable[..., Path]
) -> None:
    arf = (kit.REPORTING / "arf.xml").read_text(encoding="utf-8")
    arf = arf.replace(
        "<ai:fqdn>Host.Example</ai:fqdn>",
        "<ai:ip-address>10.0.0.1</ai:ip-address><ai:hostname> </ai:hostname>",
    )
    arf = arf.replace("<ai:hostname>host</ai:hostname>", "")
    data = xccdf.parse_arf(write("a.xml", arf)).data
    assert data is not None
    assert data.reported_host == "host.example"


JUNIT_MISMATCHES = [
    '<testsuite tests="2"><testcase name="a"/></testsuite>',
    '<testsuite failures="1"><testcase name="a"/></testsuite>',
    '<testsuite errors="1"><testcase name="a"><failure/></testcase></testsuite>',
    '<testsuites><testsuite tests="3"><testcase name="a"/></testsuite></testsuites>',
]


@pytest.mark.parametrize("document", JUNIT_MISMATCHES)
def test_junit_suite_attributes_must_match_the_cases(
    write: Callable[..., Path], document: str
) -> None:
    result = junit.parse_junit(write("j.xml", document))
    assert result.status is SectionStatus.ERROR
    assert result.reason is not None
    assert "does not match" in result.reason


def test_junit_matching_suite_attributes_are_accepted(write: Callable[..., Path]) -> None:
    document = (
        '<testsuite tests="3" failures="1" errors="1"><testcase name="a"/>'
        '<testcase name="b"><failure/></testcase><testcase name="c"><error/></testcase></testsuite>'
    )
    data = junit.parse_junit(write("j.xml", document)).data
    assert data is not None
    assert (data.total, data.failed, data.errors) == (3, 1, 1)


def test_cobertura_covered_counts_cannot_exceed_valid_counts(write: Callable[..., Path]) -> None:
    for kind in ("lines", "branches"):
        document = f'<coverage line-rate="1" branch-rate="1" {kind}-valid="1" {kind}-covered="2"/>'
        assert cobertura.parse_cobertura(write("c.xml", document)).status is SectionStatus.ERROR


def test_xccdf_rule_results_are_bounded_by_the_model_limit(
    kit: Any, write: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(model, "MAX_FINDINGS", 2)
    results = [(f"r{i}", "pass") for i in range(3)]
    result = xccdf.parse_xccdf(write("x.xml", kit.xccdf_text("h", results=results)))
    assert result.status is SectionStatus.ERROR
    assert result.reason is not None
    assert "more than 2" in result.reason
    arf = (kit.REPORTING / "arf.xml").read_text(encoding="utf-8")
    extra = "".join(
        f'<rule-result idref="xccdf_org.example.synthetic_rule_x{i}">'
        "<result>pass</result></rule-result>"
        for i in range(2)
    )
    over = xccdf.parse_arf(write("a.xml", arf.replace("</TestResult>", f"{extra}</TestResult>")))
    assert over.status is SectionStatus.ERROR
