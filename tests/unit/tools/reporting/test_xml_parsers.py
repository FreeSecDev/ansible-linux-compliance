from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

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
    assert (counts["pass"], counts["fail"], counts["notchecked"], counts["error"]) == (2, 1, 3, 2)
    assert data.summary.evaluated == 8
    assert data.summary.compliance_percent == 25.0


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
