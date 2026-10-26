from __future__ import annotations

from typing import Any

import pytest

from tools.reporting import stig_content
from tools.reporting.common import InvalidInputError

NS = "http://checklists.nist.gov/xccdf/1.2"


def read(xml: str) -> tuple[stig_content.StigBenchmark, ...]:
    return stig_content.read_benchmarks(xml.encode("utf-8"))


def test_a_benchmark_gives_its_rules_in_document_order(stig: Any) -> None:
    benchmark = read(stig.benchmark_xml(rules=3))[0]
    assert benchmark.stig_id == "Synthetic_Linux_STIG"
    assert benchmark.version == stig.VERSION
    assert benchmark.release_info == "Release: 2 Benchmark Date: 01 Oct 2026"
    assert benchmark.notice == "terms-of-use"
    assert benchmark.target is None
    assert [rule.group_id for rule in benchmark.rules] == ["V-900001", "V-900002", "V-900003"]
    first = benchmark.rules[0]
    assert first.rule_ref == "SV-900001r1_rule"
    assert first.check_ref == ("synthetic-oval.xml", "oval:syn:def:1")
    assert first.check_content == "Synthetic check 1."
    assert first.ccis == ("CCI-000001",)
    assert first.legacy_ids == ("SV-1",)
    assert first.description["Documentable"] == "false"
    assert first.description["Mitigations"] == ""
    assert first.group_description == "<GroupDescription></GroupDescription>"
    assert set(benchmark.rule_map()) == {rule.rule_id for rule in benchmark.rules}


def test_a_data_stream_gives_every_benchmark_of_its_components(stig: Any) -> None:
    other = stig.benchmark_xml(rules=1, benchmark="xccdf_mil.disa.stig_benchmark_Other_STIG")
    found = read(stig.data_stream(stig.benchmark_xml(rules=2), "<other/>", other))
    assert [item.stig_id for item in found] == ["Synthetic_Linux_STIG", "Other_STIG"]


def test_nested_groups_and_foreign_rules_are_handled(stig: Any) -> None:
    nested = (
        f'<Benchmark xmlns="{NS}" id="xccdf_mil.disa.stig_benchmark_X"><version>1</version>'
        '<Group id="xccdf_org.example_group_outer">'
        f"{stig.group(1, 'low')}"
        '<Rule id="xccdf_org.ssgproject.content_rule_x" severity="low"/></Group>'
        '<Group id="xccdf_mil.disa.stig_group_V-1">'
        '<Rule id="xccdf_org.ssgproject.content_rule_y" severity="low"/></Group>'
        '<Group id="xccdf_mil.disa.stig_group_V-2"><Rule id="xccdf_mil.disa.stig_rule_SV-2r1_rule" '
        'severity="medium"><check><check-content>  </check-content></check></Rule></Group>'
        "</Benchmark>"
    )
    benchmark = read(nested)[0]
    assert [rule.rule_ref for rule in benchmark.rules] == ["SV-900001r1_rule", "SV-2r1_rule"]
    bare = benchmark.rules[1]
    assert (bare.title, bare.version, bare.weight, bare.check_ref) == ("", "", "10.0", ("", ""))
    assert (bare.check_content, bare.target_key, bare.ccis) == ("", "", ())
    assert bare.description["VulnDiscussion"] == ""
    assert (benchmark.title, benchmark.release_info, benchmark.notice) == ("", "", "")


def test_the_target_facts_are_read_and_loopback_addresses_dropped(stig: Any) -> None:
    benchmark = read(stig.benchmark_xml(rules=1, test_result=stig.result_xml()))[0]
    assert benchmark.target is not None
    assert benchmark.target.names == ("web01", "web01")
    assert benchmark.target.fqdns == ("web01.example",)
    assert benchmark.target.addresses == ("192.0.2.10", "2001:db8::10")
    assert benchmark.target.profile_id == stig.PROFILE
    assert benchmark.target.benchmark_id == stig.BENCHMARK
    bare = read(stig.benchmark_xml(rules=1, test_result='<TestResult id="t"/>'))[0]
    assert bare.target == stig_content.TargetFacts((), (), (), None, None)


def test_addresses_that_are_not_ip_addresses_are_ignored(stig: Any) -> None:
    result = stig.result_xml(addresses=("not-an-address", "::", "198.51.100.7"))
    benchmark = read(stig.benchmark_xml(rules=1, test_result=result))[0]
    assert benchmark.target is not None
    assert benchmark.target.addresses == ("198.51.100.7",)


@pytest.mark.parametrize(
    ("xml", "message"),
    [
        ("<Benchmark/>", "neither an XCCDF 1.2 benchmark nor a SCAP source data stream"),
        (
            '<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"/>',
            "holds no XCCDF 1.2 benchmark",
        ),
        ("<!DOCTYPE x [<!ENTITY a 'b'>]><x>&a;</x>", "malformed or unsafe"),
    ],
)
def test_content_that_is_not_a_benchmark_is_refused(xml: str, message: str) -> None:
    with pytest.raises(InvalidInputError, match=message):
        read(xml)


def test_a_rule_without_a_disa_severity_or_listed_twice_is_refused(stig: Any) -> None:
    with pytest.raises(InvalidInputError, match="has no severity of high, medium or low"):
        read(stig.benchmark_xml(rules=1).replace('severity="high"', 'severity="unknown"'))
    twice = stig.benchmark_xml(rules=1).replace(
        "</Benchmark>", stig.group(1, "low") + "</Benchmark>"
    )
    with pytest.raises(InvalidInputError, match="lists a DISA rule more than once"):
        read(twice)


def test_two_test_results_are_refused(stig: Any) -> None:
    result = stig.result_xml()
    with pytest.raises(InvalidInputError, match="more than one TestResult"):
        read(stig.benchmark_xml(rules=1, test_result=result + result))


def test_description_fields_unescape_and_clean_their_text() -> None:
    fields = stig_content.description_fields(
        "<VulnDiscussion>a &lt;b&gt; &amp;amp; \u202e c</VulnDiscussion><IAControls>x</IAControls>"
    )
    assert fields["VulnDiscussion"] == "a <b> &amp;  c"
    assert fields["IAControls"] == "x"
    assert fields["Responsibility"] == ""
