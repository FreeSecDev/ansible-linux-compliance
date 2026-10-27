"""The rule version that a DISA benchmark uses for the STIG ID of a rule (FREES-170)."""

from __future__ import annotations

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import catalog
from tests.unit.plugins.module_utils.compliance.test_catalog_stig_ids import PROFILE, RULE, parse

NS = 'xmlns:x="http://checklists.nist.gov/xccdf/1.2"'


def document(rule_body: str) -> bytes:
    profile = (
        f'<x:Profile id="{PROFILE}"><x:title>STIG</x:title>'
        f'<x:select idref="{RULE}a" selected="true"/></x:Profile>'
    )
    rule = f'<x:Rule id="{RULE}a"><x:title>A</x:title>{rule_body}</x:Rule>'
    body = f'<x:Benchmark {NS} id="xccdf_org.example.synthetic_benchmark_demo">'
    return f"{body}<x:version>001.005.007</x:version>{profile}{rule}</x:Benchmark>".encode()


def test_the_first_rule_version_is_kept_cleaned() -> None:
    versions = "<x:version> UBTU-24-100010 </x:version><x:version>UBTU-24-999999</x:version>"
    benchmark = parse(document(versions))
    assert benchmark.rules[0].version == "UBTU-24-100010"
    assert benchmark.version == "001.005.007"


def test_a_rule_without_a_version_has_an_empty_one() -> None:
    assert parse(document("")).rules[0].version == ""


def test_the_rule_version_does_not_replace_the_benchmark_version() -> None:
    benchmark = parse(document("<x:version>UBTU-24-100010</x:version>"))
    assert benchmark.version == "001.005.007"
    assert catalog.profile_rules(benchmark, benchmark.profiles[0])[0].version == "UBTU-24-100010"
