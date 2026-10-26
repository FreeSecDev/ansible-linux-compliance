from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import catalog

NS = 'xmlns:x="http://checklists.nist.gov/xccdf/1.2"'
STIG = next(iter(catalog.STIG_ID_REFERENCES))
SRG = (
    "https://www.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cgeneral-purpose-os"
)
RULE = "xccdf_org.example.synthetic_rule_"
PROFILE = "xccdf_org.example.synthetic_profile_stig"


def document(references: str, profile_versions: str = "") -> bytes:
    profile = (
        f'<x:Profile id="{PROFILE}">{profile_versions}<x:title>STIG</x:title>'
        f'<x:select idref="{RULE}a" selected="true"/></x:Profile>'
    )
    rule = f'<x:Rule id="{RULE}a"><x:title>A</x:title>{references}</x:Rule>'
    body = f'<x:Benchmark {NS} id="xccdf_org.example.synthetic_benchmark_demo">'
    return f"{body}<x:version>1.0</x:version>{profile}{rule}</x:Benchmark>".encode()


def parse(data: bytes) -> catalog.Benchmark:
    return catalog.single_benchmark(catalog.parse_benchmarks([data]))


def test_only_the_own_text_of_stig_id_references_is_kept_in_document_order() -> None:
    references = (
        f'<x:reference href="{SRG}">SRG-OS-000001-GPOS-00001</x:reference>'
        f'<x:reference href="{STIG}"> SYNT-01-000020 </x:reference>'
        f'<x:reference href="{STIG}">SYNT-01-<x:b>000010</x:b></x:reference>'
        "<x:reference>SYNT-01-000030</x:reference>"
    )
    benchmark = parse(document(references))
    assert benchmark.rules[0].stig_ids == ("SYNT-01-000020", "SYNT-01-")


def test_a_rule_without_references_has_no_stig_ids_and_a_profile_no_version() -> None:
    benchmark = parse(document(""))
    assert benchmark.rules[0].stig_ids == ()
    assert benchmark.profiles[0].version == ""


def test_the_first_profile_version_is_kept() -> None:
    versions = "<x:version>V1R5</x:version><x:version>V9R9</x:version>"
    assert parse(document("", versions)).profiles[0].version == "V1R5"


def test_too_many_stig_id_references_are_refused() -> None:
    references = f'<x:reference href="{STIG}">SYNT-01-000010</x:reference>' * (
        catalog.MAX_STIG_IDS + 1
    )
    with pytest.raises(catalog.CatalogError, match="more than 64 STIG ID references"):
        parse(document(references))
