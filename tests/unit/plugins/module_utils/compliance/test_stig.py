"""The STIG mapping of collection toggles and control families to SCC rules (FREES-170)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    placement,
    stig,
)

SCC_BENCHMARK = "xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG"
CAC_BENCHMARK, CAC_PROFILE = stig.STIG_PROFILES[SCC_BENCHMARK]
CAC = "xccdf_org.ssgproject.content_rule_"
DISA = "xccdf_mil.disa.stig_rule_SV-"


def mapping_document(**overrides: Any) -> dict[str, Any]:
    profile: dict[str, Any] = {
        "profile_id": CAC_PROFILE,
        "stig_release": "V1R5",
        "stig_ids": {
            "UBTU-24-100010": [CAC + "sshd_banner"],
            "UBTU-24-100020": [CAC + "banner_issue_net", CAC + "sshd_banner_net"],
            "UBTU-24-100030": [CAC + "audit_sshd", CAC + "sshd_ciphers", CAC + "sshd_macs"],
            "UBTU-24-100040": [CAC + "uncatalogued_rule"],
        },
        "rules_without_stig_id": [],
    }
    profile.update(overrides)
    stream = {
        "name": "ubuntu2404",
        "file_name": "ssg-ubuntu2404-ds.xml",
        "sha256": "0" * 64,
        "benchmark_id": CAC_BENCHMARK,
        "benchmark_version": "0.1.82",
        "profiles": [profile],
    }
    return {
        "schema_version": 1,
        "generator": "tools/content/generate_stig_mapping.py",
        "source": "ComplianceAsCode/content v0.1.82",
        "join_key": "STIG ID",
        "datastreams": [stream],
    }


def mapping_text(**overrides: Any) -> str:
    return json.dumps(mapping_document(**overrides))


FAMILIES = stig.Families(
    family_of={
        CAC + "sshd_banner": "ssh",
        CAC + "banner_issue_net": "banners",
        CAC + "sshd_banner_net": "ssh",
        CAC + "audit_sshd": "auditd",
        CAC + "sshd_ciphers": "ssh",
        CAC + "sshd_macs": "ssh",
    },
    umbrellas={"faillock": "pam"},
    tags_of={CAC + "sshd_ciphers": ("crypto_policy",)},
)


def scc_rule(number: int, stig_id: str | None) -> stig.SccRule:
    return stig.SccRule(f"{DISA}{number}r1_rule", stig_id)


RULES = (
    scc_rule(1, "UBTU-24-100010"),
    scc_rule(2, "UBTU-24-100020"),
    scc_rule(3, "UBTU-24-100030"),
    scc_rule(4, "UBTU-24-100040"),
    scc_rule(5, "UBTU-24-999999"),
    scc_rule(6, None),
)


def profile() -> stig.StigProfile:
    return stig.mapping_for(mapping_text(), SCC_BENCHMARK, "001.005.007")


def by_rule(items: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(item["rule_id"]): item for item in items}


class TestMapping:
    """Reading the pinned mapping and checking its release against the SCC benchmark."""

    def test_the_paired_profile_is_read_with_its_release(self) -> None:
        read = profile()
        assert (read.benchmark_id, read.profile_id, read.stig_release) == (
            CAC_BENCHMARK,
            CAC_PROFILE,
            "V1R5",
        )
        assert read.checks["UBTU-24-100020"] == (CAC + "banner_issue_net", CAC + "sshd_banner_net")
        assert CAC + "uncatalogued_rule" in read.mapped_rules()

    def test_a_release_mismatch_is_refused(self) -> None:
        with pytest.raises(stig.MappingError, match="implements V1R5, but the SCC benchmark"):
            stig.mapping_for(mapping_text(), SCC_BENCHMARK, "001.006.001")
        with pytest.raises(stig.MappingError, match="is no DISA release"):
            stig.mapping_for(mapping_text(), SCC_BENCHMARK, "draft")
        with pytest.raises(stig.MappingError, match="implements V2R1"):
            stig.mapping_for(mapping_text(stig_release="V2R1"), SCC_BENCHMARK, "001.005.007")

    def test_a_benchmark_without_a_paired_mapping_is_refused(self) -> None:
        with pytest.raises(stig.MappingError, match="no STIG mapping is paired"):
            stig.mapping_for(mapping_text(), "xccdf_mil.disa.stig_benchmark_Other", "001.005")

    @pytest.mark.parametrize(
        ("version", "info", "release"),
        [
            ("001.005.007", "", "V1R5"),
            ("2.12", "", "V2R12"),
            ("1", "Release: 5 Benchmark Date: 01 Jul 2026", "V1R5"),
            ("1", "no release", None),
            ("V1R5", "", None),
        ],
    )
    def test_the_release_of_a_disa_version(
        self, version: str, info: str, release: str | None
    ) -> None:
        assert stig.release_of(version, info) == release

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            (1, "must be the text of the file"),
            ("{", "not valid JSON"),
            ('{"a": 1, "a": 2}', "repeats the key 'a'"),
            ("[]", "the STIG mapping must be an object"),
            ('{"schema_version": 1}', "must have exactly the keys"),
        ],
    )
    def test_an_invalid_document_is_refused(self, text: object, message: str) -> None:
        with pytest.raises(stig.MappingError, match=message):
            stig.read_profile(text, CAC_BENCHMARK, CAC_PROFILE)

    def test_an_oversized_document_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(stig, "MAX_MAPPING_CHARS", 10)
        with pytest.raises(stig.MappingError, match="at most 10"):
            stig.read_profile(mapping_text(), CAC_BENCHMARK, CAC_PROFILE)

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"schema_version": 2}, "schema_version 1"),
            ({"datastreams": {}}, "datastreams must be an array"),
            ({"datastreams": [1]}, r"datastreams\[0\] must be an object"),
            ({"datastreams": [{"name": "x"}]}, r"datastreams\[0\] must have exactly"),
            ({"datastreams": []}, "holds 0 entries"),
        ],
    )
    def test_an_invalid_structure_is_refused(self, change: dict[str, Any], message: str) -> None:
        document = {**mapping_document(), **change}
        with pytest.raises(stig.MappingError, match=message):
            stig.read_profile(json.dumps(document), CAC_BENCHMARK, CAC_PROFILE)

    def test_a_profile_listed_twice_is_refused(self) -> None:
        document = mapping_document()
        stream = document["datastreams"][0]
        stream["profiles"] = [stream["profiles"][0], stream["profiles"][0]]
        with pytest.raises(stig.MappingError, match="holds 2 entries"):
            stig.read_profile(json.dumps(document), CAC_BENCHMARK, CAC_PROFILE)

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"stig_release": "1.5"}, "stig_release is not a valid identifier"),
            ({"stig_ids": {}}, "non-empty object with sorted STIG IDs"),
            ({"stig_ids": {"B-24-000001": [CAC + "a"], "A-24-000001": [CAC + "a"]}}, "sorted"),
            ({"stig_ids": {"bad": [CAC + "a"]}}, "key 'bad' is not a valid identifier"),
            ({"stig_ids": {"UBTU-24-100010": []}}, "must name at least one rule"),
            ({"stig_ids": {"UBTU-24-100010": [CAC + "b", CAC + "a"]}}, "sorted and unique"),
            ({"stig_ids": {"UBTU-24-100010": ["not a rule"]}}, "is not a valid identifier"),
            ({"stig_ids": {"UBTU-24-100010": "x"}}, "must be an array"),
            ({"rules_without_stig_id": [], "extra": 1}, "must have exactly the keys"),
        ],
    )
    def test_an_invalid_entry_is_refused(self, overrides: dict[str, Any], message: str) -> None:
        with pytest.raises(stig.MappingError, match=message):
            stig.read_profile(mapping_text(**overrides), CAC_BENCHMARK, CAC_PROFILE)

    def test_the_pinned_mapping_file_of_the_repository_is_paired_and_current(self) -> None:
        text = (Path(__file__).resolve().parents[5] / "content" / "stig-mapping.json").read_text()
        read = stig.mapping_for(text, SCC_BENCHMARK, "001.005.007")
        assert read.stig_release == "V1R5"
        assert len(read.checks) == 194


class TestSccRules:
    """The rules of the SCC profile and their STIG IDs."""

    def test_rules_keep_a_valid_stig_id_and_drop_any_other_version(self) -> None:
        rules = stig.scc_rules(
            [
                {"rule_id": DISA + "1r1_rule", "version": "UBTU-24-100010", "title": "t"},
                {"rule_id": DISA + "2r1_rule", "version": ""},
                {"rule_id": DISA + "3r1_rule", "version": "1.0"},
            ]
        )
        assert [rule.stig_id for rule in rules] == ["UBTU-24-100010", None, None]

    @pytest.mark.parametrize(
        ("raw", "message"),
        [
            ({}, "must be an array"),
            ([1], "must be an object"),
            ([{"rule_id": "bad", "version": ""}], "an SCC rule_id is not a valid identifier"),
            ([{"rule_id": DISA + "1r1_rule"}], "has no version string"),
            (
                [
                    {"rule_id": DISA + "1r1_rule", "version": ""},
                    {"rule_id": DISA + "1r1_rule", "version": ""},
                ],
                "more than once",
            ),
        ],
    )
    def test_invalid_rules_are_refused(self, raw: object, message: str) -> None:
        with pytest.raises(stig.MappingError, match=message):
            stig.scc_rules(raw)


class TestResolution:
    """Which SCC rules toggles disable, the partial disables and the family placement."""

    def test_nothing_disabled_places_every_rule(self) -> None:
        result = stig.resolve(RULES, profile(), {}, FAMILIES)
        assert result.disabled == []
        assert result.partial == []
        assert [item["rule_id"] for item in result.placements] == [r.rule_id for r in RULES]

    def test_a_rule_is_disabled_only_when_all_its_mapped_rules_are(self) -> None:
        disabled = {
            CAC + "sshd_banner": "linux_compliance_ssh_enabled",
            CAC + "sshd_banner_net": "linux_compliance_ssh_enabled",
        }
        result = stig.resolve(RULES, profile(), disabled, FAMILIES)
        assert result.disabled == [
            {"rule_id": DISA + "1r1_rule", "disabled_by": "linux_compliance_ssh_enabled"}
        ]
        assert [item["rule_id"] for item in result.partial] == [DISA + "2r1_rule"]

    def test_a_partial_disable_keeps_the_rule_enabled_and_notes_the_toggles(self) -> None:
        disabled = {
            CAC + "sshd_ciphers": "linux_compliance_ssh_enabled",
            CAC + "audit_sshd": "linux_compliance_auditd_enabled",
        }
        result = stig.resolve(RULES, profile(), disabled, FAMILIES)
        assert result.disabled == []
        note = result.partial[0]
        assert note == {
            "rule_id": DISA + "3r1_rule",
            "stig_id": "UBTU-24-100030",
            "disabled_by": ["linux_compliance_auditd_enabled", "linux_compliance_ssh_enabled"],
            "disabled_rules": [CAC + "audit_sshd", CAC + "sshd_ciphers"],
            "enabled_rules": [CAC + "sshd_macs"],
            "note": (
                "partially disabled by linux_compliance_auditd_enabled, "
                "linux_compliance_ssh_enabled"
            ),
        }
        placed = by_rule(result.placements)[DISA + "3r1_rule"]
        assert placed["partially_disabled_by"] == note["disabled_by"]

    def test_disabled_by_is_the_variable_that_disables_most_mapped_rules(self) -> None:
        disabled = {
            CAC + "audit_sshd": "linux_compliance_auditd_enabled",
            CAC + "sshd_ciphers": "linux_compliance_ssh_enabled",
            CAC + "sshd_macs": "linux_compliance_ssh_enabled",
        }
        result = stig.resolve(RULES, profile(), disabled, FAMILIES)
        assert result.disabled == [
            {"rule_id": DISA + "3r1_rule", "disabled_by": "linux_compliance_ssh_enabled"}
        ]

    def test_a_tie_between_variables_picks_the_alphabetically_first(self) -> None:
        disabled = {
            CAC + "banner_issue_net": "linux_compliance_banners_enabled",
            CAC + "sshd_banner_net": "linux_compliance_ssh_enabled",
        }
        result = stig.resolve(RULES, profile(), disabled, FAMILIES)
        assert result.disabled == [
            {"rule_id": DISA + "2r1_rule", "disabled_by": "linux_compliance_banners_enabled"}
        ]

    def test_unmapped_rules_are_never_disabled_by_a_toggle(self) -> None:
        everything = dict.fromkeys(FAMILIES.family_of, "linux_compliance_ssh_enabled")
        everything[CAC + "uncatalogued_rule"] = "linux_compliance_rule_uncatalogued_rule_enabled"
        result = stig.resolve(RULES, profile(), everything, FAMILIES)
        disabled = {item["rule_id"] for item in result.disabled}
        assert DISA + "5r1_rule" not in disabled
        assert DISA + "6r1_rule" not in disabled
        assert len(disabled) == 4

    def test_an_explicit_entry_wins_and_disables_even_an_unmapped_rule(self) -> None:
        explicit = {
            DISA + "6r1_rule": "linux_compliance_site_exclusion_enabled",
            DISA + "2r1_rule": "linux_compliance_site_exclusion_enabled",
        }
        disabled = {CAC + "sshd_banner_net": "linux_compliance_ssh_enabled"}
        result = stig.resolve(RULES, profile(), disabled, FAMILIES, explicit)
        assert by_rule(result.disabled) == {
            DISA + "2r1_rule": {
                "rule_id": DISA + "2r1_rule",
                "disabled_by": "linux_compliance_site_exclusion_enabled",
            },
            DISA + "6r1_rule": {
                "rule_id": DISA + "6r1_rule",
                "disabled_by": "linux_compliance_site_exclusion_enabled",
            },
        }
        assert result.partial == []

    def test_a_single_family_places_the_rule_under_it(self) -> None:
        placed = by_rule(stig.resolve(RULES, profile(), {}, FAMILIES).placements)
        assert placed[DISA + "1r1_rule"] == {
            "rule_id": DISA + "1r1_rule",
            "family": "ssh",
            "topic": "ssh",
            "tags": [],
            "stig_id": "UBTU-24-100010",
            "mapped_rules": [CAC + "sshd_banner"],
            "partially_disabled_by": [],
        }

    def test_several_families_pick_the_majority_and_keep_the_rest_as_tags(self) -> None:
        placed = by_rule(stig.resolve(RULES, profile(), {}, FAMILIES).placements)
        rule = placed[DISA + "3r1_rule"]
        assert rule["family"] == "ssh"
        assert rule["tags"] == ["auditd", "crypto_policy"]

    def test_a_tie_between_families_picks_the_alphabetically_first(self) -> None:
        placed = by_rule(stig.resolve(RULES, profile(), {}, FAMILIES).placements)
        assert placed[DISA + "2r1_rule"]["family"] == "banners"
        assert placed[DISA + "2r1_rule"]["tags"] == ["ssh"]

    def test_the_topic_is_the_umbrella_of_the_family(self) -> None:
        families = stig.Families({CAC + "sshd_banner": "faillock"}, {"faillock": "pam"}, {})
        placed = by_rule(stig.resolve(RULES[:1], profile(), {}, families).placements)
        assert (placed[DISA + "1r1_rule"]["family"], placed[DISA + "1r1_rule"]["topic"]) == (
            "faillock",
            "pam",
        )

    def test_rules_without_a_catalogued_mapped_rule_are_unmapped(self) -> None:
        placed = by_rule(stig.resolve(RULES, profile(), {}, FAMILIES).placements)
        for number, stig_id, mapped in (
            (4, "UBTU-24-100040", [CAC + "uncatalogued_rule"]),
            (5, "UBTU-24-999999", []),
            (6, None, []),
        ):
            rule = placed[f"{DISA}{number}r1_rule"]
            assert rule["family"] == rule["topic"] == placement.UNMAPPED_FAMILY
            assert rule["tags"] == []
            assert rule["stig_id"] == stig_id
            assert rule["mapped_rules"] == mapped

    def test_the_primary_family_counts_rules(self) -> None:
        assert stig.primary_family(["b", "a", "b"]) == "b"
        assert stig.primary_family(["b", "a"]) == "a"
