"""The scc_toggles filter: toggles and control families for the DISA rules of SCC (FREES-170)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    audit_disabled_rules as audit_filter,
)
from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    scc_toggles as scc_filter,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    placement,
    toggles,
)
from tests.unit.plugins.module_utils.compliance.test_stig import (
    CAC,
    DISA,
    SCC_BENCHMARK,
    mapping_document,
    mapping_text,
)

REPOSITORY = Path(__file__).resolve().parents[4]
FAMILIES: list[dict[str, object]] = [
    {"name": "ssh", "disruptive": True},
    {"name": "banners", "disruptive": False},
    {"name": "auditd", "disruptive": True},
    {"name": "crypto_policy", "disruptive": True},
]
AUDIT_ONLY: dict[str, list[str]] = {
    "ssh": [CAC + "sshd_banner", CAC + "sshd_banner_net", CAC + "sshd_ciphers", CAC + "sshd_macs"],
    "banners": [CAC + "banner_issue_net"],
    "auditd": [CAC + "audit_sshd"],
}
SCC_RULES: list[dict[str, object]] = [
    {"rule_id": DISA + "1r1_rule", "version": "UBTU-24-100010", "severity": "medium"},
    {"rule_id": DISA + "2r1_rule", "version": "UBTU-24-100020", "severity": "medium"},
    {"rule_id": DISA + "3r1_rule", "version": "UBTU-24-100030", "severity": "medium"},
    {"rule_id": DISA + "4r1_rule", "version": "UBTU-24-100040", "severity": "medium"},
    {"rule_id": DISA + "5r1_rule", "version": "UBTU-24-999999", "severity": "medium"},
]
SSH_OFF = {"linux_compliance_ssh_enabled": False}


def resolve(**overrides: object) -> dict[str, Any]:
    options: dict[str, object] = {
        "audit_only": AUDIT_ONLY,
        "families": FAMILIES,
        "tags": {"crypto_policy": [CAC + "sshd_ciphers"]},
        "toggles": {},
        "disabled_rules": [],
        "mapping": mapping_text(),
        "benchmark_id": SCC_BENCHMARK,
        "benchmark_version": "001.005.007",
        "rules": SCC_RULES,
    }
    options.update(overrides)
    return scc_filter.scc_toggles([], options)


def by_rule(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item["rule_id"]): item for item in items}


def test_the_filter_is_registered() -> None:
    assert scc_filter.FilterModule().filters()["scc_toggles"] is scc_filter.scc_toggles


def test_without_toggles_nothing_is_disabled_and_every_rule_is_placed() -> None:
    result = resolve()
    assert result["errors"] == []
    assert result["disabled_rules"] == []
    assert len(result["control_placement"]) == len(SCC_RULES)
    assert result["summary"] == {
        "rules": 5,
        "mapped": 4,
        "unmapped": 1,
        "disabled": 0,
        "partially_disabled": 0,
        "stig_release": "V1R5",
    }


def test_a_disabled_topic_disables_the_fully_mapped_rules_and_notes_the_partial_ones() -> None:
    result = resolve(toggles=SSH_OFF)
    assert result["errors"] == []
    assert result["disabled_rules"] == [
        {"rule_id": DISA + "1r1_rule", "disabled_by": "linux_compliance_ssh_enabled"}
    ]
    partial = by_rule(result["partially_disabled"])
    assert set(partial) == {DISA + "2r1_rule", DISA + "3r1_rule"}
    assert (
        partial[DISA + "2r1_rule"]["note"] == "partially disabled by linux_compliance_ssh_enabled"
    )
    placed = by_rule(result["control_placement"])
    assert placed[DISA + "3r1_rule"]["partially_disabled_by"] == ["linux_compliance_ssh_enabled"]
    assert placed[DISA + "3r1_rule"]["family"] == "ssh"
    assert placed[DISA + "3r1_rule"]["tags"] == ["auditd", "crypto_policy"]


def test_a_subsystem_tag_disables_the_rules_of_another_family_too() -> None:
    result = resolve(toggles={"linux_compliance_crypto_policy_enabled": False})
    partial = by_rule(result["partially_disabled"])
    assert partial[DISA + "3r1_rule"]["disabled_by"] == ["linux_compliance_crypto_policy_enabled"]


def test_the_toggles_are_resolved_exactly_as_for_openscap() -> None:
    mapped = sorted({rule for rules in AUDIT_ONLY.values() for rule in rules})
    openscap = audit_filter.audit_disabled_rules(
        [],
        {
            "audit_only": AUDIT_ONLY,
            "families": FAMILIES,
            "tags": {"crypto_policy": [CAC + "sshd_ciphers"]},
            "toggles": SSH_OFF,
            "profile_rule_ids": mapped,
            "disabled_rules": [],
        },
    )
    disabled = cast("list[dict[str, object]]", openscap["disabled_rules"])
    assert {item["rule_id"] for item in disabled} == set(AUDIT_ONLY["ssh"])
    result = resolve(toggles=SSH_OFF)
    off = {
        rule
        for item in result["partially_disabled"]
        for rule in cast("list[str]", item["disabled_rules"])
    }
    assert off | {CAC + "sshd_banner"} == set(AUDIT_ONLY["ssh"])


def test_an_explicit_scc_rule_is_disabled_with_its_variable() -> None:
    entry = {"rule_id": DISA + "5r1_rule", "disabled_by": "linux_compliance_site_enabled"}
    result = resolve(disabled_rules=[entry])
    assert result["disabled_rules"] == [entry]


def test_an_explicit_uncatalogued_rule_counts_as_a_disabled_mapped_rule() -> None:
    result = resolve(disabled_rules=[{"rule_id": CAC + "uncatalogued_rule"}])
    assert result["disabled_rules"] == [
        {
            "rule_id": DISA + "4r1_rule",
            "disabled_by": toggles.rule_toggle_name(CAC + "uncatalogued_rule"),
        }
    ]
    named = resolve(
        disabled_rules=[
            {"rule_id": CAC + "uncatalogued_rule", "disabled_by": "linux_compliance_x_enabled"}
        ]
    )
    assert named["disabled_rules"][0]["disabled_by"] == "linux_compliance_x_enabled"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"disabled_rules": [{"rule_id": DISA + "5r1_rule"}]},
            "needs a disabled_by",
        ),
        (
            {"disabled_rules": [{"rule_id": "xccdf_org.other_rule_x"}]},
            "neither a rule of the SCC profile nor a ComplianceAsCode rule",
        ),
        (
            {"disabled_rules": [{"rule_id": CAC + "sshd_banner"}]},
            "is in the rule catalogue",
        ),
        ({"benchmark_version": "001.006.001"}, "implements V1R5, but the SCC benchmark"),
        ({"benchmark_version": ""}, "benchmark_version must be a non-empty string"),
        ({"benchmark_id": 1}, "benchmark_id must be a non-empty string"),
        ({"rules": [{"rule_id": "bad", "version": ""}]}, "is not a valid identifier"),
        ({"mapping": "{"}, "not valid JSON"),
        ({"toggles": {"linux_compliance_ssh_enabled": "no"}}, "boolean"),
        (
            {"families": [*FAMILIES, {"name": placement.UNMAPPED_FAMILY, "disruptive": False}]},
            "reserved for unmapped SCC rules",
        ),
    ],
)
def test_invalid_input_is_an_error_and_disables_nothing(
    overrides: dict[str, object], message: str
) -> None:
    result = resolve(**overrides)
    assert any(message in error for error in result["errors"]), result["errors"]
    assert result["disabled_rules"] == []
    assert result["control_placement"] == []


@pytest.mark.parametrize("options", [None, [], {"audit_only": {}}])
def test_options_must_have_exactly_the_documented_keys(options: object) -> None:
    result: dict[str, Any] = scc_filter.scc_toggles([], options)
    assert "options must be a mapping with exactly" in result["errors"][0]
    assert result["summary"] == {}


def test_a_mismatch_of_mapping_and_benchmark_release_refuses_the_run() -> None:
    document = mapping_document(stig_release="V1R6")
    result = resolve(mapping=json.dumps(document))
    expected = (
        "the STIG mapping implements V1R6, but the SCC benchmark version '001.005.007' is V1R5; "
        "the toggles are not mapped across releases, so nothing was scanned"
    )
    assert result["errors"] == [expected]


def test_the_shipped_catalogue_and_mapping_place_an_ssh_topic_under_ssh() -> None:
    catalogue = yaml.safe_load(
        (REPOSITORY / "roles" / "remediate" / "vars" / "rules.yml").read_text(encoding="utf-8")
    )
    mapping = (REPOSITORY / "content" / "stig-mapping.json").read_text(encoding="utf-8")
    stig_ids = sorted(json.loads(mapping)["datastreams"][0]["profiles"][0]["stig_ids"])
    rules = [
        {"rule_id": f"{DISA}{index}r1_rule", "version": stig_id}
        for index, stig_id in enumerate(stig_ids)
    ]
    result: dict[str, Any] = scc_filter.scc_toggles(
        catalogue["__linux_compliance_remediate_rules"],
        {
            "audit_only": catalogue["__linux_compliance_remediate_audit_only"],
            "families": catalogue["__linux_compliance_remediate_families"],
            "tags": catalogue["__linux_compliance_remediate_tags"],
            "toggles": SSH_OFF,
            "disabled_rules": [],
            "mapping": mapping,
            "benchmark_id": SCC_BENCHMARK,
            "benchmark_version": "001.005.007",
            "rules": rules,
        },
    )
    assert result["errors"] == []
    assert result["summary"]["unmapped"] == 0
    disabled = {item["rule_id"] for item in result["disabled_rules"]}
    placed = by_rule(result["control_placement"])
    assert disabled
    assert all(placed[rule_id]["family"] == "ssh" for rule_id in disabled)
    assert {item["disabled_by"] for item in result["disabled_rules"]} == {
        "linux_compliance_ssh_enabled"
    }
