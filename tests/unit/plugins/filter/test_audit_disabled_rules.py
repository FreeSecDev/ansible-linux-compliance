from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    audit_disabled_rules as audit_filter,
)
from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    remediation_plan as plan_filter,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)

PREFIX = "xccdf_org.ssgproject.content_rule_"
CRONTAB = PREFIX + "file_permissions_crontab"
PASSWD = PREFIX + "file_permissions_etc_passwd"
ROOT_LOGIN = PREFIX + "sshd_disable_root_login"
IMMUTABLE = PREFIX + "audit_rules_immutable"
FAMILY = "linux_compliance_file_permissions_enabled"
FAMILIES: list[dict[str, object]] = [
    {"name": "file_permissions", "disruptive": False},
    {"name": "ssh", "disruptive": True},
    {"name": "auditd", "disruptive": True},
]
CATALOGUE_FILE = Path(__file__).resolve().parents[4] / "roles" / "remediate" / "vars" / "rules.yml"


def rule(rule_id: str, family: str = "file_permissions") -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "family": family,
        "disruptive": family != "file_permissions",
        "reversible": True,
        "revert_strategy": "recorded_value",
        "toggle": toggles.rule_toggle_name(rule_id),
        "runbook": None,
        "parameters": {},
    }


def catalogue() -> list[dict[str, object]]:
    return [rule(PASSWD), rule(CRONTAB), rule(ROOT_LOGIN, "ssh")]


def resolve(**overrides: object) -> dict[str, object]:
    options: dict[str, object] = {
        "audit_only": {},
        "families": FAMILIES,
        "toggles": {},
        "profile_rule_ids": [CRONTAB, PASSWD, ROOT_LOGIN, IMMUTABLE],
        "disabled_rules": [],
    }
    options.update(overrides)
    return audit_filter.audit_disabled_rules(catalogue(), options)


def test_the_filter_is_registered() -> None:
    filters = audit_filter.FilterModule().filters()
    assert filters["audit_disabled_rules"] is audit_filter.audit_disabled_rules


def test_nothing_is_disabled_without_toggles() -> None:
    assert resolve() == {"errors": [], "disabled_rules": [], "warnings": []}


def test_a_rule_toggle_disables_one_rule() -> None:
    result = resolve(toggles={toggles.rule_toggle_name(CRONTAB): False})
    assert result["disabled_rules"] == [
        {"rule_id": CRONTAB, "disabled_by": toggles.rule_toggle_name(CRONTAB)}
    ]


def test_a_family_toggle_disables_the_whole_topic_and_names_itself() -> None:
    result = resolve(toggles={FAMILY: False})
    assert result["disabled_rules"] == [
        {"rule_id": CRONTAB, "disabled_by": FAMILY},
        {"rule_id": PASSWD, "disabled_by": FAMILY},
    ]


def test_a_rule_toggle_overrides_its_disabled_family() -> None:
    result = resolve(toggles={FAMILY: False, toggles.rule_toggle_name(CRONTAB): True})
    assert result["disabled_rules"] == [{"rule_id": PASSWD, "disabled_by": FAMILY}]


def test_a_disruptive_family_is_disabled_without_the_allow_list() -> None:
    result = resolve(toggles={"linux_compliance_ssh_enabled": False})
    assert result["disabled_rules"] == [
        {"rule_id": ROOT_LOGIN, "disabled_by": "linux_compliance_ssh_enabled"}
    ]


def test_only_rules_of_the_profile_are_disabled() -> None:
    result = resolve(toggles={FAMILY: False}, profile_rule_ids=[PASSWD, IMMUTABLE])
    assert result["disabled_rules"] == [{"rule_id": PASSWD, "disabled_by": FAMILY}]


def test_explicit_entries_for_uncatalogued_rules_are_kept_and_sorted() -> None:
    explicit = {"rule_id": IMMUTABLE, "disabled_by": "linux_compliance_auditd_enabled"}
    result = resolve(toggles={FAMILY: False}, disabled_rules=[explicit])
    assert result["disabled_rules"] == [
        explicit,
        {"rule_id": CRONTAB, "disabled_by": FAMILY},
        {"rule_id": PASSWD, "disabled_by": FAMILY},
    ]


def test_an_explicit_entry_for_a_catalogued_rule_is_an_error() -> None:
    result = resolve(disabled_rules=[{"rule_id": CRONTAB}])
    assert result["disabled_rules"] == []
    errors = cast("list[str]", result["errors"])
    assert len(errors) == 1
    assert toggles.rule_toggle_name(CRONTAB) in errors[0]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"disabled_rules": "x"}, "linux_compliance_audit_disabled_rules must be a list"),
        ({"disabled_rules": ["x"]}, "needs a rule_id string"),
        ({"disabled_rules": [{"rule_id": 1}]}, "needs a rule_id string"),
        ({"profile_rule_ids": None}, "profile_rule_ids must list"),
        ({"profile_rule_ids": [1]}, "profile_rule_ids must list"),
        ({"toggles": {FAMILY: "false"}}, f"{FAMILY} must be a boolean"),
        ({"toggles": {"linux_compliance_audit_enabled": False}}, "namespace of a role"),
        ({"toggles": {"linux_compliance_rule_typo_enabled": False}}, "catalogued rule"),
        ({"families": []}, "the family registry must be a list"),
    ],
)
def test_invalid_input_is_an_error_and_disables_nothing(
    overrides: dict[str, object], message: str
) -> None:
    result = resolve(**overrides)
    assert result["disabled_rules"] == []
    assert any(message in error for error in cast("list[str]", result["errors"]))


@pytest.mark.parametrize("given", [None, {}, {"families": FAMILIES}, {"x": 1}])
def test_options_must_have_exactly_the_documented_keys(given: object) -> None:
    result = audit_filter.audit_disabled_rules(catalogue(), given)
    assert result["disabled_rules"] == []
    assert "options must be a mapping with exactly" in cast("list[str]", result["errors"])[0]


@pytest.mark.parametrize(
    "given",
    [
        {},
        {FAMILY: False},
        {toggles.rule_toggle_name(CRONTAB): False},
        {FAMILY: False, toggles.rule_toggle_name(CRONTAB): True},
        {FAMILY: False, toggles.rule_toggle_name(CRONTAB): False},
        {"linux_compliance_ssh_enabled": False, toggles.rule_toggle_name(PASSWD): False},
    ],
)
def test_the_audit_and_the_remediation_agree_on_every_disabled_rule(
    given: dict[str, bool],
) -> None:
    profile = [CRONTAB, PASSWD, ROOT_LOGIN]
    audit = resolve(toggles=given, profile_rule_ids=profile)
    plan = plan_filter.remediation_plan(
        catalogue(),
        {
            "audit_only": {},
            "families": FAMILIES,
            "enabled": True,
            "allow_disruptive": ["ssh"],
            "toggles": given,
            "profile_rule_ids": profile,
            "ledger_entries": [],
        },
    )
    assert plan["errors"] == []
    assert audit["disabled_rules"] == plan["disabled_rules"]


def test_rule_toggles_that_follow_a_disabled_family_give_the_same_result_as_unset_ones() -> None:
    data = cast("dict[str, object]", yaml.safe_load(CATALOGUE_FILE.read_text(encoding="utf-8")))
    real_rules = data["__linux_compliance_remediate_rules"]
    real_audit_only = data["__linux_compliance_remediate_audit_only"]
    real_families = data["__linux_compliance_remediate_families"]
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(real_rules, real_audit_only, real_families, {}, errors)
    assert errors.items == []
    profile = [str(item["rule_id"]) for item in loaded.rules]
    family_off = {FAMILY: False}
    members = [item for item in loaded.rules if item["family"] == "file_permissions"]
    templated = {**family_off, **{str(item["toggle"]): False for item in members}}
    results = [
        audit_filter.audit_disabled_rules(
            real_rules,
            {
                "audit_only": real_audit_only,
                "families": real_families,
                "toggles": given,
                "profile_rule_ids": profile,
                "disabled_rules": [],
            },
        )
        for given in (family_off, templated)
    ]
    assert results[0]["errors"] == []
    assert results[0] == results[1]
    disabled = cast("list[dict[str, object]]", results[0]["disabled_rules"])
    assert len(disabled) == len(members) > 100
    assert {item["disabled_by"] for item in disabled} == {FAMILY}


def test_a_topic_toggle_without_catalogued_rules_warns_that_it_excludes_nothing() -> None:
    result = resolve(toggles={"linux_compliance_auditd_enabled": False})
    assert result["disabled_rules"] == []
    warnings = cast("list[str]", result["warnings"])
    assert len(warnings) == 1
    assert warnings[0].startswith("WARNING: linux_compliance_auditd_enabled is false")
    assert "so it excludes nothing" in warnings[0]


def test_a_topic_toggle_whose_rules_are_outside_the_profile_warns() -> None:
    result = resolve(toggles={FAMILY: False}, profile_rule_ids=[ROOT_LOGIN, IMMUTABLE])
    assert result["disabled_rules"] == []
    assert len(cast("list[str]", result["warnings"])) == 1
    assert FAMILY in cast("list[str]", result["warnings"])[0]


def test_a_topic_toggle_that_excludes_a_rule_does_not_warn() -> None:
    result = resolve(toggles={FAMILY: False, "linux_compliance_ssh_enabled": True})
    assert result["warnings"] == []


def test_errors_suppress_warnings() -> None:
    result = resolve(toggles={"linux_compliance_auditd_enabled": False, FAMILY: "x"})
    assert result["warnings"] == []
