from __future__ import annotations

from typing import cast

import pytest

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
SSSD = PREFIX + "sssd_enable_smartcards"
CHRONY = PREFIX + "chronyd_sync_clock"
JOURNALD = PREFIX + "journald_compress"
SERVICES = "linux_compliance_services_enabled"
SSSD_TOPIC = "linux_compliance_sssd_enabled"
FAMILIES: list[dict[str, object]] = [
    {"name": "file_permissions", "disruptive": False},
    {"name": "journald", "disruptive": False, "umbrella": "logging"},
    {"name": "sssd", "disruptive": True, "umbrella": "services"},
    {"name": "time_sync", "disruptive": True, "umbrella": "services"},
]


def rule(rule_id: str, family: str) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "family": family,
        "disruptive": family in {"sssd", "time_sync"},
        "reversible": True,
        "revert_strategy": "owned_dropin",
        "toggle": toggles.rule_toggle_name(rule_id),
        "runbook": None,
        "parameters": {},
    }


def catalogue() -> list[dict[str, object]]:
    return [
        rule(CRONTAB, "file_permissions"),
        rule(JOURNALD, "journald"),
        rule(SSSD, "sssd"),
        rule(CHRONY, "time_sync"),
    ]


def run(
    allow: list[object] | None = None, given: dict[str, object] | None = None
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    result = plan_filter.remediation_plan(
        catalogue(),
        {
            "audit_only": {},
            "tags": {},
            "families": FAMILIES,
            "enabled": True,
            "allow_disruptive": allow or [],
            "toggles": given or {},
            "profile_rule_ids": [CRONTAB, JOURNALD, SSSD, CHRONY],
            "ledger_entries": [],
            "family_aliases": {},
        },
    )
    rules = cast("list[dict[str, object]]", result["rules"])
    return result, {str(item["rule_id"]): item for item in rules}


def test_an_allow_listed_umbrella_allows_every_disruptive_family_it_groups() -> None:
    result, rules = run(["services"])
    assert result["errors"] == []
    assert rules[SSSD]["action"] == "apply"
    assert rules[CHRONY]["action"] == "apply"
    families = cast("list[dict[str, object]]", result["families"])
    assert [family["name"] for family in families] == [
        "file_permissions",
        "journald",
        "sssd",
        "time_sync",
    ]


def test_an_allow_listed_family_of_an_umbrella_allows_only_itself() -> None:
    result, rules = run(["sssd"])
    assert result["errors"] == []
    assert rules[SSSD]["action"] == "apply"
    assert rules[CHRONY]["action"] == "skip"
    assert rules[CHRONY]["reason"] == "disruptive_not_allowed"


@pytest.mark.parametrize(
    ("allow", "message"),
    [
        (["logging"], "allow-list entry logging is not a disruptive family"),
        (["service"], "allow-list entry 'service' is not a registered family or umbrella"),
    ],
)
def test_an_umbrella_without_a_disruptive_family_or_an_unknown_one_is_refused(
    allow: list[object], message: str
) -> None:
    assert run(allow)[0]["errors"] == [message]


def test_an_umbrella_toggle_switches_off_its_families_and_names_itself_in_the_plan() -> None:
    result, rules = run(["services"], {SERVICES: False, SSSD_TOPIC: True})
    assert result["errors"] == []
    for rule_id in (SSSD, CHRONY):
        assert rules[rule_id]["action"] == "none"
        assert rules[rule_id]["reason"] == "disabled_by_toggle"
        assert rules[rule_id]["disabled_by"] == SERVICES
    assert rules[CRONTAB]["action"] == "apply"
    assert result["disabled_rules"] == [
        {"rule_id": CHRONY, "disabled_by": SERVICES},
        {"rule_id": SSSD, "disabled_by": SERVICES},
    ]


def test_the_audit_resolves_umbrellas_exactly_like_remediation() -> None:
    given: dict[str, object] = {SERVICES: False, SSSD_TOPIC: True}
    plan = run(["services"], given)[0]
    audit = audit_filter.audit_disabled_rules(
        catalogue(),
        {
            "audit_only": {},
            "tags": {},
            "families": FAMILIES,
            "toggles": given,
            "profile_rule_ids": [CRONTAB, JOURNALD, SSSD, CHRONY],
            "disabled_rules": [],
        },
    )
    assert audit == {"errors": [], "disabled_rules": plan["disabled_rules"], "warnings": []}


def test_an_umbrella_with_no_rule_in_the_profile_warns_in_both_filters() -> None:
    given: dict[str, object] = {"linux_compliance_logging_enabled": False}
    result = plan_filter.remediation_plan(
        catalogue(),
        {
            "audit_only": {},
            "tags": {},
            "families": FAMILIES,
            "enabled": True,
            "allow_disruptive": [],
            "toggles": given,
            "profile_rule_ids": [CRONTAB],
            "ledger_entries": [],
            "family_aliases": {},
        },
    )
    audit = audit_filter.audit_disabled_rules(
        catalogue(),
        {
            "audit_only": {},
            "tags": {},
            "families": FAMILIES,
            "toggles": given,
            "profile_rule_ids": [CRONTAB],
            "disabled_rules": [],
        },
    )
    warnings = cast("list[str]", audit["warnings"])
    assert len(warnings) == 1
    assert warnings[0].startswith(
        "WARNING: linux_compliance_logging_enabled is false, but no catalogued rule of the "
        "families that logging groups (journald)"
    )
    notices = cast("list[str]", result["notices"])
    assert [notice for notice in notices if notice.startswith("WARNING:")] == warnings
