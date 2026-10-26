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
CRON_SERVICE = PREFIX + "service_cron_enabled"
FAMILIES: list[dict[str, object]] = [
    {"name": "file_permissions", "disruptive": False},
    {"name": "cron", "disruptive": True, "umbrella": "services"},
]
CRON = "linux_compliance_cron_enabled"
SERVICES = "linux_compliance_services_enabled"
FILE_PERMISSIONS = "linux_compliance_file_permissions_enabled"


def native() -> list[dict[str, object]]:
    return [
        {
            "rule_id": CRONTAB,
            "family": "file_permissions",
            "disruptive": False,
            "reversible": True,
            "revert_strategy": "recorded_value",
            "toggle": toggles.rule_toggle_name(CRONTAB),
            "runbook": None,
            "parameters": {"path": "/etc/crontab", "max_mode": "0600"},
        }
    ]


def entry(family: object) -> dict[str, object]:
    return {
        "rule_id": CRONTAB,
        "family": family,
        "revert_strategy": "recorded_value",
        "prior_values": [{"name": "mode", "value": "0644", "sensitive": False}],
        "collection_version": "0.1.0",
        "applied_at": "2026-10-26T00:00:00Z",
    }


def run(
    given: dict[str, object] | None = None,
    *,
    tags: object = None,
    ledger: list[object] | None = None,
    aliases: object = None,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    result = plan_filter.remediation_plan(
        native(),
        {
            "audit_only": {"file_permissions": [], "cron": [CRON_SERVICE]},
            "tags": {"cron": [CRONTAB]} if tags is None else tags,
            "families": FAMILIES,
            "enabled": True,
            "allow_disruptive": [],
            "toggles": given or {},
            "profile_rule_ids": [CRONTAB, CRON_SERVICE],
            "ledger_entries": ledger or [],
            "family_aliases": {} if aliases is None else aliases,
        },
    )
    rules = cast("list[dict[str, object]]", result["rules"])
    return result, {str(item["rule_id"]): item for item in rules}


def audit(given: dict[str, object], tags: object = None) -> dict[str, object]:
    return audit_filter.audit_disabled_rules(
        native(),
        {
            "audit_only": {"file_permissions": [], "cron": [CRON_SERVICE]},
            "tags": {"cron": [CRONTAB]} if tags is None else tags,
            "families": FAMILIES,
            "toggles": given,
            "profile_rule_ids": [CRONTAB, CRON_SERVICE],
            "disabled_rules": [],
        },
    )


@pytest.mark.parametrize("off", [CRON, SERVICES])
def test_a_tag_toggle_or_its_umbrella_cleans_up_a_tagged_native_rule(off: str) -> None:
    result, rules = run({off: False}, ledger=[entry("file_permissions")])
    assert result["errors"] == []
    assert rules[CRONTAB]["action"] == "cleanup"
    assert rules[CRONTAB]["disabled_by"] == off
    assert result["disabled_rules"] == [
        {"rule_id": CRONTAB, "disabled_by": off},
        {"rule_id": CRON_SERVICE, "disabled_by": off},
    ]
    assert audit({off: False})["disabled_rules"] == result["disabled_rules"]


def test_the_family_wins_the_controlling_variable_over_the_tag() -> None:
    _, rules = run({CRON: False, FILE_PERMISSIONS: False})
    assert rules[CRONTAB]["disabled_by"] == FILE_PERMISSIONS
    assert rules[CRONTAB]["action"] == "none"


def test_a_tagged_rule_of_a_non_disruptive_family_needs_no_allow_list() -> None:
    result, rules = run()
    assert result["errors"] == []
    assert rules[CRONTAB]["action"] == "apply"
    assert rules[CRON_SERVICE]["action"] == "not_implemented"


def test_a_tag_toggle_that_is_true_does_not_switch_the_family_back_on() -> None:
    _, rules = run({CRON: True, SERVICES: True, FILE_PERMISSIONS: False})
    assert rules[CRONTAB]["disabled_by"] == FILE_PERMISSIONS


def test_without_tags_the_tag_toggle_leaves_the_rule_alone() -> None:
    _, rules = run({CRON: False}, tags={})
    assert rules[CRONTAB]["action"] == "apply"
    assert audit({CRON: False}, tags={})["disabled_rules"] == [
        {"rule_id": CRON_SERVICE, "disabled_by": CRON}
    ]


def test_invalid_tags_fail_both_filters() -> None:
    result, _ = run(tags={"cron": [CRON_SERVICE]})
    message = f"{CRON_SERVICE} belongs to the family cron and cannot also be tagged with it"
    assert result["errors"] == [message]
    assert audit({}, tags={"cron": [CRON_SERVICE]})["errors"] == [message]


def test_a_ledger_entry_under_a_former_family_name_needs_its_alias() -> None:
    off: dict[str, object] = {FILE_PERMISSIONS: False}
    refused, _ = run(off, ledger=[entry("permissions")])
    assert refused["errors"] == [f"{CRONTAB}: the ledger records family 'permissions'"]
    result, rules = run(
        off, ledger=[entry("permissions")], aliases={"permissions": ["file_permissions"]}
    )
    assert result["errors"] == []
    assert rules[CRONTAB]["action"] == "cleanup"
    assert rules[CRONTAB]["pending_cleanup"] is False


def test_an_alias_to_another_family_does_not_accept_the_entry() -> None:
    result, _ = run(ledger=[entry("permissions")], aliases={"permissions": ["cron"]})
    assert result["errors"] == [f"{CRONTAB}: the ledger records family 'permissions'"]


def test_an_entry_without_a_family_string_is_still_refused_with_aliases() -> None:
    result, _ = run(ledger=[entry(None)], aliases={"permissions": ["file_permissions"]})
    assert result["errors"] == [f"{CRONTAB}: the ledger records family None"]


def test_invalid_aliases_fail_the_plan() -> None:
    result, _ = run(aliases={"permissions": ["nfs"]})
    assert result["errors"] == ["the alias permissions must list registered families"]


@pytest.mark.parametrize(
    ("recorded", "aliases", "expected"),
    [
        ("file_permissions", {}, True),
        ("permissions", {}, False),
        ("permissions", {"permissions": frozenset({"file_permissions"})}, True),
        ("permissions", {"permissions": frozenset({"cron"})}, False),
        (None, {"permissions": frozenset({"file_permissions"})}, False),
    ],
)
def test_a_recorded_family_matches_its_rule_or_an_alias(
    recorded: object, aliases: dict[str, frozenset[str]], expected: bool
) -> None:
    assert plan_filter.recorded_family_matches(recorded, "file_permissions", aliases) is expected
