from __future__ import annotations

import functools
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

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CATALOGUE = REPOSITORY_ROOT / "roles" / "remediate" / "vars" / "rules.yml"
SOURCE = REPOSITORY_ROOT / "content" / "catalogue.yml"
PREFIX = "xccdf_org.ssgproject.content_rule_"
CRONTAB = PREFIX + "file_permissions_crontab"
SMARTCARDS = PREFIX + "sssd_enable_smartcards"
GNOME_SMARTCARD = PREFIX + "dconf_gnome_lock_screen_on_smartcard_removal"
JOURNALD_RSYSLOG = PREFIX + "ensure_journald_and_rsyslog_not_active_together"
PAM_UNIX_REMEMBER = PREFIX + "accounts_password_pam_unix_remember"
PAM_UNIX_NO_REMEMBER = PREFIX + "accounts_password_pam_unix_no_remember"
APPARMOR_WATCHES = (
    PREFIX + "audit_rules_mac_modification_etc_apparmor",
    PREFIX + "audit_rules_mac_modification_etc_apparmor_d",
    PREFIX + "audit_rules_privileged_commands_apparmor_parser",
)
SELINUX_WATCHES = (
    PREFIX + "audit_rules_mac_modification",
    PREFIX + "audit_rules_execution_setsebool",
)


def toggle(topic: str) -> str:
    return toggles.toggle_name(topic)


@functools.cache
def data() -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(CATALOGUE.read_text(encoding="utf-8")))


@functools.cache
def catalogue() -> toggles.Catalogue:
    errors = toggles.Errors()
    loaded = toggles.with_tags(
        toggles.load_catalogue(
            data()["__linux_compliance_remediate_rules"],
            data()["__linux_compliance_remediate_audit_only"],
            data()["__linux_compliance_remediate_families"],
            {},
            errors,
        ),
        data()["__linux_compliance_remediate_tags"],
        errors,
    )
    assert errors.items == []
    return loaded


def family(rule_id: str) -> str:
    return next(str(rule["family"]) for rule in catalogue().rules if rule["rule_id"] == rule_id)


def every_rule() -> list[str]:
    return [str(rule["rule_id"]) for rule in catalogue().rules]


def audit(given: dict[str, object], profile: list[str] | None = None) -> dict[str, object]:
    return audit_filter.audit_disabled_rules(
        data()["__linux_compliance_remediate_rules"],
        {
            "audit_only": data()["__linux_compliance_remediate_audit_only"],
            "families": data()["__linux_compliance_remediate_families"],
            "tags": data()["__linux_compliance_remediate_tags"],
            "toggles": given,
            "profile_rule_ids": every_rule() if profile is None else profile,
            "disabled_rules": [],
        },
    )


def plan(
    given: dict[str, object],
    *,
    ledger: list[dict[str, object]] | None = None,
    aliases: dict[str, object] | None = None,
) -> dict[str, object]:
    return plan_filter.remediation_plan(
        data()["__linux_compliance_remediate_rules"],
        {
            "audit_only": data()["__linux_compliance_remediate_audit_only"],
            "families": data()["__linux_compliance_remediate_families"],
            "tags": data()["__linux_compliance_remediate_tags"],
            "enabled": True,
            "allow_disruptive": [],
            "toggles": given,
            "profile_rule_ids": every_rule(),
            "ledger_entries": ledger or [],
            "family_aliases": (
                data()["__linux_compliance_remediate_family_aliases"]
                if aliases is None
                else aliases
            ),
        },
    )


def disabled(result: dict[str, object]) -> dict[str, str]:
    assert result["errors"] == []
    entries = cast("list[dict[str, str]]", result["disabled_rules"])
    return {entry["rule_id"]: entry["disabled_by"] for entry in entries}


def planned(result: dict[str, object], rule_id: str) -> dict[str, object]:
    assert result["errors"] == []
    rules = cast("list[dict[str, object]]", result["rules"])
    return next(rule for rule in rules if rule["rule_id"] == rule_id)


def crontab_entry(recorded_family: str) -> dict[str, object]:
    return {
        "rule_id": CRONTAB,
        "family": recorded_family,
        "revert_strategy": "recorded_value",
        "prior_values": [{"name": "mode", "value": "0644", "sensitive": False}],
        "collection_version": "0.1.0",
        "applied_at": "2026-10-26T00:00:00Z",
    }


@pytest.mark.parametrize(
    ("topic", "shorts", "family_name"),
    [
        (
            "sssd",
            (
                "file_permissions_var_log_sssd",
                "file_ownerships_var_log_sssd",
                "file_groupownerships_var_log_sssd",
            ),
            "file_permissions",
        ),
        (
            "time_sync",
            (
                "file_permissions_etc_chrony_keys",
                "file_owner_etc_chrony_keys",
                "file_groupowner_etc_chrony_keys",
            ),
            "file_permissions",
        ),
        (
            "cron",
            (
                "file_owner_cron_deny",
                "file_groupowner_cron_deny",
                "file_owner_at_deny",
                "file_groupowner_at_deny",
                "file_permissions_crontab",
            ),
            "file_permissions",
        ),
        ("smartcard", ("sssd_enable_smartcards",), "sssd"),
        ("smartcard", ("dconf_gnome_lock_screen_on_smartcard_removal",), "desktop"),
        ("pwhistory", ("accounts_password_pam_unix_remember",), "pam"),
        ("pwhistory", ("accounts_password_pam_unix_no_remember",), "user_accounts"),
    ],
)
def test_a_subsystem_toggle_switches_off_the_rules_of_other_families_about_it(
    topic: str, shorts: tuple[str, ...], family_name: str
) -> None:
    rule_ids = [PREFIX + short for short in shorts]
    for rule_id in rule_ids:
        assert family(rule_id) == family_name
        assert topic in catalogue().tags[rule_id]
    expected = dict.fromkeys(rule_ids, toggle(topic))
    audited = disabled(audit({toggle(topic): False}))
    assert expected.items() <= audited.items()
    assert disabled(plan({toggle(topic): False})) == audited


def test_pwhistory_switches_off_every_password_history_rule() -> None:
    switched_off = disabled(audit({toggle("pwhistory"): False}))
    history = {
        str(rule["rule_id"])
        for rule in catalogue().rules
        if "remember" in str(rule["rule_id"]) or "pwhistory" in str(rule["rule_id"])
    }
    assert len(history) == 9
    assert history <= set(switched_off)


def test_the_cron_toggle_cleans_up_the_native_crontab_rule_without_the_allow_list() -> None:
    result = plan({toggle("cron"): False}, ledger=[crontab_entry("file_permissions")])
    crontab = planned(result, CRONTAB)
    assert crontab["action"] == "cleanup"
    assert crontab["reason"] == "disabled_by_toggle"
    assert crontab["disabled_by"] == toggle("cron")
    families = cast("list[dict[str, object]]", result["families"])
    assert [item["name"] for item in families if item["disruptive"] is True] == []
    file_permissions = next(item for item in families if item["name"] == "file_permissions")
    cleanup = cast("list[dict[str, object]]", file_permissions["cleanup"])
    assert [item["rule_id"] for item in cleanup] == [CRONTAB]


def test_a_disruptive_tag_does_not_put_a_rule_behind_the_allow_list() -> None:
    crontab = planned(plan({}), CRONTAB)
    assert catalogue().families["cron"] is True
    assert crontab["disruptive"] is False
    assert crontab["action"] == "apply"


def test_the_services_umbrella_reaches_the_rules_tagged_with_its_families() -> None:
    switched_off = disabled(audit({toggle("services"): False}))
    assert switched_off[CRONTAB] == toggle("services")
    assert switched_off[PREFIX + "file_permissions_var_log_sssd"] == toggle("services")
    assert switched_off[PREFIX + "file_owner_etc_chrony_keys"] == toggle("services")


@pytest.mark.parametrize("topic", ["apparmor", "selinux", "mandatory_access_control"])
def test_the_audit_watches_on_mandatory_access_control_stay_with_auditd(topic: str) -> None:
    switched_off = disabled(audit({toggle(topic): False}))
    for rule_id in (*APPARMOR_WATCHES, *SELINUX_WATCHES):
        assert family(rule_id) == "auditd"
        assert rule_id not in catalogue().tags
        assert rule_id not in switched_off
    audited = disabled(audit({toggle("auditd"): False}))
    assert {*APPARMOR_WATCHES, *SELINUX_WATCHES} <= set(audited)


def test_no_audit_rule_carries_a_subsystem_tag() -> None:
    families = {str(rule["rule_id"]): rule["family"] for rule in catalogue().rules}
    assert all(families[rule_id] != "auditd" for rule_id in catalogue().tags)


@pytest.mark.parametrize(
    ("rule_id", "given", "expected"),
    [
        (CRONTAB, {"cron": False}, "cron"),
        (CRONTAB, {"services": False}, "services"),
        (CRONTAB, {"services": False, "cron": False}, "services"),
        (CRONTAB, {"file_permissions": False, "cron": False}, "file_permissions"),
        (CRONTAB, {"file_permissions": False, "services": False}, "file_permissions"),
        (SMARTCARDS, {"accounts": False, "services": False}, "services"),
        (SMARTCARDS, {"smartcard": False, "sssd": False}, "sssd"),
        (SMARTCARDS, {"accounts": False, "smartcard": False}, "accounts"),
        (GNOME_SMARTCARD, {"smartcard": False, "desktop": False}, "desktop"),
        (JOURNALD_RSYSLOG, {"journald": False, "rsyslog": False}, "rsyslog"),
        (JOURNALD_RSYSLOG, {"journald": False}, "journald"),
        (JOURNALD_RSYSLOG, {"logging": False, "journald": False}, "logging"),
        (PAM_UNIX_REMEMBER, {"pwhistory": False, "pam": False}, "pam"),
        (PAM_UNIX_NO_REMEMBER, {"pwhistory": False, "pam": False}, "pam"),
        (PAM_UNIX_NO_REMEMBER, {"pwhistory": False, "accounts": False}, "accounts"),
        (PAM_UNIX_NO_REMEMBER, {"pwhistory": False, "user_accounts": False}, "user_accounts"),
    ],
)
def test_disabled_by_names_the_family_umbrella_then_the_family_then_the_tags(
    rule_id: str, given: dict[str, bool], expected: str
) -> None:
    values: dict[str, object] = {toggle(name): value for name, value in given.items()}
    assert disabled(audit(values))[rule_id] == toggle(expected)
    assert disabled(plan(values))[rule_id] == toggle(expected)


@pytest.mark.parametrize(
    ("rule_id", "given"),
    [
        (CRONTAB, {"file_permissions": False, "cron": True, "services": True}),
        (SMARTCARDS, {"sssd": False, "smartcard": True, "accounts": True}),
        (GNOME_SMARTCARD, {"desktop": False, "smartcard": True}),
        (PAM_UNIX_REMEMBER, {"pam": False, "pwhistory": True}),
    ],
)
def test_a_tag_toggle_that_is_true_never_switches_a_rule_on(
    rule_id: str, given: dict[str, bool]
) -> None:
    values: dict[str, object] = {toggle(name): value for name, value in given.items()}
    off = next(name for name, value in given.items() if not value)
    assert disabled(audit(values))[rule_id] == toggle(off)


def test_every_tag_toggle_set_to_true_changes_nothing() -> None:
    every_tag: dict[str, object] = {
        toggle(tag): True for tags in catalogue().tags.values() for tag in tags
    }
    assert disabled(audit(every_tag)) == {}
    assert disabled(plan(every_tag)) == {}


def test_an_explicit_rule_toggle_still_wins_over_a_tag() -> None:
    given: dict[str, object] = {toggle("cron"): False, toggles.rule_toggle_name(CRONTAB): True}
    assert CRONTAB not in disabled(audit(given))
    assert planned(plan(given), CRONTAB)["action"] == "apply"


def test_a_tag_alone_keeps_its_toggle_from_warning() -> None:
    result = audit({toggle("smartcard"): False}, profile=[SMARTCARDS])
    assert disabled(result) == {SMARTCARDS: toggle("smartcard")}
    assert result["warnings"] == []


def test_a_ledger_entry_under_a_former_family_name_is_still_cleaned_up() -> None:
    off: dict[str, object] = {toggle("file_permissions"): False}
    refused = plan(off, ledger=[crontab_entry("permissions")], aliases={})
    assert refused["errors"] == [f"{CRONTAB}: the ledger records family 'permissions'"]
    result = plan(
        off,
        ledger=[crontab_entry("permissions")],
        aliases={"permissions": ["file_permissions"]},
    )
    crontab = planned(result, CRONTAB)
    assert crontab["action"] == "cleanup"
    assert cast("dict[str, object]", crontab["ledger_entry"])["family"] == "permissions"


def test_the_repository_declares_no_ledger_alias_yet() -> None:
    assert data()["__linux_compliance_remediate_family_aliases"] == {}
    source = cast("dict[str, object]", yaml.safe_load(SOURCE.read_text(encoding="utf-8")))
    assert source["ledger_family_aliases"] == {}
