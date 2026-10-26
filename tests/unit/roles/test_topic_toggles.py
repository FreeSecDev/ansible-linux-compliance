from __future__ import annotations

import functools
import hashlib
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
LEGACY = REPOSITORY_ROOT / "tests" / "fixtures" / "catalog" / "legacy-families.yml"
ROLES = ("remediate", "audit")
SUBSYSTEMS = {
    "services": {
        "sssd",
        "time_sync",
        "mail",
        "cron",
        "nfs",
        "usbguard",
        "fapolicyd",
        "network_services",
    },
    "accounts": {
        "password_aging",
        "root_access",
        "umask",
        "user_sessions",
        "smartcard",
        "console_access",
        "user_accounts",
    },
    "pam": {"pam", "pwquality", "pwhistory", "faillock"},
    "logging": {"journald", "rsyslog", "logrotate"},
    "integrity": {"aide", "software_integrity", "endpoint_security"},
    "packages": {"package_updates", "package_sources", "system_packages"},
    "network": {"ipv4_parameters", "ipv6_parameters", "ipsec", "wireless", "network_settings"},
    "kernel_modules": {"filesystem_modules", "protocol_modules", "wireless_modules"},
    "firewall": {"firewalld", "nftables", "iptables", "ufw"},
    "mandatory_access_control": {"selinux", "apparmor"},
    "mounts": {"autofs", "mount_options", "partitioning"},
}
KEPT = ("auditd", "ssh", "sudo", "pam")


def load(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


@functools.cache
def data() -> dict[str, object]:
    return load(CATALOGUE)


@functools.cache
def catalogue() -> toggles.Catalogue:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(
        data()["__linux_compliance_remediate_rules"],
        data()["__linux_compliance_remediate_audit_only"],
        data()["__linux_compliance_remediate_families"],
        {},
        errors,
    )
    assert errors.items == []
    return loaded


def topics() -> list[str]:
    return toggles.topics(catalogue().families, catalogue().umbrellas)


def governed(topic: str) -> list[str]:
    return toggles.governed(topic, catalogue().families, catalogue().umbrellas)


def rules_of(topic: str) -> set[str]:
    families = governed(topic)
    return {str(rule["rule_id"]) for rule in catalogue().rules if rule["family"] in families}


def every_rule() -> list[str]:
    return sorted(str(rule["rule_id"]) for rule in catalogue().rules)


def legacy() -> list[dict[str, object]]:
    document = load(LEGACY)
    assert document["schema_version"] == 1
    return cast("list[dict[str, object]]", document["families"])


def audit(given: dict[str, object]) -> dict[str, object]:
    return audit_filter.audit_disabled_rules(
        data()["__linux_compliance_remediate_rules"],
        {
            "audit_only": data()["__linux_compliance_remediate_audit_only"],
            "families": data()["__linux_compliance_remediate_families"],
            "toggles": given,
            "profile_rule_ids": every_rule(),
            "disabled_rules": [],
        },
    )


def plan(given: dict[str, object], allow: list[str] | None = None) -> dict[str, object]:
    return plan_filter.remediation_plan(
        data()["__linux_compliance_remediate_rules"],
        {
            "audit_only": data()["__linux_compliance_remediate_audit_only"],
            "families": data()["__linux_compliance_remediate_families"],
            "enabled": True,
            "allow_disruptive": allow or [],
            "toggles": given,
            "profile_rule_ids": every_rule(),
            "ledger_entries": [],
        },
    )


def disabled(result: dict[str, object]) -> dict[str, str]:
    assert result["errors"] == []
    entries = cast("list[dict[str, str]]", result["disabled_rules"])
    return {entry["rule_id"]: entry["disabled_by"] for entry in entries}


def test_every_umbrella_groups_the_subsystems_it_was_split_into() -> None:
    for umbrella, members in SUBSYSTEMS.items():
        assert set(governed(umbrella)) == members, umbrella
    assert {topic for topic in topics() if topic not in catalogue().families} == (
        set(SUBSYSTEMS) - {"pam"}
    )


def test_auditd_ssh_sudo_and_pam_stay_topics() -> None:
    for name in KEPT:
        assert name in catalogue().families
        assert name not in catalogue().umbrellas
    assert {name for name in KEPT if governed(name) == [name]} == {"auditd", "ssh", "sudo"}


def test_every_family_has_rules_and_every_rule_exactly_one_family() -> None:
    families = [str(rule["family"]) for rule in catalogue().rules]
    assert set(families) == set(catalogue().families)
    assert len(every_rule()) == len(set(every_rule())) == 1203


@pytest.mark.parametrize("entry", legacy(), ids=lambda entry: str(entry["name"]))
def test_every_toggle_of_the_former_families_switches_off_exactly_its_former_rules(
    entry: dict[str, object],
) -> None:
    rule_ids = sorted(rules_of(str(entry["name"])))
    digest = hashlib.sha256(("\n".join(rule_ids) + "\n").encode()).hexdigest()
    assert len(rule_ids) == entry["rule_count"]
    assert digest == entry["rule_ids_sha256"]
    toggle = toggles.toggle_name(str(entry["name"]))
    assert entry["toggle"] == toggle
    switched_off = disabled(audit({toggle: False}))
    assert set(switched_off) == set(rule_ids)
    assert set(switched_off.values()) == {toggle}


def test_every_former_toggle_is_still_a_declared_default_of_both_roles() -> None:
    for role in ROLES:
        defaults = load(REPOSITORY_ROOT / "roles" / role / "defaults" / "main.yml")
        for entry in legacy():
            assert defaults[str(entry["toggle"])] is True, (role, entry["name"])


@pytest.mark.parametrize("topic", topics())
def test_every_topic_toggle_switches_off_exactly_its_rules_in_both_roles(topic: str) -> None:
    toggle = toggles.toggle_name(topic)
    expected = dict.fromkeys(rules_of(topic), toggle)
    assert expected
    audited = disabled(audit({toggle: False}))
    assert audited == expected
    assert disabled(plan({toggle: False})) == audited


def test_a_topic_toggle_cannot_widen_its_umbrella_on_the_real_catalogue() -> None:
    given: dict[str, object] = {
        "linux_compliance_services_enabled": False,
        "linux_compliance_sssd_enabled": True,
    }
    switched_off = disabled(audit(given))
    assert switched_off == dict.fromkeys(rules_of("services"), "linux_compliance_services_enabled")
    assert disabled(plan(given)) == switched_off


def test_a_topic_toggle_narrows_its_umbrella_on_the_real_catalogue() -> None:
    switched_off = disabled(audit({"linux_compliance_sssd_enabled": False}))
    assert switched_off == dict.fromkeys(rules_of("sssd"), "linux_compliance_sssd_enabled")
    assert not set(switched_off) & rules_of("time_sync")


def test_a_rule_toggle_still_wins_over_its_umbrella() -> None:
    sssd = min(rules_of("sssd"))
    rule_toggle = toggles.rule_toggle_name(sssd)
    switched_off = disabled(audit({"linux_compliance_services_enabled": False, rule_toggle: True}))
    assert sssd not in switched_off
    assert len(switched_off) == len(rules_of("services")) - 1


@pytest.mark.parametrize("entry", legacy(), ids=lambda entry: str(entry["name"]))
def test_every_former_family_keeps_its_disruptive_flag_and_allow_list_entry(
    entry: dict[str, object],
) -> None:
    name = str(entry["name"])
    members = governed(name)
    flags = {catalogue().families[family] for family in members}
    assert flags == {entry["disruptive"]}
    errors = toggles.Errors()
    allowed = plan_filter.check_allow_list(
        [name], catalogue().families, catalogue().umbrellas, errors
    )
    if entry["disruptive"] is True:
        assert errors.items == []
        assert allowed == frozenset(members)
    else:
        assert errors.items == [f"allow-list entry {name} is not a disruptive family"]
