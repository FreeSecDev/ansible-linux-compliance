from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)

PREFIX = "xccdf_org.ssgproject.content_rule_"
CRONTAB = PREFIX + "file_permissions_crontab"
SSSD = PREFIX + "sssd_enable_smartcards"
CHRONY = PREFIX + "chronyd_sync_clock"
PAM_UNIX = PREFIX + "accounts_password_pam_unix_enabled"
PWQUALITY = PREFIX + "accounts_password_pam_minlen"
SERVICES = "linux_compliance_services_enabled"
SSSD_TOPIC = "linux_compliance_sssd_enabled"
TIME_SYNC = "linux_compliance_time_sync_enabled"
PAM = "linux_compliance_pam_enabled"
PWQUALITY_TOPIC = "linux_compliance_pwquality_enabled"
FAMILIES: list[dict[str, object]] = [
    {"name": "file_permissions", "disruptive": False},
    {"name": "sssd", "disruptive": True, "umbrella": "services"},
    {"name": "time_sync", "disruptive": True, "umbrella": "services"},
    {"name": "pam", "disruptive": True},
    {"name": "pwquality", "disruptive": True, "umbrella": "pam"},
]
UMBRELLAS = {"sssd": "services", "time_sync": "services", "pwquality": "pam"}
FAMILY_FLAGS = {
    "file_permissions": False,
    "sssd": True,
    "time_sync": True,
    "pam": True,
    "pwquality": True,
}


def rule(rule_id: str, family: str) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "family": family,
        "disruptive": family != "file_permissions",
        "reversible": True,
        "revert_strategy": "audit_only",
        "toggle": toggles.rule_toggle_name(rule_id),
        "runbook": None,
        "parameters": {},
    }


def audit_only() -> dict[str, object]:
    return {
        "file_permissions": [CRONTAB],
        "sssd": [SSSD],
        "time_sync": [CHRONY],
        "pam": [PAM_UNIX],
        "pwquality": [PWQUALITY],
    }


def load(given: dict[str, object]) -> tuple[toggles.Catalogue, list[str]]:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue([], audit_only(), FAMILIES, given, errors)
    return loaded, errors.items


def state(rule_id: str, family: str, given: dict[str, bool]) -> toggles.Toggle:
    return toggles.resolve_toggle(rule(rule_id, family), given, umbrellas=UMBRELLAS)


def off(disabled_by: str) -> toggles.Toggle:
    return toggles.Toggle(on=False, disabled_by=disabled_by)


ON = toggles.Toggle(on=True, disabled_by=None)
SSSD_RULE = toggles.rule_toggle_name(SSSD)


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ({}, ON),
        ({SERVICES: True, SSSD_TOPIC: True}, ON),
        ({SERVICES: False}, off(SERVICES)),
        ({SERVICES: False, SSSD_TOPIC: True}, off(SERVICES)),
        ({SERVICES: False, SSSD_TOPIC: False}, off(SERVICES)),
        ({SERVICES: True, SSSD_TOPIC: False}, off(SSSD_TOPIC)),
        ({SSSD_TOPIC: False}, off(SSSD_TOPIC)),
        ({SERVICES: False, SSSD_RULE: True}, ON),
        ({SERVICES: False, SSSD_TOPIC: False, SSSD_RULE: True}, ON),
        ({SERVICES: False, SSSD_RULE: False}, off(SERVICES)),
        ({SERVICES: True, SSSD_TOPIC: True, SSSD_RULE: False}, off(SSSD_RULE)),
    ],
)
def test_an_umbrella_switches_its_families_off_and_a_topic_toggle_only_narrows_it(
    given: dict[str, bool], expected: toggles.Toggle
) -> None:
    assert state(SSSD, "sssd", given) == expected


def test_a_topic_toggle_leaves_the_other_families_of_its_umbrella_alone() -> None:
    assert state(CHRONY, "time_sync", {SSSD_TOPIC: False}) == ON
    assert state(CHRONY, "time_sync", {SERVICES: False}) == off(SERVICES)
    assert state(CRONTAB, "file_permissions", {SERVICES: False}) == ON


def test_a_family_that_heads_an_umbrella_switches_off_its_own_and_its_families_rules() -> None:
    assert state(PAM_UNIX, "pam", {PAM: False}) == off(PAM)
    assert state(PWQUALITY, "pwquality", {PAM: False}) == off(PAM)
    assert state(PWQUALITY, "pwquality", {PAM: False, PWQUALITY_TOPIC: True}) == off(PAM)
    assert state(PWQUALITY, "pwquality", {PWQUALITY_TOPIC: False}) == off(PWQUALITY_TOPIC)
    assert state(PAM_UNIX, "pam", {PWQUALITY_TOPIC: False}) == ON


def test_the_registry_reports_umbrellas_and_umbrella_toggles_are_known() -> None:
    loaded, errors = load({SERVICES: False, SSSD_TOPIC: True})
    assert errors == []
    assert loaded.umbrellas == UMBRELLAS
    assert loaded.toggles == {SERVICES: False, SSSD_TOPIC: True}
    assert toggles.disabled_rules(loaded.rules, loaded.toggles, None, umbrellas=UMBRELLAS) == [
        {"rule_id": CHRONY, "disabled_by": SERVICES},
        {"rule_id": SSSD, "disabled_by": SERVICES},
    ]


def test_a_name_that_is_neither_a_family_nor_an_umbrella_is_still_unknown() -> None:
    loaded, errors = load({"linux_compliance_service_enabled": False})
    assert errors == ["'linux_compliance_service_enabled' is not the toggle of a catalogued family"]
    assert loaded.toggles == {}


def test_topics_list_each_umbrella_before_its_first_family_and_governed_lists_members() -> None:
    assert toggles.topics(FAMILY_FLAGS, UMBRELLAS) == [
        "file_permissions",
        "services",
        "sssd",
        "time_sync",
        "pam",
        "pwquality",
    ]
    assert toggles.governed("services", FAMILY_FLAGS, UMBRELLAS) == ["sssd", "time_sync"]
    assert toggles.governed("pam", FAMILY_FLAGS, UMBRELLAS) == ["pam", "pwquality"]
    assert toggles.governed("sssd", FAMILY_FLAGS, UMBRELLAS) == ["sssd"]
    assert toggles.governed("unknown", FAMILY_FLAGS, UMBRELLAS) == []


@pytest.mark.parametrize(
    ("registry", "message"),
    [
        (
            [{"name": "sssd", "disruptive": True, "umbrella": "SERVICES"}],
            "family #0: invalid or reserved umbrella name 'SERVICES'",
        ),
        (
            [{"name": "sssd", "disruptive": True, "umbrella": 5}],
            "family #0: invalid or reserved umbrella name 5",
        ),
        (
            [{"name": "sssd", "disruptive": True, "umbrella": None}],
            "family #0: invalid or reserved umbrella name None",
        ),
        (
            [{"name": "sssd", "disruptive": True, "umbrella": "audit_services"}],
            "family #0: invalid or reserved umbrella name 'audit_services'",
        ),
        (
            [{"name": "sssd", "disruptive": True, "umbrella": "rule"}],
            "family #0: invalid or reserved umbrella name 'rule'",
        ),
        (
            [{"name": "sssd", "disruptive": True, "umbrella": "services", "group": "x"}],
            "family #0: keys must be exactly ['disruptive', 'name'] and optionally umbrella",
        ),
        (
            [{"name": "sssd", "disruptive": True, "umbrella": "sssd"}],
            "family sssd heads an umbrella and cannot itself belong to the umbrella sssd",
        ),
        (
            [
                {"name": "pam", "disruptive": True, "umbrella": "accounts"},
                {"name": "pwquality", "disruptive": True, "umbrella": "pam"},
            ],
            "family pam heads an umbrella and cannot itself belong to the umbrella accounts",
        ),
    ],
)
def test_invalid_umbrellas_are_errors(registry: list[dict[str, object]], message: str) -> None:
    errors = toggles.Errors()
    checked = toggles.check_registry(registry, errors)
    assert len(errors.items) == 1
    assert errors.items[0].startswith(message)
    assert "pam" not in checked.umbrellas


def test_an_invalid_registry_has_neither_families_nor_umbrellas() -> None:
    errors = toggles.Errors()
    assert toggles.check_registry("services", errors) == toggles.Registry(families={}, umbrellas={})
    assert errors.items == ["the family registry must be a list of 1 to 64 families"]


def test_an_umbrella_that_excludes_nothing_warns_once_naming_its_families() -> None:
    loaded, errors = load({SERVICES: False, SSSD_TOPIC: False})
    assert errors == []
    assert toggles.topic_warnings(loaded, frozenset({CRONTAB})) == [
        (
            f"WARNING: {SERVICES} is false, but no catalogued rule of the families that services "
            f"groups (sssd, time_sync) is selected by the profile, so it excludes nothing; rules "
            f"outside the rule catalogue are still audited (see docs/remediation-variables.md)"
        ),
        (
            f"WARNING: {SSSD_TOPIC} is false, but no catalogued rule of the sssd family is "
            f"selected by the profile, so it excludes nothing; rules outside the rule catalogue "
            f"are still audited (see docs/remediation-variables.md)"
        ),
    ]


def test_an_umbrella_that_excludes_a_rule_of_one_family_does_not_warn() -> None:
    loaded, errors = load({SERVICES: False})
    assert errors == []
    assert toggles.topic_warnings(loaded, frozenset({CHRONY})) == []
    assert toggles.topic_warnings(loaded, None) == []


def test_a_heading_family_warns_only_when_none_of_its_families_has_a_rule() -> None:
    loaded, errors = load({PAM: False})
    assert errors == []
    assert toggles.topic_warnings(loaded, frozenset({PWQUALITY})) == []
    assert toggles.topic_warnings(loaded, frozenset({CRONTAB})) == [
        (
            f"WARNING: {PAM} is false, but no catalogued rule of the families that pam groups "
            f"(pam, pwquality) is selected by the profile, so it excludes nothing; rules outside "
            f"the rule catalogue are still audited (see docs/remediation-variables.md)"
        )
    ]
