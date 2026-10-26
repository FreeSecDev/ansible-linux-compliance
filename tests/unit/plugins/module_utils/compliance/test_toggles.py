from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)

PREFIX = "xccdf_org.ssgproject.content_rule_"
CRONTAB = PREFIX + "file_permissions_crontab"
PASSWD = PREFIX + "file_permissions_etc_passwd"
ROOT_LOGIN = PREFIX + "sshd_disable_root_login"
FAMILY = "linux_compliance_file_permissions_enabled"
FAMILIES: list[dict[str, object]] = [
    {"name": "file_permissions", "disruptive": False},
    {"name": "ssh", "disruptive": True},
]


def rule(rule_id: str, family: str = "file_permissions") -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "family": family,
        "disruptive": family == "ssh",
        "reversible": True,
        "revert_strategy": "recorded_value",
        "toggle": toggles.rule_toggle_name(rule_id),
        "runbook": None,
        "parameters": {},
    }


def catalogue() -> list[dict[str, object]]:
    return [rule(PASSWD), rule(CRONTAB), rule(ROOT_LOGIN, "ssh")]


def test_names_follow_adr_0011() -> None:
    assert toggles.toggle_name("auditd") == "linux_compliance_auditd_enabled"
    assert toggles.rule_short_id(CRONTAB) == "file_permissions_crontab"
    assert toggles.rule_toggle_name(CRONTAB) == (
        "linux_compliance_rule_file_permissions_crontab_enabled"
    )


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ({}, toggles.Toggle(on=True, disabled_by=None)),
        ({FAMILY: True}, toggles.Toggle(on=True, disabled_by=None)),
        ({FAMILY: False}, toggles.Toggle(on=False, disabled_by=FAMILY)),
        (
            {toggles.rule_toggle_name(CRONTAB): False},
            toggles.Toggle(on=False, disabled_by=toggles.rule_toggle_name(CRONTAB)),
        ),
        (
            {FAMILY: True, toggles.rule_toggle_name(CRONTAB): False},
            toggles.Toggle(on=False, disabled_by=toggles.rule_toggle_name(CRONTAB)),
        ),
        (
            {FAMILY: False, toggles.rule_toggle_name(CRONTAB): True},
            toggles.Toggle(on=True, disabled_by=None),
        ),
        (
            {FAMILY: False, toggles.rule_toggle_name(CRONTAB): False},
            toggles.Toggle(on=False, disabled_by=FAMILY),
        ),
    ],
)
def test_the_rule_toggle_falls_back_to_the_family_toggle_and_then_to_on(
    given: dict[str, bool], expected: toggles.Toggle
) -> None:
    assert toggles.resolve_toggle(rule(CRONTAB), given) == expected


def test_a_generated_default_that_follows_its_family_names_the_family() -> None:
    family_off = {FAMILY: False}
    generated = {FAMILY: False, toggles.rule_toggle_name(CRONTAB): False}
    assert toggles.resolve_toggle(rule(CRONTAB), family_off) == toggles.resolve_toggle(
        rule(CRONTAB), generated
    )


def test_a_family_toggle_switches_off_only_its_own_rules() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(catalogue(), FAMILIES, {FAMILY: False}, errors)
    assert errors.items == []
    assert toggles.disabled_rules(loaded.rules, loaded.toggles, None) == [
        {"rule_id": CRONTAB, "disabled_by": FAMILY},
        {"rule_id": PASSWD, "disabled_by": FAMILY},
    ]


def test_disabled_rules_can_be_restricted_to_a_profile() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(
        catalogue(), FAMILIES, {"linux_compliance_ssh_enabled": False, FAMILY: False}, errors
    )
    assert toggles.disabled_rules(loaded.rules, loaded.toggles, frozenset({ROOT_LOGIN})) == [
        {"rule_id": ROOT_LOGIN, "disabled_by": "linux_compliance_ssh_enabled"}
    ]


@pytest.mark.parametrize(
    ("given", "message"),
    [
        ({FAMILY: "false"}, f"{FAMILY} must be a boolean"),
        ({FAMILY: None}, f"{FAMILY} must be a boolean"),
        ({FAMILY: 0}, f"{FAMILY} must be a boolean"),
        ({toggles.rule_toggle_name(CRONTAB): "{{ x }}"}, "must be a boolean"),
        ({"linux_compliance_rule_unknown_enabled": True}, "is not the toggle of a catalogued rule"),
        ({"linux_compliance_sshd_enabled": True}, "is not the toggle of a catalogued family"),
        ({"linux_compliance_audit_enabled": True}, "is in the namespace of a role"),
        ({"linux_compliance_verify_x_enabled": True}, "is in the namespace of a role"),
    ],
)
def test_invalid_and_unknown_toggles_are_errors(given: dict[str, object], message: str) -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(catalogue(), FAMILIES, given, errors)
    assert len(errors.items) == 1
    assert message in errors.items[0]
    assert loaded.toggles == {}


def test_the_global_opt_in_is_ignored() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(
        catalogue(), FAMILIES, {"linux_compliance_remediate_enabled": "anything"}, errors
    )
    assert errors.items == []
    assert loaded.toggles == {}


def test_the_catalogue_is_returned_sorted_with_its_registry() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(catalogue(), FAMILIES, {}, errors)
    assert [item["rule_id"] for item in loaded.rules] == sorted([CRONTAB, PASSWD, ROOT_LOGIN])
    assert loaded.families == {"file_permissions": False, "ssh": True}


def test_helpers_reject_strings_as_sequences_and_non_mappings() -> None:
    assert toggles.as_sequence("abc") is None
    assert toggles.as_sequence(("a",)) == ["a"]
    assert toggles.as_mapping(["a"]) is None
    assert toggles.as_mapping({1: "a"}) == {"1": "a"}
    assert toggles.in_namespace("audit_rules", ("audit",))
    assert not toggles.in_namespace("auditd", ("audit",))
    assert toggles.is_text("abc", "[a-c]+")
    assert not toggles.is_text(1, "[a-c]+")
    assert len(toggles.show("x" * 100)) == 64
