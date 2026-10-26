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
    loaded = toggles.load_catalogue(catalogue(), {}, FAMILIES, {FAMILY: False}, errors)
    assert errors.items == []
    assert toggles.disabled_rules(loaded.rules, loaded.toggles, None) == [
        {"rule_id": CRONTAB, "disabled_by": FAMILY},
        {"rule_id": PASSWD, "disabled_by": FAMILY},
    ]


def test_disabled_rules_can_be_restricted_to_a_profile() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(
        catalogue(), {}, FAMILIES, {"linux_compliance_ssh_enabled": False, FAMILY: False}, errors
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
    loaded = toggles.load_catalogue(catalogue(), {}, FAMILIES, given, errors)
    assert len(errors.items) == 1
    assert message in errors.items[0]
    assert loaded.toggles == {}


def test_the_global_opt_in_is_ignored() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(
        catalogue(), {}, FAMILIES, {"linux_compliance_remediate_enabled": "anything"}, errors
    )
    assert errors.items == []
    assert loaded.toggles == {}


def test_the_catalogue_is_returned_sorted_with_its_registry() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(catalogue(), {}, FAMILIES, {}, errors)
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


DMESG = PREFIX + "sysctl_kernel_dmesg_restrict"
USB = PREFIX + "kernel_module_usb-storage_disabled"


def test_toggle_names_are_lower_case_variable_names() -> None:
    assert toggles.rule_toggle_name(USB) == (
        "linux_compliance_rule_kernel_module_usb_storage_disabled_enabled"
    )
    assert toggles.rule_toggle_name(PREFIX + "installed_OS_is_vendor_supported") == (
        "linux_compliance_rule_installed_os_is_vendor_supported_enabled"
    )
    assert toggles.is_text(USB, toggles.RULE_PATTERN)


def test_audit_only_rules_expand_to_full_entries() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(
        catalogue(), {"ssh": [USB], "file_permissions": [DMESG]}, FAMILIES, {}, errors
    )
    assert errors.items == []
    by_id = {str(item["rule_id"]): item for item in loaded.rules}
    assert by_id[USB] == {
        "rule_id": USB,
        "family": "ssh",
        "disruptive": True,
        "reversible": True,
        "revert_strategy": "audit_only",
        "toggle": "linux_compliance_rule_kernel_module_usb_storage_disabled_enabled",
        "runbook": None,
        "parameters": {},
    }
    assert not toggles.is_native(by_id[USB])
    assert toggles.is_native(by_id[CRONTAB])
    assert [item["rule_id"] for item in loaded.rules] == sorted(by_id)


@pytest.mark.parametrize(
    ("audit_only", "message"),
    [
        (["x"], "must map families to lists of rule identifiers"),
        ({"kernel": [DMESG]}, "names the unknown family 'kernel'"),
        ({"ssh": DMESG}, "the audit_only rules of ssh must be a list"),
        ({"ssh": [1]}, "invalid rule_id 1"),
        ({"ssh": [CRONTAB]}, f"rule {CRONTAB} is listed twice"),
    ],
)
def test_an_invalid_audit_only_catalogue_is_an_error(audit_only: object, message: str) -> None:
    errors = toggles.Errors()
    toggles.load_catalogue(catalogue(), audit_only, FAMILIES, {}, errors)
    assert any(message in item for item in errors.items), errors.items


def test_a_native_entry_cannot_be_audit_only_or_take_parameters_as_audit_only() -> None:
    errors = toggles.Errors()
    entry = {**rule(DMESG), "revert_strategy": "audit_only", "parameters": {"x": 1}}
    toggles.load_catalogue([*catalogue(), entry], {}, FAMILIES, {}, errors)
    assert errors.items == [
        "list audit_only rules in the audit_only catalogue, not with the native rules",
        f"{DMESG}: an audit_only rule has no native remediation and takes no parameters",
    ]


def test_two_rules_with_the_same_toggle_are_an_error() -> None:
    errors = toggles.Errors()
    toggles.load_catalogue(
        catalogue(), {"ssh": [PREFIX + "a-b", PREFIX + "a_b"]}, FAMILIES, {}, errors
    )
    assert errors.items == [
        (
            f"{PREFIX}a_b: its toggle linux_compliance_rule_a_b_enabled is also the toggle of "
            f"{PREFIX}a-b"
        )
    ]
