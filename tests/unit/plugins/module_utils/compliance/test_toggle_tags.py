from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)

PREFIX = "xccdf_org.ssgproject.content_rule_"
CRONTAB = PREFIX + "file_permissions_crontab"
SSSD_LOGS = PREFIX + "file_permissions_var_log_sssd"
SMARTCARDS = PREFIX + "sssd_enable_smartcards"
CRON_SERVICE = PREFIX + "service_cron_enabled"
FAMILIES: list[dict[str, object]] = [
    {"name": "file_permissions", "disruptive": False},
    {"name": "sssd", "disruptive": True, "umbrella": "services"},
    {"name": "cron", "disruptive": True, "umbrella": "services"},
    {"name": "smartcard", "disruptive": True, "umbrella": "accounts"},
    {"name": "desktop", "disruptive": True},
]
FLAGS = {"file_permissions": False, "sssd": True, "cron": True, "smartcard": True, "desktop": True}
UMBRELLAS = {"sssd": "services", "cron": "services", "smartcard": "accounts"}
TAGS: dict[str, object] = {
    "cron": [CRONTAB],
    "smartcard": [SSSD_LOGS, SMARTCARDS],
    "sssd": [SSSD_LOGS],
}


def audit_only() -> dict[str, object]:
    return {
        "file_permissions": [CRONTAB, SSSD_LOGS],
        "sssd": [SMARTCARDS],
        "cron": [CRON_SERVICE],
        "smartcard": [],
        "desktop": [],
    }


def load(
    given: dict[str, object] | None = None, tags: object = None
) -> tuple[toggles.Catalogue, list[str]]:
    errors = toggles.Errors()
    loaded = toggles.with_tags(
        toggles.load_catalogue([], audit_only(), FAMILIES, given or {}, errors),
        TAGS if tags is None else tags,
        errors,
    )
    return loaded, errors.items


def rule(rule_id: str, family: str) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "family": family,
        "disruptive": FLAGS[family],
        "reversible": True,
        "revert_strategy": "audit_only",
        "toggle": toggles.rule_toggle_name(rule_id),
        "runbook": None,
        "parameters": {},
    }


def off(topic: str) -> toggles.Toggle:
    return toggles.Toggle(on=False, disabled_by=toggles.toggle_name(topic))


ON = toggles.Toggle(on=True, disabled_by=None)


def state(
    rule_id: str, family: str, tags: tuple[str, ...], given: dict[str, bool]
) -> toggles.Toggle:
    values = {toggles.toggle_name(name): value for name, value in given.items()}
    return toggles.resolve_toggle(rule(rule_id, family), values, umbrellas=UMBRELLAS, tags=tags)


def test_the_tags_of_every_tagged_rule_are_collected_and_sorted() -> None:
    loaded, errors = load()
    assert errors == []
    assert loaded.tags == {
        CRONTAB: ("cron",),
        SSSD_LOGS: ("smartcard", "sssd"),
        SMARTCARDS: ("smartcard",),
    }


def test_without_tags_no_rule_is_tagged() -> None:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue([], audit_only(), FAMILIES, {}, errors)
    assert errors.items == []
    assert loaded.tags == {}


@pytest.mark.parametrize(
    ("tags", "message"),
    [
        ([], "the subsystem tags must map families to lists of rule identifiers"),
        ({"nfs": [CRONTAB]}, "the subsystem tags name the unknown family 'nfs'"),
        ({"cron": CRONTAB}, "the rules tagged cron must be a list of rule identifiers"),
        ({"cron": ["crontab"]}, "the rules tagged cron must be a list of rule identifiers"),
        ({"cron": [SSSD_LOGS, CRONTAB]}, "the rules tagged cron must be sorted and free of"),
        ({"cron": [CRONTAB, CRONTAB]}, "the rules tagged cron must be sorted and free of"),
        (
            {"cron": [PREFIX + "missing"]},
            f"the subsystem tag cron names {PREFIX}missing, which is not catalogued",
        ),
        (
            {"cron": [CRON_SERVICE]},
            f"{CRON_SERVICE} belongs to the family cron and cannot also be tagged with it",
        ),
    ],
)
def test_invalid_tags_are_refused(tags: object, message: str) -> None:
    _loaded, errors = load(tags=tags)
    assert len(errors) == 1
    assert errors[0].startswith(message)


@pytest.mark.parametrize(
    ("family", "tags", "expected"),
    [
        ("file_permissions", (), ["file_permissions"]),
        ("file_permissions", ("cron",), ["file_permissions", "services", "cron"]),
        ("sssd", ("smartcard",), ["services", "sssd", "accounts", "smartcard"]),
        (
            "file_permissions",
            ("sssd", "smartcard"),
            ["file_permissions", "accounts", "smartcard", "services", "sssd"],
        ),
        ("sssd", ("cron",), ["services", "sssd", "cron"]),
        ("desktop", ("desktop",), ["desktop"]),
    ],
)
def test_the_controlling_topics_follow_the_documented_precedence(
    family: str, tags: tuple[str, ...], expected: list[str]
) -> None:
    assert toggles.controlling_topics(family, tags, UMBRELLAS) == expected


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ({}, ON),
        ({"cron": True, "services": True, "smartcard": True, "sssd": True}, ON),
        ({"sssd": False}, off("sssd")),
        ({"smartcard": False}, off("smartcard")),
        ({"accounts": False}, off("accounts")),
        ({"services": False}, off("services")),
        ({"smartcard": False, "sssd": False}, off("smartcard")),
        ({"services": False, "accounts": False}, off("accounts")),
        ({"file_permissions": False, "accounts": False}, off("file_permissions")),
        ({"file_permissions": False, "sssd": True, "smartcard": True}, off("file_permissions")),
    ],
)
def test_a_rule_with_two_tags_is_off_when_any_of_them_or_their_umbrellas_is_off(
    given: dict[str, bool], expected: toggles.Toggle
) -> None:
    assert state(SSSD_LOGS, "file_permissions", ("smartcard", "sssd"), given) == expected


def test_a_rule_toggle_that_is_set_wins_over_every_tag() -> None:
    values = {
        toggles.toggle_name("cron"): False,
        toggles.toggle_name("services"): False,
        toggles.rule_toggle_name(CRONTAB): True,
    }
    assert (
        toggles.resolve_toggle(
            rule(CRONTAB, "file_permissions"), values, umbrellas=UMBRELLAS, tags=("cron",)
        )
        == ON
    )
    values[toggles.rule_toggle_name(CRONTAB)] = False
    assert toggles.resolve_toggle(
        rule(CRONTAB, "file_permissions"), values, umbrellas=UMBRELLAS, tags=("cron",)
    ) == off("services")


def test_a_rule_toggle_names_itself_when_every_topic_is_on() -> None:
    values = {toggles.rule_toggle_name(CRONTAB): False}
    assert toggles.resolve_toggle(
        rule(CRONTAB, "file_permissions"), values, umbrellas=UMBRELLAS, tags=("cron",)
    ) == toggles.Toggle(on=False, disabled_by=toggles.rule_toggle_name(CRONTAB))


def test_the_tags_default_to_none_in_the_resolution() -> None:
    values = {toggles.toggle_name("cron"): False}
    assert (
        toggles.resolve_toggle(rule(CRONTAB, "file_permissions"), values, umbrellas=UMBRELLAS) == ON
    )


def test_disabled_rules_use_the_tags_of_the_catalogue() -> None:
    loaded, errors = load({toggles.toggle_name("smartcard"): False})
    assert errors == []
    found = toggles.disabled_rules(
        loaded.rules, loaded.toggles, None, umbrellas=loaded.umbrellas, tags=loaded.tags
    )
    assert found == [
        {"rule_id": SSSD_LOGS, "disabled_by": toggles.toggle_name("smartcard")},
        {"rule_id": SMARTCARDS, "disabled_by": toggles.toggle_name("smartcard")},
    ]
    assert (
        toggles.disabled_rules(loaded.rules, loaded.toggles, None, umbrellas=loaded.umbrellas) == []
    )


def test_switches_off_names_every_controlling_topic() -> None:
    loaded, _errors = load()
    sssd_logs = rule(SSSD_LOGS, "file_permissions")
    assert [
        topic
        for topic in toggles.topics(loaded.families, loaded.umbrellas)
        if toggles.switches_off(topic, sssd_logs, loaded)
    ] == ["file_permissions", "services", "sssd", "accounts", "smartcard"]


def test_a_toggle_that_reaches_only_tagged_rules_does_not_warn() -> None:
    loaded, errors = load({toggles.toggle_name("smartcard"): False})
    assert errors == []
    assert toggles.topic_warnings(loaded, frozenset({SMARTCARDS})) == []
    warnings = toggles.topic_warnings(loaded, frozenset({CRON_SERVICE}))
    assert len(warnings) == 1
    assert warnings[0].startswith("WARNING: linux_compliance_smartcard_enabled is false")


def test_a_toggle_without_rules_or_tagged_rules_still_warns() -> None:
    loaded, errors = load({toggles.toggle_name("desktop"): False})
    assert errors == []
    expected = (
        "WARNING: linux_compliance_desktop_enabled is false, but no catalogued rule of the "
        "desktop family is selected by the profile, so it excludes nothing; rules outside the "
        "rule catalogue are still audited (see docs/remediation-variables.md)"
    )
    assert toggles.topic_warnings(loaded, None) == [expected]


def test_the_ledger_family_aliases_are_validated() -> None:
    errors = toggles.Errors()
    aliases = toggles.check_family_aliases(
        {"permissions": ["file_permissions"], "crontab": ["cron", "file_permissions"]},
        FLAGS,
        errors,
    )
    assert errors.items == []
    assert aliases == {
        "permissions": frozenset({"file_permissions"}),
        "crontab": frozenset({"cron", "file_permissions"}),
    }


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ([], "the ledger family aliases must map former family names to lists of families"),
        ({"Permissions": ["file_permissions"]}, "invalid or reserved former family name"),
        ({"audit_x": ["file_permissions"]}, "invalid or reserved former family name"),
        ({"old": []}, "the alias old must list registered families"),
        ({"old": "file_permissions"}, "the alias old must list registered families"),
        ({"old": ["nfs"]}, "the alias old must list registered families"),
        ({"old": [3]}, "the alias old must list registered families"),
        ({"old": ["sssd", "cron"]}, "the alias old must be sorted, free of duplicates"),
        ({"old": ["cron", "cron"]}, "the alias old must be sorted, free of duplicates"),
        ({"cron": ["cron"]}, "the alias cron must be sorted, free of duplicates and not name"),
    ],
)
def test_invalid_ledger_family_aliases_are_refused(raw: object, message: str) -> None:
    errors = toggles.Errors()
    assert toggles.check_family_aliases(raw, FLAGS, errors) == {}
    assert len(errors.items) == 1
    assert errors.items[0].startswith(message)
