from __future__ import annotations

from typing import cast

import pytest

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
PARTITION = PREFIX + "partition_for_tmp"

FAMILIES: list[dict[str, object]] = [
    {"name": "file_permissions", "disruptive": False},
    {"name": "ssh", "disruptive": True},
    {"name": "mounts", "disruptive": True},
    {"name": "sysctl", "disruptive": False},
]


def rule(rule_id: str, family_name: str, **overrides: object) -> dict[str, object]:
    disruptive = family_name in {"ssh", "mounts"}
    entry: dict[str, object] = {
        "rule_id": rule_id,
        "family": family_name,
        "disruptive": disruptive,
        "reversible": True,
        "revert_strategy": "recorded_value",
        "toggle": toggles.rule_toggle_name(rule_id),
        "runbook": None,
        "parameters": {},
    }
    entry.update(overrides)
    return entry


def catalogue() -> list[dict[str, object]]:
    return [
        rule(PASSWD, "file_permissions"),
        rule(CRONTAB, "file_permissions"),
        rule(ROOT_LOGIN, "ssh", revert_strategy="owned_dropin"),
        rule(
            PARTITION,
            "mounts",
            reversible=False,
            revert_strategy="irreversible",
            runbook="docs/runbooks/partitioning.md",
        ),
    ]


def ledger_entry(rule_id: str, family: str) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "family": family,
        "revert_strategy": "recorded_value",
        "prior_values": [{"name": "mode", "value": "0644", "sensitive": False, "redacted": False}],
        "collection_version": "0.1.0",
        "applied_at": "2026-10-26T00:00:00Z",
    }


def options(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "audit_only": {},
        "families": FAMILIES,
        "enabled": True,
        "allow_disruptive": [],
        "toggles": {},
        "profile_rule_ids": [CRONTAB, PASSWD, ROOT_LOGIN, PARTITION],
        "ledger_entries": [],
    }
    values.update(overrides)
    return values


def run(
    rules: object = None, **overrides: object
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    result = plan_filter.remediation_plan(
        catalogue() if rules is None else rules, options(**overrides)
    )
    by_id = {
        str(item["rule_id"]): item for item in cast("list[dict[str, object]]", result["rules"])
    }
    return result, by_id


def errors_of(rules: object = None, **overrides: object) -> list[str]:
    result = run(rules, **overrides)[0]
    errors = cast("list[str]", result["errors"])
    assert errors
    assert result["rules"] == []
    assert result["families"] == []
    assert result["summary"] == dict.fromkeys(plan_filter.ACTIONS, 0)
    return errors


def test_the_filter_is_registered() -> None:
    filters = plan_filter.FilterModule().filters()
    assert filters == {"remediation_plan": plan_filter.remediation_plan}


def test_nothing_is_planned_when_remediation_is_disabled() -> None:
    result, rules = run(enabled=False, profile_rule_ids=None)
    assert result["errors"] == []
    assert result["enabled"] is False
    assert {item["action"] for item in rules.values()} == {"skip"}
    assert {item["reason"] for item in rules.values()} == {"remediation_disabled"}
    assert result["families"] == []
    assert result["summary"] == {
        "apply": 0,
        "cleanup": 0,
        "manual": 0,
        "none": 0,
        "not_implemented": 0,
        "skip": 4,
    }
    assert result["notices"] == [
        (
            "remediation is disabled (linux_compliance_remediate_enabled is false): 4 rule(s) "
            "skipped, the host was neither read nor changed"
        )
    ]


def test_a_disabled_remediation_never_cleans_up_even_with_a_ledger_entry() -> None:
    result, rules = run(
        enabled=False,
        profile_rule_ids=None,
        toggles={"linux_compliance_file_permissions_enabled": False},
        ledger_entries=[ledger_entry(CRONTAB, "file_permissions")],
    )
    assert rules[CRONTAB]["action"] == "skip"
    assert rules[CRONTAB]["pending_cleanup"] is True
    assert result["families"] == []
    assert result["disabled_rules"] == [
        {"rule_id": CRONTAB, "disabled_by": "linux_compliance_file_permissions_enabled"},
        {"rule_id": PASSWD, "disabled_by": "linux_compliance_file_permissions_enabled"},
    ]


def test_enabled_rules_are_applied_and_disruptive_families_are_skipped() -> None:
    result, rules = run()
    assert result["errors"] == []
    assert rules[CRONTAB]["action"] == "apply"
    assert rules[CRONTAB]["reason"] == "enabled"
    assert rules[ROOT_LOGIN]["action"] == "skip"
    assert rules[ROOT_LOGIN]["reason"] == "disruptive_not_allowed"
    assert rules[ROOT_LOGIN]["pending_cleanup"] is False
    assert rules[PARTITION]["reason"] == "disruptive_not_allowed"
    families = cast("list[dict[str, object]]", result["families"])
    assert [family["name"] for family in families] == ["file_permissions"]
    applied = cast("list[dict[str, object]]", families[0]["apply"])
    assert [item["rule_id"] for item in applied] == [CRONTAB, PASSWD]
    assert families[0]["cleanup"] == []
    assert families[0]["disruptive"] is False
    assert result["notices"] == [
        (
            f"{PARTITION}: skipped, family mounts is disruptive and not named in "
            "linux_compliance_remediate_allow_disruptive"
        ),
        (
            f"{ROOT_LOGIN}: skipped, family ssh is disruptive and not named in "
            "linux_compliance_remediate_allow_disruptive"
        ),
    ]
    assert result["summary"] == {
        "apply": 2,
        "cleanup": 0,
        "manual": 0,
        "none": 0,
        "not_implemented": 0,
        "skip": 2,
    }


def test_an_allow_listed_disruptive_family_is_applied_in_registry_order() -> None:
    result, rules = run(allow_disruptive=["ssh", "mounts"])
    assert rules[ROOT_LOGIN]["action"] == "apply"
    assert rules[PARTITION]["action"] == "apply"
    families = cast("list[dict[str, object]]", result["families"])
    assert [family["name"] for family in families] == ["file_permissions", "ssh", "mounts"]
    assert result["notices"] == []


def test_a_disruptive_family_that_is_not_allowed_keeps_its_pending_cleanup() -> None:
    result, rules = run(
        toggles={"linux_compliance_ssh_enabled": False},
        ledger_entries=[ledger_entry(ROOT_LOGIN, "ssh")],
    )
    assert rules[ROOT_LOGIN]["action"] == "skip"
    assert rules[ROOT_LOGIN]["pending_cleanup"] is True
    assert rules[ROOT_LOGIN]["disabled_by"] == "linux_compliance_ssh_enabled"
    assert (
        f"{ROOT_LOGIN}: skipped, family ssh is disruptive and not named in "
        "linux_compliance_remediate_allow_disruptive; it is recorded as applied and its cleanup "
        "waits for the allow-list"
    ) in cast("list[str]", result["notices"])


def test_the_rule_toggle_wins_over_the_family_toggle() -> None:
    rules = run(
        toggles={
            "linux_compliance_file_permissions_enabled": False,
            toggles.rule_toggle_name(CRONTAB): True,
        }
    )[1]
    assert rules[CRONTAB]["action"] == "apply"
    assert rules[CRONTAB]["disabled_by"] is None
    assert rules[PASSWD]["action"] == "none"
    assert rules[PASSWD]["reason"] == "disabled_by_toggle"
    assert rules[PASSWD]["disabled_by"] == "linux_compliance_file_permissions_enabled"


def test_a_rule_toggle_can_switch_off_one_rule_of_an_enabled_family() -> None:
    result, rules = run(
        toggles={
            "linux_compliance_file_permissions_enabled": True,
            toggles.rule_toggle_name(CRONTAB): False,
        }
    )
    assert rules[CRONTAB]["disabled_by"] == toggles.rule_toggle_name(CRONTAB)
    assert rules[PASSWD]["action"] == "apply"
    assert result["disabled_rules"] == [
        {"rule_id": CRONTAB, "disabled_by": toggles.rule_toggle_name(CRONTAB)}
    ]


def test_a_disabled_rule_recorded_in_the_ledger_is_cleaned_up() -> None:
    entry = ledger_entry(CRONTAB, "file_permissions")
    result, rules = run(toggles={toggles.rule_toggle_name(CRONTAB): False}, ledger_entries=[entry])
    assert rules[CRONTAB]["action"] == "cleanup"
    assert rules[CRONTAB]["reason"] == "disabled_by_toggle"
    assert rules[CRONTAB]["ledger_entry"] == entry
    assert rules[PASSWD]["ledger_entry"] is None
    families = cast("list[dict[str, object]]", result["families"])
    cleanup = cast("list[dict[str, object]]", families[0]["cleanup"])
    assert [item["rule_id"] for item in cleanup] == [CRONTAB]


def test_an_applied_rule_that_the_profile_no_longer_selects_is_cleaned_up() -> None:
    result, rules = run(
        profile_rule_ids=[PASSWD], ledger_entries=[ledger_entry(CRONTAB, "file_permissions")]
    )
    assert rules[CRONTAB]["action"] == "cleanup"
    assert rules[CRONTAB]["reason"] == "not_in_profile"
    assert rules[CRONTAB]["disabled_by"] is None
    assert result["disabled_rules"] == []


def test_a_rule_outside_the_profile_without_a_ledger_entry_does_nothing() -> None:
    result, rules = run(profile_rule_ids=[PASSWD])
    assert rules[CRONTAB]["action"] == "none"
    assert rules[CRONTAB]["reason"] == "not_in_profile"
    assert result["summary"] == {
        "apply": 1,
        "cleanup": 0,
        "manual": 0,
        "none": 1,
        "not_implemented": 0,
        "skip": 2,
    }


def test_disabled_rules_outside_the_profile_are_not_reported_for_the_audit() -> None:
    result = run(
        profile_rule_ids=[PASSWD], toggles={"linux_compliance_file_permissions_enabled": False}
    )[0]
    assert result["disabled_rules"] == [
        {"rule_id": PASSWD, "disabled_by": "linux_compliance_file_permissions_enabled"}
    ]


def test_an_irreversible_rule_is_reported_as_a_manual_action_with_its_runbook() -> None:
    result, rules = run(
        allow_disruptive=["mounts"],
        toggles={"linux_compliance_mounts_enabled": False},
        ledger_entries=[ledger_entry(PARTITION, "mounts")],
    )
    assert rules[PARTITION]["action"] == "manual"
    families = cast("list[dict[str, object]]", result["families"])
    assert [family["name"] for family in families] == ["file_permissions"]
    assert result["notices"] == [
        (
            f"{PARTITION}: no longer effective (disabled_by_toggle) but irreversible; it is not "
            "reverted automatically, follow docs/runbooks/partitioning.md"
        ),
        (
            f"{ROOT_LOGIN}: skipped, family ssh is disruptive and not named in "
            "linux_compliance_remediate_allow_disruptive"
        ),
    ]


def test_orphaned_ledger_entries_are_reported_and_left_alone() -> None:
    orphan = PREFIX + "retired_rule"
    result = run(ledger_entries=[ledger_entry(orphan, "sysctl")])[0]
    assert result["orphaned"] == [orphan]
    assert cast("list[str]", result["notices"])[-1] == (
        f"{orphan}: recorded in the state ledger but not in the rule catalogue of this "
        "collection version; nothing was changed, review it manually"
    )


def test_the_report_holds_only_the_reporting_keys() -> None:
    result = run()[0]
    report = cast("list[dict[str, object]]", result["report"])
    assert [tuple(item) for item in report] == [plan_filter.REPORT_KEYS] * 4
    assert [item["rule_id"] for item in report] == sorted([CRONTAB, PASSWD, ROOT_LOGIN, PARTITION])


def test_the_global_opt_in_is_not_mistaken_for_a_toggle() -> None:
    result = run(toggles={"linux_compliance_remediate_enabled": True})[0]
    assert result["errors"] == []


@pytest.mark.parametrize(
    "name",
    [
        "linux_compliance_audit_enabled",
        "linux_compliance_audit_foo_enabled",
        "linux_compliance_verify_enabled",
        "linux_compliance_remediate_ssh_enabled",
    ],
)
def test_undeclared_names_in_a_role_namespace_are_errors(name: str) -> None:
    assert errors_of(toggles={name: False}) == [
        (
            f"{name!r} is in the namespace of a role of the collection but is not a variable of "
            "that role; topic toggles of a family are linux_compliance_<family>_enabled"
        )
    ]


@pytest.mark.parametrize("family", sorted(toggles.DISRUPTIVE_FAMILIES))
def test_a_known_disruptive_family_cannot_be_marked_non_disruptive(family: str) -> None:
    families = [{"name": family, "disruptive": False}]
    assert errors_of([], families=families) == [
        f"family #0: family {family} is always disruptive and cannot be marked otherwise"
    ]


def test_a_disruptive_rule_outside_the_profile_with_a_ledger_entry_is_pending_cleanup() -> None:
    result, rules = run(
        profile_rule_ids=[CRONTAB], ledger_entries=[ledger_entry(ROOT_LOGIN, "ssh")]
    )
    assert rules[ROOT_LOGIN]["action"] == "skip"
    assert rules[ROOT_LOGIN]["reason"] == "disruptive_not_allowed"
    assert rules[ROOT_LOGIN]["pending_cleanup"] is True
    assert result["errors"] == []


def test_a_disruptive_rule_that_would_still_be_applied_is_not_pending_cleanup() -> None:
    rules = run(ledger_entries=[ledger_entry(ROOT_LOGIN, "ssh")])[1]
    assert rules[ROOT_LOGIN]["action"] == "skip"
    assert rules[ROOT_LOGIN]["pending_cleanup"] is False


@pytest.mark.parametrize(
    ("given", "message"),
    [
        (
            {"linux_compliance_rule_typo_enabled": False},
            "'linux_compliance_rule_typo_enabled' is not the toggle of a catalogued rule",
        ),
        (
            {"linux_compliance_sshd_enabled": False},
            "'linux_compliance_sshd_enabled' is not the toggle of a catalogued family",
        ),
        (
            {"linux_compliance_rule_enabled": False},
            "'linux_compliance_rule_enabled' is not the toggle of a catalogued rule; rule toggle",
        ),
        (
            {"something_else": False},
            "'something_else' is not the toggle of a catalogued family",
        ),
        (
            {"linux_compliance_ssh_enabled": "false"},
            (
                "linux_compliance_ssh_enabled must be a boolean; pass it as JSON, for example "
                "-e '{\"linux_compliance_ssh_enabled\": false}'"
            ),
        ),
        (
            {toggles.rule_toggle_name(CRONTAB): None},
            (
                f"{toggles.rule_toggle_name(CRONTAB)} must be a boolean; pass it as JSON, for "
                f"example -e '{{\"{toggles.rule_toggle_name(CRONTAB)}\": false}}'"
            ),
        ),
    ],
)
def test_unknown_or_invalid_toggles_are_errors(given: dict[str, object], message: str) -> None:
    errors = errors_of(toggles=given)
    assert len(errors) == 1
    assert errors[0].startswith(message)


def test_toggles_must_be_a_mapping() -> None:
    assert errors_of(toggles=["linux_compliance_ssh_enabled"]) == [
        "toggles must be a mapping of variable names to values"
    ]


@pytest.mark.parametrize(
    ("allow", "message"),
    [
        (["sshd"], "allow-list entry 'sshd' is not a registered family"),
        ([7], "allow-list entry 7 is not a registered family"),
        (["file_permissions"], "allow-list entry file_permissions is not a disruptive family"),
        ("ssh", "linux_compliance_remediate_allow_disruptive must be a list"),
    ],
)
def test_invalid_allow_list_entries_are_errors(allow: object, message: str) -> None:
    assert errors_of(allow_disruptive=allow) == [message]


def test_the_global_opt_in_must_be_a_boolean() -> None:
    result = run(enabled="true")[0]
    assert result["errors"] == ["linux_compliance_remediate_enabled must be a boolean"]
    assert result["enabled"] is False


@pytest.mark.parametrize("profile", [None, "rule", [CRONTAB, 3]])
def test_an_enabled_remediation_needs_the_profile_rules(profile: object) -> None:
    assert errors_of(profile_rule_ids=profile) == [
        "profile_rule_ids must list the rule identifiers of the discovered profile"
    ]


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ("entries", "ledger_entries must be a list"),
        (["entry"], "every ledger entry must be a mapping with a rule_id"),
        ([{"family": "ssh"}], "every ledger entry must be a mapping with a rule_id"),
        (
            [ledger_entry(CRONTAB, "ssh")],
            f"{CRONTAB}: the ledger records family 'ssh'",
        ),
    ],
)
def test_invalid_ledger_entries_are_errors(entries: object, message: str) -> None:
    assert errors_of(ledger_entries=entries) == [message]


@pytest.mark.parametrize("given", [None, {}, {"enabled": True}, {**options(), "extra": 1}])
def test_options_must_have_exactly_the_documented_keys(given: object) -> None:
    result = plan_filter.remediation_plan(catalogue(), given)
    errors = cast("list[str]", result["errors"])
    assert len(errors) == 1
    assert errors[0].startswith("options must be a mapping with exactly")
    assert result["enabled"] is False


@pytest.mark.parametrize(
    ("families", "message"),
    [
        ("ssh", "the family registry must be a list of 1 to 64 families"),
        ([], "the family registry must be a list of 1 to 64 families"),
        (
            [{"name": f"f{index}", "disruptive": False} for index in range(65)],
            "the family registry must be a list of 1 to 64 families",
        ),
        (["ssh"], "family #0: must be a mapping"),
        ([{"name": "ssh"}], "family #0: keys must be exactly ['disruptive', 'name'], got ['name']"),
        ([{"name": "SSH", "disruptive": True}], "family #0: invalid or reserved family name 'SSH'"),
        ([{"name": 5, "disruptive": True}], "family #0: invalid or reserved family name 5"),
        (
            [{"name": "audit", "disruptive": True}],
            "family #0: invalid or reserved family name 'audit'",
        ),
        (
            [{"name": "rule_x", "disruptive": True}],
            "family #0: invalid or reserved family name 'rule_x'",
        ),
        (
            [{"name": "ssh", "disruptive": True}, {"name": "ssh", "disruptive": True}],
            "family #1: family ssh is listed twice",
        ),
        ([{"name": "ssh", "disruptive": "yes"}], "family #0: disruptive must be a boolean"),
    ],
)
def test_an_invalid_family_registry_is_an_error(families: object, message: str) -> None:
    assert message in errors_of([], families=families)


def test_a_family_name_may_start_like_a_role() -> None:
    families = [{"name": "auditd", "disruptive": True}]
    result = run([], families=families, toggles={"linux_compliance_auditd_enabled": False})[0]
    assert result["errors"] == []


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ("rule", "rule #0: must be a mapping"),
        ({"rule_id": CRONTAB}, "rule #0: keys must be exactly"),
        (rule("crontab", "file_permissions"), "rule #0: invalid rule_id 'crontab'"),
        (rule(CRONTAB, "kernel"), f"{CRONTAB}: unknown family 'kernel'"),
        (rule(CRONTAB, "file_permissions", family=3), f"{CRONTAB}: unknown family 3"),
        (
            rule(CRONTAB, "file_permissions", disruptive=True),
            f"{CRONTAB}: disruptive must equal the disruptive flag of its family",
        ),
        (
            rule(CRONTAB, "file_permissions", revert_strategy="guess"),
            f"{CRONTAB}: unknown revert_strategy 'guess'",
        ),
        (
            rule(CRONTAB, "file_permissions", reversible=False),
            f"{CRONTAB}: reversible must be false exactly for the irreversible strategy",
        ),
        (
            rule(CRONTAB, "file_permissions", toggle="linux_compliance_rule_x_enabled"),
            f"{CRONTAB}: toggle must be linux_compliance_rule_file_permissions_crontab_enabled",
        ),
        (
            rule(CRONTAB, "file_permissions", revert_strategy="irreversible", reversible=False),
            f"{CRONTAB}: an irreversible rule needs a runbook link (https:// or docs/)",
        ),
        (
            rule(
                CRONTAB,
                "file_permissions",
                revert_strategy="irreversible",
                reversible=False,
                runbook="file:///etc/passwd",
            ),
            f"{CRONTAB}: an irreversible rule needs a runbook link (https:// or docs/)",
        ),
        (
            rule(CRONTAB, "file_permissions", runbook="docs/runbooks/x.md"),
            f"{CRONTAB}: only an irreversible rule has a runbook",
        ),
        (
            rule(CRONTAB, "file_permissions", parameters=[]),
            f"{CRONTAB}: parameters must be a mapping",
        ),
    ],
)
def test_an_invalid_catalogue_entry_is_an_error(entry: object, message: str) -> None:
    errors = errors_of([entry])
    assert any(error.startswith(message) for error in errors), errors


def test_a_rule_listed_twice_is_an_error() -> None:
    entries = [rule(CRONTAB, "file_permissions"), rule(CRONTAB, "file_permissions")]
    assert errors_of(entries) == [f"rule #1: rule {CRONTAB} is listed twice"]


@pytest.mark.parametrize("entries", ["rules", [rule(CRONTAB, "file_permissions")] * 4097])
def test_the_catalogue_must_be_a_bounded_list(entries: object) -> None:
    assert errors_of(entries) == ["the rule catalogue must be a list of at most 4096 rules"]


def test_an_https_runbook_is_accepted_for_an_irreversible_rule() -> None:
    entry = rule(
        PARTITION,
        "mounts",
        reversible=False,
        revert_strategy="irreversible",
        runbook="https://example.org/runbooks/partitioning",
    )
    result = run([entry])[0]
    assert result["errors"] == []


def test_errors_are_bounded() -> None:
    unknown = {f"linux_compliance_rule_unknown_{index}_enabled": True for index in range(150)}
    assert len(errors_of(toggles=unknown)) == toggles.MAX_ERRORS


def test_resolve_toggle_defaults_to_on_without_a_toggle() -> None:
    toggle = toggles.resolve_toggle(rule(CRONTAB, "file_permissions"), {})
    assert toggle == toggles.Toggle(on=True, disabled_by=None)


def test_toggle_names_follow_adr_0011() -> None:
    assert toggles.toggle_name("auditd") == "linux_compliance_auditd_enabled"
    assert (
        toggles.rule_toggle_name(CRONTAB)
        == "linux_compliance_rule_file_permissions_crontab_enabled"
    )


def warnings_of(result: dict[str, object]) -> list[str]:
    return [item for item in cast("list[str]", result["notices"]) if item.startswith("WARNING:")]


def test_a_topic_toggle_without_rules_in_the_profile_warns() -> None:
    result = run(toggles={"linux_compliance_sysctl_enabled": False})[0]
    assert len(warnings_of(result)) == 1
    assert "linux_compliance_sysctl_enabled is false" in warnings_of(result)[0]
    result = run(
        toggles={"linux_compliance_file_permissions_enabled": False},
        profile_rule_ids=[ROOT_LOGIN],
    )[0]
    assert len(warnings_of(result)) == 1


def test_without_opt_in_only_topics_without_catalogued_rules_warn() -> None:
    result = run(
        enabled=False,
        profile_rule_ids=None,
        toggles={
            "linux_compliance_sysctl_enabled": False,
            "linux_compliance_file_permissions_enabled": False,
        },
    )[0]
    assert len(warnings_of(result)) == 1
    assert "linux_compliance_sysctl_enabled" in warnings_of(result)[0]


def test_a_topic_toggle_that_switches_rules_off_does_not_warn() -> None:
    result = run(toggles={"linux_compliance_file_permissions_enabled": False})[0]
    assert warnings_of(result) == []


DMESG = PREFIX + "sysctl_kernel_dmesg_restrict"
CIPHERS = PREFIX + "sshd_use_strong_ciphers"
AUDIT_ONLY = {"sysctl": [DMESG], "ssh": [CIPHERS]}
ALL_RULES = [CRONTAB, PASSWD, ROOT_LOGIN, PARTITION, DMESG, CIPHERS]


def test_audit_only_rules_are_not_implemented_and_never_dispatched() -> None:
    result, rules = run(audit_only=AUDIT_ONLY, profile_rule_ids=ALL_RULES)
    assert result["errors"] == []
    for rule_id in (DMESG, CIPHERS):
        assert rules[rule_id]["action"] == "not_implemented"
        assert rules[rule_id]["reason"] == "audit_only"
        assert rules[rule_id]["revert_strategy"] == "audit_only"
    families = cast("list[dict[str, object]]", result["families"])
    assert [family["name"] for family in families] == ["file_permissions"]
    assert result["not_implemented"] == [
        {
            "rule_id": rule_id,
            "family": family,
            "action": "not_implemented",
            "status": "not_implemented",
            "reason": "audit_only",
            "changed": False,
            "message": (
                f"{rule_id}: no native remediation in this collection version (audit_only); "
                "nothing was changed, and the audit still reports its outcome"
            ),
        }
        for rule_id, family in ((CIPHERS, "ssh"), (DMESG, "sysctl"))
    ]
    summary = cast("dict[str, int]", result["summary"])
    assert summary["not_implemented"] == 2
    assert summary["apply"] == 2
    assert (
        "2 rule(s) of the profile have no native remediation in this collection version "
        "(audit_only) and were not remediated; they are reported as not_implemented"
    ) in cast("list[str]", result["notices"])
    report = {
        str(item["rule_id"]): item for item in cast("list[dict[str, object]]", result["report"])
    }
    assert report[CIPHERS]["action"] == "not_implemented"


def test_audit_only_rules_that_are_off_or_outside_the_profile_do_nothing() -> None:
    result, rules = run(
        audit_only=AUDIT_ONLY,
        profile_rule_ids=[CRONTAB, CIPHERS],
        toggles={"linux_compliance_ssh_enabled": False},
    )
    assert rules[DMESG]["action"] == "none"
    assert rules[DMESG]["reason"] == "not_in_profile"
    assert rules[CIPHERS]["action"] == "none"
    assert rules[CIPHERS]["reason"] == "disabled_by_toggle"
    assert rules[CIPHERS]["disabled_by"] == "linux_compliance_ssh_enabled"
    assert result["not_implemented"] == []
    assert {"rule_id": CIPHERS, "disabled_by": "linux_compliance_ssh_enabled"} in cast(
        "list[dict[str, object]]", result["disabled_rules"]
    )
    assert not any("not_implemented" in item for item in cast("list[str]", result["notices"]))


def test_audit_only_rules_are_skipped_without_the_opt_in() -> None:
    result, rules = run(audit_only=AUDIT_ONLY, enabled=False, profile_rule_ids=None)
    assert rules[DMESG]["action"] == "skip"
    assert rules[DMESG]["reason"] == "remediation_disabled"
    assert result["not_implemented"] == []


def test_an_audit_only_rule_recorded_in_the_ledger_is_a_manual_action() -> None:
    result, rules = run(
        audit_only=AUDIT_ONLY,
        profile_rule_ids=ALL_RULES,
        ledger_entries=[ledger_entry(DMESG, "sysctl")],
    )
    assert rules[DMESG]["action"] == "manual"
    assert rules[DMESG]["reason"] == "audit_only"
    assert result["families"] == [
        family
        for family in cast("list[dict[str, object]]", result["families"])
        if family["name"] == "file_permissions"
    ]
    assert (
        f"{DMESG}: recorded in the state ledger, but this collection version has no native "
        "remediation for it (audit_only), so it is neither applied nor cleaned up; review it "
        "manually and remove the ledger entry"
    ) in cast("list[str]", result["notices"])


def test_the_audit_only_option_is_validated() -> None:
    assert errors_of(audit_only={"kernel": [DMESG]}) == [
        "the audit_only catalogue names the unknown family 'kernel'"
    ]
