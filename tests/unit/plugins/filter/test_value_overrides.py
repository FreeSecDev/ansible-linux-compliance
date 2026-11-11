from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    remediation_plan as plan_filter,
)
from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    value_overrides as overrides_filter,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)

PREFIX = "xccdf_org.ssgproject.content_rule_"
MINLEN = PREFIX + "accounts_password_pam_minlen"
UMASK = PREFIX + "accounts_umask_etc_login_defs"
REMEMBER_PASSWORD_AUTH = PREFIX + "accounts_password_pam_pwhistory_remember_password_auth"
REMEMBER_SYSTEM_AUTH = PREFIX + "accounts_password_pam_pwhistory_remember_system_auth"
BANNER = PREFIX + "banner_etc_issue"
KEEPALIVE = PREFIX + "sshd_set_keepalive"
CRONTAB = PREFIX + "file_permissions_crontab"
CONTENT = "a" * 64
OTHER_CONTENT = "b" * 64
PROFILE = "cis_level1_server"
CATALOGUE_FILE = Path(__file__).resolve().parents[4] / "roles" / "remediate" / "vars" / "rules.yml"


def value_rule(
    rule_id: str,
    family: str,
    value_id: str,
    comparison: str | None,
    *profile_values: dict[str, object],
) -> dict[str, object]:
    parameters: dict[str, object] = {"value_id": value_id, "profile_values": list(profile_values)}
    if comparison is not None:
        parameters["value_comparison"] = comparison
    return {"rule_id": rule_id, "family": family, "parameters": parameters}


def entry(value: str, *profiles: str, content: str = CONTENT) -> dict[str, object]:
    return {
        "datastream": "ubuntu2404",
        "content_sha256": content,
        "profiles": list(profiles or (PROFILE,)),
        "value": [value],
    }


def catalogue() -> list[dict[str, object]]:
    return [
        value_rule(
            MINLEN,
            "pwquality",
            "var_password_pam_minlen",
            "pwquality_minlen",
            entry("15", "stig"),
            entry("14"),
            entry("12", content=OTHER_CONTENT),
        ),
        value_rule(
            UMASK, "login_defs", "var_accounts_user_umask", "login_defs_umask", entry("027")
        ),
        value_rule(
            REMEMBER_PASSWORD_AUTH,
            "pwhistory",
            "var_password_pam_remember",
            "pwhistory_remember",
            entry("24"),
        ),
        value_rule(
            REMEMBER_SYSTEM_AUTH,
            "pwhistory",
            "var_password_pam_remember",
            "pwhistory_remember",
            entry("24"),
        ),
        value_rule(BANNER, "banners", "login_banner_text", None, entry("^Authorized.*$")),
        value_rule(KEEPALIVE, "ssh", "var_sshd_set_keepalive", None, entry("1")),
        {"rule_id": CRONTAB, "family": "file_permissions", "parameters": {}},
    ]


RULE_IDS = (MINLEN, UMASK, REMEMBER_PASSWORD_AUTH, REMEMBER_SYSTEM_AUTH, BANNER, KEEPALIVE, CRONTAB)


def plan(changes: dict[str, tuple[str, str]] | None = None) -> dict[str, object]:
    planned: dict[str, tuple[str, str]] = dict.fromkeys(RULE_IDS, ("apply", "enabled"))
    planned.update(changes or {})
    return {
        "rules": [
            {"rule_id": rule_id, "action": action, "reason": reason}
            for rule_id, (action, reason) in planned.items()
        ]
    }


def resolve(
    overrides: object,
    *,
    work: object = None,
    rules: object = None,
    content: object = CONTENT,
    profile: object = PROFILE,
) -> dict[str, object]:
    return overrides_filter.value_overrides(
        catalogue() if rules is None else rules,
        {
            "overrides": overrides,
            "plan": plan() if work is None else work,
            "content_sha256": content,
            "profile": profile,
        },
    )


def errors_of(result: dict[str, object]) -> list[str]:
    assert result["rules"] == {}
    assert result["unused_overrides"] == []
    assert result["notices"] == []
    return cast("list[str]", result["errors"])


def wired_catalogue() -> list[dict[str, object]]:
    return [rule for rule in catalogue() if rule["rule_id"] not in {BANNER, KEEPALIVE, CRONTAB}]


def test_the_filter_is_registered() -> None:
    assert overrides_filter.FilterModule().filters() == {
        "value_overrides": overrides_filter.value_overrides
    }


def test_without_overrides_every_applied_value_rule_gets_its_profile_value() -> None:
    result = resolve({}, work=plan({UMASK: ("none", "not_in_profile")}))
    assert result["errors"] == []
    assert result["unused_overrides"] == []
    assert result["notices"] == []
    rules = cast("dict[str, dict[str, object]]", result["rules"])
    assert sorted(rules) == sorted(
        [MINLEN, REMEMBER_PASSWORD_AUTH, REMEMBER_SYSTEM_AUTH, BANNER, KEEPALIVE]
    )
    assert rules[MINLEN] == {
        "value_id": "var_password_pam_minlen",
        "value_source": "profile",
        "profile_value": "14",
        "target": "14",
        "comparison": "pwquality_minlen",
    }
    assert rules[KEEPALIVE]["comparison"] is None
    assert rules[BANNER]["target"] == "^Authorized.*$"


def test_the_profile_value_is_that_of_the_content_and_the_profile() -> None:
    other = cast("dict[str, dict[str, object]]", resolve({}, content=OTHER_CONTENT)["rules"])
    assert other[MINLEN]["profile_value"] == "12"
    assert other[UMASK]["profile_value"] is None
    stig = cast("dict[str, dict[str, object]]", resolve({}, profile="stig")["rules"])
    assert stig[MINLEN]["profile_value"] == "15"
    assert stig[UMASK]["target"] is None


def test_a_profile_value_split_in_parts_is_joined_as_the_families_join_it() -> None:
    split = value_rule(UMASK, "login_defs", "var_accounts_user_umask", "login_defs_umask")
    cast("dict[str, object]", split["parameters"])["profile_values"] = [
        {"content_sha256": CONTENT, "profiles": "not a list", "value": ["077"]},
        {"content_sha256": CONTENT, "profiles": [PROFILE], "value": ["0", "27"]},
    ]
    rules = cast("dict[str, dict[str, object]]", resolve({}, rules=[split])["rules"])
    assert rules[UMASK]["profile_value"] == "027"


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [(16, "16"), ("16", "16"), (14, "14"), (6, "6")],
)
def test_an_override_replaces_the_target_and_is_its_canonical_text(
    raw: object, canonical: str
) -> None:
    result = resolve({"var_password_pam_minlen": raw}, rules=wired_catalogue())
    assert result["errors"] == []
    rules = cast("dict[str, dict[str, object]]", result["rules"])
    assert rules[MINLEN] == {
        "value_id": "var_password_pam_minlen",
        "value_source": "override",
        "profile_value": "14",
        "target": canonical,
        "comparison": "pwquality_minlen",
    }
    assert rules[UMASK]["value_source"] == "profile"
    assert result["unused_overrides"] == []


def test_a_looser_override_is_taken_as_the_target_and_judged_later() -> None:
    rules = cast(
        "dict[str, dict[str, object]]",
        resolve({"var_password_pam_minlen": 8}, rules=wired_catalogue())["rules"],
    )
    assert rules[MINLEN]["target"] == "8"
    assert rules[MINLEN]["value_source"] == "override"


def test_one_override_applies_to_every_rule_of_its_value() -> None:
    result = resolve({"var_password_pam_remember": 5}, rules=wired_catalogue())
    rules = cast("dict[str, dict[str, object]]", result["rules"])
    for rule_id in (REMEMBER_PASSWORD_AUTH, REMEMBER_SYSTEM_AUTH):
        assert rules[rule_id]["target"] == "5"
        assert rules[rule_id]["value_source"] == "override"
        assert rules[rule_id]["profile_value"] == "24"


def test_a_shared_value_is_used_when_one_of_its_rules_is_applied() -> None:
    result = resolve(
        {"var_password_pam_remember": 5},
        rules=wired_catalogue(),
        work=plan({REMEMBER_PASSWORD_AUTH: ("none", "not_in_profile")}),
    )
    rules = cast("dict[str, dict[str, object]]", result["rules"])
    assert REMEMBER_PASSWORD_AUTH not in rules
    assert rules[REMEMBER_SYSTEM_AUTH]["target"] == "5"
    assert result["unused_overrides"] == []


def test_a_umask_override_keeps_its_text() -> None:
    rules = cast(
        "dict[str, dict[str, object]]",
        resolve({"var_accounts_user_umask": "077"}, rules=wired_catalogue())["rules"],
    )
    assert rules[UMASK]["target"] == "077"


@pytest.mark.parametrize(
    ("work", "reason"),
    [
        (plan({MINLEN: ("none", "not_in_profile")}), "not_in_profile"),
        (plan({MINLEN: ("cleanup", "disabled_by_toggle")}), "disabled_by_toggle"),
        (plan({MINLEN: ("manual", "not_in_profile")}), "not_in_profile"),
        (plan({MINLEN: ("skip", "disruptive_not_allowed")}), "disruptive_not_allowed"),
        (plan({MINLEN: ("skip", "remediation_disabled")}), "remediation_disabled"),
    ],
)
def test_a_key_that_no_applied_rule_uses_is_listed_with_the_plan_reason(
    work: dict[str, object], reason: str
) -> None:
    result = resolve({"var_password_pam_minlen": 16}, rules=wired_catalogue(), work=work)
    assert result["errors"] == []
    assert MINLEN not in cast("dict[str, object]", result["rules"])
    assert result["unused_overrides"] == [{"value_id": "var_password_pam_minlen", "reason": reason}]
    assert result["notices"] == [
        (
            f"var_password_pam_minlen: the value override is not used in this run ({reason}); "
            "nothing was changed for it"
        )
    ]


def test_an_unused_shared_value_takes_the_reason_of_its_first_rule() -> None:
    result = resolve(
        {"var_password_pam_remember": 5},
        rules=wired_catalogue(),
        work=plan(
            {
                REMEMBER_PASSWORD_AUTH: ("none", "not_in_profile"),
                REMEMBER_SYSTEM_AUTH: ("none", "disabled_by_toggle"),
            }
        ),
    )
    assert result["unused_overrides"] == [
        {"value_id": "var_password_pam_remember", "reason": "not_in_profile"}
    ]


@pytest.mark.parametrize(
    ("content", "profile"), [(None, PROFILE), (OTHER_CONTENT, PROFILE), (CONTENT, "stig")]
)
def test_an_override_never_stands_in_for_a_missing_profile_value(
    content: str | None, profile: str
) -> None:
    result = resolve(
        {"var_accounts_user_umask": "077"},
        rules=wired_catalogue(),
        content=content,
        profile=profile,
    )
    assert result["errors"] == []
    rules = cast("dict[str, dict[str, object]]", result["rules"])
    assert rules[UMASK] == {
        "value_id": "var_accounts_user_umask",
        "value_source": "profile",
        "profile_value": None,
        "target": None,
        "comparison": "login_defs_umask",
    }
    assert result["unused_overrides"] == [
        {"value_id": "var_accounts_user_umask", "reason": "no_profile_value_for_content"}
    ]


def test_unused_keys_are_sorted_and_each_has_a_notice() -> None:
    result = resolve(
        {"var_password_pam_minlen": 16, "var_accounts_user_umask": "077"},
        rules=wired_catalogue(),
        work=plan({MINLEN: ("none", "not_in_profile"), UMASK: ("none", "disabled_by_toggle")}),
    )
    unused = cast("list[dict[str, str]]", result["unused_overrides"])
    assert [item["value_id"] for item in unused] == [
        "var_accounts_user_umask",
        "var_password_pam_minlen",
    ]
    assert len(cast("list[str]", result["notices"])) == 2


def test_keys_are_validated_when_remediation_is_disabled() -> None:
    disabled = plan(dict.fromkeys(RULE_IDS, ("skip", "remediation_disabled")))
    assert errors_of(resolve({"var_password_pam_minlenn": 16}, work=disabled, content=None)) == [
        overrides_filter.OVERRIDES_VARIABLE
        + ": 'var_password_pam_minlenn' is not the value of a native rule of the catalogue; the "
        "keys are the short identifiers of XCCDF values, such as var_password_pam_minlen, listed "
        "in docs/remediation-variables.md"
    ]
    result = resolve(
        {"var_password_pam_minlen": 16}, rules=wired_catalogue(), work=disabled, content=None
    )
    assert result["rules"] == {}
    assert result["unused_overrides"] == [
        {"value_id": "var_password_pam_minlen", "reason": "remediation_disabled"}
    ]


def test_a_full_value_identifier_is_refused_with_its_short_form() -> None:
    (message,) = errors_of(
        resolve({"xccdf_org.ssgproject.content_value_var_password_pam_minlen": 16})
    )
    assert "is a full XCCDF value identifier" in message
    assert "such as 'var_password_pam_minlen'" in message


def test_a_key_that_is_not_a_string_is_refused() -> None:
    assert errors_of(resolve({16: 16})) == [
        f"{overrides_filter.OVERRIDES_VARIABLE}: the key 16 must be a string"
    ]


def test_a_banner_value_is_refused_naming_the_banner_text_variable() -> None:
    (message,) = errors_of(resolve({"login_banner_text": "Hello"}))
    assert "linux_compliance_remediate_banner_text" in message
    assert message.startswith(
        overrides_filter.OVERRIDES_VARIABLE + ": login_banner_text is a banner"
    )


def test_a_value_whose_rules_name_no_comparison_is_refused() -> None:
    (message,) = errors_of(resolve({"var_sshd_set_keepalive": 1}))
    assert message == (
        f"{overrides_filter.OVERRIDES_VARIABLE}: var_sshd_set_keepalive cannot be overridden yet: "
        f"{KEEPALIVE} names no value_comparison, because its family is not wired for overrides "
        "(ADR 0032 §3)"
    )


def test_a_shared_value_with_one_unwired_rule_is_refused() -> None:
    rules = wired_catalogue()
    del cast("dict[str, object]", rules[3]["parameters"])["value_comparison"]
    (message,) = errors_of(resolve({"var_password_pam_remember": 5}, rules=rules))
    assert f"cannot be overridden yet: {REMEMBER_SYSTEM_AUTH} names" in message


def test_a_shared_value_whose_rules_disagree_on_the_comparison_is_refused() -> None:
    rules = wired_catalogue()
    cast("dict[str, object]", rules[3]["parameters"])["value_comparison"] = "pwquality_at_least"
    (message,) = errors_of(resolve({"var_password_pam_remember": 5}, rules=rules))
    assert message == (
        f"{overrides_filter.OVERRIDES_VARIABLE}: the rules of var_password_pam_remember name "
        "different comparisons (pwhistory_remember, pwquality_at_least), so the catalogue is "
        "invalid"
    )


def test_an_unknown_comparison_is_refused() -> None:
    rules = wired_catalogue()
    cast("dict[str, object]", rules[0]["parameters"])["value_comparison"] = "nonsense"
    (message,) = errors_of(resolve({"var_password_pam_minlen": 16}, rules=rules))
    assert message.startswith(
        f"{overrides_filter.OVERRIDES_VARIABLE}: var_password_pam_minlen (nonsense) unknown value "
        "comparison 'nonsense'"
    )


@pytest.mark.parametrize(
    ("key", "raw"),
    [
        ("var_password_pam_minlen", True),
        ("var_password_pam_minlen", False),
        ("var_password_pam_minlen", None),
        ("var_password_pam_minlen", [16]),
        ("var_password_pam_minlen", {"value": 16}),
        ("var_password_pam_minlen", "016"),
        ("var_password_pam_minlen", "+16"),
        ("var_password_pam_minlen", 5),
        ("var_password_pam_minlen", 16.0),
        ("var_password_pam_minlen", "16 "),
        ("var_accounts_user_umask", 23),
        ("var_accounts_user_umask", "177"),
        ("var_accounts_user_umask", "0027"),
        ("var_password_pam_remember", -1),
    ],
)
def test_a_value_that_the_comparison_does_not_take_is_refused(key: str, raw: object) -> None:
    (message,) = errors_of(resolve({key: raw}, rules=wired_catalogue()))
    assert message.startswith(f"{overrides_filter.OVERRIDES_VARIABLE}: {key} (")
    assert "needs " in message


def test_every_refusal_is_reported_at_once() -> None:
    result = resolve(
        {
            "var_password_pam_minlen": True,
            "login_banner_text": "x",
            "unknown_value": 1,
            "var_accounts_user_umask": "077",
        }
    )
    assert len(errors_of(result)) == 3


@pytest.mark.parametrize("raw", ["16", ["var_password_pam_minlen"], None, 16])
def test_overrides_that_are_not_a_mapping_are_refused(raw: object) -> None:
    (message,) = errors_of(resolve(raw))
    assert message.startswith(
        "linux_compliance_remediate_value_overrides must be a mapping of XCCDF value identifiers"
    )


def test_too_many_overrides_are_refused() -> None:
    many = {f"var_{index}": index for index in range(overrides_filter.MAX_OVERRIDES + 1)}
    assert errors_of(resolve(many)) == [
        (
            f"{overrides_filter.OVERRIDES_VARIABLE} has {len(many)} keys, more than "
            f"{overrides_filter.MAX_OVERRIDES}"
        )
    ]


def test_the_errors_are_bounded() -> None:
    many = {f"var_{index}": index for index in range(toggles.MAX_ERRORS + 5)}
    assert len(errors_of(resolve(many))) == toggles.MAX_ERRORS


@pytest.mark.parametrize(
    "options",
    [
        None,
        [],
        {"overrides": {}, "plan": {}, "content_sha256": None},
        {"overrides": {}, "plan": {}, "content_sha256": None, "profile": PROFILE, "extra": 1},
    ],
)
def test_options_without_exactly_the_documented_keys_are_refused(options: object) -> None:
    result = overrides_filter.value_overrides(catalogue(), options)
    assert errors_of(result) == [
        "options must be a mapping with exactly ['content_sha256', 'overrides', 'plan', 'profile']"
    ]


@pytest.mark.parametrize(
    ("content", "profile", "expected"),
    [
        ("abc", PROFILE, "content_sha256 must be none or a SHA-256 digest, got 'abc'"),
        (64, PROFILE, "content_sha256 must be none or a SHA-256 digest, got 64"),
        (CONTENT, "", "profile must be a profile short identifier, got ''"),
        (CONTENT, None, "profile must be a profile short identifier, got None"),
    ],
)
def test_invalid_settings_are_refused(content: object, profile: object, expected: str) -> None:
    assert errors_of(resolve({}, content=content, profile=profile)) == [expected]


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        ("not a list", "the rule catalogue must be a list"),
        (["not a mapping"], "every catalogue rule must be a mapping, got 'not a mapping'"),
        (
            [{"rule_id": 1, "parameters": {"value_id": "v"}}],
            "the rule_id of a catalogue rule must be a string, got 1",
        ),
        (
            [{"rule_id": MINLEN, "family": None, "parameters": {"value_id": "v"}}],
            f"{MINLEN}: family must be a string, got None",
        ),
        (
            [{"rule_id": MINLEN, "family": "pwquality", "parameters": {"value_id": 3}}],
            f"{MINLEN}: value_id must be a string, got 3",
        ),
        (
            [
                {
                    "rule_id": MINLEN,
                    "family": "pwquality",
                    "parameters": {"value_id": "v", "value_comparison": 3},
                }
            ],
            f"{MINLEN}: value_comparison must be a string, got 3",
        ),
        (
            [
                {
                    "rule_id": MINLEN,
                    "family": "pwquality",
                    "parameters": {"value_id": "v", "profile_values": "x"},
                }
            ],
            f"{MINLEN}: profile_values must be a list of mappings",
        ),
        (
            [
                {
                    "rule_id": MINLEN,
                    "family": "pwquality",
                    "parameters": {"value_id": "v", "profile_values": ["x"]},
                }
            ],
            f"{MINLEN}: profile_values must be a list of mappings",
        ),
    ],
)
def test_a_catalogue_that_cannot_be_read_fails_closed(rules: object, expected: str) -> None:
    assert errors_of(resolve({}, rules=rules)) == [expected]


@pytest.mark.parametrize("value", ["027", [0, 27]])
def test_a_profile_value_that_is_not_a_list_of_strings_fails_closed(value: object) -> None:
    broken = value_rule(UMASK, "login_defs", "var_accounts_user_umask", "login_defs_umask")
    cast("dict[str, object]", broken["parameters"])["profile_values"] = [
        {"content_sha256": CONTENT, "profiles": [PROFILE], "value": value}
    ]
    assert errors_of(resolve({}, rules=[broken])) == [
        f"{UMASK}: a profile value must be a list of strings"
    ]


@pytest.mark.parametrize(
    ("work", "expected"),
    [
        ("not a plan", "the plan must be a mapping with a list of rules"),
        ({"rules": "x"}, "the plan must be a mapping with a list of rules"),
        ({"rules": ["x"]}, "every rule of the plan must be a mapping"),
        (
            {"rules": [{"rule_id": None}]},
            "the rule_id of a planned rule must be a string, got None",
        ),
        (
            {"rules": [{"rule_id": MINLEN, "action": 1, "reason": "enabled"}]},
            f"{MINLEN}: the planned action must be a string, got 1",
        ),
        (
            {"rules": [{"rule_id": MINLEN, "action": "apply"}]},
            f"{MINLEN}: the planned reason must be a string, got None",
        ),
        ({"rules": []}, f"{BANNER}: the catalogue rule is missing from the plan"),
    ],
)
def test_a_plan_that_cannot_be_read_fails_closed(work: object, expected: str) -> None:
    assert errors_of(resolve({}, work=work)) == [expected]


def test_a_catalogue_error_is_reported_with_the_setting_errors() -> None:
    assert errors_of(resolve({}, rules="x", profile="")) == [
        "profile must be a profile short identifier, got ''",
        "the rule catalogue must be a list",
    ]


def test_an_unknown_plan_reason_for_an_unused_key_fails_closed() -> None:
    result = resolve(
        {"var_password_pam_minlen": 16},
        rules=wired_catalogue(),
        work=plan({MINLEN: ("none", "something_new")}),
    )
    assert errors_of(result) == [f"{MINLEN}: the plan gives the unknown reason 'something_new'"]


def test_the_reasons_are_the_documented_ones() -> None:
    documented = {
        "not_in_profile",
        "disabled_by_toggle",
        "disruptive_not_allowed",
        "remediation_disabled",
        "no_profile_value_for_content",
    }
    assert set(overrides_filter.UNUSED_REASONS) == documented


def real_catalogue() -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(CATALOGUE_FILE.read_text(encoding="utf-8")))


def real_plan(data: dict[str, object], *, enabled: bool) -> dict[str, object]:
    rules = cast("list[dict[str, object]]", data["__linux_compliance_remediate_rules"])
    families = cast("list[dict[str, object]]", data["__linux_compliance_remediate_families"])
    return plan_filter.remediation_plan(
        rules,
        {
            "audit_only": data["__linux_compliance_remediate_audit_only"],
            "families": families,
            "tags": data["__linux_compliance_remediate_tags"],
            "family_aliases": data["__linux_compliance_remediate_family_aliases"],
            "enabled": enabled,
            "allow_disruptive": sorted(
                str(family["name"]) for family in families if family["disruptive"] is True
            ),
            "toggles": {},
            "profile_rule_ids": [str(rule["rule_id"]) for rule in rules] if enabled else None,
            "ledger_entries": [],
        },
    )


def test_every_value_of_the_catalogue_is_refused_until_its_family_is_wired() -> None:
    data = real_catalogue()
    rules = cast("list[dict[str, object]]", data["__linux_compliance_remediate_rules"])
    value_rules = [
        rule for rule in rules if "value_id" in cast("dict[str, object]", rule["parameters"])
    ]
    keys = {str(cast("dict[str, object]", rule["parameters"])["value_id"]) for rule in value_rules}
    assert "var_password_pam_remember" in keys
    wired = {
        str(cast("dict[str, object]", rule["parameters"])["value_id"])
        for rule in value_rules
        if "value_comparison" in cast("dict[str, object]", rule["parameters"])
    }
    work = real_plan(data, enabled=False)
    messages = errors_of(resolve(dict.fromkeys(sorted(keys - wired), "1"), rules=rules, work=work))
    assert len(messages) == len(keys - wired)
    assert all(
        "cannot be overridden yet" in message or "is a banner value" in message
        for message in messages
    )
    assert not any("is not the value of a native rule" in message for message in messages)


def test_the_real_catalogue_resolves_the_values_as_the_families_do() -> None:
    data = real_catalogue()
    rules = cast("list[dict[str, object]]", data["__linux_compliance_remediate_rules"])
    work = real_plan(data, enabled=True)
    entries = [
        (str(rule["rule_id"]), item)
        for rule in rules
        for item in cast(
            "list[dict[str, object]]",
            cast("dict[str, object]", rule["parameters"]).get("profile_values", []),
        )
    ]
    rule_id, chosen = entries[0]
    content = str(chosen["content_sha256"])
    profile = str(cast("list[str]", chosen["profiles"])[0])
    result = resolve({}, rules=rules, work=work, content=content, profile=profile)
    assert result["errors"] == []
    resolved = cast("dict[str, dict[str, object]]", result["rules"])
    assert resolved[rule_id]["profile_value"] == "".join(cast("list[str]", chosen["value"]))
    for item in resolved.values():
        assert item["value_source"] == "profile"
        assert item["target"] == item["profile_value"]
    applied_with_value = {
        str(rule["rule_id"])
        for rule in rules
        if "value_id" in cast("dict[str, object]", rule["parameters"])
    }
    assert set(resolved) == applied_with_value
