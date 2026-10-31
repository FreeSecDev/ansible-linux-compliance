"""Unit tests of the pam_conf_decision filter beyond the cases of the reader verdict table."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import pam_conf

DENY = {
    "reader": "faillock",
    "setting": "deny",
    "comparison": "at_most",
    "required": "4",
    "stack_checked": True,
}
ENFORCE = {
    "reader": "pwhistory",
    "setting": "enforce_for_root",
    "comparison": "present",
    "required": "",
    "stack_checked": False,
}


def test_the_filter_is_registered() -> None:
    assert pam_conf.FilterModule().filters() == {"pam_conf_decision": pam_conf.pam_conf_decision}


@pytest.mark.parametrize(("text", "stack"), [(None, {}), ("", None), ("", ["x"])])
def test_the_text_and_the_stack_must_be_a_string_and_a_mapping(text: object, stack: object) -> None:
    with pytest.raises(TypeError, match="text of the file"):
        pam_conf.pam_conf_decision(text, DENY, stack)


@pytest.mark.parametrize(
    "rule",
    [
        None,
        {**DENY, "extra": 1},
        {key: value for key, value in DENY.items() if key != "stack_checked"},
        {**DENY, "reader": "pwquality"},
        {**DENY, "reader": 1},
        {**DENY, "setting": "remember"},
        {**DENY, "comparison": "equals"},
        {**DENY, "required": 4},
        {**DENY, "stack_checked": "yes"},
        {**DENY, "required": ""},
        {**ENFORCE, "required": "1"},
        {**DENY, "required": "04"},
        {**DENY, "required": "1234567890"},
        {**DENY, "required": "-1"},
    ],
    ids=repr,
)
def test_an_invalid_rule_fails(rule: object) -> None:
    with pytest.raises(ValueError, match="needs a rule"):
        pam_conf.pam_conf_decision("", rule, {})


def test_a_required_time_that_pam_faillock_ignores_is_never_written() -> None:
    rule = {**DENY, "setting": "unlock_time", "comparison": "at_least", "required": "604801"}
    decision = pam_conf.pam_conf_decision("unlock_time = 900\n", rule, {})
    assert decision["status"] == "unsupported_value"
    assert "604800" in str(decision["reason"])
    assert decision["setting_line"] is None


def test_a_continuation_at_the_end_of_a_service_file_is_still_a_module_line() -> None:
    text = "auth required pam_faillock.so \\\n  preauth deny=5 \\"
    assert list(pam_conf.module_arguments(text, "pam_faillock")) == [["preauth", "deny=5"]]
    assert pam_conf.stack_overrides({"/etc/pam.d/x": text}, "faillock", "deny", checked=True) == [
        "/etc/pam.d/x"
    ]


def test_lines_that_are_not_module_lines_of_a_known_type_are_skipped() -> None:
    text = "auth\n@include common-auth\nfoo required pam_faillock.so deny=5\nauth required\n"
    assert list(pam_conf.module_arguments(text, "pam_faillock")) == []


def test_bracketed_arguments_are_one_argument_with_escaped_brackets_kept() -> None:
    text = "-AUTH [success=1 default=ignore] pam_faillock.so [conf=/x \\] y]  audit\n"
    assert list(pam_conf.module_arguments(text, "pam_faillock")) == [["conf=/x ] y", "audit"]]


def test_overrides_reads_the_arguments_as_each_module_does() -> None:
    assert pam_conf.overrides("conf=/etc/other", "pwhistory", "remember")
    assert pam_conf.overrides("root_unlock_time=5", "faillock", "unlock_time")
    assert not pam_conf.overrides("unlock_time=5", "faillock", "root_unlock_time")
    assert pam_conf.overrides("REMEMBER=1", "pwhistory", "remember")
    assert pam_conf.overrides("Enforce_For_Root", "pwhistory", "enforce_for_root")
    assert not pam_conf.overrides("enforce_for_root=1", "pwhistory", "enforce_for_root")


def test_an_unchecked_rule_is_only_overridden_by_conf() -> None:
    stack = {"/etc/pam.d/a": "password required pam_pwhistory.so enforce_for_root\n"}
    assert pam_conf.stack_overrides(stack, "pwhistory", "enforce_for_root", checked=False) == []
    stack["/etc/pam.d/b"] = "password required pam_pwhistory.so conf=/x\n"
    assert pam_conf.stack_overrides(stack, "pwhistory", "enforce_for_root", checked=False) == [
        "/etc/pam.d/b"
    ]
    decision = pam_conf.pam_conf_decision("enforce_for_root\n", ENFORCE, stack)
    assert decision["status"] == "overridden"
    assert "/etc/pam.d/b" in str(decision["reason"])


@pytest.mark.parametrize(
    ("setting", "number", "required", "expected"),
    [
        ("unlock_time", 604801, 900, False),
        ("root_unlock_time", 0, 60, False),
        ("unlock_time", 0, 0, True),
        ("unlock_time", 900, 0, False),
        ("fail_interval", 604800, 900, True),
        ("deny", 0, 3, False),
    ],
)
def test_satisfies_never_accepts_a_value_that_pam_ignores_or_reads_as_never(
    setting: str, number: int, required: int, expected: bool
) -> None:
    comparison = "at_most" if setting == "deny" else "at_least"
    assert pam_conf.satisfies(setting, comparison, number, required) is expected


@pytest.mark.parametrize(
    ("value", "bits", "expected"),
    [
        ("x", 32, None),
        ("  +7", 32, 7),
        ("-1", 32, 2**32 - 1),
        ("-1", 16, 2**16 - 1),
        ("99999999999999999999999", 32, 2**32 - 1),
        ("65536", 16, 0),
    ],
)
def test_scan_unsigned_stores_what_sscanf_stores(value: str, bits: int, expected: int) -> None:
    assert pam_conf.scan_unsigned(value, bits) == expected
