"""Unit tests of how pam_conf_decision reads the PAM stack and computes the text it writes."""

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
AUDIT = {**DENY, "setting": "audit", "comparison": "present", "required": ""}
OVERRIDE = "auth required pam_faillock.so deny=10\n"
PLAIN = "auth required pam_unix.so\n"


@pytest.mark.parametrize(
    ("line", "tokens"),
    [
        (
            "auth [default=die]pam_faillock.so deny=10\n",
            ["auth", "default=die", "pam_faillock.so", "deny=10"],
        ),
        ("a [x \\] y]b", ["a", "x ] y", "b"]),
        ("a [unterminated", ["a", "unterminated"]),
        ("a b[c]d\t e\n", ["a", "b[c]d", "e"]),
        ("  \t\n", []),
        ("[]x", ["", "x"]),
    ],
)
def test_strtok_splits_as_pam_strtok(line: str, tokens: list[str]) -> None:
    assert pam_conf.strtok(line) == tokens


def test_the_rocky_reader_ends_a_continued_line_at_a_blank_or_comment_line() -> None:
    text = "auth required pam_unix.so \\\n# site\nauth required pam_faillock.so deny=10\n"
    assert [pam_conf.strtok(line) for line in pam_conf.assembled_lines(text, "getline")] == [
        ["auth", "required", "pam_unix.so"],
        ["auth", "required", "pam_faillock.so", "deny=10"],
    ]
    assert len(list(pam_conf.assembled_lines(text, "buffer"))) == 1
    assert list(pam_conf.module_arguments(text, "pam_faillock")) == [["deny=10"]]
    blank = "auth required pam_faillock.so \\\n\n deny=10\n"
    assert list(pam_conf.module_arguments(blank, "pam_faillock")) == [["deny=10"], []]


def test_the_rocky_reader_skips_blank_lines_and_empty_continuations_outside_a_line() -> None:
    text = "  \\\n\n# c\nauth required pam_faillock.so deny=1\n"
    assert [pam_conf.strtok(line) for line in pam_conf.assembled_lines(text, "getline")] == [
        ["auth", "required", "pam_faillock.so", "deny=1"]
    ]


def test_a_continued_line_at_the_end_is_dropped_only_when_exact() -> None:
    text = "auth required pam_unix.so\nauth required pam_faillock.so \\"
    for variant in pam_conf.ASSEMBLY_VARIANTS:
        assert len(list(pam_conf.assembled_lines(text, variant, exact=True))) == 1
        assert len(list(pam_conf.assembled_lines(text, variant))) == 2


def test_module_lines_name_modules_and_include_targets() -> None:
    text = (
        "@include common-auth\n-@INCLUDE\nauth include /etc/site\nauth substack x/y\n"
        "auth required\nauth required pam_faillock.so a b\nsession\n"
    )
    lines = list(pam_conf.module_lines(text, "buffer"))
    assert [(line.module, line.arguments, line.include) for line in lines] == [
        (None, (), "common-auth"),
        (None, (), None),
        (None, (), "/etc/site"),
        (None, (), "x/y"),
        ("pam_faillock.so", ("a", "b"), None),
    ]


def test_libpam_reads_a_service_name_from_the_first_directory_that_has_it() -> None:
    stack = {
        "/etc/pam.d/login": PLAIN,
        "/usr/lib/pam.d/login": OVERRIDE,
        "/usr/lib/pam.d/systemd-user": OVERRIDE,
        "/usr/share/pam.d/systemd-user": PLAIN,
        "/usr/share/pam.d/other": OVERRIDE,
    }
    effective, problems = pam_conf.effective_stack(stack)
    assert sorted(effective) == [
        "/etc/pam.d/login",
        "/usr/lib/pam.d/systemd-user",
        "/usr/share/pam.d/other",
    ]
    assert problems == []
    decision = pam_conf.pam_conf_decision("deny = 3\n", DENY, stack)
    assert decision["status"] == "overridden"
    assert "/usr/lib/pam.d/systemd-user" in str(decision["reason"])
    assert "/usr/lib/pam.d/login" not in str(decision["reason"])


def test_an_include_of_a_path_is_followed_to_a_file_read_or_refused() -> None:
    stack = {
        "/etc/pam.d/common-auth": "auth include /usr/lib/pam.d/login\nauth substack site/auth\n",
        "/etc/pam.d/login": PLAIN,
        "/usr/lib/pam.d/login": OVERRIDE,
        "/usr/lib/pam.d/site/auth": PLAIN,
    }
    effective, problems = pam_conf.effective_stack(stack)
    assert "/usr/lib/pam.d/login" in effective
    assert "/usr/lib/pam.d/site/auth" in effective
    assert problems == []
    assert pam_conf.pam_conf_decision("deny = 3\n", DENY, stack)["status"] == "overridden"
    stack["/etc/pam.d/common-auth"] = "auth include /etc/security/site-auth\n"
    decision = pam_conf.pam_conf_decision("deny = 3\n", DENY, stack)
    assert decision["status"] == "unreadable_stack"
    assert "/etc/security/site-auth" in str(decision["reason"])


@pytest.mark.parametrize(
    "text",
    ["# " + "x" * 1021 + "\n" + OVERRIDE, "# " + "é" * 511 + "\n", "auth required\0 x\n"],
)
def test_a_service_file_that_the_readers_split_or_stop_on_is_refused(text: str) -> None:
    stack = {"/etc/pam.d/common-auth": text, "/opt/elsewhere": PLAIN}
    effective, problems = pam_conf.effective_stack(stack)
    assert "/opt/elsewhere" in effective
    assert len(problems) == 1
    assert pam_conf.pam_conf_decision("deny = 3\n", DENY, stack)["status"] == "unreadable_stack"


@pytest.mark.parametrize(
    ("text", "index", "expected"),
    [
        ("", None, "deny = 4\n"),
        ("# x\n", None, "# x\ndeny = 4\n"),
        ("# x", None, "# x\ndeny = 4"),
        ("# x\r\n", None, "# x\r\ndeny = 4\n"),
        ("deny = 10\r\naudit\r\n", 0, "deny = 4\naudit\r\n"),
    ],
)
def test_the_written_text_changes_one_line_and_keeps_every_other_byte(
    text: str, index: int | None, expected: str
) -> None:
    assert pam_conf.written_text(text, index, "deny = 4") == expected


def test_an_applied_decision_carries_the_exact_new_text_and_a_compliant_one_none() -> None:
    applied = pam_conf.pam_conf_decision("# faillock\r\ndeny = 10\r\naudit\r\n", DENY, {})
    assert applied["status"] == "applied"
    assert applied["setting_line"] == "deny = 10\r"
    assert applied["new_text"] == "# faillock\r\ndeny = 4\naudit\r\n"
    compliant = pam_conf.pam_conf_decision("# faillock\r\naudit\r\n", AUDIT, {})
    assert compliant["status"] == "compliant"
    assert compliant["new_text"] is None


@pytest.mark.parametrize(
    ("text", "status"),
    [
        ("deny = 65536\n", "unreadable_value"),
        ("deny = 3\x01\n", "unreadable_value"),
        ("deny = 3\n# \udcff\n", "unreadable_file"),
        ("# " + "é" * 511 + "\ndeny = 3\n", "unreadable_file"),
        ("# " + "é" * 510 + "\ndeny = 3\n", "compliant"),
        ("deny = 65535\n", "applied"),
    ],
)
def test_values_and_files_that_cannot_be_written_back_exactly_are_refused(
    text: str, status: str
) -> None:
    assert pam_conf.pam_conf_decision(text, DENY, {})["status"] == status


def test_a_profile_deny_above_16_bits_is_never_written() -> None:
    decision = pam_conf.pam_conf_decision("", {**DENY, "required": "65536"}, {})
    assert decision["status"] == "unsupported_value"


@pytest.mark.parametrize(
    ("text", "expected"),
    [("deny = 3\t\r", True), ("deny = 3\x0b", False), ("deny\u202e", False), ("\udc80", False)],
)
def test_recordable_follows_the_state_ledger(text: str, *, expected: bool) -> None:
    assert pam_conf.recordable(text) is expected
