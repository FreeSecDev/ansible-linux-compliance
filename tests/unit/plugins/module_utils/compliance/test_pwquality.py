"""Branches of the pwquality reader that the verdict table does not reach (FREES-200)."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    pwquality_decide,
    pwquality_restore,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pwquality,
)

MAIN = "/etc/security/pwquality.conf"
DROPIN = "/etc/security/pwquality.conf.d/50-freesecdev-minlen.conf"


def rule(value: str = "14", method: str = "main_file") -> pwquality.Rule:
    return pwquality.Rule("minlen", value, method, MAIN, DROPIN, f"minlen = {value}\n")


def test_an_option_name_longer_than_the_buffer_of_the_library_is_refused() -> None:
    assert pwquality.option_value(b"x" * 80 + b"=1") is None
    assert pwquality.option_value(b"minlen=9") == ("minlen", 9)
    assert pwquality.option_value(b"badwords=a") == ("badwords", None)
    assert pwquality.option_value(b"frobnicate=1") is None


def test_continued_pam_lines_are_joined_and_comment_lines_skipped() -> None:
    text = (
        "# password requisite pam_pwquality.so minlen=1\n"
        "password requisite pam_pwquality.so retry=3 \\\n"
        "    minlen=8 [enforce_for_root]\n"
        "password requisite pam_unix.so minlen=2\n"
        "password requisite pam_pwquality.so \\"
    )
    files = [("/etc/pam.d/site", text)]
    assert pwquality.pam_overrides(files, "minlen", 14) == ["/etc/pam.d/site: minlen=8"]
    assert pwquality.pam_overrides(files, "enforce_for_root", 1) == []
    assert pwquality.pam_overrides(files, "retry", 1) == ["/etc/pam.d/site: retry=3"]


def test_a_rule_whose_value_the_library_changes_is_overridden() -> None:
    decision = pwquality.decide(rule("5"), [], "", [])
    assert decision["status"] == "overridden"
    assert decision["reason"] == f"libpwquality reads minlen 6 from {MAIN}, not 5"


def test_a_setting_that_nothing_sets_is_not_read() -> None:
    reading = pwquality.Reading(())
    assert pwquality.why_not_effective(reading, rule(), MAIN, 0) == (
        f"libpwquality does not read minlen from {MAIN}"
    )
    assert reading.value("minlen") == 8
    assert reading.value("badwords") is None


@pytest.mark.parametrize(
    ("text", "prior", "outcome"),
    [
        ("a\nminlen = 14\n", None, {"reason": None, "already": False, "text": "a\n"}),
        ("a\nminlen = 14", None, {"reason": None, "already": False, "text": "a"}),
        ("minlen = 14\n", None, {"reason": None, "already": False, "text": ""}),
        (
            "a\r\nminlen = 14\nb\r\n",
            "MINLEN=8\r",
            {"reason": None, "already": False, "text": "a\r\nMINLEN=8\r\nb\r\n"},
        ),
        ("a\n", None, {"reason": None, "already": True, "text": "a\n"}),
        ("minlen  8\n", "minlen  8", {"reason": None, "already": True, "text": "minlen  8\n"}),
        (
            "minlen = 14\nMINLEN 9\n",
            None,
            {"reason": "modified_since_apply", "already": False, "text": "minlen = 14\nMINLEN 9\n"},
        ),
        (
            "minlen = 12\n",
            "minlen = 8",
            {"reason": "modified_since_apply", "already": False, "text": "minlen = 12\n"},
        ),
    ],
)
def test_the_restore_of_the_main_file(
    text: str, prior: str | None, outcome: dict[str, object]
) -> None:
    assert pwquality_restore.pwquality_restore(text, "minlen", "minlen = 14", prior) == outcome


def test_the_line_is_appended_after_a_line_break_when_the_file_has_none() -> None:
    assert pwquality.compose("a", "minlen = 14", []) == (1, "a\nminlen = 14")
    assert pwquality.compose("", "minlen = 14", []) == (0, "minlen = 14\n")
    assert pwquality.compose("a\nminlen=1\r\nb", "minlen = 14", [(1, "minlen=1\r")]) == (
        1,
        "a\nminlen = 14\nb",
    )


def test_the_decide_filter_passes_the_rule_and_the_files() -> None:
    decision = pwquality_decide.pwquality_decide(
        {
            "setting": "minlen",
            "value": "14",
            "method": "dropin",
            "main": MAIN,
            "dropin": DROPIN,
            "content": "minlen = 14\n",
        },
        [
            {
                "path": "/etc/security/pwquality.conf.d/90-site.conf",
                "type": "file",
                "content": "minlen 9\n",
            }
        ],
        "",
        [
            {
                "path": "/etc/pam.d/common-password",
                "content": "password requisite pam_pwquality.so\n",
            }
        ],
    )
    assert decision["status"] == "overridden"
    assert decision["reason"] == (
        "libpwquality reads minlen 9 from line 1 of /etc/security/pwquality.conf.d/90-site.conf "
        f"after {DROPIN}"
    )
    filters = pwquality_decide.FilterModule().filters()
    assert filters == {"pwquality_decide": pwquality_decide.pwquality_decide}
    restores = pwquality_restore.FilterModule().filters()
    assert restores == {"pwquality_restore": pwquality_restore.pwquality_restore}


EMPTY: list[object] = []
GOOD_RULE: dict[str, object] = {
    "setting": "minlen",
    "value": "14",
    "method": "main_file",
    "main": MAIN,
    "dropin": DROPIN,
    "content": "",
}


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (("rule", EMPTY, "", EMPTY), "the rule must be a mapping"),
        ((GOOD_RULE, "drop-ins", "", EMPTY), "the rule must be a mapping"),
        ((GOOD_RULE, EMPTY, "", "pam"), "the PAM files must be a list"),
        ((GOOD_RULE, EMPTY, 1, EMPTY), "the PAM files must be a list"),
        ((GOOD_RULE | {"value": 14}, EMPTY, "", EMPTY), "value must be a string"),
        ((GOOD_RULE, ["entry"], "", EMPTY), "every drop-in must be a mapping"),
        ((GOOD_RULE, EMPTY, "", ["file"]), "every PAM file must be a mapping"),
        ((GOOD_RULE, EMPTY, "", [{"path": "/etc/pam.d/x"}]), "content must be a string"),
    ],
)
def test_the_decide_filter_refuses_input_of_the_wrong_shape(
    arguments: tuple[object, object, object, object], message: str
) -> None:
    with pytest.raises(pwquality_decide.DecisionInputError, match=message):
        pwquality_decide.pwquality_decide(*arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        (1, "minlen", "minlen = 14", None),
        ("", None, "minlen = 14", None),
        ("", "minlen", None, None),
        ("", "minlen", "minlen = 14", 8),
    ],
)
def test_the_restore_filter_refuses_input_of_the_wrong_shape(
    arguments: tuple[object, object, object, object],
) -> None:
    with pytest.raises(pwquality_restore.RestoreInputError):
        pwquality_restore.pwquality_restore(*arguments)
