"""Unit tests of the pam_conf_restore filter, the exact inverse of the decision filter write."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    pam_conf,
    pam_conf_restore,
)

DENY = {
    "reader": "faillock",
    "setting": "deny",
    "comparison": "at_most",
    "required": "4",
    "stack_checked": True,
}
TEXTS = [
    "",
    "# faillock\n",
    "# faillock",
    "# faillock\r\ndeny = 10\r\naudit\r\n",
    "# faillock\r\naudit\r\n",
    "deny = 10 # site\nunlock_time = 900\n",
    "#deny = 1\n",
]


def test_the_filter_is_registered() -> None:
    assert pam_conf_restore.FilterModule().filters() == {
        "pam_conf_restore": pam_conf_restore.pam_conf_restore
    }


@pytest.mark.parametrize("text", TEXTS)
def test_the_restore_gives_back_every_byte_of_the_file_before_the_write(text: str) -> None:
    decision = pam_conf.pam_conf_decision(text, DENY, {})
    assert decision["status"] == "applied"
    written = str(decision["new_text"])
    restore = pam_conf_restore.pam_conf_restore(
        written, "deny", decision["setting_line"], decision["line"]
    )
    assert restore == {"reason": None, "already": False, "new_text": text}
    again = pam_conf_restore.pam_conf_restore(
        text, "deny", decision["setting_line"], decision["line"]
    )
    assert again == {"reason": None, "already": True, "new_text": text}


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("deny = 2\n", "modified_since_apply"),
        ("deny = 4\ndeny = 4\n", "modified_since_apply"),
        ("deny = 4\n\0", "modified_since_apply"),
    ],
)
def test_a_setting_changed_since_the_write_is_kept(text: str, reason: str) -> None:
    restore = pam_conf_restore.pam_conf_restore(text, "deny", None, "deny = 4")
    assert restore == {"reason": reason, "already": False, "new_text": text}


@pytest.mark.parametrize(
    ("setting_line", "written_line"),
    [
        (None, None),
        (None, "deny = 4\nx"),
        (None, "unlock_time = 4"),
        ("audit", "deny = 4"),
        ("deny = 3\x0b", "deny = 4"),
        (3, "deny = 4"),
    ],
)
def test_a_record_that_the_role_never_writes_is_refused(
    setting_line: object, written_line: object
) -> None:
    restore = pam_conf_restore.pam_conf_restore("deny = 4\n", "deny", setting_line, written_line)
    assert restore["reason"] == "invalid_record"


def test_the_arguments_must_be_a_text_and_a_setting_name() -> None:
    with pytest.raises(TypeError, match="text of the file"):
        pam_conf_restore.pam_conf_restore(None, "deny", None, "deny = 4")
    with pytest.raises(TypeError, match="text of the file"):
        pam_conf_restore.pam_conf_restore("", 1, None, "deny = 4")
    with pytest.raises(ValueError, match="lower case"):
        pam_conf_restore.pam_conf_restore("", "Deny", None, "deny = 4")
