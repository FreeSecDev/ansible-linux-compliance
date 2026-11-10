"""Filter that computes the exact text that restores one faillock.conf or pwhistory.conf line."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from ansible_collections.freesecdev.linux_compliance.plugins.filter.pam_conf import (
    edited_lines,
    recordable,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: pam_conf_restore
short_description: Compute the text that restores one recorded faillock.conf or pwhistory.conf line
version_added: "0.1.0"
description:
  - Finds the physical lines of the setting that the collection edits in the current text of
    C(/etc/security/faillock.conf) or C(/etc/security/pwhistory.conf), in the form that
    C(pam_conf_decision) edits them.
  - When those lines are exactly the recorded prior line (or none, when the file had no line),
    the setting already is as before and the text is returned unchanged. When they are exactly
    the line that the collection wrote, the prior line is put back in its place, or the written
    line is removed, and every other byte is kept. Otherwise the setting was changed since the
    apply and C(modified_since_apply) is returned.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, setting, setting_line, written_line
options:
  _input:
    description: The current text of the configuration file.
    type: str
    required: true
  setting:
    description: The name of the setting, in lower case.
    type: str
    required: true
  setting_line:
    description: The recorded physical line of the setting before the first write, or null.
    type: str
    required: true
  written_line:
    description: The recorded physical line that the collection wrote.
    type: str
    required: true
"""

EXAMPLES = r"""
- name: Compute the restored text
  ansible.builtin.set_fact:
    restore: >-
      {{ text | freesecdev.linux_compliance.pam_conf_restore('deny', none, 'deny = 4') }}
"""

RETURN = r"""
_value:
  description: The restore.
  type: dict
  contains:
    reason:
      description: >-
        C(modified_since_apply) or C(invalid_record) when the line cannot be restored, or null.
      type: str
    already:
      description: Whether the setting already is as it was before the first write.
      type: bool
    new_text:
      description: The text after the restore, or the current text when nothing is written.
      type: str
"""

SETTING: Final[str] = r"[a-z][a-z_]{1,31}"


def _valid_line(value: object, setting: str) -> bool:
    return (
        isinstance(value, str)
        and "\n" not in value
        and recordable(value)
        and edited_lines(value, setting) == [0]
    )


def pam_conf_restore(
    text: object, setting: object, setting_line: object, written_line: object
) -> dict[str, object]:
    """Return the restore of one setting; see the documentation of the filter."""
    if not isinstance(text, str) or not isinstance(setting, str):
        message = "pam_conf_restore needs the text of the file and the name of the setting"
        raise TypeError(message)
    if re.fullmatch(SETTING, setting) is None:
        message = f"pam_conf_restore needs a setting name in lower case, got {setting!r}"
        raise ValueError(message)
    if not _valid_line(written_line, setting) or not (
        setting_line is None or _valid_line(setting_line, setting)
    ):
        return {"reason": "invalid_record", "already": False, "new_text": text}
    lines = text.split("\n")
    found = edited_lines(text, setting)
    current = [lines[index] for index in found]
    if current == ([] if setting_line is None else [setting_line]):
        return {"reason": None, "already": True, "new_text": text}
    if current != [written_line] or "\0" in text:
        return {"reason": "modified_since_apply", "already": False, "new_text": text}
    index = found[0]
    if setting_line is None:
        del lines[index]
    else:
        lines[index] = str(setting_line)
    return {"reason": None, "already": False, "new_text": "\n".join(lines)}


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"pam_conf_restore": pam_conf_restore}
