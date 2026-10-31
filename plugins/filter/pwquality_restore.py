"""Filter that restores one setting of pwquality.conf, every other byte unchanged."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pwquality,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: pwquality_restore
short_description: Restore one setting of pwquality.conf, every other byte unchanged
version_added: "0.2.0"
description:
  - Finds the lines of the text that libpwquality reads as the setting, in any case and with any
    spacing (FREES-200). When that is exactly the one line that the collection wrote, returns the
    text with that line replaced by the recorded prior line, or removed with its line break when
    the setting was absent before, and every other byte unchanged.
  - Returns C(already=true) when the text already sets the setting exactly as before, and the
    reason C(modified_since_apply) when the setting is no longer the line that was written.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, setting, written, prior
options:
  _input:
    description: The text of the main file.
    type: str
    required: true
  setting:
    description: The setting, in lower case.
    type: str
    required: true
  written:
    description: The line that the collection wrote.
    type: str
    required: true
  prior:
    description: The line that set the setting before, or C(None) when it was absent.
    type: str
    required: true
"""

EXAMPLES = r"""
- name: Compose the main file with the minlen line as it was
  ansible.builtin.set_fact:
    restored: >-
      {{ text | freesecdev.linux_compliance.pwquality_restore('minlen', 'minlen = 14', none) }}
"""

RETURN = r"""
_value:
  description: The outcome, with C(reason), C(already) and C(text).
  type: dict
"""


class RestoreInputError(ValueError):
    """The filter received input of the wrong shape."""


def pwquality_restore(
    text: object, setting: object, written: object, prior: object
) -> dict[str, object]:
    """Return the outcome of :func:`pwquality.restore`."""
    if not isinstance(text, str) or not isinstance(setting, str) or not isinstance(written, str):
        message = "the text, the setting and the written line must be strings"
        raise RestoreInputError(message)
    if prior is not None and not isinstance(prior, str):
        message = "the prior line must be a string or None"
        raise RestoreInputError(message)
    return pwquality.restore(text, setting, written, prior)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"pwquality_restore": pwquality_restore}
