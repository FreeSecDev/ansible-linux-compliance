"""Filter that reads the text of auditd.conf the way auditd reads it (FREES-110)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditconf,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: auditd_conf_reading
short_description: Read the text of auditd.conf the way auditd reads it, or refuse
version_added: "0.1.0"
description:
  - Classifies the text of C(/etc/audit/auditd.conf) with the collection's reader, which the unit
    tests check against a verdict table of the real auditd of each Molecule image (ADR 0030).
  - Returns whether auditd accepts the file, refuses it or the reader cannot tell, why, the lines
    that auditd reads for each keyword (the last one wins) and the lines that auditd skips.
  - The caller must treat anything but an accepted file as a refusal; the reader never guesses.
author:
  - FreeSecDev contributors (@FreeSecDev)
positional: _input, log_megabytes
options:
  _input:
    description: The text of the file, with its line breaks.
    type: str
    required: true
  log_megabytes:
    description:
      - The size of the file system of the audit log in MiB, with which auditd converts a
        C(space_left) or C(admin_space_left) in percent; null when unknown.
    type: int
    required: false
"""

EXAMPLES = r"""
- name: Read auditd.conf as auditd reads it
  ansible.builtin.set_fact:
    auditd_reading: >-
      {{ auditd_conf_text | freesecdev.linux_compliance.auditd_conf_reading(10240) }}
"""

RETURN = r"""
_value:
  description:
    - C(accepted) (true, false, or null when the reader cannot tell), C(reason), C(settings), a
      mapping of each keyword in lower case to the lines read for it (C(line), C(value), C(text)),
      and C(skipped), the numbers of the lines that auditd skips.
  type: dict
  sample:
    accepted: true
    reason: ""
    settings:
      space_left: [{"line": 15, "value": "75", "text": "space_left = 75"}]
    skipped: []
"""


def auditd_conf_reading(text: object, log_megabytes: object = None) -> dict[str, object]:
    """Return what auditd makes of the text of an auditd.conf."""
    if not isinstance(text, str):
        message = "auditd_conf_reading needs the text of the file"
        raise TypeError(message)
    if log_megabytes is not None and (
        isinstance(log_megabytes, bool) or not isinstance(log_megabytes, int)
    ):
        message = "log_megabytes must be a whole number of MiB or null"
        raise TypeError(message)
    reading = auditconf.read(text.encode("utf-8", "surrogateescape"), log_megabytes)
    return {
        "accepted": reading.accepted,
        "reason": reading.reason,
        "settings": {
            keyword: [{"line": item.line, "value": item.value, "text": item.text} for item in found]
            for keyword, found in reading.settings.items()
        },
        "skipped": list(reading.skipped),
    }


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"auditd_conf_reading": auditd_conf_reading}
