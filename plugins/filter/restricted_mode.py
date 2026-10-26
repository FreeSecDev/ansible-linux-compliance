"""Filter that removes the permission bits a file mode may not have."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: restricted_mode
short_description: Remove from a file mode every bit that a maximum mode does not allow
version_added: "0.1.0"
description:
  - Returns the octal mode C(current & maximum) as four digits, so a file that is already more
    restrictive than the maximum keeps its mode and a more permissive one loses only the excess
    bits. This is how ComplianceAsCode remediates C(file_permissions_*) rules.
  - Both modes are octal strings of three or four digits, as returned by M(ansible.builtin.stat).
    Anything else is an error.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, maximum
options:
  _input:
    description: The current mode, for example C(0644).
    type: str
    required: true
  maximum:
    description: The most permissive mode allowed, for example C(0600).
    type: str
    required: true
"""

EXAMPLES = r"""
- name: Remove the bits that /etc/crontab may not have
  ansible.builtin.file:
    path: /etc/crontab
    mode: "{{ crontab_stat.stat.mode | freesecdev.linux_compliance.restricted_mode('0600') }}"
"""

RETURN = r"""
_value:
  description: The restricted mode as four octal digits.
  type: str
  sample: "0600"
"""

MODE_PATTERN: Final[str] = r"[0-7]{3,4}"


def _bits(value: object, name: str) -> int:
    if not isinstance(value, str) or re.fullmatch(MODE_PATTERN, value) is None:
        message = f"{name} must be an octal mode of three or four digits, got {repr(value)[:32]}"
        raise ValueError(message)
    return int(value, 8)


def restricted_mode(current: object, maximum: object) -> str:
    """Return ``current & maximum`` as a four-digit octal string."""
    return f"{_bits(current, 'the current mode') & _bits(maximum, 'the maximum mode'):04o}"


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object, object], str]]:
        """Return the filters of this plugin."""
        return {"restricted_mode": restricted_mode}
