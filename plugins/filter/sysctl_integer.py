"""Filter that reads a kernel parameter value as the kernel reads an integer (FREES-107)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sysctl_config,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: sysctl_integer
short_description: Read a kernel parameter value as the kernel reads an integer
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Returns the integer of a value only when it is in the plain decimal form
    C(^(0|-?[1-9][0-9]{0,18})$), and null for every other value, C(-0) included.
  - The kernel reads an integer parameter in base 0 (C(proc_get_long)), so C(065536) is octal and
    C(0x10) hexadecimal, and it refuses a leading C(+) and a value of 21 characters or more, and
    its unsigned handlers refuse any C(-); only the plain decimal form means the same to every
    handler of the kernel and to a reader in base 10. The remediate
    role counts a value of an integer kernel parameter as accepted only when this filter returns
    an accepted integer for it (ADR 0029).
options:
  _input:
    description: The value as a reader of the configuration or the kernel would set it.
    type: raw
    required: true
"""

EXAMPLES = r"""
- name: Decide whether a value of an integer parameter is one that the check accepts
  ansible.builtin.debug:
    msg: "{{ ('065536' | freesecdev.linux_compliance.sysctl_integer) in [65536] }}"
"""

RETURN = r"""
_value:
  description: The integer, or null when the value is not in the plain decimal form.
  type: int
"""


def sysctl_integer(value: object) -> int | None:
    """Return the integer that the kernel takes from ``value``, or None for any other form.

    Args:
        value: The value of an integer kernel parameter.

    Returns:
        The integer, or None.
    """
    return sysctl_config.kernel_integer(value)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"sysctl_integer": sysctl_integer}
