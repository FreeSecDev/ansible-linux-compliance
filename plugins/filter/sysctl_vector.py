"""Filter that reads a kernel parameter value as the kernel reads an integer vector (FREES-107)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sysctl_config,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: sysctl_vector
short_description: Read a kernel parameter value as the kernel reads an integer vector
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Returns the integers of a value such as C(32768 65535) only when it has exactly O(count)
    fields, separated by spaces and tabs, each in the plain decimal form that the filter
    C(freesecdev.linux_compliance.sysctl_integer) accepts, and null for every other value.
  - The kernel reads an integer vector such as C(net.ipv4.ip_local_port_range) with
    C(proc_dointvec), each field in base 0 and followed only by a space, a tab or a line feed, so
    C(032768 65535) is octal and C(32768 65535x) or C(32768<VT>65535) is refused. The remediate role
    counts such a value as accepted only when this filter returns the accepted integers for it
    (ADR 0029).
options:
  _input:
    description: The value as a reader of the configuration or the kernel would set it.
    type: raw
    required: true
  count:
    description: The number of fields of the vector.
    type: int
    required: true
"""

EXAMPLES = r"""
- name: Decide whether a port range is the one that the check accepts
  ansible.builtin.debug:
    msg: "{{ ('32768 65535' | freesecdev.linux_compliance.sysctl_vector(2)) == [32768, 65535] }}"
"""

RETURN = r"""
_value:
  description: The integers, or null when the value is not such a vector.
  type: list
  elements: int
"""


def sysctl_vector(value: object, count: int) -> list[int] | None:
    """Return the ``count`` integers that the kernel takes from ``value``, or None.

    Args:
        value: The value of an integer vector kernel parameter.
        count: The number of fields.

    Returns:
        The integers, or None.
    """
    return sysctl_config.kernel_vector(value, count)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"sysctl_vector": sysctl_vector}
