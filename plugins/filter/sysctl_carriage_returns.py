"""Filter that names the sysctl files that the collection must not edit in place (FREES-107)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sysctl_config,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

DOCUMENTATION = r"""
---
name: sysctl_carriage_returns
short_description: Name the sysctl files that hold a carriage return
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Returns, once each and in order, those of O(paths) whose text in O(_input) holds a carriage
    return.
  - C(ansible.builtin.lineinfile) reads a file in text mode, so a lone carriage return ends a line
    there, and writes every line back with a line feed, which turns a line that procps reads as
    part of the one before it into an assignment of its own. The remediate role therefore never
    edits a vendor line in such a file, which refuses the rule as C(unparsed_configuration), and
    never writes a line back into one on cleanup, which leaves the cleanup C(cleanup_incomplete)
    (ADR 0029).
options:
  _input:
    description: The texts of the configuration files, by path.
    type: dict
    required: true
  paths:
    description: The files that the role would edit or restore.
    type: list
    elements: str
    required: true
"""

EXAMPLES = r"""
- name: Name the vendor files that a rule would edit but that hold a carriage return
  ansible.builtin.debug:
    msg: >-
      {{ texts | freesecdev.linux_compliance.sysctl_carriage_returns(['/etc/ufw/sysctl.conf']) }}
"""

RETURN = r"""
_value:
  description: The paths whose text holds a carriage return.
  type: list
  elements: str
"""


def sysctl_carriage_returns(texts: Mapping[str, object], paths: list[object]) -> list[str]:
    """Return those of ``paths`` whose text holds a carriage return.

    Args:
        texts: The texts of the configuration files, by path.
        paths: The files that the role would edit or restore.

    Returns:
        The paths whose text holds a carriage return.

    Raises:
        ConfigError: If ``texts`` is not a mapping or a path is not a string.
    """
    return sysctl_config.carriage_return_files(texts, paths)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"sysctl_carriage_returns": sysctl_carriage_returns}
