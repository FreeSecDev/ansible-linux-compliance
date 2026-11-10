"""Filter that applies a cleanup's vendor line restores to the sysctl texts (FREES-107)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sysctl_config,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

DOCUMENTATION = r"""
---
name: sysctl_restored
short_description: Apply the vendor line restores of a cleanup to the configuration texts
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Returns the texts of the configuration files as the cleanup of the kernel parameter rules
    leaves them. Each restore names a vendor file (C(path)), the line that the collection wrote
    there (C(written)) and the recorded line before it (C(original)); where the file holds the
    written line exactly once, it becomes the original line, as the cleanup's C(lineinfile) does.
  - The remediate role judges the rules to apply on these texts, so a vendor line that the cleanup
    of another rule writes back counts in the same run (ADR 0029).
options:
  _input:
    description: The texts of the configuration files, by path.
    type: dict
    required: true
  restores:
    description: The restores of the cleanup, each with C(path), C(written) and C(original).
    type: list
    elements: dict
    required: true
"""

EXAMPLES = r"""
- name: Name the texts as the cleanup leaves them
  ansible.builtin.set_fact:
    texts_after_cleanup: "{{ texts | freesecdev.linux_compliance.sysctl_restored(restores) }}"
"""

RETURN = r"""
_value:
  description: The texts by path, with every restore applied.
  type: dict
"""


def sysctl_restored(
    texts: Mapping[str, object], restores: list[Mapping[str, object]]
) -> dict[str, object]:
    """Return ``texts`` with every restore of the cleanup applied.

    Args:
        texts: The texts of the configuration files, by path.
        restores: The restores, each with ``path``, ``written`` and ``original``.

    Returns:
        The texts as the cleanup leaves them.

    Raises:
        ConfigError: If a restore is malformed.
    """
    return sysctl_config.restore_lines(texts, restores)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"sysctl_restored": sysctl_restored}
