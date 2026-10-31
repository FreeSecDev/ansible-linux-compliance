"""Filter that decides what systemd-sysctl and procps set for a kernel parameter (FREES-107)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sysctl_config,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: sysctl_effective
short_description: Decide what systemd-sysctl and procps set for a kernel parameter
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Returns, for C(systemd) (C(systemd-sysctl) at boot) and C(procps) (C(sysctl --system)),
    the value that the reader sets last for O(key) from the given configuration entries, and the
    file it comes from, or nulls when the reader sets nothing.
  - The model follows the file order, the precedence of file names across directories, masking, the
    key forms, globs and white space as the real readers decide them; its unit tests compare it with
    what the readers of the Molecule images set (ADR 0029).
  - The remediate role uses it to refuse a kernel parameter rule whose drop-in a reader would
    not apply, and to report a rule compliant only when both readers already set an accepted
    value.
options:
  _input:
    description:
      - The entries of the configuration directories, C(/etc/sysctl.conf) and the files of
        O(after), each a mapping with C(path), C(kind) (C(file), C(link), C(directory) or
        C(other)) and C(text), the content of a file or of a link's regular target, or null.
    type: list
    elements: dict
    required: true
  key:
    description:
      - The kernel parameter in the dotted form.
    type: str
    required: true
  after:
    description:
      - Files that both readers read after every other, in order, such as ufw's
        C(/etc/ufw/sysctl.conf).
    type: list
    elements: str
    default: []
"""

EXAMPLES = r"""
- name: Decide what the readers set for rp_filter
  ansible.builtin.debug:
    msg: "{{ entries | freesecdev.linux_compliance.sysctl_effective('kernel.dmesg_restrict') }}"
"""

RETURN = r"""
_value:
  description:
    - V(systemd) and V(procps), each with C(value) and C(source), null when the reader sets
      nothing, and V(unsupported), the reasons why the model cannot decide what procps reads (a
      configuration file name that procps expands as a pattern); the caller refuses when it is not
      empty.
  type: dict
"""


def sysctl_effective(
    entries: list[dict[str, object]], key: str, after: list[str] | None = None
) -> dict[str, object]:
    """Return what each reader sets for ``key``.

    Args:
        entries: The configuration entries, with ``path``, ``kind`` and ``text``.
        key: The kernel parameter in the dotted form.
        after: Files that both readers read last.

    Returns:
        The value and source file per reader, or nulls.

    Raises:
        ConfigError: If an entry is malformed.
    """
    return sysctl_config.effective(entries, key, after or [])


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"sysctl_effective": sysctl_effective}
