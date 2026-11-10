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
      - The entries of the configuration directories, C(/etc/sysctl.conf) and ufw's
        C(/etc/ufw/ufw.conf), C(/etc/default/ufw) and C(/etc/ufw/sysctl.conf), each a mapping
        with C(path), C(kind) (C(file), C(link), C(directory) or C(other)), C(text), the
        content of a file or of a link's regular target, or null, and, for a link, C(target), which
        is C(file) for a regular file, C(null) for C(/dev/null) and anything else otherwise.
      - ufw's C(/etc/ufw/sysctl.conf) counts, after every other file, only when C(ENABLED) is
        C(yes) or C(YES) and C(IPT_SYSCTL) names that file, each read from C(/etc/default/ufw)
        and then C(ufw.conf), as ufw sources them; ufw applies nothing unless both are non-empty
        regular files, and a line of either other than a comment or a plain assignment of one of
        ufw's own variables is refused.
    type: list
    elements: dict
    required: true
  key:
    description:
      - The kernel parameter in the dotted form.
    type: str
    required: true
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
      nothing, and V(unsupported), the reasons why the model cannot decide what a reader sets
      (an entry name that procps expands as a pattern, a FIFO, socket or device, a link to
      something other than a regular file or C(/dev/null), a key with a C(..) component, a procps
      key with a second leading C(-), a procps glob that is not in canonical form, a glob
      component that starts with C(.), a glob that the model cannot translate exactly, a line
      at which systemd-sysctl stops reading, or a ufw setting the model does not follow); the
      caller refuses when it is not empty.
  type: dict
"""


def sysctl_effective(entries: list[dict[str, object]], key: str) -> dict[str, object]:
    """Return what each reader sets for ``key``.

    Args:
        entries: The configuration entries, with ``path``, ``kind`` and ``text``.
        key: The kernel parameter in the dotted form.

    Returns:
        The value and source file per reader, or nulls.

    Raises:
        ConfigError: If an entry is malformed.
    """
    return sysctl_config.effective(entries, key)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"sysctl_effective": sysctl_effective}
