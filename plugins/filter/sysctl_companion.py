"""Filter that decides whether a companion parameter makes the kernel refuse a key (FREES-107)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sysctl_config,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

DOCUMENTATION = r"""
---
name: sysctl_companion
short_description: Decide whether a companion kernel parameter makes the kernel refuse a key
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - The kernel refuses some kernel parameters while another, the companion, has certain values,
    such as C(kernel.perf_event_max_sample_rate) while C(kernel.perf_cpu_time_max_percent) is 0 or
    100.
  - Returns, for the entries after the run (O(_input)) and as they are (O(current)), and for
    C(systemd) (C(systemd-sysctl) at boot) and C(procps) (C(sysctl --system)), the setting of the
    companion at which the kernel would refuse the reader's write of O(key), with C(value) and
    C(source), or null.
  - When the companion's own rule is selected in the same run (O(rule)), its drop-in and vendor
    edits count only when its plan status is C(applied) or C(compliant); with any other status
    the companion is judged as the files leave it, and without a plan entry the result is
    C(undecided), which the caller refuses.
  - The kernel checks the companion only when O(key) is written. For C(systemd) the setting is the
    companion's last value in C(systemd-sysctl)'s own files or, when ufw applies its file after
    boot, its last value there; either refuses. C(procps) makes every assignment in turn, so for it
    the setting is the companion's value when it writes O(key) for the last time; an assignment of
    the companion outside its range leaves the value it had. A value that the filter
    C(freesecdev.linux_compliance.sysctl_integer) does not read counts as a refused one (ADR 0029).
options:
  _input:
    description:
      - The configuration entries after the run, with the drop-in and edits of the rule of
        O(key), as for C(freesecdev.linux_compliance.sysctl_effective).
    type: list
    elements: dict
    required: true
  current:
    description: The configuration entries as they are.
    type: list
    elements: dict
    required: true
  key:
    description: The kernel parameter that the kernel may refuse, in the dotted form.
    type: str
    required: true
  blocker:
    description:
      - The companion, with C(key) (the companion kernel parameter, in the dotted form),
        C(refused) (the integers at which the kernel refuses O(key)) and C(minimum) and C(maximum)
        (the range in which the kernel takes a value of the companion), as
        C(__linux_compliance_remediate_sysctl_refusing_companions) of the remediate role names it.
    type: dict
    required: true
  rule:
    description:
      - The companion's rule when it is selected in the same run, with C(plan) (its plan entry,
        with C(status), C(write) and C(edits), or null when it is not decided yet), C(path) (its
        drop-in) and C(content); null when the rule is not selected.
    type: dict
    required: false
"""

EXAMPLES = r"""
- name: Decide whether the CPU time limit makes the kernel refuse the perf sample rate
  ansible.builtin.debug:
    msg: >-
      {{ planned | freesecdev.linux_compliance.sysctl_companion(current,
         'kernel.perf_event_max_sample_rate',
         {'key': 'kernel.perf_cpu_time_max_percent', 'refused': [0, 100], 'minimum': 0,
          'maximum': 100}) }}
"""

RETURN = r"""
_value:
  description:
    - V(undecided), whether the companion's selected rule has no plan entry yet, and V(planned)
      and V(current), each with V(systemd) and V(procps), null or the companion's C(value) and
      C(source) at which the kernel would refuse the reader's write of O(key).
  type: dict
"""


def sysctl_companion(
    planned: list[dict[str, object]],
    current: list[dict[str, object]],
    key: str,
    blocker: Mapping[str, object],
    rule: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return whether ``companion`` makes the kernel refuse ``key``, after and before the run.

    Args:
        planned: The configuration entries after the run.
        current: The configuration entries as they are.
        key: The kernel parameter that the kernel may refuse.
        blocker: The companion's ``key``, the ``refused`` values at which the kernel refuses
            ``key``, and its ``minimum`` and ``maximum``.
        rule: The companion's selected rule, with ``plan``, ``path`` and ``content``, or None.

    Returns:
        ``undecided``, and per ``planned`` and ``current`` the refusing setting per reader.

    Raises:
        ConfigError: If an entry is malformed.
    """
    return sysctl_config.companion_check(planned, current, key, blocker, rule)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"sysctl_companion": sysctl_companion}
