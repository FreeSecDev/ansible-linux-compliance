"""Filter that checks the host files of an evidence bundle before they are fetched."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: evidence_host_files
short_description: Check the recorded audit evidence files on the host before they are fetched
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Recomputes the plan of P(freesecdev.linux_compliance.evidence_plan#filter) from
    C(linux_compliance_audited) and compares it with the result of M(ansible.builtin.stat) on the
    host, taken with C(follow=false).
  - Every planned file must exist, must be a regular file that is not a symbolic link, and must
    have exactly the size that the audit recorded. Anything else fails the task before any byte is
    transferred, so a symbolic link is never followed by the fetch and an oversized file is never
    copied to the controller.
positional: host, include_arf, observed
options:
  _input:
    description:
      - The fact C(linux_compliance_audited).
    type: dict
    required: true
  host:
    description:
      - The inventory host name.
    type: str
    required: true
  include_arf:
    description:
      - Whether the ARF results are collected; it must be the value given to the plan.
    type: bool
    required: true
  observed:
    description:
      - Bundle path to the result of M(ansible.builtin.stat) on the host for each planned file.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Check the host files before fetching them
  ansible.builtin.assert:
    that:
      - >-
        linux_compliance_audited
        | freesecdev.linux_compliance.evidence_host_files(inventory_hostname, false, observed)
        | length > 0
"""

RETURN = r"""
_value:
  description:
    - The checked bundle paths, sorted.
  type: list
  elements: str
"""


def evidence_host_files(
    audited: object, host: object, include_arf: object, observed: object
) -> list[str]:
    """Check the host files of a bundle before they are fetched.

    Args:
        audited: The fact ``linux_compliance_audited``.
        host: The inventory host name.
        include_arf: Whether the ARF results are collected.
        observed: Bundle path to the host ``stat`` result.

    Returns:
        The checked paths.

    Raises:
        EvidenceError: If a file is missing, a symbolic link, special or of another size.
    """
    return evidence.check_host_files(audited, host, include_arf, observed)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"evidence_host_files": evidence_host_files}
