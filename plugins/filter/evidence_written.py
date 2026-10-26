"""Filter that checks the written files of an evidence bundle before its manifest is written."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: evidence_written
short_description: Check every file of an evidence bundle before the manifest commits it
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Compares the controller C(stat) result of every file of a bundle with the SHA-256 and size that
    the manifest will record (the V(expected) result of
    P(freesecdev.linux_compliance.evidence_documents#filter)).
  - Every file must be a regular file with mode C(0600), owned by the controller user. Any
    difference fails the task, and the C(evidence) role then removes the incomplete bundle.
positional: observed, controller_uid
options:
  _input:
    description:
      - The V(expected) mapping, bundle path to V(sha256) and V(size).
    type: dict
    required: true
  observed:
    description:
      - Bundle path to the result of M(ansible.builtin.stat) with C(checksum_algorithm=sha256).
    type: dict
    required: true
  controller_uid:
    description:
      - The user ID of the controller user that owns the bundle.
    type: int
    required: true
"""

EXAMPLES = r"""
- name: Check the written files
  ansible.builtin.assert:
    that:
      - >-
        documents.expected
        | freesecdev.linux_compliance.evidence_written(observed, 1000) | length > 0
"""

RETURN = r"""
_value:
  description:
    - The checked bundle paths, sorted.
  type: list
  elements: str
"""


def evidence_written(expected: object, observed: object, controller_uid: object) -> list[str]:
    """Check the written files of a bundle.

    Args:
        expected: Bundle path to the expected SHA-256 and size.
        observed: Bundle path to the controller ``stat`` result.
        controller_uid: The user ID of the controller user.

    Returns:
        The checked paths.

    Raises:
        EvidenceError: If a file is missing or differs.
    """
    return evidence.check_written(expected, observed, controller_uid)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"evidence_written": evidence_written}
