"""Filter that lists exceptions that waived nothing on any evaluated host."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: exception_removal_candidates
short_description: List exceptions that waived nothing in any evaluation
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Takes the evaluation documents that P(freesecdev.linux_compliance.apply_exceptions#filter)
    returned for several hosts and returns the identifiers of the exceptions that are candidates for
    removal.
  - An exception is a candidate when, on every evaluated host, it waived no failure, covered no
    failure that expired and covered no failure that was scanned before its approval date.
  - That is the case when it matched nothing (stale, see
    P(freesecdev.linux_compliance.stale_exceptions#filter)), when another exception was chosen for
    every failure it covered (C(superseded)), or when its rule did not fail wherever its scope
    matched (C(not_failing)).
  - All evaluations must come from the same exceptions file and use a supported evaluation
    C(schema_version). The result only covers the hosts that were evaluated.
options:
  _input:
    description:
      - The list of evaluation documents, one per host and scan run.
    type: list
    elements: dict
    required: true
"""

EXAMPLES = r"""
- name: Report exceptions that no host of this play needs any more
  ansible.builtin.debug:
    msg: >-
      {{ ansible_play_hosts
         | map('extract', hostvars, 'linux_compliance_audit_evaluation')
         | list
         | freesecdev.linux_compliance.exception_removal_candidates }}
  run_once: true
"""

RETURN = r"""
_value:
  description:
    - The sorted identifiers of the exceptions that are stale, superseded or not failing on every
      evaluated host.
  type: list
  elements: str
"""


def exception_removal_candidates(evaluations: object) -> list[str]:
    """Return the exceptions that waived nothing on any evaluated host.

    Args:
        evaluations: The evaluation documents, one per host and scan run.

    Returns:
        The sorted exception identifiers.

    Raises:
        ExceptionsError: If the evaluations are missing, malformed or inconsistent.
    """
    return exceptions.removal_candidate_ids(evaluations)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"exception_removal_candidates": exception_removal_candidates}
