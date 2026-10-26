"""Filter that lists exceptions that matched no finding on any host."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: stale_exceptions
short_description: List exceptions that matched no finding in any evaluation
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Takes the evaluation documents that P(freesecdev.linux_compliance.apply_exceptions#filter)
    returned for several hosts and returns the identifiers of the exceptions whose status is
    C(unmatched) in every one of them.
  - Such an exception names a rule or scope that none of the evaluated hosts has. It suppresses
    nothing and should be reviewed and removed.
  - All evaluations must come from the same exceptions file and use a supported evaluation
    C(schema_version); any other version is refused. The result only covers the hosts that were
    evaluated; an exception for a host outside the play is reported as stale.
  - P(freesecdev.linux_compliance.exception_removal_candidates#filter) also lists exceptions
    that are superseded or not failing on every host.
options:
  _input:
    description:
      - The list of evaluation documents, one per host.
    type: list
    elements: dict
    required: true
"""

EXAMPLES = r"""
- name: Report exceptions that no host of this play needs
  ansible.builtin.debug:
    msg: >-
      {{ ansible_play_hosts
         | map('extract', hostvars, 'linux_compliance_audit_evaluation')
         | list
         | freesecdev.linux_compliance.stale_exceptions }}
  run_once: true
"""

RETURN = r"""
_value:
  description:
    - The sorted identifiers of the exceptions that matched no finding in any evaluation.
  type: list
  elements: str
"""


def stale_exceptions(evaluations: object) -> list[str]:
    """Return the exceptions that matched no finding in any evaluation.

    Args:
        evaluations: The evaluation documents, one per host.

    Returns:
        The sorted exception identifiers.

    Raises:
        ExceptionsError: If the evaluations are missing, malformed or inconsistent.
    """
    return exceptions.stale_exception_ids(evaluations)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"stale_exceptions": stale_exceptions}
