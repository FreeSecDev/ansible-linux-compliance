"""Filter that counts the findings of a scan run by outcome."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: scan_summary
short_description: Count the findings of a compliance scan run by outcome
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Validates a scan run with the findings model and returns the number of findings per outcome,
    the total, the run status and the off-platform marker (or null), in the same shape as the
    C(summary) of
    M(freesecdev.linux_compliance.compliance_scan).
  - The audit role uses it to summarise the waived scan run that
    P(freesecdev.linux_compliance.apply_exceptions#filter) returns, next to the raw summary.
  - The summary never states compliance. A run that did not complete has only C(error) findings.
options:
  _input:
    description:
      - The scan run, as the mapping of the findings model or its JSON text.
    type: raw
    required: true
"""

EXAMPLES = r"""
- name: Summarise the waived scan run
  ansible.builtin.debug:
    msg: "{{ evaluation.scan_run | freesecdev.linux_compliance.scan_summary }}"
"""

RETURN = r"""
_value:
  description:
    - One count per outcome (V(pass), V(fail), V(notapplicable), V(notchecked), V(error),
      V(waived) and V(disabled)), V(total) and V(run_status).
  type: dict
"""


def scan_summary(scan_run: object) -> dict[str, object]:
    """Count the findings of a scan run by outcome.

    Args:
        scan_run: The scan run mapping or JSON text.

    Returns:
        The count per outcome, the total, the run status and the off-platform marker
        of the run or ``None``.

    Raises:
        ExceptionsError: If the value is not a valid scan run.
    """
    run = exceptions.load_scan_run(scan_run)
    tally = {outcome.value: 0 for outcome in model.Outcome}
    for finding in run.findings:
        tally[finding.outcome.value] += 1
    counts: dict[str, object] = dict(tally)
    counts["total"] = len(run.findings)
    counts["run_status"] = run.status.value
    counts["off_platform"] = None if run.off_platform is None else run.off_platform.to_dict()
    return counts


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"scan_summary": scan_summary}
