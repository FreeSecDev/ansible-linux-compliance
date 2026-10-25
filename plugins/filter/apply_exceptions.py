"""Filter that applies a version-controlled exceptions file to a scan run."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: apply_exceptions
short_description: Apply a version-controlled exceptions file to a compliance scan run
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Validates an exceptions file and applies it to one scan run of one host, on the controller.
  - A C(fail) finding whose rule and scope match an exception that is in effect becomes C(waived)
    and carries the exception identifier, its justification and expiry.
  - C(pass), C(notapplicable), C(notchecked), C(error), C(disabled) and every finding of a run that
    did not complete stay unchanged.
  - The scan start time comes from the scanned host and is not trusted to extend a waiver. Expiry is
    judged at the later of the scan start and the controller's current UTC time. A scan start more
    than five minutes after the controller time fails the task. A scan that started more than
    O(max_scan_lag_hours) before the controller time is still evaluated and flagged with
    V(scan_lag_exceeded).
  - An expired exception never suppresses a failure. The finding stays C(fail); if the exception had
    already expired when the scan started, the finding also carries it with state C(expired).
  - Every exception gets a status in the result, so unused, expired and superseded exceptions are
    reported. Use P(freesecdev.linux_compliance.stale_exceptions#filter) to find exceptions that
    matched no finding on any host.
  - Any invalid entry rejects the whole file and fails the task; nothing is applied from an invalid
    file. The policy and the file format are documented in C(docs/exceptions.md).
positional: exceptions_text, host, groups
options:
  _input:
    description:
      - The scan run, as the mapping of the findings model or its JSON text.
      - Findings must not carry exception data yet.
    type: raw
    required: true
  exceptions_text:
    description:
      - The content of the exceptions file, for example from
        C(lookup('ansible.builtin.file', path)).
    type: str
    required: true
  host:
    description:
      - The inventory host name of the scanned host, normally C(inventory_hostname).
      - Host scopes are matched against this value, never against the host name the scanned host
        reports about itself.
    type: str
    required: true
  groups:
    description:
      - The inventory groups of the scanned host, normally C(group_names).
    type: list
    elements: str
    required: true
  max_scan_lag_hours:
    description:
      - How many hours the scan may have started before the controller time before the evaluation is
        flagged with V(scan_lag_exceeded). Between 1 and 8760.
    type: int
    default: 24
"""

EXAMPLES = r"""
- name: Apply the exceptions file to the scan run of this host
  ansible.builtin.set_fact:
    linux_compliance_audit_evaluation: >-
      {{ linux_compliance_audit_scan_run
         | freesecdev.linux_compliance.apply_exceptions(
             lookup('ansible.builtin.file', linux_compliance_audit_exceptions_file),
             inventory_hostname, group_names) }}
"""

RETURN = r"""
_value:
  description:
    - The evaluation document.
    - V(scan_run) is the scan run with waived and expired findings marked.
    - V(exceptions) lists every exception with its record, V(status) (V(waived), V(expired),
      V(not_yet_effective), V(not_failing), V(superseded) or V(unmatched)), the evaluated
      V(outcome) of the matched finding, V(expired) and V(superseded_by).
    - V(summary) counts the exceptions per status. V(source_sha256) is the SHA-256 of the exceptions
      text and V(target) the host and groups used for matching.
    - V(scan_started_at), V(controller_time), V(evaluated_at) (the instant at which expiry was
      judged), V(scan_lag_seconds), V(max_scan_lag_seconds) and V(scan_lag_exceeded) record the
      timing.
  type: dict
"""

MAX_SCAN_LAG_HOURS = 24 * exceptions.MAX_VALIDITY_DAYS


def apply_exceptions(
    scan_run: object,
    exceptions_text: object,
    host: object,
    groups: object,
    max_scan_lag_hours: object = 24,
) -> dict[str, object]:
    """Apply an exceptions file to one scan run.

    Args:
        scan_run: The scan run mapping or JSON text.
        exceptions_text: The exceptions file content.
        host: The inventory host name.
        groups: The inventory groups of the host.
        max_scan_lag_hours: The scan age in hours above which the evaluation is flagged.

    Returns:
        The evaluation document.

    Raises:
        ExceptionsError: If any input is invalid or the scan starts in the future.
    """
    if (
        not isinstance(max_scan_lag_hours, int)
        or isinstance(max_scan_lag_hours, bool)
        or not 1 <= max_scan_lag_hours <= MAX_SCAN_LAG_HOURS
    ):
        message = f"max_scan_lag_hours must be an integer from 1 to {MAX_SCAN_LAG_HOURS}"
        raise exceptions.ExceptionsError(message)
    now = datetime.now(timezone.utc)
    run = exceptions.load_scan_run(scan_run)
    target = exceptions.make_target(host, groups)
    parsed = exceptions.parse_exceptions(cast("str", exceptions_text), now)
    evaluation = exceptions.evaluate_run(
        run, parsed, target, now, max_scan_lag=timedelta(hours=max_scan_lag_hours)
    )
    return evaluation.to_dict()


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"apply_exceptions": apply_exceptions}
