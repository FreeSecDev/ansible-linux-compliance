"""Filter that plans the evidence bundle of one audit run."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: evidence_plan
short_description: Decide which audit evidence files enter the evidence bundle of a host
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Validates the fact C(linux_compliance_audited) that the audit role published and returns which
    files of the run directory the C(evidence) role fetches, where each one goes in the bundle, and
    which recorded files are excluded.
  - Only C(scan-run.json), C(tailoring.xml), C(scan/results.xml) and, with O(include_arf),
    C(scan/results-arf.xml) directly inside the run directory are collected. Any other file in the
    run directory is listed as excluded with reason V(not_allow_listed); a path outside the run
    directory fails the task, so a tampered fact cannot make the role fetch the state ledger or any
    other file.
  - The ARF results are excluded by default (V(arf_not_requested)) because they hold the system
    characteristics that OVAL collected, which can include matched lines of files such as
    C(/etc/shadow).
  - The format is documented in C(docs/evidence.md).
positional: host, include_arf
options:
  _input:
    description:
      - The fact C(linux_compliance_audited).
    type: dict
    required: true
  host:
    description:
      - The inventory host name, normally C(inventory_hostname). It names the bundle directory.
    type: str
    required: true
  include_arf:
    description:
      - Whether to collect C(scan/results-arf.xml).
    type: bool
    required: true
"""

EXAMPLES = r"""
- name: Plan the evidence bundle of this host
  ansible.builtin.set_fact:
    evidence_bundle_plan: >-
      {{ linux_compliance_audited
         | freesecdev.linux_compliance.evidence_plan(inventory_hostname, false) }}
"""

RETURN = r"""
_value:
  description:
    - V(directory) is the bundle directory relative to the evidence output directory
      (C(<host>/<run_id>)), V(directories) the subdirectories to create, V(fetch) the host files to
      fetch (V(source), V(path) in the bundle, V(kind), V(sha256) and V(size) recorded on the host),
      V(excluded) the recorded files that are not collected, V(applied) whether exceptions were
      applied and V(exceptions_file) the controller path of the exceptions file.
  type: dict
"""


def evidence_plan(audited: object, host: object, include_arf: object) -> dict[str, object]:
    """Return the plan of the evidence bundle of one audit run.

    Args:
        audited: The fact ``linux_compliance_audited``.
        host: The inventory host name.
        include_arf: Whether to collect the ARF results.

    Returns:
        The plan.

    Raises:
        EvidenceError: If the fact is malformed or names a file outside the run directory.
    """
    return evidence.plan_bundle(audited, host, include_arf).to_dict()


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"evidence_plan": evidence_plan}
