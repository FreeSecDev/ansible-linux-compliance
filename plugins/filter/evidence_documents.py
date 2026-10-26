"""Filter that checks fetched evidence and returns the documents of an evidence bundle."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: evidence_documents
short_description: Check fetched audit evidence and build the manifest of its evidence bundle
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Recomputes the plan of P(freesecdev.linux_compliance.evidence_plan#filter) from
    C(linux_compliance_audited) and checks every fetched file against it. Each file must be a
    regular file with mode C(0600), owned by the controller user, with exactly the SHA-256 and size
    that the audit recorded on the host. Any mismatch fails the task, and the C(evidence) role then
    removes the incomplete bundle.
  - C(scan-run.json) must be the scan run of the fact. When exceptions were applied, the exceptions
    file must still have the SHA-256 that was applied, the evaluation must verify against it and
    must have been made from the raw scan run; the stale result must come from the same file and
    include this host.
  - Returns the documents to write (the evaluation, the exceptions file, the stale result and
    C(SHA256SUMS)) and the manifest C(bundle.json), which the role writes last.
  - The manifest records the collection version, the controller time, the inventory host name, the
    machine ID of the gathered facts, the host identity the scan run reports, the run, scanner and
    content provenance, and the SHA-256 of the exceptions file. Nothing else from facts, the
    environment or the inventory is written. The format is documented in C(docs/evidence.md).
positional: collected
options:
  _input:
    description:
      - The fact C(linux_compliance_audited).
    type: dict
    required: true
  collected:
    description:
      - What the role observed on the controller, a mapping with exactly these keys.
      - V(host), the inventory host name.
      - V(include_arf), the value given to the plan.
      - V(observed), bundle path to the result of M(ansible.builtin.stat) with
        C(checksum_algorithm=sha256) for each fetched file.
      - V(scan_run_text), the fetched C(scan-run.json), read with the C(ansible.builtin.file) lookup
        and C(rstrip=false).
      - V(exceptions_text), the exceptions file read the same way when exceptions were applied, or
        null.
      - V(stale), the fact C(linux_compliance_audit_stale_exceptions) or an empty mapping.
      - V(machine_id), the machine ID from the gathered facts of the host, or null.
      - V(collection_version), the version of the collection.
      - V(controller_uid), the user ID of the controller user that owns the bundle.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Build the documents of the bundle
  ansible.builtin.set_fact:
    evidence_bundle_documents: >-
      {{ linux_compliance_audited | freesecdev.linux_compliance.evidence_documents(collected) }}
"""

RETURN = r"""
_value:
  description:
    - V(documents) maps bundle paths to the text to write before the manifest, V(manifest) is the
      text of C(bundle.json), V(manifest_sha256) its SHA-256, and V(expected) maps every bundle path
      except the manifest to its V(sha256) and V(size).
  type: dict
"""


def evidence_documents(audited: object, collected: object) -> dict[str, object]:
    """Check the fetched files of a bundle and return its documents.

    Args:
        audited: The fact ``linux_compliance_audited``.
        collected: What the role observed on the controller (see the documentation).

    Returns:
        The documents, the manifest and the expected digests.

    Raises:
        EvidenceError: On any mismatch.
    """
    return evidence.build_documents(
        audited, evidence.Collected.from_dict(collected), datetime.now(timezone.utc)
    )


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"evidence_documents": evidence_documents}
