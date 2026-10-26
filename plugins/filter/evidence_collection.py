"""Filter that accounts for the target hosts of an evidence run and builds its summary."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    collection,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: evidence_collection
short_description: Account for every target host of an evidence run and build its collection summary
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Gives every target host of a run of C(playbooks/evidence.yml) one status, V(collected),
    V(unreachable), V(limited_out), V(no_audit_result), V(no_evidence_written) or
    V(collection_failed), and builds the collection summary C(collection-<collection_id>.json)
    that the C(evidence) role writes next to the bundles.
  - The summary names every target host, the run identity (C(collection_id) and C(collected_at),
    the controller time) and, for each collected host, the run ID and the SHA-256 of its
    C(bundle.json). The report reads it with C(--evidence-collection) and names every target host
    that has no bundle in the report.
  - A host is V(limited_out) when it is not a host of the audit play, and V(unreachable) when it
    is one but did not complete fact gathering. Without the recorded play hosts both are
    V(no_audit_result).
  - The format is documented in C(docs/evidence.md).
options:
  _input:
    description:
      - What the playbook observed, a mapping with exactly these keys.
      - V(targets), the inventory hosts of the run's host pattern.
      - V(play_hosts), the hosts of the audit play, or null when they were not recorded.
      - V(reached), V(audited) and V(evidence_written), the target hosts that completed fact
        gathering, that have the fact C(linux_compliance_audited), and whose audit wrote evidence.
      - V(bundles), inventory host to its C(linux_compliance_evidence_bundle) fact. Only
        V(directory), V(run_id) and V(manifest_sha256) are used.
      - V(output_dir), the resolved output directory, used when no bundle was collected.
      - V(collection_version), the version of the collection.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Account for every target host
  ansible.builtin.set_fact:
    evidence_collection_summary: "{{ observed | freesecdev.linux_compliance.evidence_collection }}"
"""

RETURN = r"""
_value:
  description:
    - V(target_hosts), V(collected_hosts) and V(missing_hosts), one list per status other than
      V(collected), V(statuses) (host to status), V(bundles), V(collection_id), V(document) (the
      text of the summary), V(sha256) (its SHA-256), V(output_dir) and V(path) (where the role
      writes it).
  type: dict
"""


def evidence_collection(observed: object) -> dict[str, object]:
    """Account for the target hosts of a run and build its collection summary.

    Args:
        observed: What the playbook observed (see the documentation).

    Returns:
        The classification and the summary document.

    Raises:
        CollectionError: If an observation is malformed.
    """
    return collection.summarize(observed, datetime.now(timezone.utc))


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"evidence_collection": evidence_collection}
