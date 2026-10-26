"""Filter that validates an exceptions file before any host is evaluated."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: validate_exceptions
short_description: Validate a version-controlled exceptions file and describe its entries
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Parses and validates an exceptions file with exactly the rules that
    P(freesecdev.linux_compliance.apply_exceptions#filter) applies, on the controller, without a
    scan run.
  - Any invalid entry rejects the whole file and fails the task. The audit role runs this filter
    once, before any host is scanned or evaluated, so a broken file stops the play.
  - The result lists the exceptions whose scope has no C(profiles). Such an exception records a
    C(framework) but applies to every profile scanned on the matching hosts, because C(framework)
    does not restrict matching; the audit role warns about them.
  - The policy and the file format are documented in C(docs/exceptions.md).
options:
  _input:
    description:
      - The content of the exceptions file, for example from
        C(lookup('ansible.builtin.file', path, rstrip=false)).
    type: str
    required: true
"""

EXAMPLES = r"""
- name: Validate the exceptions file once
  ansible.builtin.set_fact:
    exceptions_overview: >-
      {{ lookup('ansible.builtin.file', '/srv/compliance/exceptions.yml', rstrip=false)
         | freesecdev.linux_compliance.validate_exceptions }}
  run_once: true
"""

RETURN = r"""
_value:
  description:
    - V(schema_version) of the overview, V(source_sha256) (the SHA-256 of the text, as in the
      evaluation document), V(count) and the sorted V(ids) of the exceptions.
    - V(framework_without_profiles) lists, sorted by identifier, the V(id) and V(framework) of
      every exception whose scope has no V(profiles).
    - V(validated_at) is the controller's UTC time used for the date checks.
  type: dict
"""

OVERVIEW_SCHEMA_VERSION = "1.0"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def validate_exceptions(exceptions_text: object) -> dict[str, object]:
    """Validate an exceptions file and describe it.

    Args:
        exceptions_text: The exceptions file content.

    Returns:
        The overview of the validated file.

    Raises:
        ExceptionsError: If the file is not a valid exceptions file.
    """
    now = datetime.now(timezone.utc)
    parsed = exceptions.parse_exceptions(cast("str", exceptions_text), now)
    without_profiles: list[dict[str, object]] = [
        {"framework": record.framework.value, "id": record.exception_id}
        for record in parsed.records
        if not record.scope.profiles
    ]
    return {
        "count": len(parsed.records),
        "framework_without_profiles": without_profiles,
        "ids": [record.exception_id for record in parsed.records],
        "schema_version": OVERVIEW_SCHEMA_VERSION,
        "source_sha256": parsed.source_sha256,
        "validated_at": now.strftime(TIMESTAMP_FORMAT),
    }


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"validate_exceptions": validate_exceptions}
