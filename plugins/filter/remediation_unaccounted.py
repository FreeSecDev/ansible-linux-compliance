"""Filter that finds planned remediation work without exactly one result (ADR 0011)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: remediation_unaccounted
short_description: List planned remediation work that has no result, or more than one
version_added: "0.1.0"
description:
  - Compares the results that the family task files of the remediate role reported with the plan
    of the filter M(freesecdev.linux_compliance.remediation_plan).
  - Every rule whose planned action is C(apply) or C(cleanup) must have exactly one result with the
    same rule identifier and action, and there must be no other result. Anything else means that a
    family task was skipped, for example by C(--skip-tags), or ran twice, and the role fails instead
    of reporting work that did not happen.
  - Returns one message per problem; an empty list means that every planned rule is accounted for.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, plan
options:
  _input:
    description: The results of the family task files, mappings with C(rule_id) and C(action).
    type: list
    elements: dict
    required: true
  plan:
    description: The plan returned by the C(remediation_plan) filter.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Fail when a planned rule has no result
  ansible.builtin.assert:
    that:
      - results | freesecdev.linux_compliance.remediation_unaccounted(plan) | length == 0
"""

RETURN = r"""
_value:
  description: One message per planned rule without exactly one result and per unexpected result.
  type: list
  elements: str
"""

ACCOUNTED_ACTIONS: Final[tuple[str, ...]] = ("apply", "cleanup")
MAX_MESSAGES: Final[int] = 100

Key = tuple[str, str]


def _keys(items: object, what: str) -> list[Key] | None:
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        return None
    keys: list[Key] = []
    for raw in cast("Sequence[object]", items):
        if not isinstance(raw, Mapping):
            return None
        item = cast("Mapping[str, object]", raw)
        rule_id = item.get("rule_id")
        action = item.get(what)
        if not isinstance(rule_id, str) or not isinstance(action, str):
            return None
        keys.append((rule_id, action))
    return keys


def remediation_unaccounted(results: object, plan: object) -> list[str]:
    """Return a message for every planned rule without exactly one result and every extra result."""
    rules = cast("Mapping[str, object]", plan).get("rules") if isinstance(plan, Mapping) else None
    planned = _keys(rules, "action")
    reported = _keys(results, "action")
    if planned is None:
        return ["the plan must hold a list of rules with rule_id and action"]
    if reported is None:
        return ["the results must be a list of mappings with rule_id and action"]
    expected = {key for key in planned if key[1] in ACCOUNTED_ACTIONS}
    counts: dict[Key, int] = {}
    for key in reported:
        counts[key] = counts.get(key, 0) + 1
    messages = [
        f"{rule_id}: planned {action} but no family task reported a result; was a task skipped?"
        for rule_id, action in sorted(expected - set(counts))
    ]
    messages.extend(
        f"{rule_id}: {count} results for {action}, expected exactly one"
        for (rule_id, action), count in sorted(counts.items())
        if count > 1 and (rule_id, action) in expected
    )
    messages.extend(
        f"{rule_id}: a result for {action} that the plan does not contain"
        for rule_id, action in sorted(set(counts) - expected)
    )
    return messages[:MAX_MESSAGES]


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object, object], list[str]]]:
        """Return the filters of this plugin."""
        return {"remediation_unaccounted": remediation_unaccounted}
