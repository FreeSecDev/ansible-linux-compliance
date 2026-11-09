"""Filter that composes the results of an audit rule topic of the remediate role (FREES-110)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: audit_rule_results
short_description: Compose the results of an audit rule topic, with the effect of a changed rule set
version_added: "0.1.0"
description:
  - Builds one result per cleanup and per rule to apply of an audit rule topic from the plans of
    the role (ADR 0030).
  - A result whose drop-in was written or removed carries the effect on the loaded rules as its
    machine-readable C(reason) when that effect is not a verified load. C(locked_until_reboot)
    when the loaded rules are locked (C(-e 2)), so the files take effect at the next boot only;
    C(takes_effect_at_start) when auditd does not run, so the rules are loaded when it starts. A
    verified load (every line listed by C(auditctl -l)) has no such reason.
author:
  - FreeSecDev contributors (@FreeSecDev)
positional: _input, plan, cleanup_plan, changed_ids, outcome
options:
  _input:
    description: The family of the plan, with its C(apply) and C(cleanup) rules.
    type: dict
    required: true
  plan:
    description: The apply plan of the topic, by rule identifier (C(status), C(reason)).
    type: dict
    required: true
  cleanup_plan:
    description: The cleanup plan of the topic, by rule identifier (C(reason), C(present)).
    type: dict
    required: true
  changed_ids:
    description: The rule identifiers whose drop-in or ledger entry this run changed.
    type: list
    elements: str
    required: true
  outcome:
    description:
      - C(changed) (the rule files changed outside check mode), C(loaded) (the load ran and was
        verified) and C(locked) (the loaded rules are locked).
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Compose the results
  ansible.builtin.set_fact:
    results: >-
      {{ family | freesecdev.linux_compliance.audit_rule_results(plan, cleanup_plan, changed,
         {'changed': true, 'loaded': false, 'locked': true}) }}
"""

RETURN = r"""
_value:
  description: One result per rule, with C(rule_id), C(family), C(action), C(status), C(reason),
    C(changed) and C(message).
  type: list
  elements: dict
"""

LOCKED: Final[str] = "locked_until_reboot"
NOT_RUNNING: Final[str] = "takes_effect_at_start"
EFFECTS: Final[dict[str, str]] = {
    "loaded": "the rule set was checked and loaded",
    LOCKED: "the loaded rules are locked (-e 2), so the rule files take effect at the next boot",
    NOT_RUNNING: "auditd does not run here, so the rules are loaded when it starts",
}


def _mapping(value: object, what: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        message = f"audit_rule_results needs {what} as a mapping"
        raise TypeError(message)
    return cast("Mapping[str, object]", value)


def _rules(family: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    rules = family.get(key, [])
    if not isinstance(rules, Sequence) or isinstance(rules, str):
        message = f"audit_rule_results needs the {key} rules of the family as a list"
        raise TypeError(message)
    return [_mapping(rule, f"each {key} rule") for rule in cast("Sequence[object]", rules)]


def effect(outcome: Mapping[str, object]) -> str | None:
    """Return the effect of a changed rule set: ``loaded``, a reason, or ``None`` when unchanged."""
    if not outcome.get("changed"):
        return None
    if outcome.get("loaded"):
        return "loaded"
    return LOCKED if outcome.get("locked") else NOT_RUNNING


def _path(rule: Mapping[str, object]) -> str:
    return str(_mapping(rule.get("parameters", {}), "the parameters of a rule").get("path", ""))


def _cleanup_result(
    rule: Mapping[str, object],
    planned: Mapping[str, object],
    changed: frozenset[str],
    found: str | None,
) -> dict[str, object]:
    reason = planned.get("reason")
    present = bool(planned.get("present"))
    if reason is None:
        removed = (
            "restored (the drop-in was removed"
            if present
            else "restored (the drop-in no longer existed, which is the recorded prior state,"
            " so only the ledger entry was removed"
        )
        text = f"{removed}{'; ' + EFFECTS[found] if found and present else ''})"
    else:
        text = (
            f"cleanup_incomplete ({reason}; nothing was changed, the ledger entry is kept and"
            " the cleanup is retried on the next run)"
        )
    effect_reason = None if found in (None, "loaded") else found
    return {
        "rule_id": str(rule["rule_id"]),
        "family": rule.get("family"),
        "action": "cleanup",
        "status": "restored" if reason is None else "cleanup_incomplete",
        "reason": reason if reason is not None else (effect_reason if present else None),
        "changed": str(rule["rule_id"]) in changed,
        "message": f"{_path(rule)}: {text}",
    }


def _apply_result(
    rule: Mapping[str, object],
    planned: Mapping[str, object],
    changed: frozenset[str],
    found: str | None,
) -> dict[str, object]:
    status = str(planned.get("status"))
    reason = planned.get("reason")
    if reason:
        text = f"{status} ({reason}; nothing was changed)"
    elif status == "applied" and found:
        text = f"{status} ({EFFECTS[found]})"
    else:
        text = status
    effect_reason = None if found in (None, "loaded") else found
    return {
        "rule_id": str(rule["rule_id"]),
        "family": rule.get("family"),
        "action": "apply",
        "status": status,
        "reason": reason or (effect_reason if status == "applied" else None),
        "changed": str(rule["rule_id"]) in changed,
        "message": f"{_path(rule)}: {text}",
    }


def audit_rule_results(
    family: object, plan: object, cleanup_plan: object, changed_ids: object, outcome: object
) -> list[dict[str, object]]:
    """Return the results of the topic, cleanup first, in the order of the plan."""
    rules = _mapping(family, "the family")
    applies = _mapping(plan, "the apply plan")
    cleanups = _mapping(cleanup_plan, "the cleanup plan")
    if not isinstance(changed_ids, Sequence) or isinstance(changed_ids, str):
        message = "audit_rule_results needs the changed rule identifiers as a list"
        raise TypeError(message)
    changed = frozenset(str(item) for item in cast("Sequence[object]", changed_ids))
    found = effect(_mapping(outcome, "the outcome"))
    results = [
        _cleanup_result(
            rule,
            _mapping(cleanups[str(rule["rule_id"])], "a cleanup plan entry"),
            changed,
            found,
        )
        for rule in _rules(rules, "cleanup")
    ]
    results.extend(
        _apply_result(
            rule,
            _mapping(applies[str(rule["rule_id"])], "an apply plan entry"),
            changed,
            found,
        )
        for rule in _rules(rules, "apply")
    )
    return results


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., list[dict[str, object]]]]:
        """Return the filters of this plugin."""
        return {"audit_rule_results": audit_rule_results}
