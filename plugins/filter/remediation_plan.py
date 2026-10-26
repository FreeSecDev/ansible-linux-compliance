"""Filter that resolves the remediation plan of the remediate role (ADR 0011)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

DOCUMENTATION = r"""
---
name: remediation_plan
short_description: Resolve which catalogued rules the remediate role applies, cleans up or skips
version_added: "0.1.0"
description:
  - Validates the rule catalogue and the family registry of the remediate role and resolves, for
    every catalogued rule, its effective state from the rule toggle, the family toggle, the global
    opt-in, the disruptive allow-list, the selected profile and the state ledger (ADR 0011).
  - Returns the plan as data. It never changes anything and never raises for operator input;
    invalid catalogue entries, unknown toggles, non-boolean toggle values and unknown allow-list
    entries are returned in C(errors), which the role turns into a failed task.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, options
options:
  _input:
    description: The rule catalogue, a list of mappings as in C(roles/remediate/vars/rules.yml).
    type: list
    elements: dict
    required: true
  options:
    description:
      - A mapping with exactly the keys below. A missing or unknown key is an error.
      - C(families) is the family registry in dispatch order, a list of mappings with C(name)
        and C(disruptive).
      - C(enabled) is the global opt-in C(linux_compliance_remediate_enabled).
      - C(allow_disruptive) lists the disruptive families that may be applied and cleaned up.
      - C(toggles) maps every variable whose name matches C(^linux_compliance_.+_enabled$) to its
        value. C(linux_compliance_remediate_enabled) is ignored; any other name in the namespace
        of a role is an error, every other name must be the toggle of a catalogued rule or of a
        registered family, and its value must be a boolean. The generated rule toggle defaults
        (C("{{ linux_compliance_<family>_enabled }}")) arrive templated, as booleans.
      - The validation and the toggle resolution are those of
        C(plugins/module_utils/compliance/toggles.py), which the C(audit_disabled_rules) filter
        of the audit role uses too. A rule that is off names the family toggle as C(disabled_by)
        when the family toggle is off, and its rule toggle otherwise.
      - C(profile_rule_ids) lists the full rule identifiers that the discovered profile selects.
        It is required when C(enabled) is true and ignored otherwise (pass C(none)).
      - C(ledger_entries) lists the entries of the state ledger, as the control_state module
        returns them.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Resolve the remediation plan
  ansible.builtin.set_fact:
    plan: >-
      {{ catalogue | freesecdev.linux_compliance.remediation_plan({
           'families': registry, 'enabled': true, 'allow_disruptive': [], 'toggles': {},
           'profile_rule_ids': discovered_rule_ids, 'ledger_entries': []}) }}
"""

RETURN = r"""
_value:
  description: The plan.
  type: dict
  contains:
    errors:
      description: Validation errors. The plan is empty unless this list is empty.
      type: list
      elements: str
    enabled:
      description: The global opt-in.
      type: bool
    rules:
      description:
        - Every catalogued rule sorted by rule identifier, with C(action) (C(apply), C(cleanup),
          C(manual), C(skip) or C(none)), C(reason), C(disabled_by), C(pending_cleanup) and
          C(ledger_entry).
      type: list
      elements: dict
    families:
      description:
        - The families that have work, in registry order, each with C(name), C(disruptive),
          C(apply) and C(cleanup) rule lists.
      type: list
      elements: dict
    disabled_rules:
      description:
        - Rules switched off by a toggle, with C(rule_id) and C(disabled_by), for the audit role.
      type: list
      elements: dict
    orphaned:
      description: Ledger rule identifiers that the catalogue does not contain.
      type: list
      elements: str
    report:
      description:
        - Every rule with only C(rule_id), C(family), C(action), C(reason), C(disabled_by),
          C(pending_cleanup) and C(runbook), for reports.
      type: list
      elements: dict
    notices:
      description:
        - Operator messages for skipped, manual and orphaned rules, followed by a C(WARNING:)
          message for every topic toggle that is false while no catalogued rule of its family is
          in the profile (in the catalogue when remediation is disabled).
      type: list
      elements: str
    summary:
      description: The number of rules per action.
      type: dict
"""

ACTIONS: Final[tuple[str, ...]] = ("apply", "cleanup", "manual", "none", "skip")
OPTION_KEYS: Final[frozenset[str]] = frozenset(
    {"allow_disruptive", "enabled", "families", "ledger_entries", "profile_rule_ids", "toggles"}
)
REPORT_KEYS: Final[tuple[str, ...]] = (
    "rule_id",
    "family",
    "action",
    "reason",
    "disabled_by",
    "pending_cleanup",
    "runbook",
)

Rule = toggles.Rule
Errors = toggles.Errors


@dataclass(frozen=True)
class Context:
    """The validated inputs that the decision for every rule depends on."""

    enabled: bool
    allowed: frozenset[str]
    profile: frozenset[str]
    toggle_values: Mapping[str, bool]
    ledger: Mapping[str, Rule]


def check_allow_list(raw: object, families: Mapping[str, bool], errors: Errors) -> frozenset[str]:
    """Validate the disruptive allow-list and return it as a set."""
    items = toggles.as_sequence(raw)
    if items is None:
        errors.add("linux_compliance_remediate_allow_disruptive must be a list")
        return frozenset()
    allowed: set[str] = set()
    for item in items:
        if not isinstance(item, str) or item not in families:
            errors.add(f"allow-list entry {toggles.show(item)} is not a registered family")
        elif not families[item]:
            errors.add(f"allow-list entry {item} is not a disruptive family")
        else:
            allowed.add(item)
    return frozenset(allowed)


def check_ledger(
    raw: object, rules: Sequence[Rule], errors: Errors
) -> tuple[dict[str, Rule], list[str]]:
    """Index the ledger entries by rule identifier and list those the catalogue lacks."""
    items = toggles.as_sequence(raw)
    if items is None:
        errors.add("ledger_entries must be a list")
        return {}, []
    families = {str(rule["rule_id"]): rule["family"] for rule in rules}
    entries: dict[str, Rule] = {}
    orphaned: list[str] = []
    for raw_entry in items:
        entry = toggles.as_mapping(raw_entry)
        rule_id = None if entry is None else entry.get("rule_id")
        if entry is None or not isinstance(rule_id, str):
            errors.add("every ledger entry must be a mapping with a rule_id")
        elif rule_id not in families:
            orphaned.append(rule_id)
        elif entry.get("family") != families[rule_id]:
            errors.add(f"{rule_id}: the ledger records family {toggles.show(entry.get('family'))}")
        else:
            entries[rule_id] = entry
    return entries, sorted(orphaned)


def check_profile(raw: object, errors: Errors) -> frozenset[str]:
    """Validate the rules of the selected profile; the caller checks them only when enabled."""
    items = toggles.as_sequence(raw)
    if items is None or not all(isinstance(item, str) for item in items):
        errors.add("profile_rule_ids must list the rule identifiers of the discovered profile")
        return frozenset()
    return frozenset(str(item) for item in items)


def decide(rule: Rule, toggle: toggles.Toggle, context: Context) -> tuple[str, str]:
    """Return the action and the reason for one rule."""
    rule_id = str(rule["rule_id"])
    if not context.enabled:
        return "skip", "remediation_disabled"
    if rule["disruptive"] is True and rule["family"] not in context.allowed:
        return "skip", "disruptive_not_allowed"
    if toggle.on and rule_id in context.profile:
        return "apply", "enabled"
    reason = "not_in_profile" if toggle.on else "disabled_by_toggle"
    if rule_id not in context.ledger:
        return "none", reason
    if rule["reversible"] is not True:
        return "manual", reason
    return "cleanup", reason


def plan_rule(rule: Rule, context: Context) -> Rule:
    """Return ``rule`` with its action, reason, controlling variable and ledger entry."""
    toggle = toggles.resolve_toggle(rule, context.toggle_values)
    action, reason = decide(rule, toggle, context)
    rule_id = str(rule["rule_id"])
    entry = context.ledger.get(rule_id)
    would_apply = toggle.on and (rule_id in context.profile or not context.enabled)
    planned = dict(rule)
    planned.update(
        {
            "action": action,
            "reason": reason,
            "disabled_by": toggle.disabled_by,
            "pending_cleanup": action == "skip" and entry is not None and not would_apply,
            "ledger_entry": entry,
        }
    )
    return planned


def family_plans(rules: Sequence[Rule], families: Mapping[str, bool]) -> list[Rule]:
    """Return the families that have work, in registry order, with their rules."""
    plans: list[Rule] = []
    for name, disruptive in families.items():
        members = [rule for rule in rules if rule["family"] == name]
        apply = [rule for rule in members if rule["action"] == "apply"]
        cleanup = [rule for rule in members if rule["action"] == "cleanup"]
        if apply or cleanup:
            plans.append(
                {"name": name, "disruptive": disruptive, "apply": apply, "cleanup": cleanup}
            )
    return plans


def _notice(rule: Rule) -> str | None:
    rule_id = rule["rule_id"]
    if rule["reason"] == "disruptive_not_allowed":
        pending = (
            "; it is recorded as applied and its cleanup waits for the allow-list"
            if rule["pending_cleanup"]
            else ""
        )
        return (
            f"{rule_id}: skipped, family {rule['family']} is disruptive and not named in "
            f"linux_compliance_remediate_allow_disruptive{pending}"
        )
    if rule["action"] == "manual":
        return (
            f"{rule_id}: no longer effective ({rule['reason']}) but irreversible; it is not "
            f"reverted automatically, follow {rule['runbook']}"
        )
    return None


def notices(rules: Sequence[Rule], orphaned: Sequence[str], context: Context) -> list[str]:
    """Return the operator messages for skipped, manual and orphaned rules."""
    messages: list[str] = []
    if not context.enabled:
        messages.append(
            f"remediation is disabled (linux_compliance_remediate_enabled is false): "
            f"{len(rules)} rule(s) skipped, the host was neither read nor changed"
        )
    messages.extend(message for message in map(_notice, rules) if message is not None)
    messages.extend(
        f"{rule_id}: recorded in the state ledger but not in the rule catalogue of this "
        f"collection version; nothing was changed, review it manually"
        for rule_id in orphaned
    )
    return messages


def _plan(errors: list[str]) -> dict[str, object]:
    return {
        "errors": errors,
        "enabled": False,
        "rules": [],
        "families": [],
        "disabled_rules": [],
        "orphaned": [],
        "report": [],
        "notices": [],
        "summary": dict.fromkeys(ACTIONS, 0),
    }


def _context(
    catalogue: object, options: Mapping[str, object], errors: Errors
) -> tuple[list[Rule], dict[str, bool], Context, list[str]]:
    enabled = options["enabled"]
    if not isinstance(enabled, bool):
        errors.add("linux_compliance_remediate_enabled must be a boolean")
    switched_on = enabled is True
    loaded = toggles.load_catalogue(catalogue, options["families"], options["toggles"], errors)
    rules = loaded.rules
    ledger, orphaned = check_ledger(options["ledger_entries"], rules, errors)
    context = Context(
        enabled=switched_on,
        allowed=check_allow_list(options["allow_disruptive"], loaded.families, errors),
        profile=(
            check_profile(options["profile_rule_ids"], errors) if switched_on else frozenset()
        ),
        toggle_values=loaded.toggles,
        ledger=ledger,
    )
    return rules, loaded.families, context, orphaned


def remediation_plan(catalogue: object, options: object) -> dict[str, object]:
    """Resolve the remediation plan; see the DOCUMENTATION block for the contract."""
    errors = Errors()
    given = toggles.as_mapping(options)
    if given is None or frozenset(given) != OPTION_KEYS:
        keys = [] if given is None else sorted(given)[:10]
        errors.add(f"options must be a mapping with exactly {sorted(OPTION_KEYS)}, got {keys}")
        return _plan(errors.items)
    rules, registry, context, orphaned = _context(catalogue, given, errors)
    if errors.items:
        failed = _plan(errors.items)
        failed["enabled"] = context.enabled
        return failed
    planned = [plan_rule(rule, context) for rule in rules]
    plan = _plan([])
    plan.update(
        {
            "enabled": context.enabled,
            "rules": planned,
            "families": family_plans(planned, registry),
            "disabled_rules": toggles.disabled_rules(
                rules, context.toggle_values, context.profile if context.enabled else None
            ),
            "orphaned": orphaned,
            "report": [{key: rule[key] for key in REPORT_KEYS} for rule in planned],
            "notices": notices(planned, orphaned, context)
            + toggles.topic_warnings(
                toggles.Catalogue(
                    rules=rules, families=registry, toggles=dict(context.toggle_values)
                ),
                context.profile if context.enabled else None,
            ),
            "summary": {
                action: sum(rule["action"] == action for rule in planned) for action in ACTIONS
            },
        }
    )
    return plan


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object, object], dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"remediation_plan": remediation_plan}
