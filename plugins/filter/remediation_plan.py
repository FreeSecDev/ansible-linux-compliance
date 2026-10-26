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
  - A rule with the strategy C(audit_only) has no native remediation in this collection version.
    It is never dispatched to a family file; when it would be applied it is planned as
    C(not_implemented) and gets a result with the status C(not_implemented), so a run never
    reports it as remediated.
  - Returns the plan as data. It never changes anything and never raises for operator input;
    invalid catalogue entries, unknown toggles, non-boolean toggle values and unknown allow-list
    entries are returned in C(errors), which the role turns into a failed task.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, options
options:
  _input:
    description:
      - The rules with a native remediation, C(__linux_compliance_remediate_rules) of
        C(roles/remediate/vars/rules.yml), a list of mappings.
    type: list
    elements: dict
    required: true
  options:
    description:
      - A mapping with exactly the keys below. A missing or unknown key is an error.
      - C(audit_only) maps each family to the full identifiers of its rules without a native
        remediation, C(__linux_compliance_remediate_audit_only) of the same file. They are
        expanded to catalogue entries with the strategy C(audit_only).
      - C(families) is the family registry in dispatch order, a list of mappings with C(name),
        C(disruptive) and optionally C(umbrella), the umbrella that groups the family (ADR 0011,
        topic split of FREES-53).
      - C(enabled) is the global opt-in C(linux_compliance_remediate_enabled).
      - C(allow_disruptive) lists the disruptive families that may be applied and cleaned up.
        An entry that names an umbrella allows every disruptive family that the umbrella
        groups, so an allow-list written before a family was split keeps its meaning.
      - C(toggles) maps every variable whose name matches C(^linux_compliance_.+_enabled$) to its
        value. C(linux_compliance_remediate_enabled) is ignored; any other name in the namespace
        of a role is an error, every other name must be the toggle of a catalogued rule, of a
        registered family or of an umbrella, and its value must be a boolean. A rule toggle
        copied from its family (C("{{ linux_compliance_<family>_enabled }}")) arrives templated,
        as a boolean.
      - The validation and the toggle resolution are those of
        C(plugins/module_utils/compliance/toggles.py), which the C(audit_disabled_rules) filter
        of the audit role uses too. An umbrella toggle that is false switches off every family
        it groups, whatever their topic toggles say; a rule toggle that is set wins over both.
        A rule that is off names the umbrella toggle as C(disabled_by) when the umbrella toggle is
        off, else the family toggle when the family toggle is off, and its rule toggle otherwise.
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
           'audit_only': audit_only, 'families': registry, 'enabled': true,
           'allow_disruptive': [], 'toggles': {},
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
          C(manual), C(not_implemented), C(skip) or C(none)), C(reason), C(disabled_by),
          C(pending_cleanup) and C(ledger_entry).
      type: list
      elements: dict
    families:
      description:
        - The families that have work, in registry order, each with C(name), C(disruptive),
          C(apply) and C(cleanup) rule lists.
      type: list
      elements: dict
    not_implemented:
      description:
        - One result per rule planned as C(not_implemented), with C(rule_id), C(family),
          C(action) and C(status) C(not_implemented), C(reason) C(audit_only), C(changed) false
          and a C(message). The dispatcher starts its results with them.
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
        - Operator messages for skipped, manual and orphaned rules, one message with the number
          of C(not_implemented) rules, followed by a C(WARNING:)
          message for every topic or umbrella toggle that is false while no catalogued rule of
          the families that it governs is in the profile (in the catalogue when remediation is
          disabled).
      type: list
      elements: str
    summary:
      description: The number of rules per action.
      type: dict
"""

ACTIONS: Final[tuple[str, ...]] = (
    "apply",
    "cleanup",
    "manual",
    "none",
    "not_implemented",
    "skip",
)
NOT_IMPLEMENTED: Final[str] = "not_implemented"
OPTION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "allow_disruptive",
        "audit_only",
        "enabled",
        "families",
        "ledger_entries",
        "profile_rule_ids",
        "toggles",
    }
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
    umbrellas: Mapping[str, str]


def check_allow_list(
    raw: object, families: Mapping[str, bool], umbrellas: Mapping[str, str], errors: Errors
) -> frozenset[str]:
    """Validate the disruptive allow-list and return the disruptive families that it allows.

    An entry is a disruptive family or an umbrella that groups at least one; an umbrella allows
    every disruptive family that it groups (:func:`toggles.governed`).
    """
    items = toggles.as_sequence(raw)
    if items is None:
        errors.add("linux_compliance_remediate_allow_disruptive must be a list")
        return frozenset()
    allowed: set[str] = set()
    for item in items:
        members = toggles.governed(item, families, umbrellas) if isinstance(item, str) else []
        disruptive = [family for family in members if families[family]]
        if not members:
            errors.add(
                f"allow-list entry {toggles.show(item)} is not a registered family or umbrella"
            )
        elif not disruptive:
            errors.add(f"allow-list entry {item} is not a disruptive family")
        else:
            allowed.update(disruptive)
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


def decide_audit_only(*, recorded: bool, wanted: bool, reason: str) -> tuple[str, str]:
    """Return the action and the reason for a rule without a native remediation.

    It is never applied or cleaned up. A ledger entry for it, which only an older collection
    version can have written, is a manual action; a rule that would be applied is
    ``not_implemented``; any other is ``none`` with the usual reason.
    """
    if recorded:
        return "manual", toggles.AUDIT_ONLY
    return (NOT_IMPLEMENTED, toggles.AUDIT_ONLY) if wanted else ("none", reason)


def decide(rule: Rule, toggle: toggles.Toggle, context: Context) -> tuple[str, str]:
    """Return the action and the reason for one rule."""
    rule_id = str(rule["rule_id"])
    if not context.enabled:
        return "skip", "remediation_disabled"
    wanted = toggle.on and rule_id in context.profile
    reason = "not_in_profile" if toggle.on else "disabled_by_toggle"
    if not toggles.is_native(rule):
        return decide_audit_only(recorded=rule_id in context.ledger, wanted=wanted, reason=reason)
    if rule["disruptive"] is True and rule["family"] not in context.allowed:
        return "skip", "disruptive_not_allowed"
    if wanted:
        return "apply", "enabled"
    if rule_id not in context.ledger:
        return "none", reason
    return ("cleanup" if rule["reversible"] is True else "manual"), reason


def plan_rule(rule: Rule, context: Context) -> Rule:
    """Return ``rule`` with its action, reason, controlling variable and ledger entry."""
    toggle = toggles.resolve_toggle(rule, context.toggle_values, umbrellas=context.umbrellas)
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


def not_implemented_result(rule: Rule) -> Rule:
    """Return the result of a rule that has no native remediation but would be applied."""
    return {
        "rule_id": rule["rule_id"],
        "family": rule["family"],
        "action": NOT_IMPLEMENTED,
        "status": NOT_IMPLEMENTED,
        "reason": toggles.AUDIT_ONLY,
        "changed": False,
        "message": (
            f"{rule['rule_id']}: no native remediation in this collection version (audit_only); "
            f"nothing was changed, and the audit still reports its outcome"
        ),
    }


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
    if rule["action"] == "manual" and rule["reason"] == toggles.AUDIT_ONLY:
        return (
            f"{rule_id}: recorded in the state ledger, but this collection version has no native "
            f"remediation for it (audit_only), so it is neither applied nor cleaned up; review it "
            f"manually and remove the ledger entry"
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
    missing = sum(rule["action"] == NOT_IMPLEMENTED for rule in rules)
    if missing:
        messages.append(
            f"{missing} rule(s) of the profile have no native remediation in this collection "
            f"version (audit_only) and were not remediated; they are reported as not_implemented"
        )
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
        "not_implemented": [],
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
    loaded = toggles.load_catalogue(
        catalogue, options["audit_only"], options["families"], options["toggles"], errors
    )
    rules = loaded.rules
    ledger, orphaned = check_ledger(options["ledger_entries"], rules, errors)
    context = Context(
        enabled=switched_on,
        allowed=check_allow_list(
            options["allow_disruptive"], loaded.families, loaded.umbrellas, errors
        ),
        profile=(
            check_profile(options["profile_rule_ids"], errors) if switched_on else frozenset()
        ),
        toggle_values=loaded.toggles,
        ledger=ledger,
        umbrellas=loaded.umbrellas,
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
            "not_implemented": [
                not_implemented_result(rule)
                for rule in planned
                if rule["action"] == NOT_IMPLEMENTED
            ],
            "disabled_rules": toggles.disabled_rules(
                rules,
                context.toggle_values,
                context.profile if context.enabled else None,
                umbrellas=context.umbrellas,
            ),
            "orphaned": orphaned,
            "report": [{key: rule[key] for key in REPORT_KEYS} for rule in planned],
            "notices": notices(planned, orphaned, context)
            + toggles.topic_warnings(
                toggles.Catalogue(
                    rules=rules,
                    families=registry,
                    toggles=dict(context.toggle_values),
                    umbrellas=dict(context.umbrellas),
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
