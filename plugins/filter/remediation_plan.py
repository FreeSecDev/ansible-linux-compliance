"""Filter that resolves the remediation plan of the remediate role (ADR 0011)."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Callable

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
        value. Names in the namespace of a role (for example C(linux_compliance_remediate_enabled))
        are ignored; every other name must be the toggle of a catalogued rule or of a registered
        family, and its value must be a boolean.
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
      description: Operator messages for skipped, manual and orphaned rules.
      type: list
      elements: str
    summary:
      description: The number of rules per action.
      type: dict
"""

RULE_PREFIX: Final[str] = "xccdf_org.ssgproject.content_rule_"
RULE_PATTERN: Final[str] = r"xccdf_org\.ssgproject\.content_rule_[a-z0-9][a-z0-9_]{0,127}"
FAMILY_PATTERN: Final[str] = r"[a-z][a-z0-9_]{0,63}"
TOGGLE_PATTERN: Final[str] = r"linux_compliance_([a-z0-9_]+)_enabled"
RUNBOOK_PATTERN: Final[str] = r"(?:https://|docs/)[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,512}"
ROLE_NAMESPACES: Final[tuple[str, ...]] = ("audit", "discover", "evidence", "remediate", "verify")
ROLE_TOGGLE_VARIABLES: Final[frozenset[str]] = frozenset({"linux_compliance_remediate_enabled"})
DISRUPTIVE_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "auditd",
        "bootloader",
        "crypto_policy",
        "firewall",
        "mounts",
        "network",
        "pam",
        "services",
        "ssh",
        "sudo",
    }
)
RULE_NAMESPACE: Final[str] = "rule"
STRATEGIES: Final[tuple[str, ...]] = (
    "irreversible",
    "owned_dropin",
    "recorded_state",
    "recorded_value",
)
IRREVERSIBLE: Final[str] = "irreversible"
ACTIONS: Final[tuple[str, ...]] = ("apply", "cleanup", "manual", "none", "skip")
RULE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "disruptive",
        "family",
        "parameters",
        "reversible",
        "revert_strategy",
        "rule_id",
        "runbook",
        "toggle",
    }
)
FAMILY_KEYS: Final[frozenset[str]] = frozenset({"disruptive", "name"})
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
MAX_RULES: Final[int] = 4096
MAX_FAMILIES: Final[int] = 64
MAX_ERRORS: Final[int] = 100

Rule = dict[str, object]


class Errors:
    """Collects validation errors, bounded so that hostile input cannot grow them without limit."""

    def __init__(self) -> None:
        """Start without errors."""
        self.items: list[str] = []

    def add(self, message: str) -> None:
        """Record ``message`` unless the bound is reached."""
        if len(self.items) < MAX_ERRORS:
            self.items.append(message)


@dataclass(frozen=True)
class Toggle:
    """The toggle state of a rule and the variable that decided it (``None`` for the default)."""

    on: bool
    source: str | None


@dataclass(frozen=True)
class Context:
    """The validated inputs that the decision for every rule depends on."""

    enabled: bool
    allowed: frozenset[str]
    profile: frozenset[str]
    toggles: Mapping[str, bool]
    ledger: Mapping[str, Rule]


def _show(value: object) -> str:
    return repr(value)[:64]


def _is_text(value: object, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _sequence(value: object) -> list[object] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return list(cast("Sequence[object]", value))
    return None


def _mapping(value: object) -> dict[str, object] | None:
    if isinstance(value, Mapping):
        items = cast("Mapping[object, object]", value)
        return {str(key): items[key] for key in items}
    return None


def _in_namespace(name: str, namespaces: Sequence[str]) -> bool:
    return any(name == namespace or name.startswith(f"{namespace}_") for namespace in namespaces)


def toggle_name(family: str) -> str:
    """Return the name of the topic toggle of ``family``."""
    return f"linux_compliance_{family}_enabled"


def rule_toggle_name(rule_id: str) -> str:
    """Return the name of the toggle of the rule ``rule_id`` (full XCCDF identifier)."""
    return f"linux_compliance_rule_{rule_id[len(RULE_PREFIX) :]}_enabled"


def _family_problem(item: Mapping[str, object], seen: set[str]) -> str | None:
    name = item["name"]
    disruptive = item["disruptive"]
    reserved = _in_namespace(str(name), (*ROLE_NAMESPACES, RULE_NAMESPACE))
    if not _is_text(name, FAMILY_PATTERN) or reserved:
        return f"invalid or reserved family name {_show(name)}"
    if name in seen:
        return f"family {name} is listed twice"
    if not isinstance(disruptive, bool):
        return "disruptive must be a boolean"
    if name in DISRUPTIVE_FAMILIES and not disruptive:
        return f"family {name} is always disruptive and cannot be marked otherwise"
    return None


def _check_family(index: int, raw: object, seen: set[str], errors: Errors) -> tuple[str, bool]:
    where = f"family #{index}"
    item = _mapping(raw)
    if item is None:
        errors.add(f"{where}: must be a mapping")
        return "", False
    if frozenset(item) != FAMILY_KEYS:
        errors.add(f"{where}: keys must be exactly {sorted(FAMILY_KEYS)}, got {sorted(item)[:10]}")
        return "", False
    problem = _family_problem(item, seen)
    if problem is not None:
        errors.add(f"{where}: {problem}")
        return "", False
    seen.add(str(item["name"]))
    return str(item["name"]), item["disruptive"] is True


def check_families(raw: object, errors: Errors) -> dict[str, bool]:
    """Validate the family registry and return the disruptive flag per family, in order."""
    items = _sequence(raw)
    if items is None or not 0 < len(items) <= MAX_FAMILIES:
        errors.add(f"the family registry must be a list of 1 to {MAX_FAMILIES} families")
        return {}
    seen: set[str] = set()
    families: dict[str, bool] = {}
    for index, item in enumerate(items):
        name, disruptive = _check_family(index, item, seen, errors)
        if name:
            families[name] = disruptive
    return families


def _rule_problems(rule: Rule, families: Mapping[str, bool]) -> list[str]:
    rule_id = str(rule["rule_id"])
    family = rule["family"]
    strategy = rule["revert_strategy"]
    runbook = rule["runbook"]
    problems: list[str] = []
    if not isinstance(family, str) or family not in families:
        problems.append(f"unknown family {_show(family)}")
    elif rule["disruptive"] is not families[family]:
        problems.append("disruptive must equal the disruptive flag of its family")
    if strategy not in STRATEGIES:
        problems.append(f"unknown revert_strategy {_show(strategy)}")
    elif rule["reversible"] is not (strategy != IRREVERSIBLE):
        problems.append("reversible must be false exactly for the irreversible strategy")
    if rule["toggle"] != rule_toggle_name(rule_id):
        problems.append(f"toggle must be {rule_toggle_name(rule_id)}")
    if strategy == IRREVERSIBLE and not _is_text(runbook, RUNBOOK_PATTERN):
        problems.append("an irreversible rule needs a runbook link (https:// or docs/)")
    if strategy != IRREVERSIBLE and runbook is not None:
        problems.append("only an irreversible rule has a runbook")
    if _mapping(rule["parameters"]) is None:
        problems.append("parameters must be a mapping")
    return problems


def _check_rule(
    index: int, raw: object, families: Mapping[str, bool], seen: set[str], errors: Errors
) -> Rule | None:
    where = f"rule #{index}"
    rule = _mapping(raw)
    if rule is None:
        errors.add(f"{where}: must be a mapping")
        return None
    if frozenset(rule) != RULE_KEYS:
        errors.add(f"{where}: keys must be exactly {sorted(RULE_KEYS)}, got {sorted(rule)[:10]}")
        return None
    rule_id = rule["rule_id"]
    if not _is_text(rule_id, RULE_PATTERN):
        errors.add(f"{where}: invalid rule_id {_show(rule_id)}")
        return None
    if rule_id in seen:
        errors.add(f"{where}: rule {rule_id} is listed twice")
        return None
    seen.add(str(rule_id))
    problems = _rule_problems(rule, families)
    for problem in problems:
        errors.add(f"{rule_id}: {problem}")
    return None if problems else rule


def check_catalogue(raw: object, families: Mapping[str, bool], errors: Errors) -> list[Rule]:
    """Validate the rule catalogue and return its rules sorted by rule identifier."""
    items = _sequence(raw)
    if items is None or len(items) > MAX_RULES:
        errors.add(f"the rule catalogue must be a list of at most {MAX_RULES} rules")
        return []
    seen: set[str] = set()
    checked = [_check_rule(index, item, families, seen, errors) for index, item in enumerate(items)]
    rules = [rule for rule in checked if rule is not None]
    return sorted(rules, key=lambda rule: str(rule["rule_id"]))


def check_toggles(
    raw: object, rule_toggles: frozenset[str], families: Mapping[str, bool], errors: Errors
) -> dict[str, bool]:
    """Validate the toggle variables and return the boolean value of each known toggle."""
    toggles = _mapping(raw)
    if toggles is None:
        errors.add("toggles must be a mapping of variable names to values")
        return {}
    values: dict[str, bool] = {}
    for name in sorted(toggles):
        match = re.fullmatch(TOGGLE_PATTERN, name)
        topic = match.group(1) if match is not None else ""
        if topic.startswith(f"{RULE_NAMESPACE}_"):
            known = name in rule_toggles
            kind = "rule"
        elif name in ROLE_TOGGLE_VARIABLES:
            continue
        elif match is not None and _in_namespace(topic, ROLE_NAMESPACES):
            errors.add(
                f"{_show(name)} is in the namespace of a role of the collection but is not a "
                f"variable of that role; topic toggles of a family are "
                f"linux_compliance_<family>_enabled"
            )
            continue
        else:
            known = topic in families
            kind = "family"
        value = toggles[name]
        if not known:
            errors.add(f"{_show(name)} is not the toggle of a catalogued {kind}")
        elif not isinstance(value, bool):
            errors.add(
                f"{name} must be a boolean; pass it as JSON, for example -e '{{\"{name}\": false}}'"
            )
        else:
            values[name] = value
    return values


def check_allow_list(raw: object, families: Mapping[str, bool], errors: Errors) -> frozenset[str]:
    """Validate the disruptive allow-list and return it as a set."""
    items = _sequence(raw)
    if items is None:
        errors.add("linux_compliance_remediate_allow_disruptive must be a list")
        return frozenset()
    allowed: set[str] = set()
    for item in items:
        if not isinstance(item, str) or item not in families:
            errors.add(f"allow-list entry {_show(item)} is not a registered family")
        elif not families[item]:
            errors.add(f"allow-list entry {item} is not a disruptive family")
        else:
            allowed.add(item)
    return frozenset(allowed)


def check_ledger(
    raw: object, rules: Sequence[Rule], errors: Errors
) -> tuple[dict[str, Rule], list[str]]:
    """Index the ledger entries by rule identifier and list those the catalogue lacks."""
    items = _sequence(raw)
    if items is None:
        errors.add("ledger_entries must be a list")
        return {}, []
    families = {str(rule["rule_id"]): rule["family"] for rule in rules}
    entries: dict[str, Rule] = {}
    orphaned: list[str] = []
    for raw_entry in items:
        entry = _mapping(raw_entry)
        rule_id = None if entry is None else entry.get("rule_id")
        if entry is None or not isinstance(rule_id, str):
            errors.add("every ledger entry must be a mapping with a rule_id")
        elif rule_id not in families:
            orphaned.append(rule_id)
        elif entry.get("family") != families[rule_id]:
            errors.add(f"{rule_id}: the ledger records family {_show(entry.get('family'))}")
        else:
            entries[rule_id] = entry
    return entries, sorted(orphaned)


def check_profile(raw: object, *, enabled: bool, errors: Errors) -> frozenset[str]:
    """Validate the rules of the selected profile, which are needed only when enabled."""
    if not enabled:
        return frozenset()
    items = _sequence(raw)
    if items is None or not all(isinstance(item, str) for item in items):
        errors.add("profile_rule_ids must list the rule identifiers of the discovered profile")
        return frozenset()
    return frozenset(str(item) for item in items)


def resolve_toggle(rule: Rule, toggles: Mapping[str, bool]) -> Toggle:
    """Return the toggle state of ``rule``: its rule toggle, else its family toggle, else on."""
    for name in (str(rule["toggle"]), toggle_name(str(rule["family"]))):
        if name in toggles:
            return Toggle(toggles[name], name)
    return Toggle(on=True, source=None)


def decide(rule: Rule, toggle: Toggle, context: Context) -> tuple[str, str]:
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
    toggle = resolve_toggle(rule, context.toggles)
    action, reason = decide(rule, toggle, context)
    rule_id = str(rule["rule_id"])
    entry = context.ledger.get(rule_id)
    would_apply = toggle.on and (rule_id in context.profile or not context.enabled)
    planned = dict(rule)
    planned.update(
        {
            "action": action,
            "reason": reason,
            "disabled_by": None if toggle.on else toggle.source,
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


def notices(rules: Sequence[Rule], orphaned: Sequence[str], *, enabled: bool) -> list[str]:
    """Return the operator messages for skipped, manual and orphaned rules."""
    messages: list[str] = []
    if not enabled:
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


def _plan(errors: list[str], *, enabled: bool) -> dict[str, object]:
    return {
        "errors": errors,
        "enabled": enabled,
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
    registry = check_families(options["families"], errors)
    rules = check_catalogue(catalogue, registry, errors)
    rule_toggles = frozenset(str(rule["toggle"]) for rule in rules)
    ledger, orphaned = check_ledger(options["ledger_entries"], rules, errors)
    context = Context(
        enabled=switched_on,
        allowed=check_allow_list(options["allow_disruptive"], registry, errors),
        profile=check_profile(options["profile_rule_ids"], enabled=switched_on, errors=errors),
        toggles=check_toggles(options["toggles"], rule_toggles, registry, errors),
        ledger=ledger,
    )
    return rules, registry, context, orphaned


def remediation_plan(catalogue: object, options: object) -> dict[str, object]:
    """Resolve the remediation plan; see the DOCUMENTATION block for the contract."""
    errors = Errors()
    given = _mapping(options)
    if given is None or frozenset(given) != OPTION_KEYS:
        keys = [] if given is None else sorted(given)[:10]
        errors.add(f"options must be a mapping with exactly {sorted(OPTION_KEYS)}, got {keys}")
        return _plan(errors.items, enabled=False)
    rules, registry, context, orphaned = _context(catalogue, given, errors)
    if errors.items:
        return _plan(errors.items, enabled=context.enabled)
    planned = [plan_rule(rule, context) for rule in rules]
    plan = _plan([], enabled=context.enabled)
    plan.update(
        {
            "rules": planned,
            "families": family_plans(planned, registry),
            "disabled_rules": [
                {"rule_id": rule["rule_id"], "disabled_by": rule["disabled_by"]}
                for rule in planned
                if rule["disabled_by"] is not None
                and (not context.enabled or rule["rule_id"] in context.profile)
            ],
            "orphaned": orphaned,
            "report": [{key: rule[key] for key in REPORT_KEYS} for rule in planned],
            "notices": notices(planned, orphaned, enabled=context.enabled),
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
