"""Rule catalogue, family registry and toggle resolution shared by the roles (ADR 0011).

The remediate role's catalogue (``roles/remediate/vars/rules.yml``) lists every rule that a
supported profile of the pinned content selects, with its control family; the family registry lists
every family. It is generated from the digest-verified datastreams
(``tools/roles/generate_catalogue.py``, FREES-53). A rule with a native remediation has a revert
strategy; every other rule has the strategy ``audit_only``: it can be toggled and is excluded from
the audit when it is off, but remediation never changes anything for it. Each family has a topic
toggle ``linux_compliance_<family>_enabled`` and each rule a rule toggle
``linux_compliance_rule_<rule_short_id>_enabled``, where the short identifier is written in lower
case with every character other than a letter, a digit or ``_`` replaced by ``_``. The role
defaults of both are generated from the catalogue (``tools/roles/generate_toggles.py``): a family
toggle defaults to ``true`` and a rule toggle to the value of its family toggle.

This module is the single source of truth for the toggle names, the validation of the catalogue,
the registry and the toggle variables, and the resolution of the toggle state of a rule. The
``remediation_plan`` filter of the remediate role and the ``audit_disabled_rules`` filter of the
audit role both use it, so a rule switched off once is skipped and cleaned up by remediation and
reported as ``disabled`` by the audit, with the same controlling variable. It uses only the
standard library and never raises for operator input: problems are collected in :class:`Errors`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

RULE_PREFIX: Final[str] = "xccdf_org.ssgproject.content_rule_"
RULE_PATTERN: Final[str] = r"xccdf_org\.ssgproject\.content_rule_[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}"
FAMILY_PATTERN: Final[str] = r"[a-z][a-z0-9_]{0,63}"
TOGGLE_PATTERN: Final[str] = r"linux_compliance_([a-z0-9_]+)_enabled"
TOGGLE_VARIABLE_PATTERN: Final[str] = "^linux_compliance_.+_enabled$"
RUNBOOK_PATTERN: Final[str] = r"(?:https://|docs/)[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,512}"
ROLE_NAMESPACES: Final[tuple[str, ...]] = ("audit", "discover", "evidence", "remediate", "verify")
ROLE_TOGGLE_VARIABLES: Final[frozenset[str]] = frozenset({"linux_compliance_remediate_enabled"})
DISRUPTIVE_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "accounts",
        "auditd",
        "bootloader",
        "crypto_policy",
        "desktop",
        "firewall",
        "kernel_modules",
        "mandatory_access_control",
        "mounts",
        "network",
        "packages",
        "pam",
        "services",
        "ssh",
        "sudo",
    }
)
RULE_NAMESPACE: Final[str] = "rule"
AUDIT_ONLY: Final[str] = "audit_only"
STRATEGIES: Final[tuple[str, ...]] = (
    AUDIT_ONLY,
    "irreversible",
    "owned_dropin",
    "recorded_state",
    "recorded_value",
)
IRREVERSIBLE: Final[str] = "irreversible"
TOGGLE_UNSAFE: Final[str] = r"[^a-z0-9_]"
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
    """The toggle state of a rule and the variable that switched it off (``None`` when on)."""

    on: bool
    disabled_by: str | None


@dataclass(frozen=True)
class Catalogue:
    """The validated catalogue: rules sorted by identifier, the registry and the toggle values."""

    rules: list[Rule]
    families: dict[str, bool]
    toggles: dict[str, bool]


def show(value: object) -> str:
    """Return a short representation of ``value`` for an error message."""
    return repr(value)[:64]


def is_text(value: object, pattern: str) -> bool:
    """Return whether ``value`` is a string that matches ``pattern`` completely."""
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def as_sequence(value: object) -> list[object] | None:
    """Return ``value`` as a list when it is a sequence other than a string, else ``None``."""
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return list(cast("Sequence[object]", value))
    return None


def as_mapping(value: object) -> dict[str, object] | None:
    """Return ``value`` as a dictionary with string keys when it is a mapping, else ``None``."""
    if isinstance(value, Mapping):
        items = cast("Mapping[object, object]", value)
        return {str(key): items[key] for key in items}
    return None


def in_namespace(name: str, namespaces: Sequence[str]) -> bool:
    """Return whether ``name`` equals one of ``namespaces`` or starts with one followed by ``_``."""
    return any(name == namespace or name.startswith(f"{namespace}_") for namespace in namespaces)


def toggle_name(family: str) -> str:
    """Return the name of the topic toggle of ``family``."""
    return f"linux_compliance_{family}_enabled"


def rule_short_id(rule_id: str) -> str:
    """Return the short identifier of the rule ``rule_id`` (full XCCDF identifier)."""
    return rule_id[len(RULE_PREFIX) :]


def rule_toggle_name(rule_id: str) -> str:
    """Return the name of the toggle of the rule ``rule_id`` (full XCCDF identifier).

    Ansible variable names cannot hold ``-``, ``.`` or ``+``, and toggle names are lower case, so
    the short identifier is lower-cased and every other character is replaced by ``_``:
    ``kernel_module_usb-storage_disabled`` has the toggle
    ``linux_compliance_rule_kernel_module_usb_storage_disabled_enabled``. The catalogue fails when
    two rules end up with the same toggle.
    """
    toggle_id = re.sub(TOGGLE_UNSAFE, "_", rule_short_id(rule_id).lower())
    return f"linux_compliance_rule_{toggle_id}_enabled"


def is_native(rule: Mapping[str, object]) -> bool:
    """Return whether ``rule`` has a native remediation: a strategy other than audit_only."""
    return rule["revert_strategy"] != AUDIT_ONLY


def _family_problem(item: Mapping[str, object], seen: set[str]) -> str | None:
    name = item["name"]
    disruptive = item["disruptive"]
    reserved = in_namespace(str(name), (*ROLE_NAMESPACES, RULE_NAMESPACE))
    if not is_text(name, FAMILY_PATTERN) or reserved:
        return f"invalid or reserved family name {show(name)}"
    if name in seen:
        return f"family {name} is listed twice"
    if not isinstance(disruptive, bool):
        return "disruptive must be a boolean"
    if name in DISRUPTIVE_FAMILIES and not disruptive:
        return f"family {name} is always disruptive and cannot be marked otherwise"
    return None


def _check_family(index: int, raw: object, seen: set[str], errors: Errors) -> tuple[str, bool]:
    where = f"family #{index}"
    item = as_mapping(raw)
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
    items = as_sequence(raw)
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
        problems.append(f"unknown family {show(family)}")
    elif rule["disruptive"] is not families[family]:
        problems.append("disruptive must equal the disruptive flag of its family")
    if strategy not in STRATEGIES:
        problems.append(f"unknown revert_strategy {show(strategy)}")
    elif rule["reversible"] is not (strategy != IRREVERSIBLE):
        problems.append("reversible must be false exactly for the irreversible strategy")
    elif strategy == AUDIT_ONLY and rule["parameters"] != {}:
        problems.append("an audit_only rule has no native remediation and takes no parameters")
    if rule["toggle"] != rule_toggle_name(rule_id):
        problems.append(f"toggle must be {rule_toggle_name(rule_id)}")
    if strategy == IRREVERSIBLE and not is_text(runbook, RUNBOOK_PATTERN):
        problems.append("an irreversible rule needs a runbook link (https:// or docs/)")
    if strategy != IRREVERSIBLE and runbook is not None:
        problems.append("only an irreversible rule has a runbook")
    if as_mapping(rule["parameters"]) is None:
        problems.append("parameters must be a mapping")
    return problems


def _check_rule(
    index: int, raw: object, families: Mapping[str, bool], seen: set[str], errors: Errors
) -> Rule | None:
    where = f"rule #{index}"
    rule = as_mapping(raw)
    if rule is None:
        errors.add(f"{where}: must be a mapping")
        return None
    if frozenset(rule) != RULE_KEYS:
        errors.add(f"{where}: keys must be exactly {sorted(RULE_KEYS)}, got {sorted(rule)[:10]}")
        return None
    rule_id = rule["rule_id"]
    if not is_text(rule_id, RULE_PATTERN):
        errors.add(f"{where}: invalid rule_id {show(rule_id)}")
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
    items = as_sequence(raw)
    if items is None or len(items) > MAX_RULES:
        errors.add(f"the rule catalogue must be a list of at most {MAX_RULES} rules")
        return []
    seen: set[str] = set()
    checked = [_check_rule(index, item, families, seen, errors) for index, item in enumerate(items)]
    rules = [rule for rule in checked if rule is not None]
    owners: dict[str, str] = {}
    for rule in rules:
        toggle = str(rule["toggle"])
        if toggle in owners:
            errors.add(
                f"{rule['rule_id']}: its toggle {toggle} is also the toggle of {owners[toggle]}"
            )
        owners.setdefault(toggle, str(rule["rule_id"]))
    return sorted(rules, key=lambda rule: str(rule["rule_id"]))


def check_toggles(
    raw: object, rule_toggles: frozenset[str], families: Mapping[str, bool], errors: Errors
) -> dict[str, bool]:
    """Validate the toggle variables and return the boolean value of each known toggle.

    ``raw`` maps every variable whose name matches :data:`TOGGLE_VARIABLE_PATTERN` to its value.
    The declared role variables of :data:`ROLE_TOGGLE_VARIABLES` are ignored. A rule toggle must
    belong to a catalogued rule, a name in the namespace of a role is an error, every other name
    must be the toggle of a registered family, and every value must be a boolean. A generated
    rule toggle default (``"{{ linux_compliance_<family>_enabled }}"``) reaches this function
    already templated, so it is the boolean of its family toggle.
    """
    toggles = as_mapping(raw)
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
        elif match is not None and in_namespace(topic, ROLE_NAMESPACES):
            errors.add(
                f"{show(name)} is in the namespace of a role of the collection but is not a "
                f"variable of that role; topic toggles of a family are "
                f"linux_compliance_<family>_enabled"
            )
            continue
        else:
            known = topic in families
            kind = "family"
        value = toggles[name]
        if not known:
            errors.add(f"{show(name)} is not the toggle of a catalogued {kind}")
        elif not isinstance(value, bool):
            errors.add(
                f"{name} must be a boolean; pass it as JSON, for example -e '{{\"{name}\": false}}'"
            )
        else:
            values[name] = value
    return values


def _audit_only_entry(rule_id: object, family: str, *, disruptive: bool) -> Rule:
    toggle = rule_toggle_name(rule_id) if isinstance(rule_id, str) else None
    return {
        "rule_id": rule_id,
        "family": family,
        "disruptive": disruptive,
        "reversible": True,
        "revert_strategy": AUDIT_ONLY,
        "toggle": toggle,
        "runbook": None,
        "parameters": {},
    }


def expand_audit_only(raw: object, families: Mapping[str, bool], errors: Errors) -> list[Rule]:
    """Return the full catalogue entries of the rules that have no native remediation.

    The catalogue lists these rules compactly, as a mapping of each family to the full identifiers
    of its ``audit_only`` rules, because they carry nothing but their family. Each becomes an entry
    of the usual shape: the disruptive flag of its family, ``reversible`` true (nothing is ever
    applied, so nothing needs reverting), the strategy ``audit_only``, its derived toggle, no
    runbook and no parameters. :func:`check_catalogue` validates the result together with the
    native rules.
    """
    mapping = as_mapping(raw)
    if mapping is None:
        errors.add("the audit_only catalogue must map families to lists of rule identifiers")
        return []
    entries: list[Rule] = []
    for family, value in mapping.items():
        rule_ids = as_sequence(value)
        if family not in families:
            errors.add(f"the audit_only catalogue names the unknown family {show(family)}")
        elif rule_ids is None:
            errors.add(f"the audit_only rules of {family} must be a list of rule identifiers")
        else:
            entries.extend(
                _audit_only_entry(rule_id, family, disruptive=families[family])
                for rule_id in rule_ids
            )
    return entries


def load_catalogue(
    catalogue: object, audit_only: object, families: object, toggles: object, errors: Errors
) -> Catalogue:
    """Validate the registry, the catalogue and the toggle variables together.

    ``catalogue`` lists the rules with a native remediation, each with every key of
    :data:`RULE_KEYS`, and ``audit_only`` the rules without one, per family (see
    :func:`expand_audit_only`). A native entry with the strategy ``audit_only`` is an error, so each
    rule has exactly one place in the catalogue.
    """
    registry = check_families(families, errors)
    native = as_sequence(catalogue)
    if native is not None and any(
        isinstance(item, Mapping)
        and cast("Mapping[str, object]", item).get("revert_strategy") == AUDIT_ONLY
        for item in native
    ):
        errors.add("list audit_only rules in the audit_only catalogue, not with the native rules")
    expanded = expand_audit_only(audit_only, registry, errors)
    combined = None if native is None else [*native, *expanded]
    rules = check_catalogue(combined, registry, errors)
    rule_toggles = frozenset(str(rule["toggle"]) for rule in rules)
    values = check_toggles(toggles, rule_toggles, registry, errors)
    return Catalogue(rules=rules, families=registry, toggles=values)


def resolve_toggle(rule: Rule, toggles: Mapping[str, bool]) -> Toggle:
    """Return the toggle state of ``rule`` and the variable that switched it off.

    The state is the rule toggle when it is set, else the family toggle when it is set, else on.
    When the rule is off, the controlling variable is the family toggle whenever the family toggle
    is off, because the generated default of a rule toggle is its family toggle and the two cannot
    be told apart once templated; otherwise it is the rule toggle. A rule toggle that switches a
    rule of a disabled family on again wins over the family toggle.
    """
    family = toggle_name(str(rule["family"]))
    family_on = toggles.get(family, True)
    on = toggles.get(str(rule["toggle"]), family_on)
    if on:
        return Toggle(on=True, disabled_by=None)
    return Toggle(on=False, disabled_by=str(rule["toggle"]) if family_on else family)


def disabled_rules(
    rules: Sequence[Rule], toggles: Mapping[str, bool], profile: frozenset[str] | None
) -> list[dict[str, object]]:
    """Return the rules that a toggle switches off, with ``rule_id`` and ``disabled_by``.

    When ``profile`` is not ``None``, only rules that the profile selects are returned, because the
    audit can only disable a rule that its profile selects.
    """
    found: list[dict[str, object]] = []
    for rule in rules:
        toggle = resolve_toggle(rule, toggles)
        if toggle.on or (profile is not None and rule["rule_id"] not in profile):
            continue
        found.append({"rule_id": rule["rule_id"], "disabled_by": toggle.disabled_by})
    return found


def topic_warnings(catalogue: Catalogue, profile: frozenset[str] | None) -> list[str]:
    """Return a warning for every topic toggle that is false but excludes nothing.

    A topic toggle covers only catalogued rules. The catalogue holds every rule of the supported
    profiles of the pinned content, so for those profiles the warning fires only for a family that
    has no rule in the profile at all. When the toggle is false and no catalogued rule of its family
    is selected by ``profile`` (or, when ``profile`` is ``None``, when the family has no catalogued
    rule at all), the toggle has no effect; rules of content that the catalogue does not describe,
    such as user-supplied content, are still audited. Saying so prevents the false impression that
    something was excluded.
    """
    warnings: list[str] = []
    for family in catalogue.families:
        name = toggle_name(family)
        if catalogue.toggles.get(name, True):
            continue
        covered = [
            rule
            for rule in catalogue.rules
            if rule["family"] == family and (profile is None or rule["rule_id"] in profile)
        ]
        if not covered:
            warnings.append(
                f"WARNING: {name} is false, but no catalogued rule of the {family} family is "
                f"selected by the profile, so it excludes nothing; rules outside the rule "
                f"catalogue are still audited (see docs/remediation-variables.md)"
            )
    return warnings
