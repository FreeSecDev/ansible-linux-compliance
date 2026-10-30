"""Rule catalogue, family registry and toggle resolution shared by the roles (ADR 0011).

The remediate role's catalogue (``roles/remediate/vars/rules.yml``) lists every rule that a
supported profile of the pinned content selects, with its control family; the family registry lists
every family. It is generated from the digest-verified datastreams
(``tools/roles/generate_catalogue.py``, FREES-53). A rule with a native remediation has a revert
strategy; every other rule has the strategy ``audit_only``: it can be toggled and is excluded from
the audit when it is off, but remediation never changes anything for it. Each family has a topic
toggle ``linux_compliance_<family>_enabled`` and each rule a rule toggle
``linux_compliance_rule_<rule_short_id>_enabled``, where the short identifier is written in lower
case with every character other than a letter, a digit or ``_`` replaced by ``_``. A family may
belong to one umbrella (FREES-53, topic split): an umbrella groups several families under the
toggle ``linux_compliance_<umbrella>_enabled``, which is either a name of its own, such as
``services`` for ``sssd`` and ``time_sync``, or the toggle of a family that heads the umbrella,
such as ``pam`` for ``pwquality`` and ``faillock``. There is one level only. When the umbrella
toggle is false, every family in it is off whatever its topic toggle says: a topic toggle can only
narrow an umbrella, never widen it. A rule toggle that is set still wins over both. The topic and
umbrella toggles default to ``true`` in the roles (``tools/roles/generate_toggles.py``); a rule
toggle that is not set follows its family.

A rule may also carry subsystem tags (FREES-165): families other than its own whose subsystem the
rule is about, such as ``sssd`` for the permissions of ``/var/log/sssd``, which belong to the
``file_permissions`` family. A tag only adds ways to switch the rule off: the rule is off when the
toggle of its family, of its family's umbrella, of any of its tags or of any tag's umbrella is
false. Tags never switch a rule on and play no part in the disruptive allow-list, which stays a
property of the family.

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
from dataclasses import dataclass, replace
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
        "apparmor",
        "auditd",
        "auditd_conf",
        "auditd_rules_time",
        "autofs",
        "bootloader",
        "console_access",
        "cron",
        "crypto_policy",
        "desktop",
        "faillock",
        "fapolicyd",
        "filesystem_modules",
        "firewalld",
        "iptables",
        "ipsec",
        "ipv4_parameters",
        "ipv6_parameters",
        "mail",
        "mount_options",
        "network_services",
        "network_settings",
        "nfs",
        "nftables",
        "package_sources",
        "package_updates",
        "pam",
        "partitioning",
        "password_aging",
        "protocol_modules",
        "pwhistory",
        "pwquality",
        "root_access",
        "selinux",
        "smartcard",
        "ssh",
        "sssd",
        "sudo",
        "system_packages",
        "time_sync",
        "ufw",
        "umask",
        "usbguard",
        "user_accounts",
        "user_sessions",
        "wireless",
        "wireless_modules",
    }
)
RULE_NAMESPACE: Final[str] = "rule"
RULE_TOGGLE_PREFIX: Final[str] = f"linux_compliance_{RULE_NAMESPACE}_"
HINTS: Final[dict[str, str]] = {
    "rule": (
        "; rule toggle names are linux_compliance_rule_<short id>_enabled with the short rule "
        "identifier in lower case and every character other than a letter, a digit or _ "
        "replaced by _, for example "
        "linux_compliance_rule_kernel_module_usb_storage_disabled_enabled"
    ),
    "family": "",
}
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
UMBRELLA_KEY: Final[str] = "umbrella"
EMPTY: Final[tuple[str, ...]] = ()
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
class Registry:
    """The validated family registry: the disruptive flag and the umbrella of each family."""

    families: dict[str, bool]
    umbrellas: dict[str, str]


@dataclass(frozen=True)
class Catalogue:
    """The validated catalogue: rules sorted by identifier, the registry and the toggle values.

    ``umbrellas`` maps every family that belongs to an umbrella to the name of that umbrella, and
    ``tags`` maps every rule that has subsystem tags to its tags, sorted (see :func:`check_tags`).
    """

    rules: list[Rule]
    families: dict[str, bool]
    toggles: dict[str, bool]
    umbrellas: dict[str, str]
    tags: dict[str, tuple[str, ...]]


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


def is_topic_name(name: object) -> bool:
    """Return whether ``name`` may name a family or an umbrella: a slug outside the namespaces."""
    return is_text(name, FAMILY_PATTERN) and not in_namespace(
        str(name), (*ROLE_NAMESPACES, RULE_NAMESPACE)
    )


def _family_problem(item: Mapping[str, object], seen: set[str]) -> str | None:
    name = item["name"]
    disruptive = item["disruptive"]
    if not is_topic_name(name):
        return f"invalid or reserved family name {show(name)}"
    if name in seen:
        return f"family {name} is listed twice"
    if not isinstance(disruptive, bool):
        return "disruptive must be a boolean"
    if name in DISRUPTIVE_FAMILIES and not disruptive:
        return f"family {name} is always disruptive and cannot be marked otherwise"
    if UMBRELLA_KEY in item and not is_topic_name(item[UMBRELLA_KEY]):
        return f"invalid or reserved umbrella name {show(item[UMBRELLA_KEY])}"
    return None


def _check_family(
    index: int, raw: object, seen: set[str], errors: Errors
) -> tuple[str, bool, str | None]:
    where = f"family #{index}"
    item = as_mapping(raw)
    if item is None:
        errors.add(f"{where}: must be a mapping")
        return "", False, None
    if frozenset(item) - {UMBRELLA_KEY} != FAMILY_KEYS:
        errors.add(
            f"{where}: keys must be exactly {sorted(FAMILY_KEYS)} and optionally "
            f"{UMBRELLA_KEY}, got {sorted(item)[:10]}"
        )
        return "", False, None
    problem = _family_problem(item, seen)
    if problem is not None:
        errors.add(f"{where}: {problem}")
        return "", False, None
    seen.add(str(item["name"]))
    umbrella = item.get(UMBRELLA_KEY)
    return (
        str(item["name"]),
        item["disruptive"] is True,
        None if umbrella is None else str(umbrella),
    )


def check_registry(raw: object, errors: Errors) -> Registry:
    """Validate the family registry and return the disruptive flag and umbrella per family.

    Each family is a mapping with exactly ``name`` and ``disruptive`` and optionally ``umbrella``.
    An umbrella is either a name of its own or the name of a family, which then heads it. A family
    that heads an umbrella cannot itself belong to one, so there is exactly one level, and a
    family cannot be its own umbrella.
    """
    items = as_sequence(raw)
    if items is None or not 0 < len(items) <= MAX_FAMILIES:
        errors.add(f"the family registry must be a list of 1 to {MAX_FAMILIES} families")
        return Registry(families={}, umbrellas={})
    seen: set[str] = set()
    families: dict[str, bool] = {}
    umbrellas: dict[str, str] = {}
    for index, item in enumerate(items):
        name, disruptive, umbrella = _check_family(index, item, seen, errors)
        if name:
            families[name] = disruptive
        if name and umbrella is not None:
            umbrellas[name] = umbrella
    heads = set(umbrellas.values())
    for family in [family for family in umbrellas if family in heads]:
        errors.add(
            f"family {family} heads an umbrella and cannot itself belong to the umbrella "
            f"{umbrellas[family]}; umbrellas have one level"
        )
        del umbrellas[family]
    return Registry(families=families, umbrellas=umbrellas)


def topics(families: Mapping[str, bool], umbrellas: Mapping[str, str]) -> list[str]:
    """Return every name that has a topic toggle, in registry order.

    These are the families and the umbrellas that are not a family; such an umbrella comes just
    before its first family.
    """
    names: list[str] = []
    for family in families:
        umbrella = umbrellas.get(family)
        if umbrella is not None and umbrella not in families and umbrella not in names:
            names.append(umbrella)
        names.append(family)
    return names


def governed(topic: str, families: Mapping[str, bool], umbrellas: Mapping[str, str]) -> list[str]:
    """Return the families whose rules the toggle of ``topic`` switches off, in registry order.

    These are the family named ``topic``, if there is one, and every family whose umbrella it is.
    """
    return [family for family in families if topic in (family, umbrellas.get(family))]


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
    raw: object,
    rule_toggles: frozenset[str],
    families: Mapping[str, bool],
    errors: Errors,
    *,
    umbrellas: Mapping[str, str],
) -> dict[str, bool]:
    """Validate the toggle variables and return the boolean value of each known toggle.

    ``raw`` maps every variable whose name matches :data:`TOGGLE_VARIABLE_PATTERN` to its value.
    The declared role variables of :data:`ROLE_TOGGLE_VARIABLES` are ignored. A rule toggle must
    belong to a catalogued rule, a name in the namespace of a role is an error, every other name
    must be the toggle of a registered family or of an umbrella of ``umbrellas``, and every value
    must be a boolean. A rule toggle copied from a former generated default
    (``"{{ linux_compliance_<family>_enabled }}"``) reaches this function already templated, so
    it is the boolean of its family toggle.
    """
    toggles = as_mapping(raw)
    if toggles is None:
        errors.add("toggles must be a mapping of variable names to values")
        return {}
    values: dict[str, bool] = {}
    for name in sorted(toggles):
        match = re.fullmatch(TOGGLE_PATTERN, name)
        topic = match.group(1) if match is not None else ""
        if name.startswith(RULE_TOGGLE_PREFIX):
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
            known = topic in families or topic in umbrellas.values()
            kind = "family"
        value = toggles[name]
        if not known:
            errors.add(f"{show(name)} is not the toggle of a catalogued {kind}{HINTS[kind]}")
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


def _tag_problem(tag: str, value: object, families: Mapping[str, bool]) -> str | None:
    rule_ids = as_sequence(value)
    if tag not in families:
        return f"the subsystem tags name the unknown family {show(tag)}"
    if rule_ids is None or not all(is_text(item, RULE_PATTERN) for item in rule_ids):
        return f"the rules tagged {tag} must be a list of rule identifiers"
    if [str(item) for item in rule_ids] != sorted({str(item) for item in rule_ids}):
        return f"the rules tagged {tag} must be sorted and free of duplicates"
    return None


def check_tags(
    raw: object, rules: Sequence[Rule], families: Mapping[str, bool], errors: Errors
) -> dict[str, tuple[str, ...]]:
    """Validate the subsystem tags and return the tags of every tagged rule, sorted.

    ``raw`` maps a family, the tag, to the sorted full identifiers of the catalogued rules of other
    families that it tags (``__linux_compliance_remediate_tags`` of the catalogue). A tag must be a
    registered family, and a tagged rule must be catalogued and belong to another family, because a
    family toggle already switches off the rules of its own family.
    """
    mapping = as_mapping(raw)
    if mapping is None:
        errors.add("the subsystem tags must map families to lists of rule identifiers")
        return {}
    family_of = {str(rule["rule_id"]): rule["family"] for rule in rules}
    tagged: dict[str, list[str]] = {}
    for tag, value in mapping.items():
        problem = _tag_problem(tag, value, families)
        if problem is not None:
            errors.add(problem)
            continue
        for rule_id in (str(item) for item in as_sequence(value) or []):
            if rule_id not in family_of:
                errors.add(f"the subsystem tag {tag} names {rule_id}, which is not catalogued")
            elif family_of[rule_id] == tag:
                errors.add(
                    f"{rule_id} belongs to the family {tag} and cannot also be tagged with it"
                )
            else:
                tagged.setdefault(rule_id, []).append(tag)
    return {rule_id: tuple(sorted(names)) for rule_id, names in sorted(tagged.items())}


def check_family_aliases(
    raw: object, families: Mapping[str, bool], errors: Errors
) -> dict[str, frozenset[str]]:
    """Validate the ledger family aliases and return the current families of each former name.

    ``raw`` maps a family name that the state ledger may record, because a rule was moved to
    another family after it was applied, to the sorted registered families that its rules may
    belong to now (``__linux_compliance_remediate_family_aliases``). A former name must be a valid
    family name and may still be a registered family; it cannot alias itself.
    """
    mapping = as_mapping(raw)
    if mapping is None:
        errors.add("the ledger family aliases must map former family names to lists of families")
        return {}
    aliases: dict[str, frozenset[str]] = {}
    for former, value in mapping.items():
        targets = as_sequence(value)
        names = [str(item) for item in targets or []]
        if not is_topic_name(former):
            errors.add(f"invalid or reserved former family name {show(former)} in the aliases")
        elif not names or not all(item in families for item in names):
            errors.add(f"the alias {former} must list registered families")
        elif names != sorted(set(names)) or former in names:
            errors.add(f"the alias {former} must be sorted, free of duplicates and not name itself")
        else:
            aliases[former] = frozenset(names)
    return aliases


def load_catalogue(
    catalogue: object, audit_only: object, families: object, toggles: object, errors: Errors
) -> Catalogue:
    """Validate the registry, the catalogue and the toggle variables together.

    ``catalogue`` lists the rules with a native remediation, each with every key of
    :data:`RULE_KEYS`, and ``audit_only`` the rules without one, per family (see
    :func:`expand_audit_only`). A native entry with the strategy ``audit_only`` is an error, so each
    rule has exactly one place in the catalogue. No rule is tagged; :func:`with_tags` adds the
    subsystem tags.
    """
    checked = check_registry(families, errors)
    registry = checked.families
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
    values = check_toggles(toggles, rule_toggles, registry, errors, umbrellas=checked.umbrellas)
    return Catalogue(
        rules=rules, families=registry, toggles=values, umbrellas=checked.umbrellas, tags={}
    )


def with_tags(catalogue: Catalogue, tags: object, errors: Errors) -> Catalogue:
    """Return ``catalogue`` with the subsystem tags ``tags``, validated by :func:`check_tags`."""
    return replace(catalogue, tags=check_tags(tags, catalogue.rules, catalogue.families, errors))


def controlling_topics(family: str, tags: Sequence[str], umbrellas: Mapping[str, str]) -> list[str]:
    """Return the topics whose toggles must all be on for a rule, in the order of precedence.

    These are the umbrella of the rule's family, the family, and then, for each subsystem tag in
    alphabetical order, the umbrella of the tag and the tag; a topic is listed once. The first of
    them whose toggle is false is the ``disabled_by`` of the rule.
    """
    names: list[str] = []
    for topic in (family, *sorted(tags)):
        umbrella = umbrellas.get(topic)
        for name in (topic,) if umbrella is None else (umbrella, topic):
            if name not in names:
                names.append(name)
    return names


def resolve_toggle(
    rule: Rule,
    toggles: Mapping[str, bool],
    *,
    umbrellas: Mapping[str, str],
    tags: Sequence[str] = EMPTY,
) -> Toggle:
    """Return the toggle state of ``rule`` and the variable that switched it off.

    The state is the rule toggle when it is set. Otherwise the topic of the rule is on when the
    toggle of every topic of :func:`controlling_topics` is on: the umbrella of its family (if the
    family belongs to an umbrella), its family, and for each subsystem tag in ``tags`` the umbrella
    of the tag and the tag, a toggle that is not set counting as on. So a topic toggle can only
    narrow its umbrella and never widen it, and a tag can only switch a rule off. When the rule is
    off, the controlling variable is the first of those toggles that is off, in that order: the
    family umbrella, the family, then the tags in alphabetical order, each after its umbrella;
    else the rule toggle. A rule toggle copied from its family default cannot be told apart from
    one set by the operator once templated, so the topic is named whenever it is off. A rule
    toggle that switches a rule of a disabled topic on again wins over every topic toggle.
    """
    topics_off = [
        toggle_name(topic)
        for topic in controlling_topics(str(rule["family"]), tags, umbrellas)
        if not toggles.get(toggle_name(topic), True)
    ]
    on = toggles.get(str(rule["toggle"]), not topics_off)
    if on:
        return Toggle(on=True, disabled_by=None)
    return Toggle(on=False, disabled_by=topics_off[0] if topics_off else str(rule["toggle"]))


def disabled_rules(
    rules: Sequence[Rule],
    toggles: Mapping[str, bool],
    profile: frozenset[str] | None,
    *,
    umbrellas: Mapping[str, str],
    tags: Mapping[str, Sequence[str]] | None = None,
) -> list[dict[str, object]]:
    """Return the rules that a toggle switches off, with ``rule_id`` and ``disabled_by``.

    ``tags`` maps a rule identifier to its subsystem tags (:attr:`Catalogue.tags`). When
    ``profile`` is not ``None``, only rules that the profile selects are returned, because the
    audit can only disable a rule that its profile selects.
    """
    tagged = tags or {}
    found: list[dict[str, object]] = []
    for rule in rules:
        rule_tags = tagged.get(str(rule["rule_id"]), EMPTY)
        toggle = resolve_toggle(rule, toggles, umbrellas=umbrellas, tags=rule_tags)
        if toggle.on or (profile is not None and rule["rule_id"] not in profile):
            continue
        found.append({"rule_id": rule["rule_id"], "disabled_by": toggle.disabled_by})
    return found


def switches_off(topic: str, rule: Rule, catalogue: Catalogue) -> bool:
    """Return whether the toggle of ``topic`` being false switches ``rule`` off.

    That is the case when ``topic`` is one of the :func:`controlling_topics` of the rule: its
    family, the umbrella of its family, one of its subsystem tags or the umbrella of one.
    """
    tags = catalogue.tags.get(str(rule["rule_id"]), EMPTY)
    return topic in controlling_topics(str(rule["family"]), tags, catalogue.umbrellas)


def _scope(topic: str, members: Sequence[str]) -> str:
    if list(members) == [topic]:
        return f"the {topic} family"
    return f"the families that {topic} groups ({', '.join(members)})"


def topic_warnings(catalogue: Catalogue, profile: frozenset[str] | None) -> list[str]:
    """Return a warning for every topic or umbrella toggle that is false but excludes nothing.

    A topic toggle covers only catalogued rules. The catalogue holds every rule of the supported
    profiles of the pinned content, so for those profiles the warning fires only for a family, or
    an umbrella, that has no rule in the profile at all. When the toggle is false and no
    catalogued rule that it switches off (:func:`switches_off`: a rule of a family that it governs,
    or a rule of another family that a subsystem tag of such a family reaches) is selected by
    ``profile`` (or, when ``profile`` is ``None``, when there is no such catalogued rule at all),
    the toggle has no effect; rules of content that the catalogue does not describe, such as
    user-supplied content, are still audited. Saying so prevents the false impression that
    something was excluded.
    """
    warnings: list[str] = []
    for topic in topics(catalogue.families, catalogue.umbrellas):
        name = toggle_name(topic)
        if catalogue.toggles.get(name, True):
            continue
        members = governed(topic, catalogue.families, catalogue.umbrellas)
        covered = [
            rule
            for rule in catalogue.rules
            if switches_off(topic, rule, catalogue)
            and (profile is None or rule["rule_id"] in profile)
        ]
        if not covered:
            warnings.append(
                f"WARNING: {name} is false, but no catalogued rule of {_scope(topic, members)} is "
                f"selected by the profile, so it excludes nothing; rules outside the rule "
                f"catalogue are still audited (see docs/remediation-variables.md)"
            )
    return warnings


@dataclass(frozen=True)
class AuditResolution:
    """The rules that the audit excludes, from the toggles and the explicit list.

    ``disabled`` holds the explicit entries followed by the rules that a toggle switches off, each
    with ``rule_id`` and ``disabled_by``, sorted by rule identifier; ``catalogue`` is the validated
    catalogue that was resolved and ``warnings`` the topic warnings of :func:`topic_warnings`.
    """

    catalogue: Catalogue
    disabled: list[dict[str, object]]
    warnings: list[str]


def profile_rule_set(raw: object, errors: Errors) -> frozenset[str]:
    """Return the rule identifiers of a profile, or record an error when they are not strings."""
    items = as_sequence(raw)
    if items is None or not all(isinstance(item, str) for item in items):
        errors.add("profile_rule_ids must list the rule identifiers of the discovered profile")
        return frozenset()
    return frozenset(str(item) for item in items)


def explicit_disabled_rules(
    raw: object, catalogue: Catalogue, errors: Errors
) -> list[dict[str, object]]:
    """Return the explicit ``linux_compliance_audit_disabled_rules`` entries.

    Each entry needs a ``rule_id`` string. A rule of the catalogue is an error, because the audit
    would then skip a rule that remediation still applies, so its toggle must be used instead.
    """
    items = as_sequence(raw)
    if items is None:
        errors.add("linux_compliance_audit_disabled_rules must be a list")
        return []
    catalogued = {str(rule["rule_id"]): str(rule["toggle"]) for rule in catalogue.rules}
    entries: list[dict[str, object]] = []
    for item in items:
        entry = as_mapping(item)
        rule_id = None if entry is None else entry.get("rule_id")
        if entry is None or not isinstance(rule_id, str):
            errors.add("every linux_compliance_audit_disabled_rules item needs a rule_id string")
        elif rule_id in catalogued:
            errors.add(
                f"{rule_id} is in the rule catalogue; switch it off with "
                f"{catalogued[rule_id]} or its family toggle, not with "
                f"linux_compliance_audit_disabled_rules, so that the audit and remediation agree"
            )
        else:
            entries.append(entry)
    return entries


def resolve_audit(
    catalogue: object, options: Mapping[str, object], profile: frozenset[str], errors: Errors
) -> AuditResolution:
    """Resolve the disabled rules of an audit exactly as the remediate role resolves its toggles.

    ``options`` holds ``audit_only``, ``families``, ``tags``, ``toggles`` and ``disabled_rules`` as
    the ``audit_disabled_rules`` filter documents them, and ``profile`` the rules that can be
    disabled. The OpenSCAP path (``audit_disabled_rules``) and the SCC path (``scc_toggles``) of
    the audit role both resolve their toggles here.
    """
    loaded = with_tags(
        load_catalogue(
            catalogue, options["audit_only"], options["families"], options["toggles"], errors
        ),
        options["tags"],
        errors,
    )
    explicit = explicit_disabled_rules(options["disabled_rules"], loaded, errors)
    switched_off = disabled_rules(
        loaded.rules, loaded.toggles, profile, umbrellas=loaded.umbrellas, tags=loaded.tags
    )
    combined = sorted(explicit + switched_off, key=lambda entry: str(entry["rule_id"]))
    return AuditResolution(loaded, combined, topic_warnings(loaded, profile))
