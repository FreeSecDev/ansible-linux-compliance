"""Generate the rule catalogue and the control family reference from the pinned content.

FREES-53 makes every rule toggleable: the catalogue ``roles/remediate/vars/rules.yml`` lists every
rule that a profile of ``content/manifest.yml`` selects, not only the rules with a native
remediation. This tool reads the datastreams that ``tools/content/fetch_content.py`` fetched,
through :func:`catalog.read_benchmarks`, which verifies the pinned SHA-256 before it parses a
byte, and assigns every selected rule exactly one control family with the documented mapping in
``content/catalogue.yml``. A rule is assigned by the first of these that decides it:

1. ``topic_groups``: a ComplianceAsCode group that contains the rule, at any depth. Every rule
   below it belongs to the family, whatever its identifier, so ``auditing`` takes the audit log
   permissions and the ``audit=1`` boot argument to ``auditd``. A rule below several topic groups
   belongs to the innermost one when the families of all of them belong to the same umbrella
   (``journald`` inside ``logging``); otherwise it is an error.
2. ``rule_prefixes``: the start of the short rule identifier, for rules whose mechanism defines
   the topic (file permissions, kernel parameters, kernel modules, mount options, boot
   arguments). No prefix may be the start of another, so at most one matches.
3. ``fallback_groups``: the innermost group that contains the rule and is listed here.

A family may name an ``umbrella`` (ADR 0011, topic split of FREES-53), which the catalogue
registry repeats. A rule that nothing decides, a rule that two datastreams assign to different
families, a group listed twice, a mapping entry that decides no rule and a native rule that no
profile selects are errors; nothing is guessed. Rules listed in ``native_rules`` keep their
revert strategy and parameters; every other rule gets the strategy ``audit_only``. The tool
writes the catalogue and
``docs/control-families.md``; ``make catalogue`` then runs ``generate_toggles`` for the toggles.
With ``--check`` nothing is written: a unified diff of every file that differs is printed and the
exit status is 1, which is how CI detects drift from the pinned content. Only rule identifiers,
group identifiers and profile identifiers of the BSD-licensed ComplianceAsCode content are used,
never benchmark prose.
"""

from __future__ import annotations

import argparse
import itertools
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
    toggles,
)
from tools.content import fetch_content
from tools.roles import generate_toggles

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

SOURCE: Final[Path] = Path("content/catalogue.yml")
MANIFEST: Final[Path] = Path("content/manifest.yml")
CATALOGUE: Final[Path] = generate_toggles.CATALOGUE
REFERENCE: Final[Path] = Path("docs/control-families.md")
CONTENT_DIR: Final[Path] = Path("build/content")
SCHEMA_VERSION: Final[int] = 1
GROUP_PREFIX: Final[str] = "xccdf_org.ssgproject.content_group_"
PROFILE_PREFIX: Final[str] = "xccdf_org.ssgproject.content_profile_"
SOURCE_KEYS: Final[frozenset[str]] = frozenset({"schema_version", "families", "native_rules"})
FAMILY_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "disruptive", "title", "why", "topic_groups", "rule_prefixes", "fallback_groups"}
)
UMBRELLA_KEY: Final[str] = toggles.UMBRELLA_KEY
NATIVE_KEYS: Final[frozenset[str]] = frozenset(
    {"rule_id", "revert_strategy", "runbook", "parameters"}
)
TIERS: Final[tuple[str, ...]] = ("topic_groups", "rule_prefixes", "fallback_groups")
GROUP_NAME: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
PREFIX_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}_")
CATALOGUE_PLAIN_KEYS: Final[frozenset[str]] = frozenset(
    {"family", "name", "revert_strategy", "toggle", UMBRELLA_KEY}
)
MAX_PROBLEMS: Final[int] = 50


class GenerationError(generate_toggles.GenerationError):
    """The family mapping, the content or the generated catalogue is not acceptable."""


@dataclass(frozen=True)
class Family:
    """A control family of the registry with the mapping entries that select its rules."""

    name: str
    disruptive: bool
    title: str
    why: str
    topic_groups: tuple[str, ...]
    rule_prefixes: tuple[str, ...]
    fallback_groups: tuple[str, ...]
    umbrella: str | None = None

    @property
    def scope(self) -> str:
        """Return the umbrella of the family, or its own name when it belongs to none."""
        return self.name if self.umbrella is None else self.umbrella

    def entries(self, tier: str) -> tuple[str, ...]:
        """Return the mapping entries of ``tier`` (one of :data:`TIERS`)."""
        tiers = {
            "topic_groups": self.topic_groups,
            "rule_prefixes": self.rule_prefixes,
            "fallback_groups": self.fallback_groups,
        }
        return tiers[tier]


@dataclass(frozen=True)
class Source:
    """The validated ``content/catalogue.yml``: the registry and the native rules."""

    families: tuple[Family, ...]
    native_rules: dict[str, dict[str, object]]


@dataclass(frozen=True)
class Stream:
    """A pinned datastream to read: its manifest name, local path, digest and profiles."""

    name: str
    path: Path
    sha256: str
    profile_ids: tuple[str, ...]


@dataclass(frozen=True)
class StreamRules:
    """What one datastream contributes: the rules of each profile and the groups of each rule."""

    name: str
    version: str
    profiles: dict[str, tuple[str, ...]]
    groups: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Catalogue:
    """The generated catalogue together with the data that the reference page reports."""

    source: Source
    rules: list[dict[str, object]]
    streams: tuple[StreamRules, ...]


def _fail(message: str) -> GenerationError:
    return GenerationError(message)


def _texts(value: object, where: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    items = toggles.as_sequence(value)
    if items is None or not all(
        isinstance(item, str) and pattern.fullmatch(item) for item in items
    ):
        message = f"{where} must be a list of names matching {pattern.pattern}"
        raise _fail(message)
    names = tuple(str(item) for item in items)
    if list(names) != sorted(set(names)):
        message = f"{where} must be sorted and free of duplicates"
        raise _fail(message)
    return names


def _text(table: Mapping[str, object], key: str, where: str) -> str:
    value = table[key]
    if not isinstance(value, str) or not value.strip() or not value.isprintable():
        message = f"{where}.{key} must be a non-empty printable string"
        raise _fail(message)
    return value


def _family(raw: object, index: int) -> Family:
    where = f"families[{index}]"
    table = toggles.as_mapping(raw)
    if table is None or frozenset(table) - {UMBRELLA_KEY} != FAMILY_KEYS:
        message = (
            f"{where} must be a mapping with exactly {sorted(FAMILY_KEYS)} and optionally "
            f"{UMBRELLA_KEY}"
        )
        raise _fail(message)
    if not isinstance(table["disruptive"], bool):
        message = f"{where}.disruptive must be a boolean"
        raise _fail(message)
    umbrella = table.get(UMBRELLA_KEY)
    if UMBRELLA_KEY in table and not toggles.is_topic_name(umbrella):
        message = f"{where}.umbrella must be a family or umbrella name, got {umbrella!r}"
        raise _fail(message)
    return Family(
        name=_text(table, "name", where),
        disruptive=table["disruptive"],
        title=_text(table, "title", where),
        why=_text(table, "why", where),
        topic_groups=_texts(table["topic_groups"], f"{where}.topic_groups", GROUP_NAME),
        rule_prefixes=_texts(table["rule_prefixes"], f"{where}.rule_prefixes", PREFIX_NAME),
        fallback_groups=_texts(table["fallback_groups"], f"{where}.fallback_groups", GROUP_NAME),
        umbrella=None if umbrella is None else str(umbrella),
    )


def _native(raw: object, index: int) -> tuple[str, dict[str, object]]:
    where = f"native_rules[{index}]"
    table = toggles.as_mapping(raw)
    if table is None or frozenset(table) != NATIVE_KEYS:
        message = f"{where} must be a mapping with exactly {sorted(NATIVE_KEYS)}"
        raise _fail(message)
    strategy = table["revert_strategy"]
    if strategy == toggles.AUDIT_ONLY or strategy not in toggles.STRATEGIES:
        message = f"{where}.revert_strategy must be a native revert strategy, got {strategy!r}"
        raise _fail(message)
    rule_id = table["rule_id"]
    if not toggles.is_text(rule_id, toggles.RULE_PATTERN):
        message = f"{where}.rule_id is not a ComplianceAsCode rule identifier"
        raise _fail(message)
    details = {key: table[key] for key in ("revert_strategy", "runbook", "parameters")}
    return str(rule_id), details


def _check_prefixes(families: Sequence[Family]) -> None:
    prefixes = sorted(prefix for family in families for prefix in family.rule_prefixes)
    for first, second in itertools.pairwise(prefixes):
        if second.startswith(first):
            message = (
                f"the rule prefix {first!r} is the start of {second!r}; prefixes must be disjoint"
            )
            raise _fail(message)


def _check_groups(families: Sequence[Family]) -> None:
    seen: dict[str, str] = {}
    for family in families:
        for tier in ("topic_groups", "fallback_groups"):
            for group in family.entries(tier):
                if group in seen:
                    message = f"the group {group!r} is mapped by {seen[group]} and {family.name}"
                    raise _fail(message)
                seen[group] = family.name


def parse_source(document: object) -> Source:
    """Validate the content of ``content/catalogue.yml`` and return it."""
    table = toggles.as_mapping(document)
    if table is None or frozenset(table) != SOURCE_KEYS:
        message = f"{SOURCE} must be a mapping with exactly {sorted(SOURCE_KEYS)}"
        raise _fail(message)
    if table["schema_version"] != SCHEMA_VERSION:
        message = f"{SOURCE}: schema_version must be {SCHEMA_VERSION}"
        raise _fail(message)
    raw_families = toggles.as_sequence(table["families"]) or []
    families = tuple(_family(item, index) for index, item in enumerate(raw_families))
    raw_native = toggles.as_sequence(table["native_rules"])
    if raw_native is None:
        message = f"{SOURCE}: native_rules must be a list"
        raise _fail(message)
    native = dict(_native(item, index) for index, item in enumerate(raw_native))
    if len(native) != len(raw_native):
        message = f"{SOURCE}: native_rules lists a rule twice"
        raise _fail(message)
    _check_prefixes(families)
    _check_groups(families)
    errors = toggles.Errors()
    toggles.check_registry(_registry(families), errors)
    if errors.items:
        message = f"{SOURCE}: " + "; ".join(errors.items)
        raise _fail(message)
    return Source(families=families, native_rules=native)


def load_source(path: Path) -> Source:
    """Load and validate the family mapping and the native rules in ``path``."""
    try:
        document = cast("object", yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as error:
        message = f"{path}: cannot be read as YAML: {error}"
        raise _fail(message) from error
    return parse_source(document)


def read_stream(stream: Stream) -> StreamRules:
    """Verify and parse one datastream and return its profile rules and rule groups."""
    try:
        benchmark = catalog.single_benchmark(
            catalog.read_benchmarks(str(stream.path), stream.sha256)
        )
        profiles = {
            profile_id: catalog.find_profile(benchmark, profile_id).rule_ids
            for profile_id in stream.profile_ids
        }
    except catalog.CatalogError as error:
        message = f"{stream.name}: {error}"
        raise _fail(message) from error
    groups = {
        rule.rule_id: tuple(group.removeprefix(GROUP_PREFIX) for group in rule.groups)
        for rule in benchmark.rules
    }
    return StreamRules(stream.name, benchmark.version, profiles, groups)


def _index(source: Source, tier: str) -> dict[str, str]:
    return {entry: family.name for family in source.families for entry in family.entries(tier)}


def family_of(rule_id: str, groups: Sequence[str], source: Source) -> tuple[str, tuple[str, str]]:
    """Return the family of a rule and the mapping entry (tier, entry) that decided it.

    Raises:
        GenerationError: When the rule is below two topic groups or nothing decides it.
    """
    topics = _index(source, "topic_groups")
    matched = [group for group in groups if group in topics]
    scopes = {family.name: family.scope for family in source.families}
    if len({scopes[topics[group]] for group in matched}) > 1:
        message = (
            f"{rule_id} is below the topic groups {matched}, which map to families of several "
            f"umbrellas"
        )
        raise _fail(message)
    if matched:
        return topics[matched[-1]], ("topic_groups", matched[-1])
    short = toggles.rule_short_id(rule_id)
    for prefix, family in _index(source, "rule_prefixes").items():
        if short.startswith(prefix):
            return family, ("rule_prefixes", prefix)
    fallback = _index(source, "fallback_groups")
    for group in reversed(groups):
        if group in fallback:
            return fallback[group], ("fallback_groups", group)
    message = f"{rule_id} (groups {'/'.join(groups) or 'none'}) maps to no family"
    raise _fail(message)


def selected_rules(stream: StreamRules) -> list[str]:
    """Return every rule that a profile of ``stream`` selects, sorted and unique."""
    return sorted({rule_id for rule_ids in stream.profiles.values() for rule_id in rule_ids})


def _assign(source: Source, streams: Sequence[StreamRules]) -> dict[str, str]:
    assigned: dict[str, str] = {}
    origin: dict[str, str] = {}
    used: set[tuple[str, str]] = set()
    problems: list[str] = []
    for stream in streams:
        for rule_id in selected_rules(stream):
            try:
                family, entry = family_of(rule_id, stream.groups[rule_id], source)
            except GenerationError as error:
                problems.append(str(error))
                continue
            used.add(entry)
            previous = assigned.setdefault(rule_id, family)
            first = origin.setdefault(rule_id, stream.name)
            if previous != family:
                problems.append(
                    f"{rule_id} maps to {previous} in {first} and to {family} in {stream.name}"
                )
    problems.extend(
        f"the {tier} entry {entry!r} of {family.name} decides no rule of the pinned profiles"
        for family in source.families
        for tier in TIERS
        for entry in family.entries(tier)
        if (tier, entry) not in used
    )
    problems.extend(
        f"the native rule {rule_id} is not selected by any pinned profile"
        for rule_id in sorted(source.native_rules)
        if rule_id not in assigned
    )
    if problems:
        message = f"{len(problems)} problem(s): " + "; ".join(problems[:MAX_PROBLEMS])
        raise _fail(message)
    return assigned


def catalogue_entry(rule_id: str, family: Family, source: Source) -> dict[str, object]:
    """Return the full catalogue entry of a rule in ``family``, native or ``audit_only``."""
    native = source.native_rules.get(rule_id)
    strategy = toggles.AUDIT_ONLY if native is None else str(native["revert_strategy"])
    return {
        "rule_id": rule_id,
        "family": family.name,
        "disruptive": family.disruptive,
        "reversible": strategy != toggles.IRREVERSIBLE,
        "revert_strategy": strategy,
        "toggle": toggles.rule_toggle_name(rule_id),
        "runbook": None if native is None else native["runbook"],
        "parameters": {} if native is None else native["parameters"],
    }


def _registry(families: Sequence[Family]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for family in families:
        entry: dict[str, object] = {"name": family.name, "disruptive": family.disruptive}
        if family.umbrella is not None:
            entry[UMBRELLA_KEY] = family.umbrella
        entries.append(entry)
    return entries


def registry(source: Source) -> list[dict[str, object]]:
    """Return the family registry of the catalogue, in dispatch order, with the umbrellas."""
    return _registry(source.families)


def build(source: Source, streams: Sequence[StreamRules]) -> Catalogue:
    """Assign every selected rule its family and validate the resulting catalogue."""
    assigned = _assign(source, streams)
    families = {family.name: family for family in source.families}
    rules = [
        catalogue_entry(rule_id, families[assigned[rule_id]], source)
        for rule_id in sorted(assigned)
    ]
    errors = toggles.Errors()
    toggles.load_catalogue(
        native_rules(rules), audit_only_rules(rules, source), registry(source), {}, errors
    )
    if errors.items:
        message = "the generated catalogue is invalid: " + "; ".join(errors.items)
        raise _fail(message)
    return Catalogue(source=source, rules=rules, streams=tuple(streams))


def native_rules(rules: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    """Return the entries of the rules with a native remediation, as the catalogue lists them."""
    return [rule for rule in rules if toggles.is_native(rule)]


def audit_only_rules(rules: Sequence[dict[str, object]], source: Source) -> dict[str, object]:
    """Return the ``audit_only`` rules per family in registry order, as the catalogue lists them.

    These rules carry nothing but their family, so the catalogue lists only their identifiers;
    :func:`toggles.expand_audit_only` turns them back into full entries. A family without such a
    rule maps to an empty list.
    """
    return {
        family.name: [
            rule["rule_id"]
            for rule in rules
            if rule["family"] == family.name and not toggles.is_native(rule)
        ]
        for family in source.families
    }


def render_catalogue(built: Catalogue) -> str:
    """Return ``roles/remediate/vars/rules.yml`` for ``built``."""
    data: dict[str, object] = {
        generate_toggles.FAMILIES_KEY: registry(built.source),
        generate_toggles.RULES_KEY: native_rules(built.rules),
        generate_toggles.AUDIT_ONLY_KEY: audit_only_rules(built.rules, built.source),
    }
    return generate_toggles.render_yaml(data, CATALOGUE_PLAIN_KEYS)


def _short_profile(profile_id: str) -> str:
    return profile_id.removeprefix(PROFILE_PREFIX)


def _cell(values: Iterable[object]) -> str:
    return "| " + " | ".join(str(value) for value in values) + " |"


def _profile_table(built: Catalogue, stream: StreamRules) -> list[str]:
    family_of_rule = {str(rule["rule_id"]): str(rule["family"]) for rule in built.rules}
    native = {str(rule["rule_id"]) for rule in built.rules if toggles.is_native(rule)}
    profiles = list(stream.profiles)
    lines = [
        f"### `{stream.name}` (content {stream.version})",
        "",
        _cell(["Family", *(f"`{_short_profile(profile)}`" for profile in profiles)]),
        _cell(["---"] * (len(profiles) + 1)),
    ]
    for family in built.source.families:
        counts = [
            sum(family_of_rule[rule_id] == family.name for rule_id in stream.profiles[profile])
            for profile in profiles
        ]
        lines.append(_cell([f"`{family.name}`", *counts]))
    lines.append(_cell(["All families", *(len(stream.profiles[p]) for p in profiles)]))
    lines.append(
        _cell(
            [
                "Native remediation",
                *(sum(rule in native for rule in stream.profiles[p]) for p in profiles),
            ]
        )
    )
    return [*lines, ""]


def _mapping_lines(family: Family) -> list[str]:
    def listed(entries: tuple[str, ...]) -> str:
        return ", ".join(f"`{entry}`" for entry in entries) or "none"

    return [
        (
            f"| `{family.name}` | {listed(family.topic_groups)} | "
            f"{listed(family.rule_prefixes)} | {listed(family.fallback_groups)} |"
        )
    ]


REFERENCE_INTRO: Final[tuple[str, ...]] = (
    "# Control families",
    "",
    "Scope: the control families (topics) of the rule catalogue, how every rule of the pinned",
    "profiles is assigned to one, and how many rules each family holds per profile. Audience:",
    "operators, family authors and reviewers. Jira: FREES-53. Decision:",
    "[ADR 0011](adr/0011-control-toggles-and-cleanup.md) (amendment of FREES-53).",
    "",
    "This page is generated by `make catalogue` from the family mapping",
    "[`content/catalogue.yml`](../content/catalogue.yml) and the digest-verified datastreams of",
    "[`content/manifest.yml`](../content/manifest.yml), together with the catalogue",
    "[`roles/remediate/vars/rules.yml`](../roles/remediate/vars/rules.yml). Do not edit either",
    "by hand: the CI job `test` (`make test-content-golden`) regenerates both from the pinned",
    "content and fails on any difference. Only rule, group and profile identifiers of the",
    "BSD-3-Clause ComplianceAsCode content appear here.",
    "",
    "The catalogue holds every rule that at least one pinned profile selects. Each has a rule",
    "toggle, and each family a topic toggle",
    "([remediation variable reference](remediation-variables.md)), so",
    "`linux_compliance_auditd_enabled: false` removes every auditd rule of the profile from the",
    "audit and from remediation. Each family is one subsystem, such as `sssd`, `time_sync`,",
    "`pwquality` or `firewalld`. Families that belong together are grouped by an umbrella",
    "toggle: `linux_compliance_services_enabled: false` switches off every family whose",
    "umbrella is `services`, whatever their own topic toggles say. An umbrella is either a name",
    "of its own, such as `services`, or a family that heads it, such as `pam` for `pwquality`,",
    "`pwhistory` and `faillock`. Every umbrella keeps the name of the family it was split from,",
    "so it switches off exactly the rules that family held before the split",
    "([ADR 0011](adr/0011-control-toggles-and-cleanup.md), amendment of the FREES-53 topic",
    "split). A rule without a native remediation has the strategy",
    "`audit_only`: the audit scans it, or excludes it and reports it as `disabled` when it is",
    "switched off, and remediation reports it as `not_implemented` and never changes anything",
    "for it ([remediation guide](remediation.md#effective-state-of-a-rule)).",
    "",
    "## How a rule gets its family",
    "",
    "ComplianceAsCode sorts its rules into a hierarchy of XCCDF groups, for example",
    "`system/permissions/files`. The first of these steps that decides a rule assigns its",
    "family:",
    "",
    "1. **Topic groups**: a group that contains the rule at any depth. Every rule below it",
    "   belongs to the family, whatever its identifier, so the `auditing` group takes the audit",
    "   log permissions and the `audit=1` boot argument to `auditd`. A rule below several topic",
    "   groups belongs to the innermost one when all of their families share an umbrella, so",
    "   `journald` refines `logging`; otherwise it fails the generator.",
    "2. **Rule prefixes**: the start of the short rule identifier, for rules whose mechanism",
    "   defines the topic, such as `file_permissions_`, `sysctl_`, `kernel_module_`,",
    "   `mount_option_` and `grub2_`. No prefix may be the start of another, so at most one",
    "   matches.",
    "3. **Fallback groups**: the innermost group that contains the rule and is listed.",
    "",
    "The generator fails, and nothing is guessed, when a rule maps to no family, when two",
    "datastreams assign one rule to different families, when a group is mapped twice, when a",
    "mapping entry decides no rule and when a native rule is not selected by any pinned",
    "profile.",
    "",
    "## Families",
    "",
    "The order is the dispatch order of the remediate role: non-disruptive families first, then",
    "the families in order of growing lock-out risk, with the boot loader last. Remediation",
    "applies and cleans up the rules of a disruptive family only when",
    "`linux_compliance_remediate_allow_disruptive` names it or its umbrella. The why column",
    "justifies the disruptive flag of each family. A family split from another keeps the flag of",
    "the family it came from, so the split changes nothing that the allow-list gates.",
    "",
    (
        "| Order | Family | Umbrella | Topic | Disruptive | Why | Catalogued rules | Native | "
        "`audit_only` |"
    ),
    "|---|---|---|---|---|---|---|---|---|",
)


def _umbrella_lines(built: Catalogue) -> list[str]:
    families = {family.name: family.disruptive for family in built.source.families}
    umbrellas = {
        family.name: family.umbrella
        for family in built.source.families
        if family.umbrella is not None
    }
    lines = [
        "",
        "## Umbrellas",
        "",
        "An umbrella toggle that is `false` switches off every family it groups; a family",
        "toggle can only narrow it. A rule toggle that is set wins over both. An allow-list",
        "entry that names an umbrella allows every disruptive family it groups.",
        "",
        "| Umbrella toggle | Families | Catalogued rules |",
        "|---|---|---|",
    ]
    for topic in toggles.topics(families, umbrellas):
        members = toggles.governed(topic, families, umbrellas)
        if members == [topic]:
            continue
        count = sum(rule["family"] in members for rule in built.rules)
        listed = ", ".join(f"`{member}`" for member in members)
        lines.append(_cell([f"`{toggles.toggle_name(topic)}`", listed, count]))
    return lines


def reference(built: Catalogue) -> str:
    """Return the Markdown reference page of the control families."""
    lines: list[str] = list(REFERENCE_INTRO)
    for order, family in enumerate(built.source.families, start=1):
        members = [rule for rule in built.rules if rule["family"] == family.name]
        native = sum(toggles.is_native(rule) for rule in members)
        lines.append(
            _cell(
                [
                    order,
                    f"`{family.name}`",
                    "none" if family.umbrella is None else f"`{family.umbrella}`",
                    family.title,
                    "yes" if family.disruptive else "no",
                    family.why,
                    len(members),
                    native,
                    len(members) - native,
                ]
            )
        )
    total_native = sum(toggles.is_native(rule) for rule in built.rules)
    lines.append(
        _cell(
            [
                "",
                "All",
                "",
                "",
                "",
                "",
                len(built.rules),
                total_native,
                len(built.rules) - total_native,
            ]
        )
    )
    lines.extend(_umbrella_lines(built))
    lines.extend(
        [
            "",
            "## Rules per profile",
            "",
            "Each profile counts every rule it selects once. A rule shared by several profiles",
            "or datastreams is one catalogue entry with one toggle.",
            "",
        ]
    )
    for stream in built.streams:
        lines.extend(_profile_table(built, stream))
    lines.extend(
        [
            "## Mapping",
            "",
            "| Family | Topic groups | Rule prefixes | Fallback groups |",
            "|---|---|---|---|",
        ]
    )
    for family in built.source.families:
        lines.extend(_mapping_lines(family))
    return "\n".join(lines) + "\n"


def outputs(built: Catalogue) -> dict[Path, str]:
    """Return the generated content of the catalogue and of the reference page."""
    return {CATALOGUE: render_catalogue(built), REFERENCE: reference(built)}


def streams_of(manifest: fetch_content.Manifest, content_dir: Path) -> list[Stream]:
    """Return the pinned datastreams of ``manifest`` as files below ``content_dir``."""
    streams: list[Stream] = []
    for datastream in manifest.datastreams:
        path = (content_dir / datastream.file_name).resolve()
        if not path.is_file():
            message = f"the pinned content {path} is missing; run make content"
            raise _fail(message)
        streams.append(
            Stream(
                name=datastream.name,
                path=path,
                sha256=datastream.sha256,
                profile_ids=tuple(profile.profile_id for profile in datastream.profiles),
            )
        )
    return streams


def generate(root: Path, content_dir: Path) -> dict[Path, str]:
    """Read the source, the manifest and the content below ``root`` and return the outputs."""
    source = load_source(root / SOURCE)
    try:
        manifest = fetch_content.load_manifest(root / MANIFEST)
    except fetch_content.ContentError as error:
        message = f"{MANIFEST}: {error}"
        raise _fail(message) from error
    streams = [read_stream(stream) for stream in streams_of(manifest, root / content_dir)]
    return outputs(build(source, streams))


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path())
    parser.add_argument("--content-dir", type=Path, default=CONTENT_DIR)
    parser.add_argument("--check", action="store_true", help="report drift instead of writing")
    arguments = parser.parse_args(argv)
    root = cast("Path", arguments.root)
    try:
        generated = generate(root, cast("Path", arguments.content_dir))
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if arguments.check:
        differences = generate_toggles.drift(root, generated)
        if differences:
            print("\n".join(differences), file=sys.stderr)
            print("error: the catalogue is out of date; run make catalogue", file=sys.stderr)
            return 1
        print(f"{CATALOGUE} and {REFERENCE} match the pinned content")
        return 0
    for relative, content in generated.items():
        (root / relative).write_text(content, encoding="utf-8")
    print(f"generated {CATALOGUE} and {REFERENCE} from the pinned content; run make toggles next")
    return 0


if __name__ == "__main__":
    sys.exit(main())
