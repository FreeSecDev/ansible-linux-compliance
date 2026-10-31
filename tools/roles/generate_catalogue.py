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
revert strategy and parameters; every other rule gets the strategy ``audit_only``.

``subsystem_tags`` (FREES-165) give rules secondary families, the subsystems they are about: a
rule pattern tags every rule whose short identifier contains it, a group every rule below it,
unless an exclusion with a reason lists the rule (:func:`derive_tags`). A rule of an
``untagged_families`` family that a tag finds without an exclusion, an entry that finds no rule
and an exclusion that excludes nothing are errors, so the tags cannot drift from the content.
``ledger_family_aliases`` are copied into the catalogue for the remediation plan. The tool
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
from tools.roles import generate_toggles, profile_values

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
SOURCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "families",
        "native_rules",
        "subsystem_tags",
        "untagged_families",
        "ledger_family_aliases",
    }
)
FAMILY_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "disruptive", "title", "why", "topic_groups", "rule_prefixes", "fallback_groups"}
)
TAG_KEYS: Final[frozenset[str]] = frozenset({"name", "rule_patterns", "groups", "exclusions"})
EXCLUSION_KEYS: Final[frozenset[str]] = frozenset({"reason", "rules"})
UNTAGGED_KEYS: Final[frozenset[str]] = frozenset({"family", "reason"})
TAG_TIERS: Final[tuple[str, ...]] = ("rule_patterns", "groups")
RULE_PATTERN_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9_.+-]{1,63}")
SHORT_RULE_NAME: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
UMBRELLA_KEY: Final[str] = toggles.UMBRELLA_KEY
NATIVE_KEYS: Final[frozenset[str]] = frozenset(
    {"rule_id", "revert_strategy", "runbook", "parameters"}
)
PROFILE_VALUE_KEY: Final[str] = "profile_value"
PROFILE_VALUE_ID_KEY: Final[str] = "profile_value_id"
OPTIONAL_NATIVE_KEYS: Final[frozenset[str]] = frozenset({PROFILE_VALUE_KEY, PROFILE_VALUE_ID_KEY})
GENERATED_PARAMETERS: Final[tuple[str, ...]] = ("value_id", "profile_values")
VALUE_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9_]{0,127}")
VALUE_ID: Final[re.Pattern[str]] = re.compile(
    re.escape(profile_values.VALUE_PREFIX) + r"(?P<short>[a-z0-9][a-z0-9_]{0,127})"
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
class Tag:
    """A subsystem tag: a family, the entries that find the rules about it, and the exclusions.

    ``exclusions`` maps the short identifier of every excluded rule to the documented reason.
    """

    name: str
    rule_patterns: tuple[str, ...]
    groups: tuple[str, ...]
    exclusions: dict[str, str]

    def entries(self, tier: str) -> tuple[str, ...]:
        """Return the entries of ``tier`` (one of :data:`TAG_TIERS`)."""
        return self.rule_patterns if tier == "rule_patterns" else self.groups


@dataclass(frozen=True)
class Source:
    """The validated ``content/catalogue.yml``: the registry, the native rules and the tags.

    ``untagged`` maps every family whose rules never get a subsystem tag to the reason, and
    ``aliases`` maps a former family name of the state ledger to the families that its rules may
    belong to now.
    """

    families: tuple[Family, ...]
    native_rules: dict[str, dict[str, object]]
    tags: tuple[Tag, ...]
    untagged: dict[str, str]
    aliases: dict[str, list[str]]


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
    values: profile_values.StreamValues | None = None


@dataclass(frozen=True)
class Catalogue:
    """The generated catalogue together with the data that the reference page reports.

    ``tags`` maps every subsystem tag that tags a rule to the sorted rules that it tags.
    """

    source: Source
    rules: list[dict[str, object]]
    streams: tuple[StreamRules, ...]
    tags: dict[str, list[str]]


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
    if table is None or frozenset(table) - OPTIONAL_NATIVE_KEYS != NATIVE_KEYS:
        message = (
            f"{where} must be a mapping with exactly {sorted(NATIVE_KEYS)} "
            f"and an optional {PROFILE_VALUE_KEY!r} or {PROFILE_VALUE_ID_KEY!r}"
        )
        raise _fail(message)
    if PROFILE_VALUE_KEY in table and PROFILE_VALUE_ID_KEY in table:
        message = f"{where} may set {PROFILE_VALUE_KEY!r} or {PROFILE_VALUE_ID_KEY!r}, not both"
        raise _fail(message)
    value = table.get(PROFILE_VALUE_KEY)
    if PROFILE_VALUE_KEY in table and not (isinstance(value, str) and VALUE_NAME.fullmatch(value)):
        message = f"{where}.{PROFILE_VALUE_KEY} must be the short identifier of an XCCDF value"
        raise _fail(message)
    pinned = table.get(PROFILE_VALUE_ID_KEY)
    if PROFILE_VALUE_ID_KEY in table and not (
        isinstance(pinned, str) and VALUE_ID.fullmatch(pinned)
    ):
        message = (
            f"{where}.{PROFILE_VALUE_ID_KEY} must be the full identifier of an XCCDF value, "
            f"starting with {profile_values.VALUE_PREFIX!r}"
        )
        raise _fail(message)
    parameters = toggles.as_mapping(table["parameters"])
    if parameters is None or set(parameters) & set(GENERATED_PARAMETERS):
        message = (
            f"{where}.parameters must be a mapping without the generated keys "
            f"{list(GENERATED_PARAMETERS)}"
        )
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
    if value is not None:
        details[PROFILE_VALUE_KEY] = value
    if pinned is not None:
        details[PROFILE_VALUE_ID_KEY] = pinned
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


def _exclusions(raw: object, where: str) -> dict[str, str]:
    items = toggles.as_sequence(raw)
    if items is None:
        message = f"{where}.exclusions must be a list"
        raise _fail(message)
    excluded: dict[str, str] = {}
    for index, item in enumerate(items):
        place = f"{where}.exclusions[{index}]"
        table = toggles.as_mapping(item)
        if table is None or frozenset(table) != EXCLUSION_KEYS:
            message = f"{place} must be a mapping with exactly {sorted(EXCLUSION_KEYS)}"
            raise _fail(message)
        reason = _text(table, "reason", place)
        rules = _texts(table["rules"], f"{place}.rules", SHORT_RULE_NAME)
        if not rules:
            message = f"{place}.rules must list at least one rule"
            raise _fail(message)
        for rule in rules:
            if rule in excluded:
                message = f"{where} excludes {rule} twice"
                raise _fail(message)
            excluded[rule] = reason
    return excluded


def _tag(raw: object, index: int, families: frozenset[str]) -> Tag:
    where = f"subsystem_tags[{index}]"
    table = toggles.as_mapping(raw)
    if table is None or frozenset(table) != TAG_KEYS:
        message = f"{where} must be a mapping with exactly {sorted(TAG_KEYS)}"
        raise _fail(message)
    name = table["name"]
    if not isinstance(name, str) or name not in families:
        message = f"{where}.name must be a family of the registry, got {name!r}"
        raise _fail(message)
    tag = Tag(
        name=name,
        rule_patterns=_texts(table["rule_patterns"], f"{where}.rule_patterns", RULE_PATTERN_NAME),
        groups=_texts(table["groups"], f"{where}.groups", GROUP_NAME),
        exclusions=_exclusions(table["exclusions"], where),
    )
    if not tag.rule_patterns and not tag.groups:
        message = f"{where} needs at least one rule pattern or group"
        raise _fail(message)
    return tag


def _tags(raw: object, families: frozenset[str]) -> tuple[Tag, ...]:
    items = toggles.as_sequence(raw)
    if items is None:
        message = f"{SOURCE}: subsystem_tags must be a list"
        raise _fail(message)
    tags = tuple(_tag(item, index, families) for index, item in enumerate(items))
    names = [tag.name for tag in tags]
    if names != sorted(set(names)):
        message = f"{SOURCE}: subsystem_tags must be sorted by name and name each family once"
        raise _fail(message)
    return tags


def _untagged(raw: object, families: frozenset[str]) -> dict[str, str]:
    items = toggles.as_sequence(raw)
    if items is None:
        message = f"{SOURCE}: untagged_families must be a list"
        raise _fail(message)
    untagged: dict[str, str] = {}
    for index, item in enumerate(items):
        where = f"untagged_families[{index}]"
        table = toggles.as_mapping(item)
        if table is None or frozenset(table) != UNTAGGED_KEYS:
            message = f"{where} must be a mapping with exactly {sorted(UNTAGGED_KEYS)}"
            raise _fail(message)
        family = table["family"]
        if not isinstance(family, str) or family not in families or family in untagged:
            message = f"{where}.family must be a family of the registry listed once, got {family!r}"
            raise _fail(message)
        untagged[family] = _text(table, "reason", where)
    return untagged


def _aliases(raw: object, families: Sequence[Family]) -> dict[str, list[str]]:
    errors = toggles.Errors()
    checked = toggles.check_family_aliases(
        raw, {family.name: family.disruptive for family in families}, errors
    )
    if errors.items:
        message = f"{SOURCE}: ledger_family_aliases: " + "; ".join(errors.items)
        raise _fail(message)
    return {former: sorted(targets) for former, targets in checked.items()}


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
    names = frozenset(family.name for family in families)
    return Source(
        families=families,
        native_rules=native,
        tags=_tags(table["subsystem_tags"], names),
        untagged=_untagged(table["untagged_families"], names),
        aliases=_aliases(table["ledger_family_aliases"], families),
    )


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
    try:
        values = profile_values.read_values(str(stream.path), stream.sha256)
    except profile_values.ProfileValueError as error:
        message = f"{stream.name}: {error}"
        raise _fail(message) from error
    return StreamRules(stream.name, benchmark.version, profiles, groups, values)


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


def tag_matches(rule_id: str, groups: Iterable[str], tag: Tag) -> list[tuple[str, str]]:
    """Return the entries (tier, entry) of ``tag`` that find the rule ``rule_id``.

    A rule pattern finds a rule whose short identifier, in lower case, contains it; a group finds
    a rule below it at any depth.
    """
    short = toggles.rule_short_id(rule_id).lower()
    found = [("rule_patterns", pattern) for pattern in tag.rule_patterns if pattern in short]
    below = set(groups)
    found.extend(("groups", group) for group in tag.groups if group in below)
    return found


def _listed(entries: Sequence[tuple[str, str]]) -> str:
    return ", ".join(f"{tier.replace('_', ' ').rstrip('s')} {entry!r}" for tier, entry in entries)


def _tag_rules(
    tag: Tag,
    source: Source,
    assigned: Mapping[str, str],
    groups: Mapping[str, frozenset[str]],
    problems: list[str],
) -> list[str]:
    used: set[tuple[str, str]] = set()
    excluded: set[str] = set()
    tagged: list[str] = []
    for rule_id in sorted(assigned):
        matched = tag_matches(rule_id, groups[rule_id], tag)
        used.update(matched)
        short = toggles.rule_short_id(rule_id)
        family = assigned[rule_id]
        if not matched or family == tag.name:
            continue
        if short in tag.exclusions:
            excluded.add(short)
        elif family in source.untagged:
            problems.append(
                f"{rule_id} matches the subsystem tag {tag.name} ({_listed(matched)}) but belongs "
                f"to {family}, whose rules are never tagged: list it in an exclusion of the tag "
                f"{tag.name} with a reason"
            )
        else:
            tagged.append(rule_id)
    problems.extend(
        f"the {tier} entry {entry!r} of the subsystem tag {tag.name} matches no rule of the "
        f"pinned profiles"
        for tier in TAG_TIERS
        for entry in tag.entries(tier)
        if (tier, entry) not in used
    )
    problems.extend(
        f"the subsystem tag {tag.name} excludes {short}, which is not a pinned rule of another "
        f"family that the tag matches"
        for short in sorted(set(tag.exclusions) - excluded)
    )
    return tagged


def derive_tags(
    source: Source, assigned: Mapping[str, str], groups: Mapping[str, frozenset[str]]
) -> dict[str, list[str]]:
    """Return, per subsystem tag, the sorted catalogued rules of other families that it tags.

    ``assigned`` maps every catalogued rule to its family and ``groups`` to every group that
    contains it in any datastream. A rule of another family that an entry of the tag finds is
    tagged unless an exclusion of the tag lists it. The drift check: a rule of an untagged family
    (``untagged_families``) that an entry finds fails the generation unless an exclusion lists
    it, and so do an entry that finds no rule and an exclusion that excludes nothing. A tag that
    tags no rule is left out.

    Raises:
        GenerationError: When the drift check finds a problem.
    """
    problems: list[str] = []
    tagged = {tag.name: _tag_rules(tag, source, assigned, groups, problems) for tag in source.tags}
    if problems:
        message = f"{len(problems)} subsystem tag problem(s): " + "; ".join(problems[:MAX_PROBLEMS])
        raise _fail(message)
    return {name: rules for name, rules in tagged.items() if rules}


def rule_groups(streams: Sequence[StreamRules]) -> dict[str, frozenset[str]]:
    """Return every group that contains each selected rule, in any of ``streams``."""
    found: dict[str, set[str]] = {}
    for stream in streams:
        for rule_id in selected_rules(stream):
            found.setdefault(rule_id, set()).update(stream.groups[rule_id])
    return {rule_id: frozenset(names) for rule_id, names in found.items()}


def native_parameters(
    rule_id: str, native: Mapping[str, object], streams: Sequence[StreamRules]
) -> dict[str, object]:
    """Return the parameters of a native rule, with its profile values when it names a value.

    A rule with ``profile_value`` or ``profile_value_id`` gets ``value_id`` and
    ``profile_values``: per datastream that selects it, the profiles that share one value and
    that value (:func:`profile_values.resolve`). ``profile_value`` names a value that the rule's
    checks export. ``profile_value_id`` pins the full identifier of a value that the checks do
    not export, because they accept a range; the value still comes only from each profile's
    ``refine-value`` and the value's options (ADR 0025).
    """
    parameters = dict(cast("Mapping[str, object]", native["parameters"]))
    pinned = native.get(PROFILE_VALUE_ID_KEY)
    value = (
        native.get(PROFILE_VALUE_KEY)
        if pinned is None
        else str(pinned).removeprefix(profile_values.VALUE_PREFIX)
    )
    if value is None:
        return parameters
    sources: list[profile_values.StreamProfiles] = []
    for stream in streams:
        if stream.values is None:
            message = f"{stream.name}: the values of the datastream were not read"
            raise _fail(message)
        sources.append(profile_values.StreamProfiles(stream.name, stream.values, stream.profiles))
    try:
        resolved = profile_values.resolve(sources, rule_id, str(value), pinned=pinned is not None)
    except profile_values.ProfileValueError as error:
        raise _fail(str(error)) from error
    parameters["value_id"] = value
    parameters["profile_values"] = resolved
    return parameters


def catalogue_entry(
    rule_id: str, family: Family, source: Source, streams: Sequence[StreamRules] = ()
) -> dict[str, object]:
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
        "parameters": {} if native is None else native_parameters(rule_id, native, streams),
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
    tags = derive_tags(source, assigned, rule_groups(streams))
    families = {family.name: family for family in source.families}
    rules = [
        catalogue_entry(rule_id, families[assigned[rule_id]], source, streams)
        for rule_id in sorted(assigned)
    ]
    errors = toggles.Errors()
    toggles.with_tags(
        toggles.load_catalogue(
            native_rules(rules), audit_only_rules(rules, source), registry(source), {}, errors
        ),
        tags,
        errors,
    )
    if errors.items:
        message = "the generated catalogue is invalid: " + "; ".join(errors.items)
        raise _fail(message)
    return Catalogue(source=source, rules=rules, streams=tuple(streams), tags=tags)


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
        generate_toggles.TAGS_KEY: built.tags,
        generate_toggles.ALIASES_KEY: built.source.aliases,
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
    "by hand: the CI job `test-suites` (`make test-content-golden`) regenerates both from the",
    "pinned content and fails on any difference. Only rule, group and profile identifiers of the",
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
    "so the rules of its families are exactly the rules that family held before the split",
    "([ADR 0011](adr/0011-control-toggles-and-cleanup.md), amendment of the FREES-53 topic",
    "split). Subsystem tags let a toggle also switch off rules of other families that are",
    "about its subsystem; [every such rule is listed](#what-a-toggle-switches-off-through-tags)",
    "(FREES-165). A rule without a native remediation has the strategy",
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
    for head in (topic for topic in families if topic in umbrellas.values()):
        grouped = [
            member for member in toggles.governed(head, families, umbrellas) if member != head
        ]
        names = ", ".join(f"`{member}`" for member in grouped)
        lines.extend(
            [
                "",
                f"`{head}` is both a topic and an umbrella: `{toggles.toggle_name(head)}: false`",
                f"switches off its own rules and those of {names}, and the allow-list entry",
                f"`{head}` allows all of them. There is no toggle or allow-list entry for the",
                f"rules of `{head}` alone; to remediate only those, allow `{head}` and switch",
                "the grouped families off with their own toggles.",
            ]
        )
    return lines


TAGS_INTRO: Final[tuple[str, ...]] = (
    "",
    "## Subsystem tags",
    "",
    "The steps above give every rule exactly one family, often the family of the mechanism",
    "it uses: the permissions of `/var/log/sssd` are `file_permissions`, the GNOME lock on",
    "smart card removal is `desktop`. A subsystem tag adds the family of the subsystem that",
    "such a rule is about (FREES-165), so that `linux_compliance_sssd_enabled: false` also",
    "switches off the permissions of the SSSD logs. A rule is off when the toggle of its",
    "family, of the umbrella of its family, of one of its tags or of the umbrella of a tag is",
    "`false`; a rule toggle that is set still wins. Tags only add ways to switch a rule off:",
    "a tag toggle that is `true` never switches a rule on. When several toggles are off,",
    "`disabled_by` names the first in this order: the umbrella of the family, the family, then",
    "each tag in alphabetical order, after the umbrella of that tag; else the rule toggle.",
    "",
    "Tags do not change what is disruptive. The allow-list",
    "`linux_compliance_remediate_allow_disruptive` and the disruptive flag stay properties of",
    "the family, because they gate what remediation changes on the host, and the family",
    "decides that: `file_permissions_crontab` is tagged `cron`, which is disruptive, but",
    "applying it only changes the mode of `/etc/crontab`, so it needs no allow-list entry.",
    "",
    "Tags are derived from the pinned content: a rule pattern tags every rule whose short",
    "identifier, in lower case, contains it, and a group tags every rule below it. An",
    "exclusion with a reason keeps a rule untagged. The generator fails when an entry finds no",
    "rule, when an exclusion excludes nothing and when an entry finds a rule of a family whose",
    "rules are never tagged and no exclusion lists it, so a new rule of the content cannot",
    "drift past a decision. The rules of these families are never tagged:",
    "",
)


def rule_tags(built: Catalogue) -> dict[str, tuple[str, ...]]:
    """Return the subsystem tags of every tagged rule, sorted, as :attr:`toggles.Catalogue.tags`."""
    found: dict[str, list[str]] = {}
    for tag, rule_ids in built.tags.items():
        for rule_id in rule_ids:
            found.setdefault(rule_id, []).append(tag)
    return {rule_id: tuple(sorted(tags)) for rule_id, tags in sorted(found.items())}


def _short_list(rule_ids: Iterable[str]) -> str:
    return ", ".join(f"`{toggles.rule_short_id(rule_id)}`" for rule_id in rule_ids)


def _exclusion_lines(tag: Tag) -> list[str]:
    reasons: dict[str, list[str]] = {}
    for short, reason in tag.exclusions.items():
        reasons.setdefault(reason, []).append(short)
    if not reasons:
        return []
    lines = ["", "Not tagged:", ""]
    lines.extend(
        f"- {', '.join(f'`{short}`' for short in shorts)}: {reason}."
        for reason, shorts in reasons.items()
    )
    return lines


def _tag_lines(built: Catalogue) -> list[str]:
    families_of_rules = {str(rule["rule_id"]): str(rule["family"]) for rule in built.rules}
    lines: list[str] = list(TAGS_INTRO)
    lines.extend(f"- `{family}`: {reason}." for family, reason in built.source.untagged.items())
    lines.extend(
        [
            "",
            "| Tag | Rule patterns | Groups | Tagged rules |",
            "|---|---|---|---|",
        ]
    )
    for tag in built.source.tags:
        patterns = ", ".join(f"`{pattern}`" for pattern in tag.rule_patterns) or "none"
        groups = ", ".join(f"`{group}`" for group in tag.groups) or "none"
        lines.append(_cell([f"`{tag.name}`", patterns, groups, len(built.tags.get(tag.name, []))]))
    for tag in built.source.tags:
        tagged = built.tags.get(tag.name, [])
        lines.extend(["", f"### Tag `{tag.name}`", ""])
        if tagged:
            lines.extend(["| Rule | Family |", "|---|---|"])
            lines.extend(
                _cell([f"`{toggles.rule_short_id(rule_id)}`", f"`{families_of_rules[rule_id]}`"])
                for rule_id in tagged
            )
        else:
            lines.append(
                "It tags no rule of another family of the pinned content; its entries keep new "
                "rules from drifting."
            )
        lines.extend(_exclusion_lines(tag))
    return lines


def _coverage_lines(built: Catalogue) -> list[str]:
    families = {family.name: family.disruptive for family in built.source.families}
    umbrellas = {
        family.name: family.umbrella
        for family in built.source.families
        if family.umbrella is not None
    }
    catalogue = toggles.Catalogue(
        rules=built.rules, families=families, toggles={}, umbrellas=umbrellas, tags=rule_tags(built)
    )
    lines = [
        "",
        "## What a toggle switches off through tags",
        "",
        "Every topic and umbrella toggle switches off the rules of the families it governs and,",
        "through the tags, these rules of other families. Every toggle of a former family keeps",
        "switching off exactly the rules of its families (the legacy fixture",
        "`tests/fixtures/catalog/legacy-families.yml` pins them), and switches off these rules",
        "in addition.",
        "",
        "| Toggle | Rules of its families | Added through tags | Added rules |",
        "|---|---|---|---|",
    ]
    for topic in toggles.topics(families, umbrellas):
        members = toggles.governed(topic, families, umbrellas)
        own = sum(rule["family"] in members for rule in built.rules)
        added = [
            str(rule["rule_id"])
            for rule in built.rules
            if rule["family"] not in members and toggles.switches_off(topic, rule, catalogue)
        ]
        if added:
            lines.append(
                _cell([f"`{toggles.toggle_name(topic)}`", own, len(added), _short_list(added)])
            )
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
    lines.extend(_tag_lines(built))
    lines.extend(_coverage_lines(built))
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
