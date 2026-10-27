"""Collection toggles and control families for the DISA STIG rules of SCC (ADR 0019, FREES-170).

SCC reports DISA rules, such as ``xccdf_mil.disa.stig_rule_SV-270645r1068357_rule``, while the
toggles of ADR 0011 and the control families switch and group ComplianceAsCode rules. The pinned
table ``content/stig-mapping.json`` (FREES-146) lists, for the ComplianceAsCode STIG profile of
each pinned datastream, the ComplianceAsCode rules that check each STIG ID. The DISA rule carries
its STIG ID as its XCCDF ``version``, which the audit role reads from the SCC run's own benchmark
on the managed host, so no DISA content is ever committed. This module joins the three:

- **Which mapping.** :data:`STIG_PROFILES` pairs each SCC benchmark with the ComplianceAsCode
  benchmark and STIG profile of the mapping. The release that the mapping implements
  (``V1R5``) must equal the release of the SCC benchmark's version (``001.005.007`` is V1R5);
  otherwise the run is refused (:class:`MappingError`), because a STIG ID may change meaning
  between releases. The mapping also pins the DISA benchmark ID of the profile and, where the
  pinned ComplianceAsCode stream states them, the STIG ID of each DISA rule; what the host
  reports must be that benchmark, and must not differ from those pairs (FREES-171).
- **All or nothing.** A DISA rule is disabled only when every ComplianceAsCode rule mapped to its
  STIG ID is disabled. Its ``disabled_by`` is the toggle variable that disables most of them, the
  alphabetically first on a tie. When only some are disabled, the rule stays enabled and its
  placement names the variables in ``partially_disabled_by``, and so does the run's
  ``partially_disabled`` list.
- **Unmapped rules.** A DISA rule whose STIG ID maps to no ComplianceAsCode rule, or that has no
  valid STIG ID, is never disabled by a toggle: no toggle governs it. It is scanned and reported,
  and only an explicit ``linux_compliance_audit_disabled_rules`` entry can disable it.
- **Family placement.** A DISA rule's family is the family that most of its catalogued mapped
  rules belong to, the alphabetically first on a tie. Its topic is the umbrella of that family, or
  the family when it has none. Its tags are the other families of its mapped rules and the
  subsystem tags of all of them. A rule with no catalogued mapped rule has the family and topic
  ``unmapped``.

It uses only the standard library and syntax that runs on Python 3.9.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, NoReturn, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    placement,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

STIG_PROFILES: Final[Mapping[str, tuple[str, str]]] = MappingProxyType(
    {
        "xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG": (
            "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04",
            "xccdf_org.ssgproject.content_profile_stig",
        )
    }
)
MAPPING_SCHEMA_VERSION: Final[int] = 1
MAX_MAPPING_CHARS: Final[int] = 16 * 1024 * 1024
DOCUMENT_KEYS: Final[frozenset[str]] = frozenset(
    {"schema_version", "generator", "source", "join_key", "datastreams"}
)
STREAM_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "file_name", "sha256", "benchmark_id", "benchmark_version", "profiles"}
)
PROFILE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "profile_id",
        "stig_release",
        "disa_benchmark_id",
        "stig_ids",
        "disa_rules",
        "rules_without_stig_id",
    }
)
_DISA_RULE_PREFIX: Final[str] = "xccdf_mil.disa.stig_rule_"
_DISA_RULE_REF: Final[str] = r"SV-[0-9]+r[0-9]+_rule"
_DISA_BENCHMARK: Final[str] = r"xccdf_mil\.disa\.stig_benchmark_[A-Za-z0-9_.+-]{1,200}"
_RELEASE: Final[str] = r"V([0-9]{1,3})R([0-9]{1,3})"
_DOTTED: Final[str] = r"([0-9]{1,3})\.([0-9]{1,3})(?:\.[0-9]{1,6})*"
_RULE: Final[str] = model.XCCDF_ID_PATTERNS["rule"]
MAX_ECHO_LENGTH: Final[int] = 64


class MappingError(ValueError):
    """Raised when the STIG mapping cannot be used for the SCC benchmark of a run."""


def _refuse(message: str) -> NoReturn:
    raise MappingError(message)


def _show(value: object) -> str:
    return repr(str(value)[:MAX_ECHO_LENGTH])


@dataclass(frozen=True)
class StigProfile:
    """The mapping of one ComplianceAsCode STIG profile.

    Attributes:
        benchmark_id: The ComplianceAsCode benchmark identifier.
        profile_id: The ComplianceAsCode STIG profile identifier.
        stig_release: The DISA release that the profile implements, ``V<n>R<n>``.
        disa_benchmark_id: The identifier of the DISA benchmark that the profile implements.
        checks: The ComplianceAsCode rules that check each STIG ID.
        disa_rules: The STIG ID that the pinned stream pairs with each DISA rule ID.
    """

    benchmark_id: str
    profile_id: str
    stig_release: str
    disa_benchmark_id: str
    checks: Mapping[str, tuple[str, ...]]
    disa_rules: Mapping[str, str]

    def mapped_rules(self) -> frozenset[str]:
        """Return every ComplianceAsCode rule that checks at least one STIG ID."""
        return frozenset(rule for rules in self.checks.values() for rule in rules)


@dataclass(frozen=True)
class SccRule:
    """A rule of the SCC profile and the STIG ID that its benchmark records for it."""

    rule_id: str
    stig_id: str | None


@dataclass(frozen=True)
class Families:
    """What places a ComplianceAsCode rule: its family, the umbrellas and its subsystem tags."""

    family_of: Mapping[str, str]
    umbrellas: Mapping[str, str]
    tags_of: Mapping[str, Sequence[str]]


@dataclass(frozen=True)
class Resolution:
    """The SCC rules that toggles disable, the placement of every rule and the partial disables.

    ``disabled`` and ``partial`` are sorted by rule identifier; ``placements`` holds one
    placement for every rule of the SCC profile, in the order of the profile's rules.
    """

    disabled: list[dict[str, object]]
    placements: list[dict[str, object]]
    partial: list[dict[str, object]]


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _refuse(f"the STIG mapping repeats the key {_show(key)}")
        result[key] = value
    return result


def _object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _refuse(f"{where} must be an object")
    return cast("dict[str, object]", value)


def _array(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        _refuse(f"{where} must be an array")
    return cast("list[object]", value)


def _exact(table: dict[str, object], keys: frozenset[str], where: str) -> None:
    if frozenset(table) != keys:
        _refuse(f"{where} must have exactly the keys {', '.join(sorted(keys))}")


def _identifier(value: object, pattern: str, where: str) -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        _refuse(f"{where} is not a valid identifier")
    return value


def _checks(value: object, where: str) -> Mapping[str, tuple[str, ...]]:
    table = _object(value, where)
    if not table or list(table) != sorted(table):
        _refuse(f"{where} must be a non-empty object with sorted STIG IDs")
    checks: dict[str, tuple[str, ...]] = {}
    for stig_id, raw in table.items():
        _identifier(stig_id, placement.STIG_ID_PATTERN, f"{where} key {_show(stig_id)}")
        rules = tuple(_identifier(item, _RULE, f"{where}.{stig_id}") for item in _array(raw, where))
        if not rules or list(rules) != sorted(set(rules)):
            _refuse(f"{where}.{stig_id} must name at least one rule, sorted and unique")
        checks[stig_id] = rules
    return MappingProxyType(checks)


def _disa_rules(value: object, checks: Mapping[str, tuple[str, ...]]) -> Mapping[str, str]:
    table = _object(value, "disa_rules")
    if list(table) != sorted(table):
        _refuse("disa_rules must be an object with sorted DISA rule IDs")
    pairs: dict[str, str] = {}
    for rule, raw in table.items():
        _identifier(rule, _DISA_RULE_REF, f"disa_rules key {_show(rule)}")
        stig_id = _identifier(raw, placement.STIG_ID_PATTERN, f"disa_rules.{rule}")
        if stig_id not in checks:
            _refuse(f"disa_rules.{rule} pairs a STIG ID that the profile does not map")
        pairs[rule] = stig_id
    return MappingProxyType(pairs)


def _stream_profiles(document: dict[str, object]) -> Iterable[tuple[str, dict[str, object]]]:
    for index, raw in enumerate(_array(document["datastreams"], "datastreams")):
        stream = _object(raw, f"datastreams[{index}]")
        _exact(stream, STREAM_KEYS, f"datastreams[{index}]")
        benchmark = _identifier(stream["benchmark_id"], model.XCCDF_ID_PATTERNS["benchmark"], "id")
        for number, item in enumerate(_array(stream["profiles"], f"datastreams[{index}]")):
            entry = _object(item, f"datastreams[{index}].profiles[{number}]")
            _exact(entry, PROFILE_KEYS, f"datastreams[{index}].profiles[{number}]")
            yield benchmark, entry


def read_profile(text: object, benchmark_id: str, profile_id: str) -> StigProfile:
    """Return the mapping of ``profile_id`` of ``benchmark_id`` from the mapping file ``text``.

    The document is read strictly: bounded strict JSON without duplicate keys, the exact key sets
    of ``content/stig-mapping.json`` schema 1, and the entry's identifiers checked against their
    patterns with every list sorted and unique.

    Raises:
        MappingError: If the document is invalid or holds no single entry for the profile.
    """
    if not isinstance(text, str) or len(text) > MAX_MAPPING_CHARS:
        _refuse(f"the STIG mapping must be the text of the file, at most {MAX_MAPPING_CHARS}")
    try:
        loaded: object = json.loads(text, object_pairs_hook=_reject_duplicates)
    except ValueError as error:
        if isinstance(error, MappingError):
            raise
        _refuse("the STIG mapping is not valid JSON")
    document = _object(loaded, "the STIG mapping")
    _exact(document, DOCUMENT_KEYS, "the STIG mapping")
    if document["schema_version"] != MAPPING_SCHEMA_VERSION:
        _refuse(f"the STIG mapping must have schema_version {MAPPING_SCHEMA_VERSION}")
    found = [
        entry
        for benchmark, entry in _stream_profiles(document)
        if (benchmark, entry["profile_id"]) == (benchmark_id, profile_id)
    ]
    if len(found) != 1:
        _refuse(
            f"the STIG mapping holds {len(found)} entries for {_show(profile_id)} of "
            f"{_show(benchmark_id)}, expected exactly one"
        )
    entry = found[0]
    checks = _checks(entry["stig_ids"], "stig_ids")
    return StigProfile(
        benchmark_id=benchmark_id,
        profile_id=profile_id,
        stig_release=_identifier(entry["stig_release"], _RELEASE, "stig_release"),
        disa_benchmark_id=_identifier(
            entry["disa_benchmark_id"], _DISA_BENCHMARK, "disa_benchmark"
        ),
        checks=checks,
        disa_rules=_disa_rules(entry["disa_rules"], checks),
    )


def release_of(version: str, release_info: str = "") -> str | None:
    """Return the DISA release ``V<n>R<n>`` that a DISA benchmark states, or ``None``.

    DISA SCAP benchmarks write the version as ``<version>.<release>[.<n>]`` (``001.005.007`` for
    V1R5); XCCDF STIG benchmarks write the version alone (``1``) and the release in the
    ``release-info`` text (``Release: 5 Benchmark Date: ...``). This is the rule of
    ``tools/reporting/stig_mapping.py`` that the checklist export applies.
    """
    dotted = re.fullmatch(_DOTTED, version)
    if dotted is not None:
        return f"V{int(dotted.group(1))}R{int(dotted.group(2))}"
    released = re.search(r"\bRelease:\s*([0-9]{1,3})\b", release_info)
    if re.fullmatch(r"[0-9]{1,3}", version) and released is not None:
        return f"V{int(version)}R{int(released.group(1))}"
    return None


def mapping_for(text: object, benchmark_id: str, benchmark_version: str) -> StigProfile:
    """Return the mapping for the SCC benchmark ``benchmark_id`` at ``benchmark_version``.

    Raises:
        MappingError: If no mapping is paired with the benchmark, if the mapping pins another DISA
            benchmark, or if the release that the mapping implements is not the release of the
            benchmark version.
    """
    pair = STIG_PROFILES.get(benchmark_id)
    if pair is None:
        _refuse(f"no STIG mapping is paired with the SCC benchmark {_show(benchmark_id)}")
    profile = read_profile(text, *pair)
    if profile.disa_benchmark_id != benchmark_id:
        _refuse(
            f"the STIG mapping pins the DISA benchmark {_show(profile.disa_benchmark_id)}, but "
            f"the SCC benchmark is {_show(benchmark_id)}; nothing was scanned"
        )
    release = release_of(benchmark_version)
    if release != profile.stig_release:
        _refuse(
            f"the STIG mapping implements {profile.stig_release}, but the SCC benchmark version "
            f"{_show(benchmark_version)} is {release or 'no DISA release'}; the toggles are not "
            "mapped across releases, so nothing was scanned"
        )
    return profile


def scc_rules(raw: object) -> tuple[SccRule, ...]:
    """Return the rules of the SCC profile: ``rule_id`` and ``version`` from ``profile_info``.

    A ``version`` that is not a STIG ID gives a rule without one, which no toggle governs.

    Raises:
        MappingError: If an item is not a mapping with string ``rule_id`` and ``version``, a rule
            identifier is invalid, or a rule is listed twice.
    """
    rules: list[SccRule] = []
    for item in _array(raw, "the SCC profile rules"):
        entry = _object(item, "an SCC profile rule")
        rule_id = _identifier(entry.get("rule_id"), _RULE, "an SCC rule_id")
        version = entry.get("version")
        if not isinstance(version, str):
            _refuse(f"the SCC rule {_show(rule_id)} has no version string")
        valid = re.fullmatch(placement.STIG_ID_PATTERN, version) is not None
        rules.append(SccRule(rule_id, version if valid else None))
    if len({rule.rule_id for rule in rules}) != len(rules):
        _refuse("the SCC profile lists a rule more than once")
    return tuple(rules)


def check_reported(rules: Sequence[SccRule], profile: StigProfile) -> None:
    """Refuse SCC rules whose STIG ID differs from the one that the pinned mapping pairs with them.

    The rules come from the SCC benchmark on the managed host, which the host controls. A rule
    that the mapping does not pair, which is every rule of the Ubuntu profile, is not checked.

    Raises:
        MappingError: If a reported STIG ID differs from the pinned one.
    """
    for rule in rules:
        pinned = profile.disa_rules.get(rule.rule_id.removeprefix(_DISA_RULE_PREFIX))
        if pinned is not None and pinned != rule.stig_id:
            _refuse(
                f"the SCC rule {_show(rule.rule_id)} reports the STIG ID {_show(rule.stig_id)}, "
                f"but the STIG mapping pairs it with {pinned}; nothing was scanned"
            )


def primary_family(families: Iterable[str]) -> str:
    """Return the family that occurs most often, the alphabetically first on a tie."""
    counts: dict[str, int] = {}
    for family in families:
        counts[family] = counts.get(family, 0) + 1
    return min(counts, key=lambda family: (-counts[family], family))


def _disabled_by(variables: Iterable[str]) -> str:
    return primary_family(variables)


def place(rule: SccRule, mapped: Sequence[str], families: Families) -> placement.ControlPlacement:
    """Return the control placement of ``rule`` whose STIG ID maps to ``mapped``."""
    catalogued = [name for name in mapped if name in families.family_of]
    if not catalogued:
        return placement.ControlPlacement(
            family=placement.UNMAPPED_FAMILY,
            topic=placement.UNMAPPED_FAMILY,
            tags=(),
            stig_id=rule.stig_id,
            mapped_rules=tuple(mapped),
            partially_disabled_by=(),
        )
    family = primary_family(families.family_of[name] for name in catalogued)
    tags = {families.family_of[name] for name in catalogued}
    for name in catalogued:
        tags.update(families.tags_of.get(name, ()))
    tags.discard(family)
    return placement.ControlPlacement(
        family=family,
        topic=families.umbrellas.get(family, family),
        tags=tuple(sorted(tags)),
        stig_id=rule.stig_id,
        mapped_rules=tuple(mapped),
        partially_disabled_by=(),
    )


def resolve(
    rules: Sequence[SccRule],
    profile: StigProfile,
    disabled: Mapping[str, str],
    families: Families,
    explicit: Mapping[str, str] | None = None,
) -> Resolution:
    """Resolve which SCC rules the disabled ComplianceAsCode rules disable, and place every rule.

    ``disabled`` maps each disabled ComplianceAsCode rule to its ``disabled_by`` and ``explicit``
    each SCC rule of an explicit ``linux_compliance_audit_disabled_rules`` entry to its
    ``disabled_by``, which wins over the toggles. See the module documentation for the rules.
    """
    chosen = explicit or {}
    switched: list[dict[str, object]] = []
    placements: list[dict[str, object]] = []
    partial: list[dict[str, object]] = []
    for rule in rules:
        mapped = profile.checks.get(rule.stig_id, ()) if rule.stig_id is not None else ()
        placed = place(rule, mapped, families)
        off = [name for name in mapped if name in disabled]
        variables = sorted({disabled[name] for name in off})
        if rule.rule_id in chosen:
            switched.append({"rule_id": rule.rule_id, "disabled_by": chosen[rule.rule_id]})
        elif mapped and len(off) == len(mapped):
            switched.append(
                {"rule_id": rule.rule_id, "disabled_by": _disabled_by(disabled[n] for n in off)}
            )
        elif off:
            placed = placement.ControlPlacement(
                family=placed.family,
                topic=placed.topic,
                tags=placed.tags,
                stig_id=placed.stig_id,
                mapped_rules=placed.mapped_rules,
                partially_disabled_by=tuple(variables),
            )
            partial.append(
                {
                    "rule_id": rule.rule_id,
                    "stig_id": rule.stig_id,
                    "disabled_by": variables,
                    "disabled_rules": sorted(off),
                    "enabled_rules": sorted(name for name in mapped if name not in disabled),
                    "note": f"partially disabled by {', '.join(variables)}",
                }
            )
        placements.append({"rule_id": rule.rule_id, **placed.to_dict()})
    return Resolution(
        sorted(switched, key=lambda item: str(item["rule_id"])),
        placements,
        sorted(partial, key=lambda item: str(item["rule_id"])),
    )
