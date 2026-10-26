"""DISA STIG benchmark definitions read from the operator's own scan content (FREES-147).

A STIG Viewer checklist needs each rule's group ID (``V-``), rule ID (``SV-``), STIG ID,
titles, severity and CCIs. The normalized findings carry only the rule ID and the
outcome, so these fields come from the XCCDF 1.2 benchmark that the scan evaluated, at
export time, and are never committed to the repository (ADR 0020):

- an evidence bundle's own XCCDF results, which embed the evaluated benchmark and the
  ``TestResult`` with the target facts of the scanned host;
- or a file named with ``--checklist-content``: an XCCDF 1.2 benchmark, XCCDF results or a
  SCAP 1.2 or 1.3 source data stream, for example the pinned DISA benchmark.

Every file is read through :mod:`tools.reporting.xmlsafe` (no DTD, no entities, bounded
size, depth and element count). Only groups and rules with DISA identifiers are read; a
benchmark whose rules are not DISA STIG rules (ComplianceAsCode content, for example)
yields no rules. Text is cut to a bound and stripped of control and formatting
characters, and the checklist writers escape it again.
"""

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from tools.reporting.common import InvalidInputError, clean_text
from tools.reporting.xmlsafe import XmlNode, parse_xml

XCCDF_NAMESPACE: Final[str] = "http://checklists.nist.gov/xccdf/1.2"
DATA_STREAM_NAMESPACE: Final[str] = "http://scap.nist.gov/schema/scap/source/1.2"
DISA_BENCHMARK_PREFIX: Final[str] = "xccdf_mil.disa.stig_benchmark_"
DISA_RULE: Final[re.Pattern[str]] = re.compile(
    r"xccdf_mil\.disa\.stig_rule_(SV-[0-9]+r[0-9]+_rule)"
)
DISA_GROUP: Final[re.Pattern[str]] = re.compile(r"xccdf_mil\.disa\.stig_group_(V-[0-9]+)")
SEVERITIES: Final[frozenset[str]] = frozenset({"high", "medium", "low"})
CCI_SYSTEMS: Final[frozenset[str]] = frozenset({"http://cyber.mil/cci", "http://iase.disa.mil/cci"})
LEGACY_SYSTEMS: Final[frozenset[str]] = frozenset({"http://cyber.mil/legacy"})
FQDN_FACTS: Final[frozenset[str]] = frozenset(
    {"urn:xccdf:fact:asset:identifier:fqdn", "urn:scap:fact:asset:identifier:fqdn"}
)
HOST_NAME_FACTS: Final[frozenset[str]] = frozenset(
    {"urn:xccdf:fact:asset:identifier:host_name", "urn:scap:fact:asset:identifier:host_name"}
)
DPMS_TARGET: Final[str] = "DPMS Target"
MAX_FIELD_LENGTH: Final[int] = 65536
MAX_SHORT_LENGTH: Final[int] = 512
MAX_ADDRESSES: Final[int] = 16
DESCRIPTION_FIELDS: Final[tuple[str, ...]] = (
    "VulnDiscussion",
    "FalsePositives",
    "FalseNegatives",
    "Documentable",
    "Mitigations",
    "SeverityOverrideGuidance",
    "PotentialImpacts",
    "ThirdPartyTools",
    "MitigationControl",
    "Responsibility",
    "IAControls",
)
_ENTITIES: Final[tuple[tuple[str, str], ...]] = (
    ("&lt;", "<"),
    ("&gt;", ">"),
    ("&quot;", '"'),
    ("&apos;", "'"),
    ("&amp;", "&"),
)


@dataclass(frozen=True)
class StigRule:
    """The checklist fields of one DISA STIG rule.

    Attributes:
        rule_id: The full XCCDF rule ID, which the findings carry.
        rule_ref: The DISA rule ID with its revision, ``SV-<n>r<n>_rule``.
        group_id: The DISA group ID (vulnerability number), ``V-<n>``.
        group_title: The title of the group (the SRG ID in DISA content).
        group_description: The description of the group.
        version: The STIG ID (the rule's XCCDF ``version``).
        title: The rule title.
        severity: ``high``, ``medium`` or ``low``.
        weight: The rule weight as written in the content.
        description: The fields of the rule description, by DISA tag name.
        check_content: The first check text of the rule, or empty.
        check_ref: The ``href`` and ``name`` of the first check content reference.
        fix_text: The fix text.
        ccis: The CCI identifiers of the rule.
        legacy_ids: The legacy identifiers of the rule.
        target_key: The DPMS target key of the rule, or empty.
    """

    rule_id: str
    rule_ref: str
    group_id: str
    group_title: str
    group_description: str
    version: str
    title: str
    severity: str
    weight: str
    description: Mapping[str, str]
    check_content: str
    check_ref: tuple[str, str]
    fix_text: str
    ccis: tuple[str, ...]
    legacy_ids: tuple[str, ...]
    target_key: str


@dataclass(frozen=True)
class TargetFacts:
    """What the ``TestResult`` of XCCDF results says about the scanned host.

    Attributes:
        names: Every ``target`` and host name fact, lower-cased, in document order.
        fqdns: Every fqdn fact, in document order.
        addresses: Every ``target-address`` that is a routable IP address.
        benchmark_id: The benchmark that the ``TestResult`` names, or ``None``.
        profile_id: The profile that the ``TestResult`` names, or ``None``.
    """

    names: tuple[str, ...]
    fqdns: tuple[str, ...]
    addresses: tuple[str, ...]
    benchmark_id: str | None
    profile_id: str | None


@dataclass(frozen=True)
class StigBenchmark:
    """The checklist fields of one DISA STIG benchmark, rules in document order.

    Attributes:
        benchmark_id: The full XCCDF benchmark ID.
        title: The benchmark title.
        version: The benchmark version.
        release_info: The ``release-info`` plain text, or empty.
        description: The benchmark description.
        notice: The ID of the benchmark notice, or empty.
        rules: The DISA rules of the benchmark.
        target: The target facts of the ``TestResult``, or ``None`` without one.
    """

    benchmark_id: str
    title: str
    version: str
    release_info: str
    description: str
    notice: str
    rules: tuple[StigRule, ...]
    target: TargetFacts | None

    @property
    def stig_id(self) -> str:
        """Return the benchmark ID without the XCCDF 1.2 prefix of DISA content."""
        return self.benchmark_id.removeprefix(DISA_BENCHMARK_PREFIX)

    def rule_map(self) -> Mapping[str, StigRule]:
        """Return the rules by full XCCDF rule ID."""
        return MappingProxyType({rule.rule_id: rule for rule in self.rules})


def _xccdf(node: XmlNode, local: str) -> bool:
    return node.tag == f"{{{XCCDF_NAMESPACE}}}{local}"


def _children(node: XmlNode, local: str) -> list[XmlNode]:
    return [child for child in node.children if _xccdf(child, local)]


def _text(node: XmlNode, local: str, limit: int = MAX_SHORT_LENGTH) -> str:
    found = _children(node, local)
    return clean_text(found[0].text.strip(), limit) if found else ""


def _unescape(text: str) -> str:
    for entity, character in _ENTITIES:
        text = text.replace(entity, character)
    return text


def description_fields(text: str) -> dict[str, str]:
    """Return the DISA description fields (``<VulnDiscussion>`` and the others) of ``text``.

    DISA writes them as escaped markup inside the XCCDF description, so after parsing
    they are plain text with tags. A field that is absent is empty.
    """
    fields: dict[str, str] = {}
    for name in DESCRIPTION_FIELDS:
        found = re.search(rf"<{name}>(.*?)</{name}>", text, re.DOTALL)
        value = "" if found is None else _unescape(found.group(1)).strip()
        fields[name] = clean_text(value, MAX_FIELD_LENGTH)
    return fields


def _check(rule: XmlNode) -> tuple[str, tuple[str, str]]:
    content = ""
    reference = ("", "")
    for check in _children(rule, "check"):
        texts = [child.text.strip() for child in _children(check, "check-content")]
        if not content and texts and texts[0]:
            content = clean_text(texts[0], MAX_FIELD_LENGTH)
        refs = _children(check, "check-content-ref")
        if reference == ("", "") and refs:
            reference = (
                clean_text(refs[0].attributes.get("href", ""), MAX_SHORT_LENGTH),
                clean_text(refs[0].attributes.get("name", ""), MAX_SHORT_LENGTH),
            )
    return content, reference


def _idents(rule: XmlNode, systems: frozenset[str]) -> tuple[str, ...]:
    values = (
        clean_text(ident.text.strip(), MAX_SHORT_LENGTH)
        for ident in _children(rule, "ident")
        if ident.attributes.get("system") in systems
    )
    return tuple(value for value in values if value)


def _target_key(rule: XmlNode) -> str:
    for reference in _children(rule, "reference"):
        locals_ = {child.local: child.text.strip() for child in reference.children}
        if locals_.get("type") == DPMS_TARGET:
            return clean_text(locals_.get("identifier", ""), MAX_SHORT_LENGTH)
    return ""


def _rule(group: XmlNode, group_id: str, rule: XmlNode) -> StigRule | None:
    matched = DISA_RULE.fullmatch(rule.attributes.get("id", ""))
    if matched is None:
        return None
    severity = rule.attributes.get("severity", "")
    if severity not in SEVERITIES:
        message = f"the DISA rule {matched.group(1)} has no severity of high, medium or low"
        raise InvalidInputError(message)
    check_content, check_ref = _check(rule)
    descriptions = _children(rule, "description")
    return StigRule(
        rule_id=matched.group(0),
        rule_ref=matched.group(1),
        group_id=group_id,
        group_title=_text(group, "title"),
        group_description=_text(group, "description", MAX_FIELD_LENGTH),
        version=_text(rule, "version"),
        title=_text(rule, "title", MAX_FIELD_LENGTH),
        severity=severity,
        weight=clean_text(rule.attributes.get("weight", "10.0"), 32),
        description=MappingProxyType(
            description_fields(descriptions[0].text if descriptions else "")
        ),
        check_content=check_content,
        check_ref=check_ref,
        fix_text=_text(rule, "fixtext", MAX_FIELD_LENGTH),
        ccis=_idents(rule, CCI_SYSTEMS),
        legacy_ids=_idents(rule, LEGACY_SYSTEMS),
        target_key=_target_key(rule),
    )


def _rules(benchmark: XmlNode) -> tuple[StigRule, ...]:
    rules: list[StigRule] = []
    pending = list(reversed(_children(benchmark, "Group")))
    while pending:
        group = pending.pop()
        pending.extend(reversed(_children(group, "Group")))
        matched = DISA_GROUP.fullmatch(group.attributes.get("id", ""))
        if matched is None:
            continue
        for node in _children(group, "Rule"):
            rule = _rule(group, matched.group(1), node)
            if rule is not None:
                rules.append(rule)
    identifiers = [rule.rule_id for rule in rules]
    if len(set(identifiers)) != len(identifiers):
        message = "the benchmark lists a DISA rule more than once"
        raise InvalidInputError(message)
    return tuple(rules)


def _routable(text: str) -> str | None:
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if address.is_loopback or address.is_link_local or address.is_unspecified:
        return None
    return str(address)


def _target(benchmark: XmlNode) -> TargetFacts | None:
    results = _children(benchmark, "TestResult")
    if not results:
        return None
    if len(results) > 1:
        message = "the XCCDF results hold more than one TestResult"
        raise InvalidInputError(message)
    result = results[0]
    facts = [fact for node in _children(result, "target-facts") for fact in node.children]
    names = [node.text for node in _children(result, "target")] + [
        fact.text for fact in facts if fact.attributes.get("name") in HOST_NAME_FACTS
    ]
    fqdns = [fact.text for fact in facts if fact.attributes.get("name") in FQDN_FACTS]
    addresses = [_routable(node.text) for node in _children(result, "target-address")]
    routable = list(dict.fromkeys(address for address in addresses if address is not None))
    benchmark_refs = _children(result, "benchmark")
    profiles = _children(result, "profile")
    return TargetFacts(
        names=tuple(clean_text(name.strip().lower(), 253) for name in names if name.strip()),
        fqdns=tuple(clean_text(fqdn.strip(), 253) for fqdn in fqdns if fqdn.strip()),
        addresses=tuple(routable[:MAX_ADDRESSES]),
        benchmark_id=benchmark_refs[0].attributes.get("id") if benchmark_refs else None,
        profile_id=profiles[0].attributes.get("idref") if profiles else None,
    )


def _plain_text(benchmark: XmlNode, identifier: str) -> str:
    for node in _children(benchmark, "plain-text"):
        if node.attributes.get("id") == identifier:
            return clean_text(node.text.strip(), MAX_SHORT_LENGTH)
    return ""


def _benchmark(node: XmlNode) -> StigBenchmark:
    notices = _children(node, "notice")
    return StigBenchmark(
        benchmark_id=clean_text(node.attributes.get("id", ""), 256),
        title=_text(node, "title"),
        version=_text(node, "version"),
        release_info=_plain_text(node, "release-info"),
        description=_text(node, "description", MAX_FIELD_LENGTH),
        notice=clean_text(notices[0].attributes.get("id", ""), MAX_SHORT_LENGTH) if notices else "",
        rules=_rules(node),
        target=_target(node),
    )


def _benchmark_nodes(root: XmlNode) -> list[XmlNode]:
    if _xccdf(root, "Benchmark"):
        return [root]
    if root.tag != f"{{{DATA_STREAM_NAMESPACE}}}data-stream-collection":
        message = "the content is neither an XCCDF 1.2 benchmark nor a SCAP source data stream"
        raise InvalidInputError(message)
    components = [
        child for child in root.children if child.tag == f"{{{DATA_STREAM_NAMESPACE}}}component"
    ]
    return [
        child
        for component in components
        for child in component.children
        if _xccdf(child, "Benchmark")
    ]


def read_benchmarks(data: bytes) -> tuple[StigBenchmark, ...]:
    """Return every XCCDF 1.2 benchmark of the content ``data``, in document order.

    Raises:
        InvalidInputError: If the XML is unsafe or malformed, is not XCCDF 1.2 or a
            source data stream, holds no benchmark, or has a DISA rule without a valid
            severity or listed twice.
    """
    benchmarks = tuple(_benchmark(node) for node in _benchmark_nodes(parse_xml(data)))
    if not benchmarks:
        message = "the content holds no XCCDF 1.2 benchmark"
        raise InvalidInputError(message)
    return benchmarks
