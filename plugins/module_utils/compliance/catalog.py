"""Benchmark and profile discovery in SCAP datastreams on a managed host.

A datastream is untrusted until its SHA-256 matches the digest pinned in the
content manifest (ADR 0015). :func:`read_benchmarks` hashes the file first and
raises :class:`DigestMismatchError` without parsing a single byte on a mismatch.
The parse then reads the file again and hashes it again, so content that changes
between the two reads is also rejected.

Parsing goes through :mod:`xmlsafe` only: a bounded, streaming expat parser that
rejects DOCTYPE and ENTITY declarations. Elements are never stored; only the
benchmark, its profiles (with their version) and the identifier, severity and title
of its rules are kept, and the text of each rule's ``reference`` whose ``href`` is one
of :data:`STIG_ID_REFERENCES`: the DISA STIG IDs that ComplianceAsCode records for a
rule (FREES-146). The text of a rule's own ``version`` is kept too: a DISA benchmark
records the rule's STIG ID there (FREES-170). That text is kept as written; whoever
uses it validates it.

Rule selection follows XCCDF. Each ``select`` of a profile is classified by what
the benchmark defines, never by the shape of the identifier: the identifier of a
rule decides that rule, the identifier of a group decides that group. The last
``select`` wins. A rule the profile does not mention keeps the ``selected`` default
of the rule itself (true when absent), and a group is selected when the last
``select`` says so or else by its own default (true when absent).

Before root opens a datastream, :func:`vetted_content_path` resolves its real
path and vets the way to it, so that no user other than root (or the one other
owner that the caller accepts) can replace the file, for example with a FIFO whose
``open`` would block. The audit and the discover modules share it.

The catalog fails closed and never returns a partial or guessed rule list. These
raise :class:`UnsupportedContentError`: a profile with ``extends``, a ``select``
of an identifier that is neither a rule nor a group, an identifier that is both,
and a selected rule inside a deselected group. The pinned ComplianceAsCode
profiles contain group deselections only, and no selected rule sits below one.

Nothing here runs a process, writes a file or changes the host.
"""

from __future__ import annotations

import hashlib
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, NoReturn

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    scanner,
    xmlsafe,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Sequence

XCCDF_NAMESPACE: Final[str] = "http://checklists.nist.gov/xccdf/1.2"
DATASTREAM_NAMESPACE: Final[str] = "http://scap.nist.gov/schema/scap/source/1.2"
DATASTREAM_SUFFIX: Final[str] = "-ds.xml"
DEFAULT_MAX_BYTES: Final[int] = 256 * 1024 * 1024
MAX_PATH_LENGTH: Final[int] = 4096
MAX_DIRECTORY_ENTRIES: Final[int] = 10_000
MAX_PROFILES: Final[int] = 1_000
MAX_RULES: Final[int] = 100_000
MAX_TEXT_LENGTH: Final[int] = 512
_TEXT_BUDGET: Final[int] = MAX_TEXT_LENGTH * 4
HASH_CHUNK_BYTES: Final[int] = xmlsafe.READ_CHUNK_BYTES
ROOT_UID: Final[int] = 0
MAX_SYMLINKS: Final[int] = 40
MAX_ECHO_LENGTH: Final[int] = 64
ERROR_UNSAFE_CONTENT: Final[str] = "unsafe_content_dir"
ERROR_SCRIPT_CHECK: Final[str] = "script_check_content"
OVAL_CHECK_SYSTEM: Final[str] = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OCIL_CHECK_SYSTEM: Final[str] = "http://scap.nist.gov/schema/ocil/2"
SCE_CHECK_SYSTEM: Final[str] = "http://open-scap.org/page/SCE"
SCE_NAMESPACE: Final[str] = "http://open-scap.org/page/SCE_xccdf_stream"
ACCEPTED_CHECK_SYSTEMS: Final[frozenset[str]] = frozenset({OVAL_CHECK_SYSTEM, OCIL_CHECK_SYSTEM})
PROCESS_DIRECTORY: Final[str] = "/proc/self"
SEVERITIES: Final[frozenset[str]] = frozenset({"unknown", "info", "low", "medium", "high"})
STIG_ID_REFERENCES: Final[frozenset[str]] = frozenset(
    {"https://www.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux"}
)
DISA_RULE_REFERENCES: Final[frozenset[str]] = frozenset(
    {"https://www.cyber.mil/stigs/srg-stig-tools/"}
)
MAX_STIG_IDS: Final[int] = 64

_GROUP_ID: Final[str] = r"xccdf_[A-Za-z0-9_.+-]+"
_MAX_ID_LENGTH: Final[int] = 256
_SHA256: Final[str] = r"[0-9a-f]{64}"
_VERSION: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._+:~-]{0,63}"
_XML_LANG: Final[str] = "http://www.w3.org/XML/1998/namespace}lang"
_DROPPED_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})
_BOOLEANS: Final[dict[str, bool]] = {"true": True, "1": True, "false": False, "0": False}
_GROUP_OR_OTHER_WRITE: Final[int] = stat.S_IWGRP | stat.S_IWOTH
_ANCESTOR: Final[str] = "the content directory or an ancestor"


def _qualified(local: str) -> str:
    return f"{{{XCCDF_NAMESPACE}}}{local}"


_BENCHMARK: Final[str] = _qualified("Benchmark")
_PROFILE: Final[str] = _qualified("Profile")
_GROUP: Final[str] = _qualified("Group")
_RULE: Final[str] = _qualified("Rule")
_TITLE: Final[str] = _qualified("title")
_VERSION_TAG: Final[str] = _qualified("version")
_SELECT: Final[str] = _qualified("select")
_REFERENCE: Final[str] = _qualified("reference")
_COLLECTION: Final[str] = f"{{{DATASTREAM_NAMESPACE}}}data-stream-collection"
_CHECK: Final[str] = _qualified("check")
_EXTENDED_COMPONENT: Final[str] = f"{{{DATASTREAM_NAMESPACE}}}extended-component"
_SCE_PREFIX: Final[str] = f"{{{SCE_NAMESPACE}}}"

_OUTSIDE: Final[str] = "outside"
_BENCH: Final[str] = "benchmark"
_PROFILE_KIND: Final[str] = "profile"
_GROUP_KIND: Final[str] = "group"
_RULE_KIND: Final[str] = "rule"
_TITLE_KIND: Final[str] = "title"
_VERSION_KIND: Final[str] = "version"
_PROFILE_VERSION_KIND: Final[str] = "profile_version"
_STIG_ID_KIND: Final[str] = "stig_id"
_RULE_VERSION_KIND: Final[str] = "rule_version"
_DISA_RULE_KIND: Final[str] = "disa_rule"
_PART: Final[str] = "part"
_SELECT_KIND: Final[str] = "select"
_OTHER: Final[str] = "other"
_COLLECTING: Final[frozenset[str]] = frozenset(
    {
        _TITLE_KIND,
        _VERSION_KIND,
        _PROFILE_VERSION_KIND,
        _STIG_ID_KIND,
        _RULE_VERSION_KIND,
        _DISA_RULE_KIND,
        _PART,
    }
)
_TITLE_OWNERS: Final[frozenset[str]] = frozenset({_BENCH, _PROFILE_KIND, _RULE_KIND})


class CatalogError(ValueError):
    """Raised when content is missing, unsafe, malformed or not what was pinned."""


class DigestMismatchError(CatalogError):
    """Raised when a datastream does not have the pinned SHA-256."""


class ProfileNotFoundError(CatalogError):
    """Raised when a requested profile is not in the benchmark."""


class UnsupportedContentError(CatalogError):
    """Raised when content uses an XCCDF construct whose rule selection is not resolved.

    The catalog never returns a partial or guessed list of rules: a profile that
    extends another profile, or that selects a rule inside a deselected group,
    fails the whole datastream.
    """


class UnsafeContentError(CatalogError):
    """Raised when a user other than root or the accepted owner could replace the datastream.

    Modules report it as ``unsafe_content_dir``.
    """


class ScriptCheckError(CatalogError):
    """Raised when content carries a check that would run a script this collection did not write.

    The OpenSCAP Script Check Engine runs the shell scripts that a datastream embeds as root
    while it audits (threat model T-AUDIT-2). Only OVAL and OCIL checks are accepted, and no
    extended component or SCE element may be present (FREES-191, ADR 0026). Modules report it
    as ``script_check_content``.
    """


def _fail(message: str) -> NoReturn:
    raise CatalogError(message)


def refuse_script_check(name: str, attributes: dict[str, str]) -> None:
    """Refuse an element that would make the scanner run a script of the content.

    That is an XCCDF ``check`` whose ``system`` is not OVAL or OCIL (the Script Check Engine
    uses ``http://open-scap.org/page/SCE``), any element of the SCE namespace, and any
    data stream ``extended-component``, which is where a datastream embeds its scripts.

    Raises:
        ScriptCheckError: When ``name`` and ``attributes`` are such an element.
    """
    if name == _CHECK and attributes.get("system", "") not in ACCEPTED_CHECK_SYSTEMS:
        system = _echo(attributes.get("system", ""))
        message = (
            f"the content holds a check with the system {system}, which runs a script that this "
            "collection did not write; only OVAL and OCIL checks are accepted"
        )
        raise ScriptCheckError(message)
    if name == _EXTENDED_COMPONENT or name.startswith(_SCE_PREFIX):
        message = (
            "the content embeds a Script Check Engine script or an extended component, which the "
            "scanner could run; fetch the content with make content, which removes them"
        )
        raise ScriptCheckError(message)


class ScriptCheckScanner:
    """Parse events that only refuse script checks, for a document that is otherwise copied."""

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        """Refuse a script check (:func:`refuse_script_check`)."""
        refuse_script_check(name, attributes)

    def end(self, name: str, /) -> None:
        """Ignore an element end."""

    def text(self, data: str, /) -> None:
        """Ignore character data."""


def _unsafe(message: str) -> NoReturn:
    raise UnsafeContentError(message)


def _echo(value: object) -> str:
    return repr(str(value)[:MAX_ECHO_LENGTH])


@dataclass(frozen=True)
class Rule:
    """A rule that a benchmark defines.

    Attributes:
        rule_id: Full XCCDF rule identifier.
        severity: ``unknown``, ``info``, ``low``, ``medium`` or ``high``.
        title: Rule title, empty when the content has none.
        groups: Full identifiers of the groups that contain the rule, outermost
            first, in the order of the XCCDF group hierarchy.
        stig_ids: The text of the rule's DISA STIG ID references, in document
            order, cleaned but not validated.
        version: The text of the rule's own first ``version``, cleaned but not
            validated, empty when it has none. A DISA benchmark records the rule's
            STIG ID there, for example ``UBTU-24-100010``.
        disa_rules: The text of the rule's DISA rule ID references
            (``SV-257777r1155676_rule``), in document order, cleaned but not validated.
    """

    rule_id: str
    severity: str
    title: str
    groups: tuple[str, ...] = ()
    stig_ids: tuple[str, ...] = ()
    version: str = ""
    disa_rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class Profile:
    """A profile and the rules it selects.

    Attributes:
        profile_id: Full XCCDF profile identifier.
        title: Profile title, empty when the content has none.
        rule_ids: Identifiers of the selected rules, sorted and unique.
        version: The profile's own version, empty when the content has none. A
            ComplianceAsCode STIG profile names the DISA release it implements
            there, for example ``V1R5``.
    """

    profile_id: str
    title: str
    rule_ids: tuple[str, ...]
    version: str = ""


@dataclass(frozen=True)
class Benchmark:
    """A benchmark with its profiles and rule definitions.

    Attributes:
        benchmark_id: Full XCCDF benchmark identifier.
        version: Version of the benchmark content.
        title: Benchmark title, empty when the content has none.
        profiles: Profiles in document order.
        rules: Every rule that the benchmark defines, in document order.
    """

    benchmark_id: str
    version: str
    title: str
    profiles: tuple[Profile, ...]
    rules: tuple[Rule, ...]


def _clean(text: str) -> str:
    kept = "".join(" " if unicodedata.category(c) in _DROPPED_CATEGORIES else c for c in text)
    return " ".join(kept.split())[:MAX_TEXT_LENGTH]


def _xccdf_id(value: object, kind: str, name: str) -> str:
    try:
        return scanner.check_xccdf_id(value, kind, name)
    except scanner.ScanRequestError as error:
        raise CatalogError(str(error)) from error


def _boolean(value: str | None, name: str, *, default: bool | None) -> bool:
    if value is None:
        if default is None:
            _fail(f"{name} is missing")
        return default
    flag = _BOOLEANS.get(value.strip())
    if flag is None:
        _fail(f"{name} is not a boolean")
    return flag


class _Frame:
    __slots__ = ("accept", "kind")

    def __init__(self, kind: str, *, accept: bool = False) -> None:
        self.kind = kind
        self.accept = accept


class _RuleDraft:
    __slots__ = (
        "default",
        "disa_rules",
        "groups",
        "rule_id",
        "severity",
        "stig_ids",
        "title",
        "version",
    )

    def __init__(
        self, rule_id: str, severity: str, groups: tuple[str, ...], *, default: bool
    ) -> None:
        self.rule_id = rule_id
        self.groups = groups
        self.severity = severity
        self.default = default
        self.title: str | None = None
        self.stig_ids: list[str] = []
        self.disa_rules: list[str] = []
        self.version: str | None = None


class _ProfileDraft:
    __slots__ = ("profile_id", "selects", "title", "version")

    def __init__(self, profile_id: str) -> None:
        self.profile_id = profile_id
        self.title: str | None = None
        self.version: str | None = None
        self.selects: dict[str, bool] = {}


class _BenchmarkDraft:
    __slots__ = ("benchmark_id", "groups", "profiles", "rules", "title", "version")

    def __init__(self, benchmark_id: str) -> None:
        self.benchmark_id = benchmark_id
        self.version: str | None = None
        self.title: str | None = None
        self.profiles: list[_ProfileDraft] = []
        self.rules: list[_RuleDraft] = []
        self.groups: dict[str, bool] = {}


def _unsupported(message: str) -> NoReturn:
    raise UnsupportedContentError(message)


def _finish_profile(draft: _ProfileDraft, benchmark: _BenchmarkDraft) -> Profile:
    definitions = {rule.rule_id: rule for rule in benchmark.rules}
    rule_selects: dict[str, bool] = {}
    group_selects: dict[str, bool] = {}
    for idref, flag in draft.selects.items():
        if idref in definitions:
            rule_selects[idref] = flag
        elif idref in benchmark.groups:
            group_selects[idref] = flag
        else:
            _unsupported(
                f"profile {draft.profile_id!r} selects {idref!r}, which the benchmark defines "
                "as neither a rule nor a group; no rule list is returned"
            )
    selected = sorted(
        rule_id for rule_id, rule in definitions.items() if rule_selects.get(rule_id, rule.default)
    )
    for rule_id in selected:
        for group_id in definitions[rule_id].groups:
            if not group_selects.get(group_id, benchmark.groups[group_id]):
                _unsupported(
                    f"profile {draft.profile_id!r} selects rule {rule_id!r} inside the "
                    f"deselected group {group_id!r}; this is not resolved, so no rule list "
                    "is returned"
                )
    return Profile(draft.profile_id, draft.title or "", tuple(selected), draft.version or "")


def _finish_benchmark(draft: _BenchmarkDraft) -> Benchmark:
    if draft.version is None:
        _fail(f"benchmark {draft.benchmark_id!r} has no version")
    if draft.groups.keys() & {rule.rule_id for rule in draft.rules}:
        _unsupported(f"benchmark {draft.benchmark_id!r} uses one identifier for a rule and a group")
    return Benchmark(
        benchmark_id=draft.benchmark_id,
        version=draft.version,
        title=draft.title or "",
        profiles=tuple(_finish_profile(profile, draft) for profile in draft.profiles),
        rules=tuple(
            Rule(
                r.rule_id,
                r.severity,
                r.title or "",
                r.groups,
                tuple(r.stig_ids),
                r.version or "",
                tuple(r.disa_rules),
            )
            for r in draft.rules
        ),
    )


class _Collector:
    """Receives parse events and keeps only benchmark, profile and rule data."""

    def __init__(self) -> None:
        self.frames: list[_Frame] = []
        self.benchmarks: list[Benchmark] = []
        self.benchmark = _BenchmarkDraft("")
        self.profile = _ProfileDraft("")
        self.rule = _RuleDraft("", "unknown", (), default=False)
        self.parts: list[str] = []
        self.profile_ids: set[str] = set()
        self.rule_ids: set[str] = set()
        self.group_path: list[str] = []
        self.openers: dict[tuple[str, str], Callable[[dict[str, str]], _Frame]] = {
            (_BENCH, _RULE): self._open_rule,
            (_GROUP_KIND, _RULE): self._open_rule,
            (_BENCH, _GROUP): self._open_group,
            (_GROUP_KIND, _GROUP): self._open_group,
            (_BENCH, _PROFILE): self._open_profile,
            (_BENCH, _VERSION_TAG): self._open_version,
            (_BENCH, _TITLE): self._open_title,
            (_PROFILE_KIND, _TITLE): self._open_title,
            (_RULE_KIND, _TITLE): self._open_title,
            (_PROFILE_KIND, _SELECT): self._open_select,
            (_PROFILE_KIND, _VERSION_TAG): self._open_profile_version,
            (_RULE_KIND, _REFERENCE): self._open_reference,
            (_RULE_KIND, _VERSION_TAG): self._open_rule_version,
        }

    def start(self, name: str, attributes: dict[str, str]) -> None:
        refuse_script_check(name, attributes)
        if not self.frames:
            if name not in {_COLLECTION, _BENCHMARK}:
                _fail("the root is not a SCAP 1.2 data stream collection or an XCCDF 1.2 Benchmark")
            parent = _Frame(_OUTSIDE)
        else:
            parent = self.frames[-1]
        self.frames.append(self._classify(parent.kind, name, attributes))

    def _classify(self, parent: str, tag: str, attributes: dict[str, str]) -> _Frame:
        if parent in {_TITLE_KIND, _PART}:
            return _Frame(_PART)
        if parent == _OUTSIDE:
            return self._open_benchmark(attributes) if tag == _BENCHMARK else _Frame(_OUTSIDE)
        opener = self.openers.get((parent, tag))
        return _Frame(_OTHER) if opener is None else opener(attributes)

    def _open_group(self, attributes: dict[str, str]) -> _Frame:
        group_id = attributes.get("id", "")
        if len(group_id) > _MAX_ID_LENGTH or re.fullmatch(_GROUP_ID, group_id) is None:
            _fail("group id is missing or malformed")
        groups = self.benchmark.groups
        if group_id in groups:
            _fail(f"group {group_id!r} appears more than once")
        if len(groups) >= MAX_RULES:
            _fail(f"the benchmark has more than {MAX_RULES} groups")
        groups[group_id] = _boolean(attributes.get("selected"), "group selected", default=True)
        self.group_path.append(group_id)
        return _Frame(_GROUP_KIND)

    def _open_version(self, _attributes: dict[str, str]) -> _Frame:
        self.parts = []
        return _Frame(_VERSION_KIND)

    def _open_profile_version(self, _attributes: dict[str, str]) -> _Frame:
        self.parts = []
        return _Frame(_PROFILE_VERSION_KIND)

    def _open_rule_version(self, _attributes: dict[str, str]) -> _Frame:
        self.parts = []
        return _Frame(_RULE_VERSION_KIND)

    def _open_reference(self, attributes: dict[str, str]) -> _Frame:
        href = attributes.get("href")
        if href in DISA_RULE_REFERENCES:
            if len(self.rule.disa_rules) >= MAX_STIG_IDS:
                _fail(
                    f"rule {self.rule.rule_id!r} has more than {MAX_STIG_IDS} DISA rule references"
                )
            self.parts = []
            return _Frame(_DISA_RULE_KIND)
        if href not in STIG_ID_REFERENCES:
            return _Frame(_OTHER)
        if len(self.rule.stig_ids) >= MAX_STIG_IDS:
            _fail(f"rule {self.rule.rule_id!r} has more than {MAX_STIG_IDS} STIG ID references")
        self.parts = []
        return _Frame(_STIG_ID_KIND)

    def _open_title(self, attributes: dict[str, str]) -> _Frame:
        self.parts = []
        lang = attributes.get(_XML_LANG)
        return _Frame(_TITLE_KIND, accept=lang is None or lang.lower().startswith("en"))

    def _open_benchmark(self, attributes: dict[str, str]) -> _Frame:
        draft = _BenchmarkDraft(_xccdf_id(attributes.get("id"), "benchmark", "benchmark id"))
        if any(item.benchmark_id == draft.benchmark_id for item in self.benchmarks):
            _fail(f"benchmark {draft.benchmark_id!r} appears more than once")
        self.benchmark = draft
        self.profile_ids = set()
        self.rule_ids = set()
        self.group_path = []
        return _Frame(_BENCH)

    def _open_profile(self, attributes: dict[str, str]) -> _Frame:
        benchmark = self.benchmark
        draft = _ProfileDraft(_xccdf_id(attributes.get("id"), "profile", "profile id"))
        if "extends" in attributes:
            message = (
                f"profile {draft.profile_id!r} extends another profile; inheritance is not "
                "resolved, so no rule list is returned"
            )
            raise UnsupportedContentError(message)
        if draft.profile_id in self.profile_ids:
            _fail(f"profile {draft.profile_id!r} appears more than once")
        if len(self.profile_ids) >= MAX_PROFILES:
            _fail(f"the benchmark has more than {MAX_PROFILES} profiles")
        self.profile_ids.add(draft.profile_id)
        benchmark.profiles.append(draft)
        self.profile = draft
        return _Frame(_PROFILE_KIND)

    def _open_rule(self, attributes: dict[str, str]) -> _Frame:
        benchmark = self.benchmark
        rule_id = _xccdf_id(attributes.get("id"), "rule", "rule id")
        if rule_id in self.rule_ids:
            _fail(f"rule {rule_id!r} appears more than once")
        if len(self.rule_ids) >= MAX_RULES:
            _fail(f"the benchmark has more than {MAX_RULES} rules")
        self.rule_ids.add(rule_id)
        severity = attributes.get("severity", "unknown")
        draft = _RuleDraft(
            rule_id,
            severity if severity in SEVERITIES else "unknown",
            tuple(self.group_path),
            default=_boolean(attributes.get("selected"), "rule selected", default=True),
        )
        benchmark.rules.append(draft)
        self.rule = draft
        return _Frame(_RULE_KIND)

    def _open_select(self, attributes: dict[str, str]) -> _Frame:
        profile = self.profile
        flag = _boolean(attributes.get("selected"), "select selected", default=None)
        idref = attributes.get("idref", "")
        if len(idref) > _MAX_ID_LENGTH:
            _unsupported(f"profile {profile.profile_id!r} has a select identifier that is too long")
        if len(profile.selects) >= MAX_RULES and idref not in profile.selects:
            _fail(f"profile {profile.profile_id!r} selects more than {MAX_RULES} items")
        profile.selects[idref] = flag
        return _Frame(_SELECT_KIND)

    def end(self, _name: str) -> None:
        frame = self.frames.pop()
        kind = frame.kind
        if kind == _GROUP_KIND:
            self.group_path.pop()
        elif kind == _BENCH:
            self.benchmarks.append(_finish_benchmark(self.benchmark))
        elif kind == _VERSION_KIND:
            self._store_version()
        elif kind == _PROFILE_VERSION_KIND and self.profile.version is None:
            self.profile.version = _clean("".join(self.parts))
        elif kind == _STIG_ID_KIND:
            self.rule.stig_ids.append(_clean("".join(self.parts)))
        elif kind == _DISA_RULE_KIND:
            self.rule.disa_rules.append(_clean("".join(self.parts)))
        elif kind == _RULE_VERSION_KIND and self.rule.version is None:
            self.rule.version = _clean("".join(self.parts))
        elif kind == _TITLE_KIND and frame.accept:
            self._store_title(self.frames[-1].kind)

    def _store_version(self) -> None:
        benchmark = self.benchmark
        value = "".join(self.parts).strip()
        if benchmark.version is not None:
            return
        if re.fullmatch(_VERSION, value) is None:
            _fail("the benchmark version is not a valid version string")
        benchmark.version = value

    def _store_title(self, owner: str) -> None:
        value = _clean("".join(self.parts))
        targets: dict[str, _BenchmarkDraft | _ProfileDraft | _RuleDraft] = {
            _BENCH: self.benchmark,
            _PROFILE_KIND: self.profile,
            _RULE_KIND: self.rule,
        }
        target = targets[owner]
        if target.title is None:
            target.title = value

    def text(self, data: str) -> None:
        if self.frames[-1].kind in _COLLECTING and sum(map(len, self.parts)) < _TEXT_BUDGET:
            self.parts.append(data)


def parse_benchmarks(
    chunks: Iterable[bytes], bounds: xmlsafe.XmlBounds | None = None
) -> tuple[Benchmark, ...]:
    """Parse datastream bytes that are already trusted, without a digest check.

    Prefer :func:`read_benchmarks`, which verifies the digest first.

    Raises:
        CatalogError: If the document is unsafe, malformed or has no benchmark.
    """
    collector = _Collector()
    try:
        xmlsafe.parse_chunks(chunks, collector, bounds)
    except xmlsafe.XmlSafetyError as error:
        raise CatalogError(str(error)) from error
    if not collector.benchmarks:
        _fail("the document contains no XCCDF 1.2 Benchmark")
    return tuple(collector.benchmarks)


def _expected_digest(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(_SHA256, value.lower()) is None:
        _fail("the expected SHA-256 must be 64 hexadecimal characters")
    return value.lower()


def _checked_path(path: object) -> str:
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_LENGTH:
        _fail(f"the path must be a non-empty string of at most {MAX_PATH_LENGTH} characters")
    if any(unicodedata.category(character) == "Cc" for character in path):
        _fail("the path contains a control character")
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        _fail("the path must be absolute and must not contain '..'")
    return path


def locate_datastreams(directory: str) -> tuple[str, ...]:
    """List the datastream files directly inside a directory.

    A datastream is a regular file, not a symlink, whose name ends in ``-ds.xml``.
    Subdirectories are not searched. The directory itself may not be a symlink.

    Returns:
        Sorted absolute paths.

    Raises:
        CatalogError: If the directory is invalid, unreadable or too large.
    """
    base = Path(_checked_path(directory))
    try:
        if not stat.S_ISDIR(base.lstat().st_mode):
            _fail("the content path is neither a regular file nor a directory")
        entries = sorted(base.iterdir())
        if len(entries) > MAX_DIRECTORY_ENTRIES:
            _fail(f"the directory has more than {MAX_DIRECTORY_ENTRIES} entries")
        return tuple(
            str(entry)
            for entry in entries
            if entry.name.endswith(DATASTREAM_SUFFIX) and stat.S_ISREG(entry.lstat().st_mode)
        )
    except OSError as error:
        _fail(f"the directory cannot be read: {error.strerror or type(error).__name__}")


def resolve_content_path(path: str) -> str:
    """Return the datastream file that ``path`` names.

    A regular file is returned as is. A directory must hold exactly one
    datastream file, which is returned; zero or several is an error because the
    choice is never guessed.

    Raises:
        CatalogError: If the path is invalid, missing or ambiguous.
    """
    checked = _checked_path(path)
    try:
        mode = Path(checked).lstat().st_mode
    except OSError as error:
        _fail(f"the content path cannot be read: {error.strerror or type(error).__name__}")
    if stat.S_ISREG(mode):
        return checked
    found = locate_datastreams(checked)
    if len(found) != 1:
        _fail(f"expected exactly one datastream in the directory, found {len(found)}")
    return found[0]


@dataclass(frozen=True)
class _Status:
    mode: int
    uid: int


def _inspect(path: Path) -> _Status | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        _unsafe(f"content_path cannot be inspected: {error.strerror or type(error).__name__}")
    return _Status(info.st_mode, info.st_uid)


def _existing(path: Path) -> _Status:
    info = _inspect(path)
    if info is None:
        _fail(f"the content path cannot be read: {_echo(path)} does not exist")
    return info


def _still_there(path: Path) -> _Status:
    info = _inspect(path)
    if info is None:
        _unsafe(f"content_path vanished while it was inspected: {_echo(path)}")
    return info


def _accepted_owner(info: _Status, *, owner_uid: int | None) -> bool:
    return info.uid in {ROOT_UID, effective_uid() if owner_uid is None else owner_uid}


def _vet_directory(path: Path, info: _Status, *, owner_uid: int | None) -> None:
    if not stat.S_ISDIR(info.mode):
        _unsafe(f"content_path component is not a directory: {_echo(path)}")
    if not _accepted_owner(info, owner_uid=owner_uid):
        _unsafe(f"{_ANCESTOR} has an unexpected owner: {_echo(path)}")
    if info.mode & _GROUP_OR_OTHER_WRITE and not info.mode & stat.S_ISVTX:
        _unsafe(f"{_ANCESTOR} is writable by group or others: {_echo(path)}")


def _link_target(path: Path, info: _Status, *, owner_uid: int | None) -> Path:
    if not _accepted_owner(info, owner_uid=owner_uid):
        _unsafe(f"a symlink on the way to content_path has an unexpected owner: {_echo(path)}")
    try:
        return path.readlink()
    except OSError as error:
        _unsafe(f"content_path cannot be inspected: {error.strerror or type(error).__name__}")


def _real_directory(path: Path, *, owner_uid: int | None) -> Path:
    """Resolve a directory like ``realpath`` and vet everything the resolution uses.

    The walk starts at ``/`` and keeps a resolved prefix that contains no symlink.
    Each component it adds is vetted with the directory rules before the walk goes
    on, so the directory that holds a symlink is always a vetted component of that
    prefix. A symlink must be owned by root or ``owner_uid``; its target replaces it
    and is resolved against the prefix, ``..`` included. More than
    :data:`MAX_SYMLINKS` symlinks, which every loop reaches, are refused.
    """
    resolved = Path("/")
    _vet_directory(resolved, _existing(resolved), owner_uid=owner_uid)
    pending = list(path.parts[1:])
    followed = 0
    while pending:
        name = pending.pop(0)
        if name == "..":
            resolved = resolved.parent
            continue
        candidate = resolved / name
        info = _existing(candidate)
        if not stat.S_ISLNK(info.mode):
            _vet_directory(candidate, info, owner_uid=owner_uid)
            resolved = candidate
            continue
        followed += 1
        if followed > MAX_SYMLINKS:
            _unsafe(
                f"content_path follows more than {MAX_SYMLINKS} symlinks, "
                f"probably a loop: {_echo(candidate)}"
            )
        target = _link_target(candidate, info, owner_uid=owner_uid)
        if target.is_absolute():
            resolved = Path("/")
        pending[:0] = target.parts[1:] if target.is_absolute() else target.parts
    return resolved


def vetted_content_path(path: str, *, owner_uid: int | None = None) -> str:
    """Resolve the datastream that ``path`` names and vet the way to it.

    Root reads the datastream, and :class:`xmlsafe.RegularFile` checks the type
    with ``lstat`` before it opens the path. A user who could replace the file in
    between could swap it for a FIFO and block the ``open``. So before anything is
    opened:

    - the directory part of ``path`` is resolved to its real path. Every component
      of the resolved chain, from ``/`` to the directory that holds the datastream,
      must be a directory that is not a symlink, owned by root or ``owner_uid``,
      and not writable by group or others unless its sticky bit is set. Every
      symlink that the resolution follows must be owned by root or ``owner_uid``,
      and the directory that holds it is a component of the resolved chain, so it
      obeys the same rules. A symlink that another user owns, or that sits in a
      directory that another user can change, is refused, and so is a loop;
    - the final component of ``path`` is not followed: a regular file is the
      datastream, a directory must hold exactly one (see
      :func:`resolve_content_path`) and obeys the directory rules too;
    - the datastream must be a regular file owned by root or ``owner_uid`` and
      not writable by group or others. A hard link is not a separate object: the
      owner and mode belong to the file, whatever name reaches it.

    Nothing is opened, created or repaired. The caller reads, hashes and copies
    the returned path, never ``path``.

    Args:
        path: Absolute ``content_path`` as the operator gave it.
        owner_uid: The only owner besides root that is accepted. Keyword-only;
            when omitted, :func:`effective_uid` is accepted, which the discover
            modules rely on. The audit forwards its own seam, root in production.

    Returns:
        The real path of the datastream file.

    Raises:
        UnsafeContentError: For every violation of the rules above.
        CatalogError: If the path is invalid, missing or ambiguous.
    """
    given = Path(_checked_path(path))
    target = _real_directory(given.parent, owner_uid=owner_uid) / given.name
    datastream = Path(resolve_content_path(str(target)))
    if datastream != target:
        _vet_directory(target, _still_there(target), owner_uid=owner_uid)
    info = _still_there(datastream)
    if not stat.S_ISREG(info.mode):
        _unsafe(f"the datastream is not a regular file: {_echo(datastream)}")
    if not _accepted_owner(info, owner_uid=owner_uid):
        _unsafe(f"the datastream has an unexpected owner: {_echo(datastream)}")
    if info.mode & _GROUP_OR_OTHER_WRITE:
        _unsafe(f"the datastream is writable by group or others: {_echo(datastream)}")
    return str(datastream)


def effective_uid() -> int:
    """Return the user that this process runs as, or root when that is unknown.

    The owner of ``/proc/self`` is the effective user of the process. When it
    cannot be read, root is returned, which accepts fewer owners and so fails
    closed.
    """
    try:
        return Path(PROCESS_DIRECTORY).stat().st_uid
    except OSError:
        return ROOT_UID


def _handle_digest(handle: BinaryIO, max_bytes: int) -> str:
    digest = hashlib.sha256()
    try:
        for chunk in xmlsafe.iter_handle_chunks(handle, max_bytes):
            digest.update(chunk)
    except xmlsafe.XmlSafetyError as error:
        raise CatalogError(str(error)) from error
    return digest.hexdigest()


def verify_digest(path: str, expected_sha256: str, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    """Hash a file and compare it with the pinned digest.

    Returns:
        The digest, which equals ``expected_sha256`` in lower case.

    Raises:
        DigestMismatchError: If the digest differs.
        CatalogError: If the digest or path is invalid, or the file is unsafe.
    """
    expected = _expected_digest(expected_sha256)
    try:
        with xmlsafe.RegularFile(_checked_path(path), max_bytes) as handle:
            actual = _handle_digest(handle, max_bytes)
    except xmlsafe.XmlSafetyError as error:
        raise CatalogError(str(error)) from error
    if actual != expected:
        message = f"content digest mismatch: expected {expected}, found {actual}"
        raise DigestMismatchError(message)
    return actual


class _HashedChunks:
    def __init__(self, handle: BinaryIO, max_bytes: int) -> None:
        self.handle = handle
        self.max_bytes = max_bytes
        self.digest = hashlib.sha256()

    def __iter__(self) -> Iterator[bytes]:
        for chunk in xmlsafe.iter_handle_chunks(self.handle, self.max_bytes):
            self.digest.update(chunk)
            yield chunk


def read_benchmarks(
    path: str,
    expected_sha256: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    bounds: xmlsafe.XmlBounds | None = None,
) -> tuple[Benchmark, ...]:
    """Verify a datastream against its pinned digest and parse it.

    The file is opened once. Its digest is checked before any parsing, then the
    same descriptor is rewound and parsed while it is hashed again, so a file that
    changes in between, or a path that is swapped after the type check, can only
    ever deliver bytes that have the pinned digest or an error.

    Args:
        path: Absolute path of the datastream file.
        expected_sha256: Pinned SHA-256 from the content manifest.
        max_bytes: Largest accepted file size.
        bounds: Element and depth bounds for the parser.

    Returns:
        The benchmarks in document order.

    Raises:
        DigestMismatchError: If the file does not have the pinned digest.
        UnsupportedContentError: If a profile uses an unresolved construct.
        CatalogError: For every other rejection.
    """
    expected = _expected_digest(expected_sha256)
    checked = _checked_path(path)
    try:
        with xmlsafe.RegularFile(checked, max_bytes) as handle:
            actual = _handle_digest(handle, max_bytes)
            if actual != expected:
                message = f"content digest mismatch: expected {expected}, found {actual}"
                raise DigestMismatchError(message)
            chunks = _HashedChunks(handle, max_bytes)
            benchmarks = parse_benchmarks(chunks, bounds)
    except xmlsafe.XmlSafetyError as error:
        raise CatalogError(str(error)) from error
    if chunks.digest.hexdigest() != expected:
        message = "the content changed while it was being read"
        raise DigestMismatchError(message)
    return benchmarks


def single_benchmark(benchmarks: Sequence[Benchmark]) -> Benchmark:
    """Return the only benchmark, or fail because the choice would be a guess."""
    if len(benchmarks) != 1:
        _fail(f"expected exactly one benchmark in the datastream, found {len(benchmarks)}")
    return benchmarks[0]


def find_profile(benchmark: Benchmark, profile_id: str) -> Profile:
    """Return the profile with the given full identifier.

    Raises:
        ProfileNotFoundError: If the benchmark does not contain it. No other
            profile is ever substituted.
        CatalogError: If the identifier is not a valid XCCDF profile identifier.
    """
    wanted = _xccdf_id(profile_id, "profile", "profile id")
    for profile in benchmark.profiles:
        if profile.profile_id == wanted:
            return profile
    message = f"profile {wanted!r} is not in benchmark {benchmark.benchmark_id!r}"
    raise ProfileNotFoundError(message)


def profile_rules(benchmark: Benchmark, profile: Profile) -> tuple[Rule, ...]:
    """Return the definitions of the rules that a profile selects, sorted by identifier."""
    definitions = {rule.rule_id: rule for rule in benchmark.rules}
    return tuple(definitions[rule_id] for rule_id in profile.rule_ids)


def error_type(error: CatalogError) -> str:
    """Return the stable ``error_type`` identifier that modules report for an error."""
    if isinstance(error, DigestMismatchError):
        return "digest_mismatch"
    if isinstance(error, ProfileNotFoundError):
        return "profile_not_found"
    if isinstance(error, UnsupportedContentError):
        return "unsupported_content"
    if isinstance(error, UnsafeContentError):
        return ERROR_UNSAFE_CONTENT
    if isinstance(error, ScriptCheckError):
        return ERROR_SCRIPT_CHECK
    return "invalid_content"


def benchmark_report(path: str, expected_sha256: str) -> dict[str, object]:
    """Describe the benchmark and profiles of a verified datastream.

    The path is resolved and vetted with :func:`vetted_content_path` before it is
    opened, accepting root and :func:`effective_uid` as owners. The result holds
    only JSON-serializable values. See :func:`read_benchmarks` for the
    verification and the other errors.
    """
    content = vetted_content_path(path)
    benchmark = single_benchmark(read_benchmarks(content, expected_sha256))
    return {
        "content_path": content,
        "content_sha256": _expected_digest(expected_sha256),
        "benchmark_id": benchmark.benchmark_id,
        "benchmark_version": benchmark.version,
        "benchmark_title": benchmark.title,
        "profiles": [
            {
                "profile_id": profile.profile_id,
                "title": profile.title,
                "rule_count": len(profile.rule_ids),
            }
            for profile in benchmark.profiles
        ],
    }


def profile_report(path: str, expected_sha256: str, profile_id: str) -> dict[str, object]:
    """Describe one profile of a verified datastream and the rules it selects.

    The path is vetted like in :func:`benchmark_report`.

    Raises:
        ProfileNotFoundError: If the benchmark does not contain the profile.
            No other profile is substituted.
        UnsafeContentError: If the way to the datastream is unsafe.
    """
    content = vetted_content_path(path)
    benchmark = single_benchmark(read_benchmarks(content, expected_sha256))
    profile = find_profile(benchmark, profile_id)
    rules = profile_rules(benchmark, profile)
    return {
        "content_path": content,
        "content_sha256": _expected_digest(expected_sha256),
        "benchmark_id": benchmark.benchmark_id,
        "benchmark_version": benchmark.version,
        "profile_id": profile.profile_id,
        "profile_title": profile.title,
        "rule_count": len(rules),
        "rule_ids": [rule.rule_id for rule in rules],
        "rules": [
            {
                "rule_id": rule.rule_id,
                "severity": rule.severity,
                "title": rule.title,
                "version": rule.version,
            }
            for rule in rules
        ],
    }
