"""Benchmark and profile discovery in SCAP datastreams on a managed host.

A datastream is untrusted until its SHA-256 matches the digest pinned in the
content manifest (ADR 0015). :func:`read_benchmarks` hashes the file first and
raises :class:`DigestMismatchError` without parsing a single byte on a mismatch.
The parse then reads the file again and hashes it again, so content that changes
between the two reads is also rejected.

Parsing goes through :mod:`xmlsafe` only: a bounded, streaming expat parser that
rejects DOCTYPE and ENTITY declarations. Elements are never stored; only the
benchmark, its profiles and the identifier, severity and title of its rules are
kept.

Rule selection follows XCCDF. Each ``select`` of a profile is classified by what
the benchmark defines, never by the shape of the identifier: the identifier of a
rule decides that rule, the identifier of a group decides that group. The last
``select`` wins. A rule the profile does not mention keeps the ``selected`` default
of the rule itself (true when absent), and a group is selected when the last
``select`` says so or else by its own default (true when absent).

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
SEVERITIES: Final[frozenset[str]] = frozenset({"unknown", "info", "low", "medium", "high"})

_GROUP_ID: Final[re.Pattern[str]] = re.compile(r"xccdf_[A-Za-z0-9_.+-]+")
_MAX_ID_LENGTH: Final[int] = 256
_SHA256: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_VERSION: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:~-]{0,63}")
_XML_LANG: Final[str] = "http://www.w3.org/XML/1998/namespace}lang"
_DROPPED_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})
_BOOLEANS: Final[dict[str, bool]] = {"true": True, "1": True, "false": False, "0": False}


def _qualified(local: str) -> str:
    return f"{{{XCCDF_NAMESPACE}}}{local}"


_BENCHMARK: Final[str] = _qualified("Benchmark")
_PROFILE: Final[str] = _qualified("Profile")
_GROUP: Final[str] = _qualified("Group")
_RULE: Final[str] = _qualified("Rule")
_TITLE: Final[str] = _qualified("title")
_VERSION_TAG: Final[str] = _qualified("version")
_SELECT: Final[str] = _qualified("select")
_COLLECTION: Final[str] = f"{{{DATASTREAM_NAMESPACE}}}data-stream-collection"

_OUTSIDE: Final[str] = "outside"
_BENCH: Final[str] = "benchmark"
_PROFILE_KIND: Final[str] = "profile"
_GROUP_KIND: Final[str] = "group"
_RULE_KIND: Final[str] = "rule"
_TITLE_KIND: Final[str] = "title"
_VERSION_KIND: Final[str] = "version"
_PART: Final[str] = "part"
_SELECT_KIND: Final[str] = "select"
_OTHER: Final[str] = "other"
_COLLECTING: Final[frozenset[str]] = frozenset({_TITLE_KIND, _VERSION_KIND, _PART})
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


def _fail(message: str) -> NoReturn:
    raise CatalogError(message)


@dataclass(frozen=True)
class Rule:
    """A rule that a benchmark defines.

    Attributes:
        rule_id: Full XCCDF rule identifier.
        severity: ``unknown``, ``info``, ``low``, ``medium`` or ``high``.
        title: Rule title, empty when the content has none.
    """

    rule_id: str
    severity: str
    title: str


@dataclass(frozen=True)
class Profile:
    """A profile and the rules it selects.

    Attributes:
        profile_id: Full XCCDF profile identifier.
        title: Profile title, empty when the content has none.
        rule_ids: Identifiers of the selected rules, sorted and unique.
    """

    profile_id: str
    title: str
    rule_ids: tuple[str, ...]


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
    __slots__ = ("default", "groups", "rule_id", "severity", "title")

    def __init__(
        self, rule_id: str, severity: str, groups: tuple[str, ...], *, default: bool
    ) -> None:
        self.rule_id = rule_id
        self.groups = groups
        self.severity = severity
        self.default = default
        self.title: str | None = None


class _ProfileDraft:
    __slots__ = ("profile_id", "selects", "title")

    def __init__(self, profile_id: str) -> None:
        self.profile_id = profile_id
        self.title: str | None = None
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
    return Profile(draft.profile_id, draft.title or "", tuple(selected))


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
        rules=tuple(Rule(r.rule_id, r.severity, r.title or "") for r in draft.rules),
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
        }

    def start(self, name: str, attributes: dict[str, str]) -> None:
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
        if len(group_id) > _MAX_ID_LENGTH or _GROUP_ID.fullmatch(group_id) is None:
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
        elif kind == _TITLE_KIND and frame.accept:
            self._store_title(self.frames[-1].kind)

    def _store_version(self) -> None:
        benchmark = self.benchmark
        value = "".join(self.parts).strip()
        if benchmark.version is not None:
            return
        if _VERSION.fullmatch(value) is None:
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
    if not isinstance(value, str) or _SHA256.fullmatch(value.lower()) is None:
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
        with xmlsafe.open_regular(_checked_path(path), max_bytes) as handle:
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
        with xmlsafe.open_regular(checked, max_bytes) as handle:
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
    return "invalid_content"


def benchmark_report(path: str, expected_sha256: str) -> dict[str, object]:
    """Describe the benchmark and profiles of a verified datastream.

    The result holds only JSON-serializable values. See :func:`read_benchmarks`
    for the verification and the errors.
    """
    content = resolve_content_path(path)
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

    Raises:
        ProfileNotFoundError: If the benchmark does not contain the profile.
            No other profile is substituted.
    """
    content = resolve_content_path(path)
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
            {"rule_id": rule.rule_id, "severity": rule.severity, "title": rule.title}
            for rule in rules
        ],
    }
