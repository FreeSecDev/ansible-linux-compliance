"""Normalized compliance findings model.

The model is shared by managed-host code and controller-side reporting. It uses
only the Python standard library and syntax that runs on Python 3.9, the oldest
managed-node interpreter supported by ansible-core 2.20 (ADR 0013).

Every entity is an immutable dataclass validated in ``__post_init__``.
Validation failures raise :class:`ModelError`. ``to_dict`` and ``from_dict``
convert to and from JSON-compatible mappings; ``from_dict`` rejects unknown and
missing keys. Collections of keyed items are stored sorted so that equal
entities serialize identically. :func:`dumps` and :func:`loads` write and read
the deterministic JSON document of a :class:`ScanRun`.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, NoReturn, TypeVar, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

SCHEMA_VERSION: Final[str] = "1.0"
SUPPORTED_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({SCHEMA_VERSION})

MAX_ID_LENGTH: Final[int] = 256
MAX_TITLE_LENGTH: Final[int] = 512
MAX_TEXT_LENGTH: Final[int] = 8192
MAX_EVIDENCE_LENGTH: Final[int] = 65536
MAX_ITEMS: Final[int] = 4096
MAX_FINDINGS: Final[int] = 100000
MAX_EVIDENCE_ITEMS: Final[int] = 64
MAX_DOCUMENT_CHARS: Final[int] = 128 * 1024 * 1024

TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%SZ"

_TIMESTAMP: Final[str] = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
_SHA256: Final[str] = r"[0-9a-f]{64}"
_MACHINE_ID: Final[str] = r"[0-9a-f]{32}"
_IDENTIFIER_PATTERN: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._:+-]*"
_SLUG: Final[str] = r"[a-z0-9][a-z0-9._-]*"
_VARIABLE: Final[str] = r"[a-z][a-z0-9_]*"
_IDENTIFIER_FORBIDDEN_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})
_TEXT_ALLOWED_CONTROLS: Final[frozenset[str]] = frozenset({"\t", "\n", "\r"})
_BIDI_CONTROLS: Final[frozenset[str]] = frozenset(
    {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}
)
MAX_ECHO_LENGTH: Final[int] = 64
_XCCDF_PATTERNS: Final[Mapping[str, str]] = MappingProxyType(
    {
        kind: rf"xccdf_[A-Za-z0-9_.-]+?_{kind}_[A-Za-z0-9_.+-]+"
        for kind in ("rule", "profile", "benchmark")
    }
)
XCCDF_ID_PATTERNS: Final[Mapping[str, str]] = _XCCDF_PATTERNS

T = TypeVar("T")
E = TypeVar("E", bound=Enum)


class ModelError(ValueError):
    """Raised when a value or document violates the findings model."""


_XCCDF_RESULT_OK: Final[str] = "pass"


class Outcome(Enum):
    """Platform outcome of evaluating one rule on one host."""

    PASS = _XCCDF_RESULT_OK
    FAIL = "fail"
    NOTAPPLICABLE = "notapplicable"
    NOTCHECKED = "notchecked"
    ERROR = "error"
    WAIVED = "waived"
    DISABLED = "disabled"


class ResultFlag(Enum):
    """Qualifier retained when an XCCDF result is folded into an outcome."""

    FIXED = "fixed"
    INFORMATIONAL = "informational"
    NOTSELECTED = "notselected"


class Severity(Enum):
    """Rule severity as published by the benchmark content."""

    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ControlClass(Enum):
    """Classification of a control by what the platform can do with it."""

    DIRECTLY_AUDITABLE = "directly_auditable"
    AUTOMATABLE_REMEDIATION = "automatable_remediation"
    EVIDENCE_ONLY = "evidence_only"
    MANUAL_ORGANIZATIONAL = "manual_organizational"
    UNSUPPORTED = "unsupported"


class EvaluationMethod(Enum):
    """How the scanner evaluates a rule."""

    OVAL = "oval"
    SCE = "sce"
    OCIL = "ocil"
    EVIDENCE = "evidence"
    MANUAL = "manual"
    NONE = "none"


class RemediationMethod(Enum):
    """How the platform remediates a rule."""

    NATIVE_MODULE = "native_module"
    NONE = "none"


class RevertStrategy(Enum):
    """How a remediation is reverted when the rule is disabled (ADR 0011)."""

    OWNED_DROPIN = "owned_dropin"
    RECORDED_VALUE = "recorded_value"
    RECORDED_STATE = "recorded_state"
    IRREVERSIBLE = "irreversible"


class FrameworkId(Enum):
    """Compliance frameworks referenced by rules."""

    CIS = "cis"
    STIG = "stig"
    NIST_800_53 = "nist_800_53"
    NIST_800_171 = "nist_800_171"
    PCI_DSS = "pci_dss"
    ANSSI = "anssi"


class ExceptionState(Enum):
    """State of the exception record that applies to a finding."""

    NONE = "none"
    ACTIVE = "active"
    EXPIRED = "expired"


class RemediationStatus(Enum):
    """Result of a remediation or cleanup attempt for one rule."""

    APPLIED = "applied"
    ALREADY_COMPLIANT = "already_compliant"
    SKIPPED = "skipped"
    FAILED = "failed"
    REVERTED = "reverted"
    CLEANUP_INCOMPLETE = "cleanup_incomplete"
    NOT_REMEDIATED = "not_remediated"


class ScanStatus(Enum):
    """Whether the scanner itself ran to completion."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


_AUDITABLE_METHODS: Final[frozenset[EvaluationMethod]] = frozenset(
    {EvaluationMethod.OVAL, EvaluationMethod.SCE, EvaluationMethod.OCIL}
)
_CLASS_EVALUATION: Final[Mapping[ControlClass, frozenset[EvaluationMethod]]] = MappingProxyType(
    {
        ControlClass.DIRECTLY_AUDITABLE: _AUDITABLE_METHODS,
        ControlClass.AUTOMATABLE_REMEDIATION: _AUDITABLE_METHODS,
        ControlClass.EVIDENCE_ONLY: frozenset({EvaluationMethod.EVIDENCE}),
        ControlClass.MANUAL_ORGANIZATIONAL: frozenset({EvaluationMethod.MANUAL}),
        ControlClass.UNSUPPORTED: frozenset({EvaluationMethod.NONE}),
    }
)
_FLAG_OUTCOMES: Final[Mapping[ResultFlag, Outcome]] = MappingProxyType(
    {
        ResultFlag.FIXED: Outcome.PASS,
        ResultFlag.INFORMATIONAL: Outcome.NOTCHECKED,
        ResultFlag.NOTSELECTED: Outcome.NOTCHECKED,
    }
)
_UNCHANGED_STATUSES: Final[frozenset[RemediationStatus]] = frozenset(
    {
        RemediationStatus.ALREADY_COMPLIANT,
        RemediationStatus.SKIPPED,
        RemediationStatus.NOT_REMEDIATED,
    }
)


@dataclass(frozen=True)
class XccdfMapping:
    """Platform outcome for an XCCDF result value, with an optional qualifier."""

    outcome: Outcome
    flag: ResultFlag | None = None


_ERROR_MAPPING: Final[XccdfMapping] = XccdfMapping(Outcome.ERROR)
_XCCDF_MAPPING: Final[Mapping[str, XccdfMapping]] = MappingProxyType(
    {
        "pass": XccdfMapping(Outcome.PASS),
        "fail": XccdfMapping(Outcome.FAIL),
        "notapplicable": XccdfMapping(Outcome.NOTAPPLICABLE),
        "notchecked": XccdfMapping(Outcome.NOTCHECKED),
        "error": XccdfMapping(Outcome.ERROR),
        "fixed": XccdfMapping(Outcome.PASS, ResultFlag.FIXED),
        "informational": XccdfMapping(Outcome.NOTCHECKED, ResultFlag.INFORMATIONAL),
        "notselected": XccdfMapping(Outcome.NOTCHECKED, ResultFlag.NOTSELECTED),
        "unknown": _ERROR_MAPPING,
    }
)


def map_xccdf_result(value: object) -> XccdfMapping:
    """Map an XCCDF result value to a platform outcome.

    The match is exact and case-sensitive. A value that is not listed in the
    mapping table, including ``waived``, ``disabled`` and every non-string,
    maps to ``error``. Waived and disabled findings are produced from exception
    and tailoring data, never from scanner output.

    Args:
        value: The raw XCCDF result value.

    Returns:
        The mapped outcome and the qualifier to retain, if any.
    """
    if not isinstance(value, str):
        return _ERROR_MAPPING
    return _XCCDF_MAPPING.get(value, _ERROR_MAPPING)


def _fail(message: str) -> NoReturn:
    raise ModelError(message)


def _safe(value: object) -> str:
    return repr(str(value)[:MAX_ECHO_LENGTH])


def _has_forbidden_characters(value: str, *, multiline: bool) -> bool:
    for character in value:
        if multiline:
            if character in _TEXT_ALLOWED_CONTROLS:
                continue
            if unicodedata.category(character) == "Cc" or character in _BIDI_CONTROLS:
                return True
        elif unicodedata.category(character) in _IDENTIFIER_FORBIDDEN_CATEGORIES:
            return True
    return False


def _text(
    value: object,
    name: str,
    *,
    max_length: int = MAX_TITLE_LENGTH,
    pattern: str | None = None,
    multiline: bool = False,
) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    if not value.strip():
        _fail(f"{name} must not be empty")
    if not multiline and value != value.strip():
        _fail(f"{name} must not have surrounding whitespace")
    if len(value) > max_length:
        _fail(f"{name} exceeds {max_length} characters")
    if _has_forbidden_characters(value, multiline=multiline):
        _fail(f"{name} contains control or formatting characters")
    if pattern is not None and re.fullmatch(pattern, value) is None:
        _fail(f"{name} has an invalid format")
    return value


def _optional_text(value: object, name: str, *, max_length: int = MAX_TEXT_LENGTH) -> str | None:
    if value is None:
        return None
    return _text(value, name, max_length=max_length, multiline=True)


def _instance(value: object, name: str, kind: type[T]) -> T:
    if not isinstance(value, kind):
        _fail(f"{name} must be of type {kind.__name__}")
    return value


def _optional_instance(value: object, name: str, kind: type[T]) -> T | None:
    if value is None:
        return None
    return _instance(value, name, kind)


def _enum(value: object, name: str, kind: type[E]) -> E:
    return _instance(value, name, kind)


def _flag(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{name} must be a boolean")
    return value


def _items(value: object, name: str, kind: type[T], max_items: int = MAX_ITEMS) -> tuple[T, ...]:
    if not isinstance(value, tuple):
        _fail(f"{name} must be a tuple")
    items = cast("tuple[object, ...]", value)
    if len(items) > max_items:
        _fail(f"{name} exceeds {max_items} items")
    for item in items:
        if not isinstance(item, kind):
            _fail(f"{name} items must be {kind.__name__}")
    return cast("tuple[T, ...]", items)


def _texts(
    value: object,
    name: str,
    *,
    max_length: int = MAX_ID_LENGTH,
    pattern: str | None = None,
) -> tuple[str, ...]:
    items = _items(value, name, str)
    for item in items:
        _text(item, f"{name} item", max_length=max_length, pattern=pattern)
    return items


def _unique(values: tuple[object, ...], name: str) -> None:
    if len(set(values)) != len(values):
        _fail(f"{name} contains duplicates")


def _timestamp(value: object, name: str) -> str:
    text = _text(value, name, max_length=20, pattern=_TIMESTAMP)
    try:
        _instant(text)
    except ValueError:
        _fail(f"{name} is not a valid UTC timestamp")
    return text


def _instant(text: str) -> datetime:
    return datetime.strptime(text, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def _xccdf_id(value: object, name: str, kind: str) -> str:
    return _text(value, name, max_length=MAX_ID_LENGTH, pattern=_XCCDF_PATTERNS[kind])


def validate_xccdf_id(value: object, name: str, kind: str) -> str:
    """Validate a full XCCDF identifier with the rules the model applies.

    Args:
        value: The candidate identifier.
        name: The field name used in error messages.
        kind: ``rule``, ``profile`` or ``benchmark``.

    Returns:
        The identifier, unchanged.

    Raises:
        ModelError: If the kind is unknown or the value is not a valid identifier.
    """
    if kind not in _XCCDF_PATTERNS:
        _fail(f"unknown XCCDF identifier kind {_safe(kind)}")
    return _xccdf_id(value, name, kind)


def validate_text(
    value: object,
    name: str,
    *,
    max_length: int,
    pattern: str | None = None,
    multiline: bool = False,
) -> str:
    """Validate a text field with the rules the model applies to its own fields.

    Identifier-like text (``multiline`` false) rejects surrounding whitespace and
    every character of Unicode category Cc, Cf, Zl or Zp. Free text allows tab,
    newline and carriage return and rejects other control characters and the
    bidi controls. Blank text is always rejected.

    Args:
        value: The candidate text.
        name: The field name used in error messages.
        max_length: The maximum number of characters.
        pattern: An optional anchored regular expression the text must match.
        multiline: Whether the text is free text rather than an identifier.

    Returns:
        The text, unchanged.

    Raises:
        ModelError: If the value violates the rules.
    """
    return _text(value, name, max_length=max_length, pattern=pattern, multiline=multiline)


class _Reader:
    def __init__(self, data: object, where: str, keys: tuple[str, ...]) -> None:
        if not isinstance(data, dict):
            _fail(f"{where} must be an object")
        mapping = cast("dict[str, object]", data)
        unknown = sorted(_safe(key) for key in mapping if key not in keys)
        if unknown:
            _fail(f"{where} has unknown keys: {', '.join(unknown[:5])}")
        missing = sorted(key for key in keys if key not in mapping)
        if missing:
            _fail(f"{where} is missing keys: {', '.join(missing)}")
        self._data = mapping
        self._where = where

    def _value(self, key: str, kind: type[T], label: str) -> T:
        value = self._data[key]
        if not isinstance(value, kind):
            _fail(f"{self._where}.{key} must be {label}")
        return value

    def text(self, key: str) -> str:
        return self._value(key, str, "a string")

    def optional_text(self, key: str) -> str | None:
        if self._data[key] is None:
            return None
        return self.text(key)

    def flag(self, key: str) -> bool:
        return self._value(key, bool, "a boolean")

    def array(self, key: str) -> list[object]:
        return cast("list[object]", self._value(key, list, "an array"))

    def strings(self, key: str) -> tuple[str, ...]:
        items = self.array(key)
        if not all(isinstance(item, str) for item in items):
            _fail(f"{self._where}.{key} must contain only strings")
        return tuple(str(item) for item in items)

    def enum(self, key: str, kind: type[E]) -> E:
        return self._member(key, self._data[key], kind)

    def enums(self, key: str, kind: type[E]) -> tuple[E, ...]:
        return tuple(self._member(key, item, kind) for item in self.array(key))

    def _member(self, key: str, value: object, kind: type[E]) -> E:
        if not isinstance(value, str):
            _fail(f"{self._where}.{key} must contain only strings")
        try:
            return kind(value)
        except ValueError:
            _fail(f"{self._where}.{key} has unknown value {_safe(value)}")

    def objects(self, key: str, parse: Callable[[object], T]) -> tuple[T, ...]:
        return tuple(parse(item) for item in self.array(key))

    def nested(self, key: str, parse: Callable[[object], T]) -> T:
        return parse(self._data[key])

    def optional_nested(self, key: str, parse: Callable[[object], T]) -> T | None:
        if self._data[key] is None:
            return None
        return parse(self._data[key])


@dataclass(frozen=True)
class Provenance:
    """Where a piece of content came from and which bytes it was read from."""

    source: str
    content_version: str
    content_sha256: str

    def __post_init__(self) -> None:
        """Validate the provenance record."""
        _text(self.source, "provenance.source", max_length=MAX_ID_LENGTH)
        _text(self.content_version, "provenance.content_version", max_length=64)
        _text(self.content_sha256, "provenance.content_sha256", max_length=64, pattern=_SHA256)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "content_sha256": self.content_sha256,
            "content_version": self.content_version,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: object) -> Provenance:
        """Build a record from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "provenance", ("source", "content_version", "content_sha256"))
        return cls(
            reader.text("source"), reader.text("content_version"), reader.text("content_sha256")
        )


@dataclass(frozen=True)
class ScannerInfo:
    """Name and version of the scanner that produced a scan run."""

    name: str
    version: str

    def __post_init__(self) -> None:
        """Validate the scanner description."""
        _text(self.name, "scanner.name", max_length=64, pattern=_SLUG)
        _text(self.version, "scanner.version", max_length=64, pattern=_IDENTIFIER_PATTERN)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"name": self.name, "version": self.version}

    @classmethod
    def from_dict(cls, data: object) -> ScannerInfo:
        """Build a record from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "scanner", ("name", "version"))
        return cls(reader.text("name"), reader.text("version"))


@dataclass(frozen=True)
class Framework:
    """A compliance framework."""

    framework_id: FrameworkId
    name: str

    def __post_init__(self) -> None:
        """Validate the framework."""
        _enum(self.framework_id, "framework.framework_id", FrameworkId)
        _text(self.name, "framework.name")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"framework_id": self.framework_id.value, "name": self.name}

    @classmethod
    def from_dict(cls, data: object) -> Framework:
        """Build a framework from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "framework", ("framework_id", "name"))
        return cls(reader.enum("framework_id", FrameworkId), reader.text("name"))


@dataclass(frozen=True)
class FrameworkVersion:
    """A published version of a compliance framework."""

    framework: Framework
    version: str

    def __post_init__(self) -> None:
        """Validate the framework version."""
        _instance(self.framework, "framework_version.framework", Framework)
        _text(self.version, "framework_version.version", max_length=64)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"framework": self.framework.to_dict(), "version": self.version}

    @classmethod
    def from_dict(cls, data: object) -> FrameworkVersion:
        """Build a framework version from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "framework_version", ("framework", "version"))
        return cls(reader.nested("framework", Framework.from_dict), reader.text("version"))


@dataclass(frozen=True)
class Applicability:
    """Versions of one distribution to which a rule applies."""

    distribution_id: str
    versions: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate and canonically order the applicability."""
        _text(self.distribution_id, "applicability.distribution_id", max_length=64, pattern=_SLUG)
        versions = _texts(
            self.versions, "applicability.versions", max_length=32, pattern=_IDENTIFIER_PATTERN
        )
        if not versions:
            _fail("applicability.versions must not be empty")
        _unique(versions, "applicability.versions")
        object.__setattr__(self, "versions", tuple(sorted(versions)))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"distribution_id": self.distribution_id, "versions": list(self.versions)}

    @classmethod
    def from_dict(cls, data: object) -> Applicability:
        """Build an applicability from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "applicability", ("distribution_id", "versions"))
        return cls(reader.text("distribution_id"), reader.strings("versions"))


@dataclass(frozen=True)
class Reference:
    """A mapping from a rule to a control of a compliance framework."""

    framework: FrameworkId
    control_id: str
    provenance: Provenance

    def __post_init__(self) -> None:
        """Validate the reference."""
        _enum(self.framework, "reference.framework", FrameworkId)
        _text(self.control_id, "reference.control_id", max_length=128)
        _instance(self.provenance, "reference.provenance", Provenance)

    def sort_key(self) -> str:
        """Return the canonical ordering and identity key."""
        return f"{self.framework.value}\x00{self.control_id}"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "control_id": self.control_id,
            "framework": self.framework.value,
            "provenance": self.provenance.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> Reference:
        """Build a reference from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "reference", ("framework", "control_id", "provenance"))
        return cls(
            reader.enum("framework", FrameworkId),
            reader.text("control_id"),
            reader.nested("provenance", Provenance.from_dict),
        )


@dataclass(frozen=True)
class Rule:
    """A benchmark rule, identified by its full XCCDF identifier."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    category: str
    control_class: ControlClass
    applicability: tuple[Applicability, ...]
    evaluation_method: EvaluationMethod
    remediation_method: RemediationMethod
    revert_strategy: RevertStrategy | None
    references: tuple[Reference, ...]

    def __post_init__(self) -> None:
        """Validate and canonically order the rule."""
        _xccdf_id(self.rule_id, "rule.rule_id", "rule")
        _text(self.title, "rule.title")
        _text(self.description, "rule.description", max_length=MAX_TEXT_LENGTH, multiline=True)
        _enum(self.severity, "rule.severity", Severity)
        _text(self.category, "rule.category", max_length=64, pattern=_SLUG)
        _enum(self.control_class, "rule.control_class", ControlClass)
        applicability = _items(self.applicability, "rule.applicability", Applicability)
        if not applicability:
            _fail("rule.applicability must not be empty")
        _unique(tuple(item.distribution_id for item in applicability), "rule.applicability")
        _enum(self.evaluation_method, "rule.evaluation_method", EvaluationMethod)
        _enum(self.remediation_method, "rule.remediation_method", RemediationMethod)
        if self.revert_strategy is not None:
            _enum(self.revert_strategy, "rule.revert_strategy", RevertStrategy)
        references = _items(self.references, "rule.references", Reference, 256)
        _unique(tuple(item.sort_key() for item in references), "rule.references")
        self._check_consistency()
        object.__setattr__(
            self,
            "applicability",
            tuple(sorted(applicability, key=lambda item: item.distribution_id)),
        )
        object.__setattr__(self, "references", tuple(sorted(references, key=Reference.sort_key)))

    def _check_consistency(self) -> None:
        if self.evaluation_method not in _CLASS_EVALUATION[self.control_class]:
            _fail("rule.evaluation_method does not match rule.control_class")
        remediable = self.control_class is ControlClass.AUTOMATABLE_REMEDIATION
        if remediable != (self.remediation_method is RemediationMethod.NATIVE_MODULE):
            _fail("rule.remediation_method does not match rule.control_class")
        if remediable != (self.revert_strategy is not None):
            _fail("rule.revert_strategy is required exactly for remediable rules")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "applicability": [item.to_dict() for item in self.applicability],
            "category": self.category,
            "control_class": self.control_class.value,
            "description": self.description,
            "evaluation_method": self.evaluation_method.value,
            "references": [item.to_dict() for item in self.references],
            "remediation_method": self.remediation_method.value,
            "revert_strategy": None if self.revert_strategy is None else self.revert_strategy.value,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
        }

    @classmethod
    def from_dict(cls, data: object) -> Rule:
        """Build a rule from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(
            data,
            "rule",
            (
                "rule_id",
                "title",
                "description",
                "severity",
                "category",
                "control_class",
                "applicability",
                "evaluation_method",
                "remediation_method",
                "revert_strategy",
                "references",
            ),
        )
        revert = reader.optional_text("revert_strategy")
        return cls(
            rule_id=reader.text("rule_id"),
            title=reader.text("title"),
            description=reader.text("description"),
            severity=reader.enum("severity", Severity),
            category=reader.text("category"),
            control_class=reader.enum("control_class", ControlClass),
            applicability=reader.objects("applicability", Applicability.from_dict),
            evaluation_method=reader.enum("evaluation_method", EvaluationMethod),
            remediation_method=reader.enum("remediation_method", RemediationMethod),
            revert_strategy=None
            if revert is None
            else reader.enum("revert_strategy", RevertStrategy),
            references=reader.objects("references", Reference.from_dict),
        )


@dataclass(frozen=True)
class Profile:
    """A benchmark profile: a named selection of rules."""

    profile_id: str
    title: str
    rule_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate and canonically order the profile."""
        _xccdf_id(self.profile_id, "profile.profile_id", "profile")
        _text(self.title, "profile.title")
        rule_ids = _items(self.rule_ids, "profile.rule_ids", str)
        for rule_id in rule_ids:
            _xccdf_id(rule_id, "profile.rule_ids item", "rule")
        _unique(rule_ids, "profile.rule_ids")
        object.__setattr__(self, "rule_ids", tuple(sorted(rule_ids)))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"profile_id": self.profile_id, "rule_ids": list(self.rule_ids), "title": self.title}

    @classmethod
    def from_dict(cls, data: object) -> Profile:
        """Build a profile from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "profile", ("profile_id", "title", "rule_ids"))
        return cls(reader.text("profile_id"), reader.text("title"), reader.strings("rule_ids"))


@dataclass(frozen=True)
class Benchmark:
    """A benchmark: rules and profiles from one pinned content item."""

    benchmark_id: str
    title: str
    version: str
    framework_version: FrameworkVersion | None
    provenance: Provenance
    profiles: tuple[Profile, ...]
    rules: tuple[Rule, ...]

    def __post_init__(self) -> None:
        """Validate and canonically order the benchmark."""
        _xccdf_id(self.benchmark_id, "benchmark.benchmark_id", "benchmark")
        _text(self.title, "benchmark.title")
        _text(self.version, "benchmark.version", max_length=64)
        _optional_instance(self.framework_version, "benchmark.framework_version", FrameworkVersion)
        _instance(self.provenance, "benchmark.provenance", Provenance)
        profiles = _items(self.profiles, "benchmark.profiles", Profile)
        rules = _items(self.rules, "benchmark.rules", Rule)
        _unique(tuple(profile.profile_id for profile in profiles), "benchmark.profiles")
        rule_ids = tuple(rule.rule_id for rule in rules)
        _unique(rule_ids, "benchmark.rules")
        for profile in profiles:
            if not set(profile.rule_ids) <= set(rule_ids):
                _fail(f"profile {profile.profile_id} selects a rule that the benchmark lacks")
        object.__setattr__(
            self, "profiles", tuple(sorted(profiles, key=lambda item: item.profile_id))
        )
        object.__setattr__(self, "rules", tuple(sorted(rules, key=lambda item: item.rule_id)))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "benchmark_id": self.benchmark_id,
            "framework_version": None
            if self.framework_version is None
            else self.framework_version.to_dict(),
            "profiles": [item.to_dict() for item in self.profiles],
            "provenance": self.provenance.to_dict(),
            "rules": [item.to_dict() for item in self.rules],
            "title": self.title,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: object) -> Benchmark:
        """Build a benchmark from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(
            data,
            "benchmark",
            (
                "benchmark_id",
                "title",
                "version",
                "framework_version",
                "provenance",
                "profiles",
                "rules",
            ),
        )
        return cls(
            benchmark_id=reader.text("benchmark_id"),
            title=reader.text("title"),
            version=reader.text("version"),
            framework_version=reader.optional_nested(
                "framework_version", FrameworkVersion.from_dict
            ),
            provenance=reader.nested("provenance", Provenance.from_dict),
            profiles=reader.objects("profiles", Profile.from_dict),
            rules=reader.objects("rules", Rule.from_dict),
        )


@dataclass(frozen=True)
class HostIdentity:
    """Identity of the managed host that was scanned."""

    hostname: str
    distribution_id: str
    distribution_version: str
    architecture: str
    machine_id: str | None

    def __post_init__(self) -> None:
        """Validate the host identity."""
        _text(self.hostname, "host.hostname", max_length=253, pattern=_IDENTIFIER_PATTERN)
        _text(self.distribution_id, "host.distribution_id", max_length=64, pattern=_SLUG)
        _text(
            self.distribution_version,
            "host.distribution_version",
            max_length=32,
            pattern=_IDENTIFIER_PATTERN,
        )
        _text(self.architecture, "host.architecture", max_length=32, pattern=_SLUG)
        if self.machine_id is not None:
            _text(self.machine_id, "host.machine_id", max_length=32, pattern=_MACHINE_ID)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "architecture": self.architecture,
            "distribution_id": self.distribution_id,
            "distribution_version": self.distribution_version,
            "hostname": self.hostname,
            "machine_id": self.machine_id,
        }

    @classmethod
    def from_dict(cls, data: object) -> HostIdentity:
        """Build a host identity from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(
            data,
            "host",
            ("hostname", "distribution_id", "distribution_version", "architecture", "machine_id"),
        )
        return cls(
            reader.text("hostname"),
            reader.text("distribution_id"),
            reader.text("distribution_version"),
            reader.text("architecture"),
            reader.optional_text("machine_id"),
        )


@dataclass(frozen=True)
class Evidence:
    """A bounded piece of host evidence that supports a finding."""

    kind: str
    source: str
    content: str

    def __post_init__(self) -> None:
        """Validate the evidence."""
        _text(self.kind, "evidence.kind", max_length=64, pattern=_SLUG)
        _text(self.source, "evidence.source", max_length=MAX_ID_LENGTH)
        _text(self.content, "evidence.content", max_length=MAX_EVIDENCE_LENGTH, multiline=True)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"content": self.content, "kind": self.kind, "source": self.source}

    @classmethod
    def from_dict(cls, data: object) -> Evidence:
        """Build evidence from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "evidence", ("kind", "source", "content"))
        return cls(reader.text("kind"), reader.text("source"), reader.text("content"))


@dataclass(frozen=True)
class ExceptionStatus:
    """Whether an exception record applies to a finding."""

    state: ExceptionState
    exception_id: str | None
    reason: str | None
    expires_at: str | None

    def __post_init__(self) -> None:
        """Validate the exception status."""
        _enum(self.state, "exception.state", ExceptionState)
        details = (self.exception_id, self.reason, self.expires_at)
        if self.state is ExceptionState.NONE:
            if any(detail is not None for detail in details):
                _fail("exception details require an active or expired exception")
            return
        _text(
            self.exception_id, "exception.exception_id", max_length=128, pattern=_IDENTIFIER_PATTERN
        )
        _text(self.reason, "exception.reason", max_length=MAX_TEXT_LENGTH, multiline=True)
        _timestamp(self.expires_at, "exception.expires_at")

    @classmethod
    def none(cls) -> ExceptionStatus:
        """Return the status of a finding without an exception."""
        return cls(ExceptionState.NONE, None, None, None)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "exception_id": self.exception_id,
            "expires_at": self.expires_at,
            "reason": self.reason,
            "state": self.state.value,
        }

    @classmethod
    def from_dict(cls, data: object) -> ExceptionStatus:
        """Build a status from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "exception", ("state", "exception_id", "reason", "expires_at"))
        return cls(
            reader.enum("state", ExceptionState),
            reader.optional_text("exception_id"),
            reader.optional_text("reason"),
            reader.optional_text("expires_at"),
        )


@dataclass(frozen=True)
class RemediationResult:
    """The result of a remediation or cleanup attempt for one rule."""

    rule_id: str
    status: RemediationStatus
    changed: bool
    message: str | None

    def __post_init__(self) -> None:
        """Validate the remediation result."""
        _xccdf_id(self.rule_id, "remediation.rule_id", "rule")
        _enum(self.status, "remediation.status", RemediationStatus)
        _flag(self.changed, "remediation.changed")
        _optional_text(self.message, "remediation.message", max_length=4096)
        if self.changed and self.status in _UNCHANGED_STATUSES:
            _fail(f"remediation.status {self.status.value} cannot report a change")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "changed": self.changed,
            "message": self.message,
            "rule_id": self.rule_id,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: object) -> RemediationResult:
        """Build a result from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(data, "remediation", ("rule_id", "status", "changed", "message"))
        return cls(
            reader.text("rule_id"),
            reader.enum("status", RemediationStatus),
            reader.flag("changed"),
            reader.optional_text("message"),
        )


@dataclass(frozen=True)
class Finding:
    """The normalized result of evaluating one rule on one host."""

    rule_id: str
    outcome: Outcome
    evaluated_outcome: Outcome
    severity: Severity
    message: str | None
    evidence: tuple[Evidence, ...]
    exception: ExceptionStatus
    remediation: RemediationResult | None
    disabled_by: str | None
    flags: tuple[ResultFlag, ...]

    def __post_init__(self) -> None:
        """Validate and canonically order the finding."""
        _xccdf_id(self.rule_id, "finding.rule_id", "rule")
        _enum(self.outcome, "finding.outcome", Outcome)
        _enum(self.evaluated_outcome, "finding.evaluated_outcome", Outcome)
        _enum(self.severity, "finding.severity", Severity)
        _optional_text(self.message, "finding.message", max_length=4096)
        _items(self.evidence, "finding.evidence", Evidence, MAX_EVIDENCE_ITEMS)
        _instance(self.exception, "finding.exception", ExceptionStatus)
        _optional_instance(self.remediation, "finding.remediation", RemediationResult)
        if self.disabled_by is not None:
            _text(self.disabled_by, "finding.disabled_by", max_length=128, pattern=_VARIABLE)
        flags = _items(self.flags, "finding.flags", ResultFlag, len(ResultFlag))
        _unique(flags, "finding.flags")
        self._check_links()
        object.__setattr__(self, "flags", tuple(sorted(flags, key=lambda flag: flag.value)))

    def _check_links(self) -> None:
        waived = self.outcome is Outcome.WAIVED
        active = self.exception.state is ExceptionState.ACTIVE
        if waived and not active:
            _fail("finding.outcome waived requires an active exception")
        if waived and self.evaluated_outcome is not Outcome.FAIL:
            _fail("finding.outcome waived requires an evaluated outcome of fail")
        if not waived and self.evaluated_outcome is not self.outcome:
            _fail("finding.evaluated_outcome may differ from finding.outcome only when waived")
        if active and self.outcome is Outcome.FAIL:
            _fail("a failed rule under an active exception must be reported as waived")
        if (self.outcome is Outcome.DISABLED) != (self.disabled_by is not None):
            _fail("finding.outcome disabled requires exactly finding.disabled_by")
        if self.remediation is not None and self.remediation.rule_id != self.rule_id:
            _fail("finding.remediation belongs to a different rule")
        for flag in self.flags:
            if self.outcome is not _FLAG_OUTCOMES[flag]:
                _fail(f"finding.flags {flag.value} does not match outcome {self.outcome.value}")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "disabled_by": self.disabled_by,
            "evaluated_outcome": self.evaluated_outcome.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "exception": self.exception.to_dict(),
            "flags": [flag.value for flag in self.flags],
            "message": self.message,
            "outcome": self.outcome.value,
            "remediation": None if self.remediation is None else self.remediation.to_dict(),
            "rule_id": self.rule_id,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, data: object) -> Finding:
        """Build a finding from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(
            data,
            "finding",
            (
                "rule_id",
                "outcome",
                "evaluated_outcome",
                "severity",
                "message",
                "evidence",
                "exception",
                "remediation",
                "disabled_by",
                "flags",
            ),
        )
        return cls(
            rule_id=reader.text("rule_id"),
            outcome=reader.enum("outcome", Outcome),
            evaluated_outcome=reader.enum("evaluated_outcome", Outcome),
            severity=reader.enum("severity", Severity),
            message=reader.optional_text("message"),
            evidence=reader.objects("evidence", Evidence.from_dict),
            exception=reader.nested("exception", ExceptionStatus.from_dict),
            remediation=reader.optional_nested("remediation", RemediationResult.from_dict),
            disabled_by=reader.optional_text("disabled_by"),
            flags=reader.enums("flags", ResultFlag),
        )


@dataclass(frozen=True)
class ScanRun:
    """One scanner execution against one host, with its normalized findings."""

    run_id: str
    started_at: str
    finished_at: str
    host: HostIdentity
    scanner: ScannerInfo
    content: Provenance
    benchmark_id: str
    profile_id: str
    status: ScanStatus
    error_message: str | None
    findings: tuple[Finding, ...]

    def __post_init__(self) -> None:
        """Validate and canonically order the scan run."""
        _text(self.run_id, "scan_run.run_id", max_length=128, pattern=_IDENTIFIER_PATTERN)
        started = _timestamp(self.started_at, "scan_run.started_at")
        finished = _timestamp(self.finished_at, "scan_run.finished_at")
        if finished < started:
            _fail("scan_run.finished_at precedes scan_run.started_at")
        _instance(self.host, "scan_run.host", HostIdentity)
        _instance(self.scanner, "scan_run.scanner", ScannerInfo)
        _instance(self.content, "scan_run.content", Provenance)
        _xccdf_id(self.benchmark_id, "scan_run.benchmark_id", "benchmark")
        _xccdf_id(self.profile_id, "scan_run.profile_id", "profile")
        _enum(self.status, "scan_run.status", ScanStatus)
        _optional_text(self.error_message, "scan_run.error_message", max_length=4096)
        findings = _items(self.findings, "scan_run.findings", Finding, MAX_FINDINGS)
        _unique(tuple(finding.rule_id for finding in findings), "scan_run.findings")
        self._check_status(findings)
        self._check_exceptions(findings)
        object.__setattr__(
            self, "findings", tuple(sorted(findings, key=lambda finding: finding.rule_id))
        )

    def _check_exceptions(self, findings: tuple[Finding, ...]) -> None:
        started = _instant(self.started_at)
        for finding in findings:
            state = finding.exception.state
            if state is ExceptionState.NONE:
                continue
            expiry = _instant(_timestamp(finding.exception.expires_at, "exception.expires_at"))
            if state is ExceptionState.ACTIVE and expiry <= started:
                _fail(f"exception for {finding.rule_id} is active but expired at scan start")
            if state is ExceptionState.EXPIRED and expiry > started:
                _fail(
                    f"exception for {finding.rule_id} is marked expired but is valid at scan start"
                )

    def _check_status(self, findings: tuple[Finding, ...]) -> None:
        if (self.status is ScanStatus.COMPLETED) != (self.error_message is None):
            _fail("scan_run.error_message is required exactly when the scanner did not complete")
        not_completed = self.status is not ScanStatus.COMPLETED
        if not_completed and any(finding.outcome is not Outcome.ERROR for finding in findings):
            _fail("a failed scanner execution may only produce error findings")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping that includes the schema version."""
        return {
            "benchmark_id": self.benchmark_id,
            "content": self.content.to_dict(),
            "error_message": self.error_message,
            "finished_at": self.finished_at,
            "findings": [item.to_dict() for item in self.findings],
            "host": self.host.to_dict(),
            "profile_id": self.profile_id,
            "run_id": self.run_id,
            "scanner": self.scanner.to_dict(),
            "schema_version": SCHEMA_VERSION,
            "started_at": self.started_at,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: object) -> ScanRun:
        """Build a scan run from a mapping, rejecting unknown and missing keys."""
        reader = _Reader(
            data,
            "scan_run",
            (
                "schema_version",
                "run_id",
                "started_at",
                "finished_at",
                "host",
                "scanner",
                "content",
                "benchmark_id",
                "profile_id",
                "status",
                "error_message",
                "findings",
            ),
        )
        version = reader.text("schema_version")
        if version not in SUPPORTED_SCHEMA_VERSIONS:
            _fail(f"unsupported schema_version {_safe(version)}")
        return cls(
            run_id=reader.text("run_id"),
            started_at=reader.text("started_at"),
            finished_at=reader.text("finished_at"),
            host=reader.nested("host", HostIdentity.from_dict),
            scanner=reader.nested("scanner", ScannerInfo.from_dict),
            content=reader.nested("content", Provenance.from_dict),
            benchmark_id=reader.text("benchmark_id"),
            profile_id=reader.text("profile_id"),
            status=reader.enum("status", ScanStatus),
            error_message=reader.optional_text("error_message"),
            findings=reader.objects("findings", Finding.from_dict),
        )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate key {_safe(key)}")
        result[key] = value
    return result


def _reject_constant(constant: str) -> NoReturn:
    _fail(f"non-finite number {constant}")


def dumps(run: ScanRun) -> str:
    """Serialize a scan run to deterministic JSON.

    Keys are sorted, separators are compact, non-ASCII is escaped and non-finite
    numbers are impossible, so equal runs produce identical text.

    Args:
        run: The scan run to serialize.

    Returns:
        The JSON document, which contains ``schema_version``.
    """
    return json.dumps(
        run.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def loads(text: str) -> ScanRun:
    """Parse a scan run from a JSON document.

    Args:
        text: The JSON document produced by :func:`dumps`.

    Returns:
        The validated scan run.

    Raises:
        ModelError: If the text is oversized, is not valid JSON, has duplicate
            keys or non-finite numbers, or does not satisfy the model.
    """
    _instance(text, "document", str)
    if len(text) > MAX_DOCUMENT_CHARS:
        _fail("document exceeds the size limit")
    try:
        document = json.loads(
            text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
        )
    except ModelError:
        raise
    except (ValueError, RecursionError):
        _fail("document is not valid JSON")
    return ScanRun.from_dict(document)
