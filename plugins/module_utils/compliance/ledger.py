"""On-host state ledger of applied remediations.

The ledger records, for every rule that the collection applied, what is needed to
revert it when the rule is disabled (ADR 0011): the rule identifier, the control
family, the revert strategy, the prior values, the collection version and the time
of application. It lives in ``/var/lib/freesecdev/linux_compliance/state.json``,
owned by root with mode ``0600`` in a ``0700`` directory.

The module uses only the Python standard library and syntax that runs on Python
3.9. All file access goes through :mod:`fileio`, the single audited file helper.

The file is a JSON document with ``schema_version`` and a list of ``entries``
sorted by rule identifier, serialised deterministically. Version 2 (ADR 0032) adds an
optional ``value`` record to an entry (where the value a rule wrote came from) and a
top-level list of ``deviations``, the register of rules whose value in force is
looser than the profile. Version 1 is still written when nothing needs version 2, so
an existing ledger keeps its bytes. Every document has exactly one form: a version 2
document that needs nothing of version 2 is refused. Reading is strict: the size is
bounded, duplicate keys, ``NaN`` and ``Infinity``, unknown or missing keys and
unsupported schema versions are refused. A corrupt or unsafe ledger raises
:class:`LedgerError`; it is never repaired, reset or replaced silently. A missing
ledger is an empty ledger.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final, NoReturn, TypeVar, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    fileio,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance.model import (
    TIMESTAMP_FORMAT,
    RevertStrategy,
)

if TYPE_CHECKING:
    from collections.abc import Callable

LEDGER_DIRECTORY: Final[str] = "/var/lib/freesecdev/linux_compliance"
LEDGER_FILENAME: Final[str] = "state.json"
SCHEMA_VERSION: Final[int] = 2
BASE_SCHEMA_VERSION: Final[int] = 1
SUPPORTED_SCHEMA_VERSIONS: Final[frozenset[int]] = frozenset({BASE_SCHEMA_VERSION, SCHEMA_VERSION})
MAX_LEDGER_BYTES: Final[int] = 4 * 1024 * 1024
MAX_ENTRIES: Final[int] = 4096
MAX_DEVIATIONS: Final[int] = MAX_ENTRIES
MAX_PRIOR_VALUES: Final[int] = 64
MAX_VALUE_LENGTH: Final[int] = 4096
MAX_RULE_ID_LENGTH: Final[int] = 256
MAX_FAMILY_LENGTH: Final[int] = 64
MAX_NAME_LENGTH: Final[int] = 128
MAX_VERSION_LENGTH: Final[int] = 64
MAX_VALUE_ID_LENGTH: Final[int] = 128
VALUE_SOURCES: Final[frozenset[str]] = frozenset({"profile", "override"})

ERROR_TYPES: Final[frozenset[str]] = fileio.REASONS | frozenset(
    {"corrupt", "unsupported_schema", "invalid_entry", "conflict", "ledger_full"}
)

_RULE_ID: Final[str] = r"xccdf_[A-Za-z0-9_.-]+?_rule_[A-Za-z0-9_.+-]+"
_FAMILY: Final[str] = r"[a-z0-9][a-z0-9._-]*"
_NAME: Final[str] = r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]*"
_VERSION: Final[str] = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?"
_TIMESTAMP: Final[str] = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
_VALUE_ID: Final[str] = r"[a-z0-9][a-z0-9_]*"
_VALUE_SOURCE: Final[str] = r"profile|override"
_ALLOWED_CONTROLS: Final[frozenset[str]] = frozenset({"\t", "\n", "\r"})
_BIDI_CONTROLS: Final[frozenset[str]] = frozenset(
    chr(code) for code in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
)
_ENTRY_KEYS: Final[tuple[str, ...]] = (
    "applied_at",
    "collection_version",
    "family",
    "prior_values",
    "revert_strategy",
    "rule_id",
)
_VALUED_ENTRY_KEYS: Final[tuple[str, ...]] = (*_ENTRY_KEYS, "value")
_VALUE_KEYS: Final[tuple[str, ...]] = ("name", "sensitive", "value")
_VALUE_RECORD_KEYS: Final[tuple[str, ...]] = ("profile_value", "target", "value_id", "value_source")
_DEVIATION_KEYS: Final[tuple[str, ...]] = (
    "collection_version",
    "effective_value",
    "profile_value",
    "recorded_at",
    "rule_id",
    "value_id",
)
_BASE_DOCUMENT_KEYS: Final[tuple[str, ...]] = ("entries", "schema_version")
_DOCUMENT_KEYS: Final[tuple[str, ...]] = ("deviations", "entries", "schema_version")
_NEEDS_PRIOR_VALUES: Final[frozenset[RevertStrategy]] = frozenset(
    {RevertStrategy.RECORDED_VALUE, RevertStrategy.RECORDED_STATE}
)

T = TypeVar("T")


class LedgerError(Exception):
    """A ledger refusal or failure with a stable ``error_type``."""

    def __init__(self, error_type: str, message: str) -> None:
        """Store the stable error type and the message."""
        super().__init__(message)
        self.error_type = error_type


def _fail(error_type: str, message: str) -> NoReturn:
    raise LedgerError(error_type, message)


def _invalid(message: str) -> NoReturn:
    _fail("invalid_entry", message)


def _text(value: object, name: str, max_length: int, pattern: str) -> str:
    if not isinstance(value, str):
        _invalid(f"{name} must be a string")
    if not value or len(value) > max_length:
        _invalid(f"{name} must have 1 to {max_length} characters")
    if re.fullmatch(pattern, value) is None:
        _invalid(f"{name} has an invalid format")
    return value


def _value_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _invalid(f"{name} must be a string or null")
    if len(value) > MAX_VALUE_LENGTH:
        _invalid(f"{name} exceeds {MAX_VALUE_LENGTH} characters")
    for character in value:
        category = unicodedata.category(character)
        if (
            character in _BIDI_CONTROLS
            or category == "Cs"
            or (category == "Cc" and character not in _ALLOWED_CONTROLS)
        ):
            _invalid(f"{name} contains control characters")
    return value


def _setting_text(value: object, name: str) -> str:
    if not isinstance(value, str):
        _invalid(f"{name} must be a string")
    if len(value) > MAX_VALUE_LENGTH:
        _invalid(f"{name} exceeds {MAX_VALUE_LENGTH} characters")
    for character in value:
        if character in _BIDI_CONTROLS or unicodedata.category(character) in {"Cc", "Cs"}:
            _invalid(f"{name} contains control characters")
    return value


def _timestamp(value: object, name: str) -> str:
    text = _text(value, name, len("2000-01-01T00:00:00Z"), _TIMESTAMP)
    try:
        datetime.strptime(text, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        _invalid(f"{name} is not a valid UTC timestamp")
    return text


def check_value_id(value: object) -> str:
    """Validate the short identifier of an XCCDF value.

    Raises:
        LedgerError: With ``invalid_entry`` unless it is a lower-case identifier of at
            most 128 characters, such as ``var_password_pam_minlen``.
    """
    return _text(value, "value_id", MAX_VALUE_ID_LENGTH, _VALUE_ID)


def _instance(value: object, name: str, kind: type[T]) -> T:
    if not isinstance(value, kind):
        _invalid(f"{name} must be of type {kind.__name__}")
    return value


def _prior_value_items(value: object) -> tuple[PriorValue, ...]:
    if not isinstance(value, tuple):
        _invalid("prior_values must be a tuple")
    items = cast("tuple[object, ...]", value)
    for item in items:
        _instance(item, "prior_values item", PriorValue)
    return cast("tuple[PriorValue, ...]", items)


def _flag(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        _invalid(f"{name} must be a boolean")
    return value


def _mapping(value: object, name: str, keys: tuple[str, ...]) -> dict[str, object]:
    if not isinstance(value, dict):
        _invalid(f"{name} must be an object")
    data = cast("dict[str, object]", value)
    if set(data) != set(keys):
        _invalid(f"{name} must have exactly the keys {', '.join(keys)}")
    return data


def _has_value(data: object) -> bool:
    return isinstance(data, dict) and "value" in cast("dict[str, object]", data)


def _entry_mapping(value: object) -> dict[str, object]:
    return _mapping(value, "entry", _VALUED_ENTRY_KEYS if _has_value(value) else _ENTRY_KEYS)


def _list(value: object, name: str, max_items: int) -> list[object]:
    if not isinstance(value, list):
        _invalid(f"{name} must be a list")
    items = cast("list[object]", value)
    if len(items) > max_items:
        _invalid(f"{name} exceeds {max_items} items")
    return items


@dataclass(frozen=True)
class PriorValue:
    """One recorded prior value; ``value`` is ``None`` if the setting did not exist."""

    name: str
    value: str | None
    sensitive: bool = False

    def __post_init__(self) -> None:
        """Validate the prior value."""
        _text(self.name, "prior value name", MAX_NAME_LENGTH, _NAME)
        _value_text(self.value, "prior value")
        _flag(self.sensitive, "prior value sensitive")

    def to_dict(self) -> dict[str, object]:
        """Return the on-disk mapping."""
        return {"name": self.name, "sensitive": self.sensitive, "value": self.value}

    def view(self, *, reveal: bool) -> dict[str, object]:
        """Return the reporting mapping; sensitive values are redacted unless revealed."""
        redacted = self.sensitive and not reveal
        return {
            "name": self.name,
            "redacted": redacted,
            "sensitive": self.sensitive,
            "value": None if redacted else self.value,
        }

    @classmethod
    def from_dict(cls, data: object) -> PriorValue:
        """Build a prior value from its on-disk mapping."""
        fields = _mapping(data, "prior value", _VALUE_KEYS)
        return cls(
            cast("str", fields["name"]),
            cast("str | None", fields["value"]),
            cast("bool", fields["sensitive"]),
        )


@dataclass(frozen=True)
class ValueRecord:
    """Where the value that a rule wrote came from (ADR 0032).

    ``value_source`` is ``profile`` when the target is the selected profile's value and
    ``override`` when the operator chose it; ``target`` is the value the family aimed
    at, ``profile_value`` the profile's value for the same XCCDF value.
    """

    value_id: str
    value_source: str
    profile_value: str
    target: str

    def __post_init__(self) -> None:
        """Validate the value record."""
        check_value_id(self.value_id)
        _text(self.value_source, "value_source", len("override"), _VALUE_SOURCE)
        _setting_text(self.profile_value, "profile_value")
        _setting_text(self.target, "target")

    def to_dict(self) -> dict[str, object]:
        """Return the on-disk mapping, which is also the reporting mapping."""
        return {
            "profile_value": self.profile_value,
            "target": self.target,
            "value_id": self.value_id,
            "value_source": self.value_source,
        }

    @classmethod
    def from_dict(cls, data: object) -> ValueRecord:
        """Build a value record from its on-disk mapping."""
        fields = _mapping(data, "value", _VALUE_RECORD_KEYS)
        return cls(
            cast("str", fields["value_id"]),
            cast("str", fields["value_source"]),
            cast("str", fields["profile_value"]),
            cast("str", fields["target"]),
        )


@dataclass(frozen=True)
class LedgerEntry:
    """What was applied for one rule and how to revert it.

    ``value`` is ``None`` for an entry that records no value, which reads as a value
    taken from the profile.
    """

    rule_id: str
    family: str
    revert_strategy: RevertStrategy
    prior_values: tuple[PriorValue, ...]
    collection_version: str
    applied_at: str
    value: ValueRecord | None = None

    def __post_init__(self) -> None:
        """Validate the entry and order its prior values by name."""
        _text(self.rule_id, "rule_id", MAX_RULE_ID_LENGTH, _RULE_ID)
        _text(self.family, "family", MAX_FAMILY_LENGTH, _FAMILY)
        _instance(self.revert_strategy, "revert_strategy", RevertStrategy)
        _text(self.collection_version, "collection_version", MAX_VERSION_LENGTH, _VERSION)
        _timestamp(self.applied_at, "applied_at")
        if self.value is not None:
            _instance(self.value, "value", ValueRecord)
        values = self._checked_prior_values()
        object.__setattr__(self, "prior_values", tuple(sorted(values, key=_value_name)))

    def _checked_prior_values(self) -> tuple[PriorValue, ...]:
        values = _prior_value_items(self.prior_values)
        if len(values) > MAX_PRIOR_VALUES:
            _invalid(f"prior_values exceeds {MAX_PRIOR_VALUES} items")
        if len({item.name for item in values}) != len(values):
            _invalid("prior_values contains duplicate names")
        if self.revert_strategy in _NEEDS_PRIOR_VALUES and not values:
            _invalid(f"revert strategy {self.revert_strategy.value} needs prior values")
        if self.revert_strategy not in _NEEDS_PRIOR_VALUES and values:
            _invalid(f"revert strategy {self.revert_strategy.value} takes no prior values")
        return values

    def same_content(self, other: LedgerEntry) -> bool:
        """Return whether ``other`` differs at most in the application time."""
        return self.to_dict() == {**other.to_dict(), "applied_at": self.applied_at}

    def to_dict(self) -> dict[str, object]:
        """Return the on-disk mapping; ``value`` appears only when it is recorded."""
        data: dict[str, object] = {
            "applied_at": self.applied_at,
            "collection_version": self.collection_version,
            "family": self.family,
            "prior_values": [item.to_dict() for item in self.prior_values],
            "revert_strategy": self.revert_strategy.value,
            "rule_id": self.rule_id,
        }
        if self.value is not None:
            data["value"] = self.value.to_dict()
        return data

    def view(self, *, reveal: bool = False) -> dict[str, object]:
        """Return the reporting mapping; sensitive values are redacted unless revealed.

        ``value_source`` is always present: an entry without a value record reads as
        ``profile``.
        """
        return {
            "applied_at": self.applied_at,
            "collection_version": self.collection_version,
            "family": self.family,
            "prior_values": [item.view(reveal=reveal) for item in self.prior_values],
            "revert_strategy": self.revert_strategy.value,
            "rule_id": self.rule_id,
            "value": None if self.value is None else self.value.to_dict(),
            "value_source": "profile" if self.value is None else self.value.value_source,
        }

    @classmethod
    def from_dict(cls, data: object) -> LedgerEntry:
        """Build an entry from its on-disk mapping, rejecting unknown and missing keys.

        ``value`` is optional here; a version 1 document that holds one is refused
        because it is not in the form that :func:`dumps` writes.
        """
        fields = _entry_mapping(data)
        strategy = fields["revert_strategy"]
        try:
            revert = RevertStrategy(strategy)
        except ValueError:
            _invalid("revert_strategy is not a known strategy")
        values = _list(fields["prior_values"], "prior_values", MAX_PRIOR_VALUES)
        value = ValueRecord.from_dict(fields["value"]) if "value" in fields else None
        return cls(
            cast("str", fields["rule_id"]),
            cast("str", fields["family"]),
            revert,
            tuple(PriorValue.from_dict(item) for item in values),
            cast("str", fields["collection_version"]),
            cast("str", fields["applied_at"]),
            value,
        )


@dataclass(frozen=True)
class DeviationRecord:
    """A rule whose value in force is looser than the profile's (ADR 0032).

    The record is kept apart from the revert entries: a looser value that the host
    already has needs a record although nothing was written, and there is nothing to
    revert for it.
    """

    rule_id: str
    value_id: str
    profile_value: str
    effective_value: str
    recorded_at: str
    collection_version: str

    def __post_init__(self) -> None:
        """Validate the deviation record."""
        _text(self.rule_id, "rule_id", MAX_RULE_ID_LENGTH, _RULE_ID)
        check_value_id(self.value_id)
        _setting_text(self.profile_value, "profile_value")
        _setting_text(self.effective_value, "effective_value")
        _timestamp(self.recorded_at, "recorded_at")
        _text(self.collection_version, "collection_version", MAX_VERSION_LENGTH, _VERSION)

    def same_content(self, other: DeviationRecord) -> bool:
        """Return whether ``other`` differs at most in the time it was recorded."""
        return self.to_dict() == {**other.to_dict(), "recorded_at": self.recorded_at}

    def to_dict(self) -> dict[str, object]:
        """Return the on-disk mapping, which is also the reporting mapping."""
        return {
            "collection_version": self.collection_version,
            "effective_value": self.effective_value,
            "profile_value": self.profile_value,
            "recorded_at": self.recorded_at,
            "rule_id": self.rule_id,
            "value_id": self.value_id,
        }

    @classmethod
    def from_dict(cls, data: object) -> DeviationRecord:
        """Build a deviation record from its on-disk mapping."""
        fields = _mapping(data, "deviation", _DEVIATION_KEYS)
        return cls(
            cast("str", fields["rule_id"]),
            cast("str", fields["value_id"]),
            cast("str", fields["profile_value"]),
            cast("str", fields["effective_value"]),
            cast("str", fields["recorded_at"]),
            cast("str", fields["collection_version"]),
        )


@dataclass(frozen=True)
class LedgerDocument:
    """The whole ledger: the revert entries and the deviation register."""

    entries: tuple[LedgerEntry, ...] = ()
    deviations: tuple[DeviationRecord, ...] = ()

    @property
    def schema_version(self) -> int:
        """Return the version this document is written with.

        Version 1 when no entry records a value and the register is empty, so that a
        ledger without overrides keeps its bytes; version 2 otherwise.
        """
        if self.deviations or any(entry.value is not None for entry in self.entries):
            return SCHEMA_VERSION
        return BASE_SCHEMA_VERSION


def _value_name(value: PriorValue) -> str:
    return value.name


def _rule_id_of(entry: LedgerEntry | DeviationRecord) -> str:
    return entry.rule_id


def check_rule_id(value: object) -> str:
    """Validate a rule identifier.

    Raises:
        LedgerError: With ``invalid_entry`` if it is not a full XCCDF rule identifier.
    """
    return _text(value, "rule_id", MAX_RULE_ID_LENGTH, _RULE_ID)


def check_family(value: object) -> str:
    """Validate a control family name.

    Raises:
        LedgerError: With ``invalid_entry`` if it is not a lower-case slug.
    """
    return _text(value, "family", MAX_FAMILY_LENGTH, _FAMILY)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("corrupt", "the ledger contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(constant: str) -> NoReturn:
    _fail("corrupt", f"the ledger contains the non-finite number {constant}")


def dumps(entries: tuple[LedgerEntry, ...], deviations: tuple[DeviationRecord, ...] = ()) -> bytes:
    """Serialise entries and deviations to the deterministic ledger document.

    The document is version 1, with only ``entries``, when no entry records a value
    and there is no deviation, and version 2, with ``deviations`` as well, otherwise.

    Raises:
        LedgerError: With ``ledger_full`` if there are too many entries or deviations
            or the document would exceed :data:`MAX_LEDGER_BYTES`.
    """
    if len(entries) > MAX_ENTRIES:
        _fail("ledger_full", f"the ledger cannot hold more than {MAX_ENTRIES} entries")
    if len(deviations) > MAX_DEVIATIONS:
        _fail("ledger_full", f"the ledger cannot hold more than {MAX_DEVIATIONS} deviations")
    version = LedgerDocument(entries, deviations).schema_version
    document: dict[str, object] = {
        "entries": [entry.to_dict() for entry in sorted(entries, key=_rule_id_of)],
        "schema_version": version,
    }
    if version == SCHEMA_VERSION:
        document["deviations"] = [item.to_dict() for item in sorted(deviations, key=_rule_id_of)]
    data = (json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("ascii")
    if len(data) > MAX_LEDGER_BYTES:
        _fail("ledger_full", "the ledger would exceed its size limit")
    return data


def _document_fields(document: object) -> tuple[int, dict[str, object]]:
    if not isinstance(document, dict) or "schema_version" not in document:
        _fail("corrupt", "the ledger is not an object with a schema version")
    data = cast("dict[str, object]", document)
    version = data["schema_version"]
    if isinstance(version, bool) or not isinstance(version, int):
        _fail("corrupt", "the ledger schema version is not an integer")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        _fail("unsupported_schema", "the ledger schema version is not supported")
    keys = _DOCUMENT_KEYS if version == SCHEMA_VERSION else _BASE_DOCUMENT_KEYS
    return version, _mapping(data, "ledger", keys)


def _parse_document(version: int, fields: dict[str, object]) -> LedgerDocument:
    entries = tuple(
        LedgerEntry.from_dict(item) for item in _list(fields["entries"], "entries", MAX_ENTRIES)
    )
    deviations = tuple(
        DeviationRecord.from_dict(item)
        for item in _list(fields.get("deviations", []), "deviations", MAX_DEVIATIONS)
    )
    if len({entry.rule_id for entry in entries}) != len(entries):
        _fail("corrupt", "the ledger contains a rule more than once")
    if len({item.rule_id for item in deviations}) != len(deviations):
        _fail("corrupt", "the ledger records a deviation of a rule more than once")
    parsed = LedgerDocument(
        tuple(sorted(entries, key=_rule_id_of)), tuple(sorted(deviations, key=_rule_id_of))
    )
    if parsed.schema_version != version:
        _fail("corrupt", f"the content of the ledger does not match its schema version {version}")
    return parsed


def load_document(data: bytes) -> LedgerDocument:
    """Parse and validate a ledger document of version 1 or 2.

    A version 1 document has an empty deviation register and entries without value
    records.

    Raises:
        LedgerError: With ``corrupt`` for malformed JSON, duplicate keys, non-finite
            numbers, wrong shapes, invalid or duplicate entries or deviations, a value
            record in a version 1 document and a version 2 document that needs nothing
            of version 2, and with ``unsupported_schema`` for another schema version.
    """
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):
        _fail("corrupt", "the ledger is not valid JSON")
    try:
        version, fields = _document_fields(document)
        return _parse_document(version, fields)
    except LedgerError as error:
        if error.error_type == "invalid_entry":
            _fail("corrupt", f"the ledger is invalid: {error}")
        raise


def loads(data: bytes) -> tuple[LedgerEntry, ...]:
    """Parse and validate a ledger document and return its entries.

    Raises:
        LedgerError: As :func:`load_document`.
    """
    return load_document(data).entries


def _translate(error: fileio.SafeFileError) -> LedgerError:
    return LedgerError(error.reason, str(error))


@dataclass(frozen=True)
class RecordResult:
    """Outcome of recording an entry."""

    entry: LedgerEntry
    previous: LedgerEntry | None
    changed: bool


@dataclass(frozen=True)
class RemoveResult:
    """Outcome of removing an entry."""

    previous: LedgerEntry | None
    changed: bool


@dataclass(frozen=True)
class DeviationResult:
    """Outcome of recording a deviation."""

    record: DeviationRecord
    previous: DeviationRecord | None
    changed: bool


@dataclass(frozen=True)
class RemoveDeviationResult:
    """Outcome of removing a deviation."""

    previous: DeviationRecord | None
    changed: bool


class Ledger:
    """The on-host ledger.

    Production code constructs ``Ledger()``. ``state_dir``, ``owner_uid`` and
    ``lock_timeout`` are keyword-only and exist so that unit tests can use a directory
    they own; the guard bans these keywords in plugin code and module arguments never
    reach them.
    """

    def __init__(
        self,
        *,
        state_dir: str = LEDGER_DIRECTORY,
        owner_uid: int = fileio.ROOT_UID,
        lock_timeout: float = fileio.DEFAULT_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        """Store the location, required owner and lock timeout."""
        self._state_dir = state_dir
        self._owner_uid = owner_uid
        self._lock_timeout = lock_timeout

    @property
    def path(self) -> str:
        """Return the ledger file path, for reporting only."""
        return f"{self._state_dir.rstrip('/')}/{LEDGER_FILENAME}"

    def _read(self, directory: fileio.SafeDirectory) -> LedgerDocument:
        try:
            data = directory.read(LEDGER_FILENAME, MAX_LEDGER_BYTES)
        except fileio.SafeFileError as error:
            raise _translate(error) from error
        return LedgerDocument() if data is None else load_document(data)

    def _transact(
        self,
        update: Callable[[LedgerDocument], tuple[LedgerDocument, T]],
        *,
        write: bool,
        create: bool,
    ) -> T:
        try:
            directory = fileio.open_directory(
                self._state_dir, owner_uid=self._owner_uid, create=create
            )
            if directory is None:
                return update(LedgerDocument())[1]
            try:
                if write:
                    directory.lock(self._lock_timeout)
                current = self._read(directory)
                updated, result = update(current)
                if write and updated != current:
                    directory.sweep_temporaries(LEDGER_FILENAME)
                    directory.write(LEDGER_FILENAME, dumps(updated.entries, updated.deviations))
                return result
            finally:
                directory.close()
        except fileio.SafeFileError as error:
            raise _translate(error) from error

    def document(self) -> LedgerDocument:
        """Return the entries and the deviations of one read. A missing ledger is empty."""
        return self._transact(lambda current: (current, current), write=False, create=False)

    def entries(self) -> tuple[LedgerEntry, ...]:
        """Return every entry sorted by rule identifier. A missing ledger is empty."""
        return self.document().entries

    def deviations(self) -> tuple[DeviationRecord, ...]:
        """Return every deviation sorted by rule identifier. A missing ledger has none."""
        return self.document().deviations

    def get(self, rule_id: str) -> LedgerEntry | None:
        """Return the entry of ``rule_id``, or ``None``."""
        check_rule_id(rule_id)
        return next((entry for entry in self.entries() if entry.rule_id == rule_id), None)

    def record(
        self, entry: LedgerEntry, *, replace: bool = False, dry_run: bool = False
    ) -> RecordResult:
        """Record ``entry``.

        An identical entry already present is left untouched (same applied time).
        A different one is a ``conflict`` unless ``replace`` is set.

        Args:
            entry: The entry to record.
            replace: Replace a different existing entry.
            dry_run: Compute the result without writing or creating anything.

        Raises:
            LedgerError: On conflict, a full ledger, or an unsafe or corrupt ledger.
        """

        def update(current: LedgerDocument) -> tuple[LedgerDocument, RecordResult]:
            entries = current.entries
            previous = next((item for item in entries if item.rule_id == entry.rule_id), None)
            if previous is not None and previous.same_content(entry):
                return current, RecordResult(previous, previous, changed=False)
            if previous is not None and not replace:
                _fail("conflict", "the rule is already recorded with different content")
            others = tuple(item for item in entries if item.rule_id != entry.rule_id)
            updated = LedgerDocument((*others, entry), current.deviations)
            return updated, RecordResult(entry, previous, changed=True)

        return self._transact(update, write=not dry_run, create=not dry_run)

    def remove(self, rule_id: str, *, dry_run: bool = False) -> RemoveResult:
        """Remove the entry of ``rule_id``. A missing entry is not an error.

        Raises:
            LedgerError: On an unsafe or corrupt ledger.
        """
        check_rule_id(rule_id)

        def update(current: LedgerDocument) -> tuple[LedgerDocument, RemoveResult]:
            entries = current.entries
            previous = next((item for item in entries if item.rule_id == rule_id), None)
            kept = tuple(item for item in entries if item.rule_id != rule_id)
            updated = LedgerDocument(kept, current.deviations)
            return updated, RemoveResult(previous, changed=previous is not None)

        return self._transact(update, write=not dry_run, create=False)

    def record_deviation(
        self, record: DeviationRecord, *, dry_run: bool = False
    ) -> DeviationResult:
        """Record that the value in force of a rule is looser than the profile's.

        A record with the same content already present is left untouched (same time).
        A different record of the rule is replaced: the register holds the current
        state, not history.

        Raises:
            LedgerError: On a full ledger, or an unsafe or corrupt ledger.
        """
        _instance(record, "deviation", DeviationRecord)

        def update(current: LedgerDocument) -> tuple[LedgerDocument, DeviationResult]:
            deviations = current.deviations
            previous = next((item for item in deviations if item.rule_id == record.rule_id), None)
            if previous is not None and previous.same_content(record):
                return current, DeviationResult(previous, previous, changed=False)
            others = tuple(item for item in deviations if item.rule_id != record.rule_id)
            updated = LedgerDocument(current.entries, (*others, record))
            return updated, DeviationResult(record, previous, changed=True)

        return self._transact(update, write=not dry_run, create=not dry_run)

    def remove_deviation(self, rule_id: str, *, dry_run: bool = False) -> RemoveDeviationResult:
        """Remove the deviation of ``rule_id``. A missing record is not an error.

        Raises:
            LedgerError: On an unsafe or corrupt ledger.
        """
        check_rule_id(rule_id)

        def update(current: LedgerDocument) -> tuple[LedgerDocument, RemoveDeviationResult]:
            deviations = current.deviations
            previous = next((item for item in deviations if item.rule_id == rule_id), None)
            kept = tuple(item for item in deviations if item.rule_id != rule_id)
            updated = LedgerDocument(current.entries, kept)
            return updated, RemoveDeviationResult(previous, changed=previous is not None)

        return self._transact(update, write=not dry_run, create=False)
