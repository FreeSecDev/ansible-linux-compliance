"""On-host state ledger of applied remediations.

The ledger records, for every rule that the collection applied, what is needed to
revert it when the rule is disabled (ADR 0011): the rule identifier, the control
family, the revert strategy, the prior values, the collection version and the time
of application. It lives in ``/var/lib/freesecdev/linux_compliance/state.json``,
owned by root with mode ``0600`` in a ``0700`` directory.

The module uses only the Python standard library and syntax that runs on Python
3.9. All file access goes through :mod:`fileio`, the single audited file helper.

The file is a JSON document with ``schema_version`` and a list of ``entries``
sorted by rule identifier, serialised deterministically. Reading is strict: the
size is bounded, duplicate keys, ``NaN`` and ``Infinity``, unknown or missing keys
and unsupported schema versions are refused. A corrupt or unsafe ledger raises
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
SCHEMA_VERSION: Final[int] = 1
MAX_LEDGER_BYTES: Final[int] = 4 * 1024 * 1024
MAX_ENTRIES: Final[int] = 4096
MAX_PRIOR_VALUES: Final[int] = 64
MAX_VALUE_LENGTH: Final[int] = 4096
MAX_RULE_ID_LENGTH: Final[int] = 256
MAX_FAMILY_LENGTH: Final[int] = 64
MAX_NAME_LENGTH: Final[int] = 128
MAX_VERSION_LENGTH: Final[int] = 64

ERROR_TYPES: Final[frozenset[str]] = fileio.REASONS | frozenset(
    {"corrupt", "unsupported_schema", "invalid_entry", "conflict", "ledger_full"}
)

_RULE_ID: Final[str] = r"xccdf_[A-Za-z0-9_.-]+?_rule_[A-Za-z0-9_.+-]+"
_FAMILY: Final[str] = r"[a-z0-9][a-z0-9._-]*"
_NAME: Final[str] = r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]*"
_VERSION: Final[str] = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?"
_TIMESTAMP: Final[str] = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
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
_VALUE_KEYS: Final[tuple[str, ...]] = ("name", "sensitive", "value")
_DOCUMENT_KEYS: Final[tuple[str, ...]] = ("entries", "schema_version")
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
class LedgerEntry:
    """What was applied for one rule and how to revert it."""

    rule_id: str
    family: str
    revert_strategy: RevertStrategy
    prior_values: tuple[PriorValue, ...]
    collection_version: str
    applied_at: str

    def __post_init__(self) -> None:
        """Validate the entry and order its prior values by name."""
        _text(self.rule_id, "rule_id", MAX_RULE_ID_LENGTH, _RULE_ID)
        _text(self.family, "family", MAX_FAMILY_LENGTH, _FAMILY)
        _instance(self.revert_strategy, "revert_strategy", RevertStrategy)
        _text(self.collection_version, "collection_version", MAX_VERSION_LENGTH, _VERSION)
        self._check_timestamp()
        values = self._checked_prior_values()
        object.__setattr__(self, "prior_values", tuple(sorted(values, key=_value_name)))

    def _check_timestamp(self) -> None:
        _text(self.applied_at, "applied_at", len("2000-01-01T00:00:00Z"), _TIMESTAMP)
        try:
            datetime.strptime(self.applied_at, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            _invalid("applied_at is not a valid UTC timestamp")

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
        """Return the on-disk mapping."""
        return {
            "applied_at": self.applied_at,
            "collection_version": self.collection_version,
            "family": self.family,
            "prior_values": [item.to_dict() for item in self.prior_values],
            "revert_strategy": self.revert_strategy.value,
            "rule_id": self.rule_id,
        }

    def view(self, *, reveal: bool = False) -> dict[str, object]:
        """Return the reporting mapping; sensitive values are redacted unless revealed."""
        return {
            "applied_at": self.applied_at,
            "collection_version": self.collection_version,
            "family": self.family,
            "prior_values": [item.view(reveal=reveal) for item in self.prior_values],
            "revert_strategy": self.revert_strategy.value,
            "rule_id": self.rule_id,
        }

    @classmethod
    def from_dict(cls, data: object) -> LedgerEntry:
        """Build an entry from its on-disk mapping, rejecting unknown and missing keys."""
        fields = _mapping(data, "entry", _ENTRY_KEYS)
        strategy = fields["revert_strategy"]
        try:
            revert = RevertStrategy(strategy)
        except ValueError:
            _invalid("revert_strategy is not a known strategy")
        values = _list(fields["prior_values"], "prior_values", MAX_PRIOR_VALUES)
        return cls(
            cast("str", fields["rule_id"]),
            cast("str", fields["family"]),
            revert,
            tuple(PriorValue.from_dict(item) for item in values),
            cast("str", fields["collection_version"]),
            cast("str", fields["applied_at"]),
        )


def _value_name(value: PriorValue) -> str:
    return value.name


def _rule_id_of(entry: LedgerEntry) -> str:
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


def dumps(entries: tuple[LedgerEntry, ...]) -> bytes:
    """Serialise entries to the deterministic ledger document.

    Raises:
        LedgerError: With ``ledger_full`` if there are too many entries or the
            document would exceed :data:`MAX_LEDGER_BYTES`.
    """
    if len(entries) > MAX_ENTRIES:
        _fail("ledger_full", f"the ledger cannot hold more than {MAX_ENTRIES} entries")
    document = {
        "entries": [entry.to_dict() for entry in sorted(entries, key=_rule_id_of)],
        "schema_version": SCHEMA_VERSION,
    }
    data = (json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("ascii")
    if len(data) > MAX_LEDGER_BYTES:
        _fail("ledger_full", "the ledger would exceed its size limit")
    return data


def loads(data: bytes) -> tuple[LedgerEntry, ...]:
    """Parse and validate a ledger document.

    Raises:
        LedgerError: With ``corrupt`` for malformed JSON, duplicate keys, non-finite
            numbers, wrong shapes, invalid or duplicate entries, and with
            ``unsupported_schema`` for another schema version.
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
        fields = _mapping(document, "ledger", _DOCUMENT_KEYS)
        version = fields["schema_version"]
        if isinstance(version, bool) or not isinstance(version, int):
            _fail("corrupt", "the ledger schema version is not an integer")
        if version != SCHEMA_VERSION:
            _fail("unsupported_schema", "the ledger schema version is not supported")
        entries = tuple(
            LedgerEntry.from_dict(item) for item in _list(fields["entries"], "entries", MAX_ENTRIES)
        )
    except LedgerError as error:
        if error.error_type == "invalid_entry":
            _fail("corrupt", f"the ledger is invalid: {error}")
        raise
    if len({entry.rule_id for entry in entries}) != len(entries):
        _fail("corrupt", "the ledger contains a rule more than once")
    return tuple(sorted(entries, key=_rule_id_of))


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

    def _read(self, directory: fileio.SafeDirectory) -> tuple[LedgerEntry, ...]:
        try:
            data = directory.read(LEDGER_FILENAME, MAX_LEDGER_BYTES)
        except fileio.SafeFileError as error:
            raise _translate(error) from error
        return () if data is None else loads(data)

    def _transact(
        self,
        update: Callable[[tuple[LedgerEntry, ...]], tuple[tuple[LedgerEntry, ...], T]],
        *,
        write: bool,
        create: bool,
    ) -> T:
        try:
            directory = fileio.open_directory(
                self._state_dir, owner_uid=self._owner_uid, create=create
            )
            if directory is None:
                return update(())[1]
            try:
                if write:
                    directory.lock(self._lock_timeout)
                entries = self._read(directory)
                updated, result = update(entries)
                if write and updated != entries:
                    directory.sweep_temporaries(LEDGER_FILENAME)
                    directory.write(LEDGER_FILENAME, dumps(updated))
                return result
            finally:
                directory.close()
        except fileio.SafeFileError as error:
            raise _translate(error) from error

    def entries(self) -> tuple[LedgerEntry, ...]:
        """Return every entry sorted by rule identifier. A missing ledger is empty."""
        return self._transact(lambda entries: (entries, entries), write=False, create=False)

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

        def update(
            entries: tuple[LedgerEntry, ...],
        ) -> tuple[tuple[LedgerEntry, ...], RecordResult]:
            previous = next((item for item in entries if item.rule_id == entry.rule_id), None)
            if previous is not None and previous.same_content(entry):
                return entries, RecordResult(previous, previous, changed=False)
            if previous is not None and not replace:
                _fail("conflict", "the rule is already recorded with different content")
            others = tuple(item for item in entries if item.rule_id != entry.rule_id)
            return (*others, entry), RecordResult(entry, previous, changed=True)

        return self._transact(update, write=not dry_run, create=not dry_run)

    def remove(self, rule_id: str, *, dry_run: bool = False) -> RemoveResult:
        """Remove the entry of ``rule_id``. A missing entry is not an error.

        Raises:
            LedgerError: On an unsafe or corrupt ledger.
        """
        check_rule_id(rule_id)

        def update(
            entries: tuple[LedgerEntry, ...],
        ) -> tuple[tuple[LedgerEntry, ...], RemoveResult]:
            previous = next((item for item in entries if item.rule_id == rule_id), None)
            kept = tuple(item for item in entries if item.rule_id != rule_id)
            return kept, RemoveResult(previous, changed=previous is not None)

        return self._transact(update, write=not dry_run, create=False)
