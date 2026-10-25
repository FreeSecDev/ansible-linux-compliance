"""Shared result types, bounded file reading, strict JSON loading and serialization."""

import hashlib
import json
import math
import os
import stat
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Final, cast

DEFAULT_MAX_BYTES: Final[int] = 64 * 1024 * 1024
MAX_TEXT_LENGTH: Final[int] = 512
MAX_DETAIL_ITEMS: Final[int] = 1000
MAX_COUNT: Final[int] = 10**9
MAX_EPOCH_SECONDS: Final[int] = 10**11
MAX_PATH_LENGTH: Final[int] = 4096
OPEN_FAILED: Final[str] = (
    "input file cannot be opened (not a directory, or a symbolic link in the path)"
)
MAX_ENTRIES: Final[int] = 10000
MAX_SUBENTRIES: Final[int] = 1000
_READ_CHUNK: Final[int] = 1024 * 1024
_DIRECTORY_FLAGS: Final[int] = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_FILE_FLAGS: Final[int] = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_KEPT_CONTROLS: Final[frozenset[str]] = frozenset({"\n", "\t"})
_DROPPED_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})

type Json = bool | int | float | str | list[Json] | dict[str, Json] | None


class SectionStatus(Enum):
    """Explicit availability of an input or a report section."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    PARTIAL = "partial"


class InvalidInputError(ValueError):
    """Raised when an input is malformed, unexpected or unsafe."""


class MissingInputError(InvalidInputError):
    """Raised when an input file does not exist."""


@dataclass(frozen=True)
class ArtifactRef:
    """Reference to the original input file, kept unchanged for traceability."""

    path: str
    sha256: str | None
    size: int | None


@dataclass(frozen=True)
class ParseResult[T]:
    """Outcome of parsing one input file: typed data or an explicit reason."""

    format: str
    status: SectionStatus
    reason: str | None
    artifact: ArtifactRef
    data: T | None


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 of ``data`` as lower-case hex."""
    return hashlib.sha256(data).hexdigest()


def clean_text(value: str, limit: int = MAX_TEXT_LENGTH) -> str:
    """Remove control and formatting characters and cut the text to ``limit`` characters."""
    kept = "".join(
        character
        for character in value
        if character in _KEPT_CONTROLS or unicodedata.category(character) not in _DROPPED_CATEGORIES
    )
    return kept[:limit]


def _open_regular(path: Path) -> int:
    parts = path.parts[1:] if path.is_absolute() else path.parts
    if not parts:
        message = "input path is not a regular file"
        raise InvalidInputError(message)
    directory = os.open("/" if path.is_absolute() else ".", _DIRECTORY_FLAGS)
    try:
        for name in parts[:-1]:
            child = os.open(name, _DIRECTORY_FLAGS | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(parts[-1], _FILE_FLAGS, dir_fd=directory)
    finally:
        os.close(directory)


def _read_bytes(path: Path, max_bytes: int) -> bytes:
    try:
        descriptor = _open_regular(path)
    except FileNotFoundError:
        message = "input file does not exist"
        raise MissingInputError(message) from None
    except InvalidInputError:
        raise
    except (OSError, ValueError):
        message = OPEN_FAILED
        raise InvalidInputError(message) from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            message = "input path is not a regular file"
            raise InvalidInputError(message)
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(_READ_CHUNK, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        message = "input file cannot be read"
        raise InvalidInputError(message) from None
    finally:
        os.close(descriptor)
    if total > max_bytes:
        message = f"input is larger than {max_bytes} bytes"
        raise InvalidInputError(message)
    if not total:
        message = "input file is empty"
        raise InvalidInputError(message)
    return b"".join(chunks)


def run_parser[T](
    path: Path, format_name: str, max_bytes: int, build: Callable[[bytes], T]
) -> ParseResult[T]:
    """Read ``path`` with a size bound and turn the bytes into typed data.

    A missing file is ``unavailable``. Every other problem, including empty,
    oversized, symlinked, malformed or unexpected input, is ``error``. Neither is
    ever treated as a pass. The artifact reference keeps the path as supplied and
    the SHA-256 of exactly the bytes that were parsed.
    """
    display = clean_text(str(path), MAX_PATH_LENGTH)
    try:
        data = _read_bytes(path, max_bytes)
    except MissingInputError as error:
        absent = ArtifactRef(display, None, None)
        return ParseResult(format_name, SectionStatus.UNAVAILABLE, str(error), absent, None)
    except InvalidInputError as error:
        unread = ArtifactRef(display, None, None)
        return ParseResult(format_name, SectionStatus.ERROR, str(error), unread, None)
    reference = ArtifactRef(display, sha256_hex(data), len(data))
    try:
        payload = build(data)
    except InvalidInputError as error:
        return ParseResult(format_name, SectionStatus.ERROR, str(error), reference, None)
    return ParseResult(format_name, SectionStatus.AVAILABLE, None, reference, payload)


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = "JSON document contains a duplicate key"
            raise InvalidInputError(message)
        result[key] = value
    return result


def _finite_float(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):
        message = "JSON document contains a non-finite number"
        raise InvalidInputError(message)
    return number


def bounded[T](items: list[T], limit: int, name: str) -> list[T]:
    """Return ``items`` or raise :class:`InvalidInputError` when it has more than ``limit``."""
    if len(items) > limit:
        message = f"{name} has more than {limit} entries"
        raise InvalidInputError(message)
    return items


def _no_constant(_constant: str) -> object:
    message = "JSON document contains a non-finite number"
    raise InvalidInputError(message)


def decode_text(data: bytes) -> str:
    """Decode strict UTF-8 or raise :class:`InvalidInputError`."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        message = "input is not valid UTF-8"
        raise InvalidInputError(message) from None


def load_json(data: bytes) -> object:
    """Parse strict JSON: UTF-8 only, no duplicate keys, no NaN or Infinity."""
    text = decode_text(data)
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_no_constant,
            parse_float=_finite_float,
        )
    except InvalidInputError:
        raise
    except (ValueError, RecursionError):
        message = "input is not valid JSON"
        raise InvalidInputError(message) from None


def as_object(value: object, name: str) -> dict[str, object]:
    """Return ``value`` as a string-keyed mapping or raise :class:`InvalidInputError`."""
    if not isinstance(value, dict):
        message = f"{name} must be an object"
        raise InvalidInputError(message)
    return {str(key): item for key, item in cast("dict[object, object]", value).items()}


def is_object(value: object) -> bool:
    """Return whether ``value`` is a JSON object."""
    return isinstance(value, dict)


def as_list(value: object, name: str) -> list[object]:
    """Return ``value`` as a list or raise :class:`InvalidInputError`."""
    if not isinstance(value, list):
        message = f"{name} must be an array"
        raise InvalidInputError(message)
    return list(cast("list[object]", value))


def as_text(value: object, name: str) -> str:
    """Return a cleaned, bounded, non-empty string or raise :class:`InvalidInputError`."""
    if not isinstance(value, str):
        message = f"{name} must be a string"
        raise InvalidInputError(message)
    cleaned = clean_text(value)
    if not cleaned:
        message = f"{name} must not be empty"
        raise InvalidInputError(message)
    return cleaned


def as_count(value: object, name: str) -> int:
    """Return a non-negative integer below one billion or raise :class:`InvalidInputError`."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_COUNT:
        message = f"{name} must be a non-negative integer"
        raise InvalidInputError(message)
    return value


def as_rate(value: object, name: str) -> float:
    """Return a finite number between 0 and 1 or raise :class:`InvalidInputError`."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        message = f"{name} must be a number between 0 and 1"
        raise InvalidInputError(message)
    return float(value)


def require(mapping: Mapping[str, object], key: str, name: str) -> object:
    """Return a required key of ``mapping`` or raise :class:`InvalidInputError`."""
    if key not in mapping:
        message = f"{name} is missing {key}"
        raise InvalidInputError(message)
    return mapping[key]


def optional_text(mapping: Mapping[str, object], key: str, name: str) -> str | None:
    """Return a cleaned string for an optional key; a present non-string is an error."""
    value = mapping.get(key)
    if value is None:
        return None
    return as_text(value, f"{name}.{key}")


def optional_list(mapping: Mapping[str, object], key: str, name: str) -> list[object]:
    """Return a list for an optional key; absent or null means empty."""
    value = mapping.get(key)
    return [] if value is None else as_list(value, f"{name}.{key}")


def optional_object(mapping: Mapping[str, object], key: str, name: str) -> dict[str, object]:
    """Return a mapping for an optional key; absent or null means empty."""
    value = mapping.get(key)
    return {} if value is None else as_object(value, f"{name}.{key}")


def dig(value: object, *path: str | int) -> object:
    """Follow keys and list indexes through nested JSON; return ``None`` if any step is absent."""
    current: object = value
    for step in path:
        if isinstance(step, int):
            if not isinstance(current, list):
                return None
            sequence = cast("list[object]", current)
            if step >= len(sequence):
                return None
            current = sequence[step]
        else:
            if not isinstance(current, dict):
                return None
            mapping = cast("dict[str, object]", current)
            if step not in mapping:
                return None
            current = mapping[step]
    return current


def maybe_text(value: object) -> str | None:
    """Return a cleaned non-empty string, or ``None`` for anything else."""
    if isinstance(value, str):
        return clean_text(value) or None
    return None


def maybe_count(value: object, limit: int = MAX_COUNT) -> int | None:
    """Return a non-negative integer up to ``limit``, or ``None`` for anything else."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= limit:
        return None
    return value


SEVERITY_ORDER: Final[tuple[str, ...]] = ("critical", "high", "medium", "low", "info", "unknown")


def severity_counts(severities: list[str]) -> dict[str, int]:
    """Count severities; every known severity is present, even with zero."""
    counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
    for severity in severities:
        counts[severity] += 1
    return counts


def to_json(value: object) -> Json:
    """Convert report values to plain JSON types, recursing through containers."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Enum):
        return to_json(value.value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_json(to_dict())
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: to_json(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        return {str(key): to_json(item) for key, item in mapping.items()}
    if isinstance(value, (list, tuple)):
        return [to_json(item) for item in cast("list[object]", value)]
    message = f"cannot serialize {type(value).__name__}"
    raise TypeError(message)


def dumps(document: Json) -> str:
    """Serialize deterministically: sorted keys, two-space indent, ASCII, trailing newline."""
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
