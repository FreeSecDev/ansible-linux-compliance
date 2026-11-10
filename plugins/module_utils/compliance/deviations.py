"""Operator deviations of the findings model (FREES-203, ADR 0032 sections 4 and 5).

An operator may override the value that a native rule writes
(``linux_compliance_remediate_value_overrides``). When the value in force after
remediation is looser than the value of the selected profile, the rule has a
:class:`Deviation`: the short id of the XCCDF ``Value``, the profile value and the
value in force. :class:`model.Finding` carries it as ``deviation`` together with
the flag ``operator_deviation``, and :class:`model.RemediationResult` carries it
with the source of the target value (:class:`ValueSource`). Values are the
canonical text that the family's comparison function produces, so two equal
values are never a deviation. :mod:`model` turns a :class:`DeviationError` into
a ``ModelError`` when it reads a document.

The module uses only the standard library and syntax that runs on Python 3.9.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Final, NoReturn, cast

DEVIATION_KEY: Final[str] = "deviation"
VALUE_SOURCE_KEY: Final[str] = "value_source"
KEYS: Final[tuple[str, ...]] = ("value_id", "profile_value", "effective_value")
RESULT_KEYS: Final[tuple[str, ...]] = (
    VALUE_SOURCE_KEY,
    "profile_value",
    "effective_value",
    DEVIATION_KEY,
)
VALUE_ID_PATTERN: Final[str] = r"[a-z0-9][a-z0-9_]{0,127}"
MAX_VALUE_LENGTH: Final[int] = 4096
MAX_ECHO_LENGTH: Final[int] = 64
_FORBIDDEN_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Zl", "Zp"})


class DeviationError(ValueError):
    """Raised when a deviation or the value fields of a remediation result are invalid."""


class ValueSource(Enum):
    """Where the target value of a remediated rule came from."""

    PROFILE = "profile"
    OVERRIDE = "override"


def _fail(message: str) -> NoReturn:
    raise DeviationError(message)


def _instance(value: object, name: str, kind: type[object]) -> None:
    if not isinstance(value, kind):
        _fail(f"{name} must be of type {kind.__name__}")


def value_text(value: object, name: str) -> str:
    """Validate one value as the model holds it.

    A value is a non-empty string of at most :data:`MAX_VALUE_LENGTH`
    characters, without surrounding whitespace and without any character of
    Unicode category Cc, Cf, Zl or Zp.

    Args:
        value: The candidate value.
        name: The field name used in error messages.

    Returns:
        The value, unchanged.

    Raises:
        DeviationError: If the value violates the rules.
    """
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    if not value.strip():
        _fail(f"{name} must not be empty")
    if value != value.strip():
        _fail(f"{name} must not have surrounding whitespace")
    if len(value) > MAX_VALUE_LENGTH:
        _fail(f"{name} exceeds {MAX_VALUE_LENGTH} characters")
    if any(unicodedata.category(character) in _FORBIDDEN_CATEGORIES for character in value):
        _fail(f"{name} contains control or formatting characters")
    return value


@dataclass(frozen=True)
class Deviation:
    """A value in force that is looser than the profile value, set by the operator."""

    value_id: str
    profile_value: str
    effective_value: str

    def __post_init__(self) -> None:
        """Validate the deviation."""
        _instance(self.value_id, f"{DEVIATION_KEY}.value_id", str)
        if re.fullmatch(VALUE_ID_PATTERN, self.value_id) is None:
            _fail(f"{DEVIATION_KEY}.value_id has an invalid format")
        value_text(self.profile_value, f"{DEVIATION_KEY}.profile_value")
        value_text(self.effective_value, f"{DEVIATION_KEY}.effective_value")
        if self.profile_value == self.effective_value:
            _fail(f"{DEVIATION_KEY}.effective_value must differ from the profile value")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "effective_value": self.effective_value,
            "profile_value": self.profile_value,
            "value_id": self.value_id,
        }

    @classmethod
    def from_dict(cls, data: object) -> Deviation:
        """Build a deviation from a mapping, rejecting unknown and missing keys."""
        if not isinstance(data, dict):
            _fail(f"{DEVIATION_KEY} must be an object")
        mapping = cast("dict[str, object]", data)
        unknown = sorted(repr(str(key)[:MAX_ECHO_LENGTH]) for key in mapping if key not in KEYS)
        if unknown:
            _fail(f"{DEVIATION_KEY} has unknown keys: {', '.join(unknown[:5])}")
        missing = sorted(key for key in KEYS if key not in mapping)
        if missing:
            _fail(f"{DEVIATION_KEY} is missing keys: {', '.join(missing)}")
        return cls(
            cast("str", mapping["value_id"]),
            cast("str", mapping["profile_value"]),
            cast("str", mapping["effective_value"]),
        )


def check_result_values(
    source: ValueSource | None,
    profile_value: str | None,
    effective_value: str | None,
    found: Deviation | None,
    *,
    deviated: bool,
) -> None:
    """Check the value fields of a remediation result against each other.

    Without a source every value field is absent. With one, the profile value is
    required and the value in force is optional (a rule that failed or was
    skipped has none). A deviation is present exactly when the status is
    ``deviation`` (``deviated``); it needs the source ``override`` and repeats
    the profile value and the value in force of the result.

    Raises:
        DeviationError: If the fields contradict each other.
    """
    if source is None:
        if (profile_value, effective_value, found) != (None, None, None):
            _fail("remediation value fields require remediation.value_source")
        if deviated:
            _fail("remediation.status deviation requires remediation.deviation")
        return
    _instance(source, "remediation.value_source", ValueSource)
    value_text(profile_value, "remediation.profile_value")
    if effective_value is not None:
        value_text(effective_value, "remediation.effective_value")
    _check_deviation(source, profile_value, effective_value, found, deviated=deviated)


def _check_deviation(
    source: ValueSource,
    profile_value: str | None,
    effective_value: str | None,
    found: Deviation | None,
    *,
    deviated: bool,
) -> None:
    if found is not None:
        _instance(found, "remediation.deviation", Deviation)
    if deviated != (found is not None):
        _fail("remediation.status deviation requires exactly remediation.deviation")
    if found is None:
        return
    if source is not ValueSource.OVERRIDE:
        _fail("remediation.deviation requires remediation.value_source override")
    if (found.profile_value, found.effective_value) != (profile_value, effective_value):
        _fail("remediation.deviation must repeat the profile value and the value in force")
