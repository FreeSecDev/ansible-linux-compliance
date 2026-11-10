"""Compare the value of a native rule with the value of the profile (FREES-203, ADR 0032 §3).

An operator may replace the profile's value of a native rule with a value of their own
(``linux_compliance_remediate_value_overrides``). Whether that value, or the value that a family
keeps because the host already holds a stricter one, still meets the profile depends on the
setting and on how its reader reads it: a larger ``minlen`` is stricter, a larger ``deny`` is
looser, ``deny = 0`` never locks and is the loosest, ``unlock_time = 0`` never unlocks and is the
strictest, and a umask is stricter when it masks at least the bits of the profile's umask.

Each such rule of the catalogue names a comparator in ``value_comparison``; :data:`COMPARATORS`
holds them by name. A comparator has three operations:

- ``validate(raw)`` takes an operator's value (a YAML integer that is not a boolean, or a string)
  and returns its canonical text, or raises :class:`ValueOverrideError`. It accepts only values
  that the family's own validator accepts for a profile value and that the reader reads as
  written, so an override never writes a line that the reader reads differently;
- ``meets(candidate, profile)`` returns whether the canonical value ``candidate`` is at least as
  strict as the canonical value ``profile``. It is reflexive and transitive;
- ``stricter(first, second)`` returns the stricter of two canonical values, or for a umask the
  union of their bits, which is at least as strict as both.

:func:`judge` and :func:`stricter_of` apply a comparator by name. :func:`stricter_of` is the merge
of the ``login_defs`` family, which keeps a value of the host that is stricter than the target.

A value outside the bounds of a comparator but listed as its loosest or strictest value can be
judged, because a host may hold it, but is never accepted as an override: ``deny = 0`` is judged
looser than every profile value, and refused by :meth:`IntegerOrder.validate`, as the faillock
family refuses a maximum of 0.

Only the Python standard library is used, and nothing here touches a host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pwquality,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

AT_LEAST: Final[str] = "at_least"
AT_MOST: Final[str] = "at_most"
DIRECTIONS: Final[frozenset[str]] = frozenset({AT_LEAST, AT_MOST})
DECIMAL: Final[str] = r"-?(?:0|[1-9][0-9]{0,17})"
NEGATIVE_ZERO: Final[str] = "-0"
UMASK: Final[str] = r"[0-7]{3}"
UMASK_BASE: Final[int] = 8
MAX_TEXT_LENGTH: Final[int] = 1024
SHOWN_LENGTH: Final[int] = 80
LOGIN_DEFS_MAXIMUM: Final[int] = 999999
PWQUALITY_LIMIT: Final[int] = 999999
PAM_NUMBER_MAXIMUM: Final[int] = 999999999
FAILLOCK_MAX_TIME: Final[int] = 604800
FAILLOCK_MAX_DENY: Final[int] = 65535
FAILLOCK_NEVER: Final[int] = 0
FAILLOCK_NO_LOCK: Final[int] = 0
PWQUALITY_OFF: Final[int] = 0
LOOSEST_TIER: Final[int] = 0
ORDERED_TIER: Final[int] = 1
STRICTEST_TIER: Final[int] = 2


class ValueOverrideError(ValueError):
    """A value that a comparator cannot take or judge, or a comparator that does not exist."""


class Comparator(Protocol):
    """The comparison of one setting with the profile's value; see the module documentation."""

    def validate(self, raw: object, /) -> str:
        """Return the canonical text of an operator's value, or raise ValueOverrideError."""
        ...

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether ``candidate`` is at least as strict as ``profile``."""
        ...

    def stricter(self, first: str, second: str, /) -> str:
        """Return the stricter of two canonical values."""
        ...


def shown(raw: object) -> str:
    """Return a bounded representation of a value for an error message."""
    try:
        text = repr(raw)
    except ValueError:
        return f"a value of type {type(raw).__name__} too large to show"
    return text if len(text) <= SHOWN_LENGTH else text[: SHOWN_LENGTH - 3] + "..."


def whole_number(raw: object) -> int | None:
    """Return an integer that is not a boolean, or the number of its canonical decimal text."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw != NEGATIVE_ZERO and re.fullmatch(DECIMAL, raw) is not None:
        return int(raw)
    return None


@dataclass(frozen=True)
class IntegerOrder:
    """A whole number that is stricter the larger (``at_least``) or the smaller (``at_most``).

    Attributes:
        direction: ``at_least`` or ``at_most``.
        minimum: The smallest value that an override may take.
        maximum: The largest value that an override may take.
        loosest: Values that are looser than every other value, such as ``deny = 0``.
        strictest: Values that are stricter than every other value, such as
            ``unlock_time = 0``.
    """

    direction: str
    minimum: int
    maximum: int
    loosest: frozenset[int] = frozenset()
    strictest: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        """Refuse an order without a direction, with empty bounds or with overlapping values."""
        if self.direction not in DIRECTIONS or self.minimum > self.maximum:
            message = (
                f"an integer order needs a direction of {sorted(DIRECTIONS)} and a minimum not "
                f"above its maximum, got {self.direction!r}, {self.minimum} and {self.maximum}"
            )
            raise ValueError(message)
        if self.loosest & self.strictest:
            message = "no value of an integer order can be both the loosest and the strictest"
            raise ValueError(message)

    def validate(self, raw: object, /) -> str:
        """Return the decimal text of a whole number within the bounds, or raise."""
        number = whole_number(raw)
        if number is None or not self.minimum <= number <= self.maximum:
            message = (
                f"needs a whole number from {self.minimum} to {self.maximum}, as a YAML integer "
                f"or its decimal text without a plus sign or a leading zero, got {shown(raw)}"
            )
            raise ValueOverrideError(message)
        return str(number)

    def _read(self, text: object) -> int:
        """Return the number of a canonical value that this order can judge, or raise."""
        number = whole_number(text) if isinstance(text, str) else None
        if number is None or not (
            self.minimum <= number <= self.maximum or number in self.loosest | self.strictest
        ):
            message = (
                f"cannot judge {shown(text)}: it is not the decimal text of a whole number from "
                f"{self.minimum} to {self.maximum} or of a loosest or strictest value"
            )
            raise ValueOverrideError(message)
        return number

    def _rank(self, number: int) -> tuple[int, int]:
        """Return a key that is larger the stricter the number is."""
        if number in self.loosest:
            return (LOOSEST_TIER, 0)
        if number in self.strictest:
            return (STRICTEST_TIER, 0)
        return (ORDERED_TIER, number if self.direction == AT_LEAST else -number)

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether ``candidate`` is at least as strict as ``profile``."""
        return self._rank(self._read(candidate)) >= self._rank(self._read(profile))

    def stricter(self, first: str, second: str, /) -> str:
        """Return the stricter of two values, the first when they are as strict."""
        one, other = self._read(first), self._read(second)
        return str(other if self._rank(other) > self._rank(one) else one)


@dataclass(frozen=True)
class UmaskBits:
    """A umask of three octal digits that is stricter the more permission bits it masks."""

    def validate(self, raw: object, /) -> str:
        """Return a umask given as a string of three octal digits, or raise."""
        if not isinstance(raw, str) or re.fullmatch(UMASK, raw) is None:
            message = (
                "needs a umask of exactly three octal digits as a quoted string, such as '027'; "
                "a YAML integer is refused because YAML 1.1 reads 027 as the octal number 23, "
                f"got {shown(raw)}"
            )
            raise ValueOverrideError(message)
        return raw

    def _bits(self, text: str) -> int:
        """Return the bits of a canonical umask, or raise."""
        return int(self.validate(text), UMASK_BASE)

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether ``candidate`` masks every bit that ``profile`` masks."""
        required = self._bits(profile)
        return self._bits(candidate) & required == required

    def stricter(self, first: str, second: str, /) -> str:
        """Return the union of the bits of both umasks, which is at least as strict as each."""
        return f"{self._bits(first) | self._bits(second):03o}"


@dataclass(frozen=True)
class Exact:
    """A value without an order: any other value than the profile's is looser.

    Attributes:
        pattern: The regular expression that the whole value must match.
    """

    pattern: str

    def validate(self, raw: object, /) -> str:
        """Return the text of a value that matches the pattern, or raise."""
        text = str(raw) if isinstance(raw, int) and not isinstance(raw, bool) else raw
        if (
            not isinstance(text, str)
            or len(text) > MAX_TEXT_LENGTH
            or re.fullmatch(self.pattern, text) is None
        ):
            message = (
                f"needs a value of at most {MAX_TEXT_LENGTH} characters that matches "
                f"{self.pattern!r}, got {shown(raw)}"
            )
            raise ValueOverrideError(message)
        return text

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether ``candidate`` is the profile's value."""
        return self.validate(candidate) == self.validate(profile)

    def stricter(self, first: str, second: str, /) -> str:
        """Return the value when both are the same; values without an order have no stricter."""
        if not self.meets(first, second):
            message = (
                f"{shown(first)} and {shown(second)} are compared exactly and have no order, "
                "so neither is the stricter"
            )
            raise ValueOverrideError(message)
        return first


COMPARATORS: Final[Mapping[str, Comparator]] = MappingProxyType(
    {
        "login_defs_at_least": IntegerOrder(AT_LEAST, 0, LOGIN_DEFS_MAXIMUM),
        "login_defs_at_most": IntegerOrder(AT_MOST, 0, LOGIN_DEFS_MAXIMUM),
        "login_defs_umask": UmaskBits(),
        "pwquality_at_least": IntegerOrder(AT_LEAST, 0, PWQUALITY_LIMIT),
        "pwquality_minlen": IntegerOrder(AT_LEAST, pwquality.MIN_LENGTH_FLOOR, PWQUALITY_LIMIT),
        "pwquality_minclass": IntegerOrder(AT_LEAST, 0, pwquality.CLASSES),
        "pwquality_credit": IntegerOrder(AT_MOST, -PWQUALITY_LIMIT, PWQUALITY_LIMIT),
        "pwquality_max_or_off": IntegerOrder(
            AT_MOST, 0, PWQUALITY_LIMIT, loosest=frozenset({PWQUALITY_OFF})
        ),
        "pwquality_flag": IntegerOrder(AT_LEAST, 0, 1),
        "pwquality_retry": IntegerOrder(AT_MOST, 1, PWQUALITY_LIMIT),
        "pwhistory_remember": IntegerOrder(AT_LEAST, 0, PAM_NUMBER_MAXIMUM),
        "faillock_deny": IntegerOrder(
            AT_MOST, 1, FAILLOCK_MAX_DENY, loosest=frozenset({FAILLOCK_NO_LOCK})
        ),
        "faillock_interval": IntegerOrder(AT_LEAST, 0, FAILLOCK_MAX_TIME),
        "faillock_unlock_time": IntegerOrder(
            AT_LEAST, 0, FAILLOCK_MAX_TIME, strictest=frozenset({FAILLOCK_NEVER})
        ),
    }
)


def comparator(name: str) -> Comparator:
    """Return the comparator of ``name``, or raise ValueOverrideError for an unknown name."""
    found = COMPARATORS.get(name)
    if found is None:
        message = f"unknown value comparison {shown(name)}; known: {', '.join(sorted(COMPARATORS))}"
        raise ValueOverrideError(message)
    return found


def judge(name: str, profile: str, effective: str) -> bool:
    """Return whether the value in force ``effective`` meets the profile's value.

    Both values are canonical texts; a value that the comparator cannot judge raises
    ValueOverrideError, so that a value is never reported as meeting the profile by mistake.
    """
    return comparator(name).meets(effective, profile)


def stricter_of(name: str, target: str, readings: Sequence[str]) -> str:
    """Return the stricter of the target and every value that the readers read, as canonical text.

    This is the merge of the ``login_defs`` family: with ``at_least`` the largest value, with
    ``at_most`` the smallest and with a umask the union of the bits. The target itself is checked
    even without readings.
    """
    found = comparator(name)
    chosen = found.stricter(target, target)
    for reading in readings:
        chosen = found.stricter(chosen, reading)
    return chosen
