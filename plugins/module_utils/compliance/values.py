"""Compare the value of a native rule with the value of the profile (FREES-203, ADR 0032 §3).

An operator may replace the profile's value of a native rule with a value of their own
(``linux_compliance_remediate_value_overrides``). Whether that value, or the value that a family
keeps because the host already holds a stricter one, still meets the profile depends on the
setting and on how its reader reads it: a larger ``minlen`` is stricter, a larger ``deny`` is
looser, ``deny = 0`` never locks and is the loosest, ``unlock_time = 0`` never unlocks and is the
strictest, and a umask is stricter when it masks at least the bits of the profile's umask.

Each such rule of the catalogue names a comparator in ``value_comparison``; :data:`COMPARATORS`
holds them by name. A comparator has four operations:

- ``validate(raw)`` takes an operator's value (a YAML integer that is not a boolean, or a string)
  and returns its canonical text, or raises :class:`ValueOverrideError`. It accepts only values
  that the family's own validator accepts for a profile value and that the reader reads as
  written, so an override never writes a line that the reader reads differently;
- ``read_profile(text)`` returns the canonical text of a profile's value, or raises. It is
  ``validate`` for every comparator but a choice set, whose profile value is a set of keywords
  (``syslog|single|halt``) while an override is one keyword;
- ``meets(candidate, profile)`` returns whether the canonical value ``candidate`` is at least as
  strict as the canonical value ``profile``. It is reflexive and transitive;
- ``stricter(first, second)`` returns the stricter of two canonical values, or for a umask the
  union of their bits, which is at least as strict as both. Values without an order, and sets
  without a common member, have no stricter value, and it raises.

:func:`judge` and :func:`stricter_of` apply a comparator by name. :func:`stricter_of` is the merge
of the ``login_defs`` family, which keeps a value of the host that is stricter than the target.

A value outside the bounds of a comparator but listed as its loosest or strictest value can be
judged, because a host may hold it, but is never accepted as an override: ``deny = 0`` is judged
looser than every profile value, and refused by :meth:`IntegerOrder.validate`, as the faillock
family refuses a maximum of 0.

The text families compare what their reader reads back. The ``ssh`` comparators take the forms
that ``sshd -T`` prints: whole seconds, never a time with a unit such as ``5m``
(:class:`SshdInteger`), ``MaxStartups`` as ``start:rate:full`` compared per component
(:class:`SshdMaxStartups`), and algorithm lists as a subset of the profile's list, without the
``+``, ``-`` and ``^`` modifiers (:class:`AlgorithmSubset`). An auditd action is one keyword of
the setting's own vocabulary in :data:`auditconf.KEYWORDS`, which meets the profile when it is
one of the profile's choices (:class:`ChoiceSet`). The sudo ``logfile``, the auditd
``action_mail_acct`` and ``freq`` and every kernel parameter are compared exactly
(:class:`Exact`), and ``timestamp_timeout`` and the auditd sizes are integer orders.

Only the Python standard library is used, and nothing here touches a host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditconf,
    pwquality,
    sysctl_config,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

AT_LEAST: Final[str] = "at_least"
AT_MOST: Final[str] = "at_most"
DIRECTIONS: Final[frozenset[str]] = frozenset({AT_LEAST, AT_MOST})
DECIMAL: Final[str] = r"-?(?:0|[1-9][0-9]{0,17})"
NEGATIVE_ZERO: Final[str] = "-0"
UMASK: Final[str] = r"0[0-7]{2}"
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
SSHD_INT_MAX: Final[int] = 2147483647
SSHD_NO_LIMIT: Final[int] = 0
SSHD_STARTUPS: Final[str] = r"(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9})"
SSHD_MAX_RATE: Final[int] = 100
ALGORITHM: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}"
ALGORITHM_SEPARATOR: Final[str] = ","
MAX_ALGORITHMS: Final[int] = 64
CHOICE_SEPARATOR: Final[str] = "|"
AUDITD_EXEC_ACTION: Final[str] = "exec"
MAX_CHOICES: Final[int] = 8
SUDO_TIMEOUT_MAXIMUM: Final[int] = 9999
SUDO_LOGFILE: Final[str] = r"/[A-Za-z0-9_-][A-Za-z0-9._/-]{0,254}"
AUDITD_NUMBER_MAXIMUM: Final[int] = 999999999
AUDITD_NUMBER: Final[str] = r"0|[1-9][0-9]{0,8}"
AUDITD_MAIL_ACCOUNT: Final[str] = r"[A-Za-z0-9._-]{2,64}"
AUDITD_MAX_PERCENT: Final[int] = auditconf.MAX_PERCENT - 1
AUDITD_CHOICE_SETTINGS: Final[tuple[str, ...]] = (
    "admin_space_left_action",
    "disk_error_action",
    "disk_full_action",
    "flush",
    "max_log_file_action",
    "name_format",
    "space_left_action",
)


class ValueOverrideError(ValueError):
    """A value that a comparator cannot take or judge, or a comparator that does not exist."""


class Comparator(Protocol):
    """The comparison of one setting with the profile's value; see the module documentation."""

    def validate(self, raw: object, /) -> str:
        """Return the canonical text of an operator's value, or raise ValueOverrideError."""
        raise NotImplementedError

    def read_profile(self, text: str, /) -> str:
        """Return the canonical text of a profile's value, or raise ValueOverrideError."""
        raise NotImplementedError

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether ``candidate`` is at least as strict as ``profile``."""
        raise NotImplementedError

    def stricter(self, first: str, second: str, /) -> str:
        """Return the stricter of two canonical values."""
        raise NotImplementedError


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

    def read_profile(self, text: str, /) -> str:
        """Return the canonical text of a profile's value, as :meth:`validate` does."""
        return self.validate(text)

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
    """A umask of a zero and two octal digits that is stricter the more permission bits it masks.

    Only this form is read alike by every reader of ``UMASK`` in ``/etc/login.defs``:
    shadow-utils reads the value with ``strtol`` and base 0, so ``177`` is the decimal number 177
    (octal 261), while ``pam_umask`` reads it as octal 177 (ADR 0024). A umask with the owner's
    bits therefore cannot be taken or judged.
    """

    def validate(self, raw: object, /) -> str:
        """Return a umask given as a string of a zero and two octal digits, or raise."""
        if not isinstance(raw, str) or re.fullmatch(UMASK, raw) is None:
            message = (
                "needs a umask of a zero and two octal digits as a quoted string, such as '027'; "
                "a YAML integer is refused because YAML 1.1 reads 027 as the octal number 23, and "
                "a umask without the leading zero, such as '177', because shadow-utils reads it "
                f"as a decimal number and pam_umask as an octal one, got {shown(raw)}"
            )
            raise ValueOverrideError(message)
        return raw

    def read_profile(self, text: str, /) -> str:
        """Return the canonical text of a profile's umask, as :meth:`validate` does."""
        return self.validate(text)

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

    def read_profile(self, text: str, /) -> str:
        """Return the canonical text of a profile's value, as :meth:`validate` does."""
        return self.validate(text)

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


@dataclass(frozen=True)
class SshdInteger:
    """A whole number of an sshd keyword, in the form that ``sshd -T`` prints it.

    sshd reads these keywords with ``strtonum`` or, for times, ``convtime``, up to ``INT_MAX``.
    ``convtime`` also reads units such as ``5m``, and both read signs and leading zeros; only the
    plain decimal form is taken, so the value written is the value that ``sshd -T`` prints and
    that is compared.

    Attributes:
        direction: ``at_least`` or ``at_most``.
        zero_loosest: Whether 0 turns the limit off and is looser than every other value, as for
            ``ClientAliveInterval``, ``ClientAliveCountMax`` and ``LoginGraceTime``.
        seconds: Whether the keyword is a time in seconds, which only changes the messages.
    """

    direction: str
    zero_loosest: bool = False
    seconds: bool = False

    def _order(self) -> IntegerOrder:
        loosest = frozenset({SSHD_NO_LIMIT}) if self.zero_loosest else frozenset[int]()
        return IntegerOrder(self.direction, 0, SSHD_INT_MAX, loosest=loosest)

    def validate(self, raw: object, /) -> str:
        """Return the decimal text of a whole number from 0 to ``INT_MAX``, or raise."""
        try:
            return self._order().validate(raw)
        except ValueOverrideError as error:
            if not self.seconds:
                raise
            message = (
                f"needs a whole number of seconds from 0 to {SSHD_INT_MAX}, as a YAML integer or "
                "its decimal text; a time with a unit such as 5m is refused, so that the value "
                f"written is the value that sshd -T prints, got {shown(raw)}"
            )
            raise ValueOverrideError(message) from error

    def read_profile(self, text: str, /) -> str:
        """Return the canonical text of a profile's value, as :meth:`validate` does."""
        return self.validate(text)

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether ``candidate`` is at least as strict as ``profile``."""
        return self._order().meets(candidate, profile)

    def stricter(self, first: str, second: str, /) -> str:
        """Return the stricter of two values, the first when they are as strict."""
        return self._order().stricter(first, second)


@dataclass(frozen=True)
class SshdMaxStartups:
    """``MaxStartups start:rate:full``, stricter with a smaller start and full and a larger rate.

    sshd refuses a start or full below 1, a start above full and a rate outside 1 to 100. It also
    reads a single number as ``start``, with ``full`` equal to it and the default rate, and reads
    signs and leading zeros; only the three plain decimal components that ``sshd -T`` prints are
    taken. The order is per component, as the content's check compares each one, so it is
    partial: ``5:30:100`` and ``10:30:50`` are each looser than the other in one component.
    """

    def _components(self, raw: object) -> tuple[int, int, int] | None:
        found = re.fullmatch(SSHD_STARTUPS, raw) if isinstance(raw, str) else None
        if found is None:
            return None
        start, rate, full = (int(group) for group in found.groups())
        if not (1 <= start <= full <= SSHD_INT_MAX and 1 <= rate <= SSHD_MAX_RATE):
            return None
        return start, rate, full

    def validate(self, raw: object, /) -> str:
        """Return the text of a valid ``start:rate:full`` as sshd -T prints it, or raise."""
        if self._components(raw) is None:
            message = (
                "needs start:rate:full as a string of three decimal numbers, such as "
                f"'10:30:60', with 1 <= start <= full <= {SSHD_INT_MAX} and a rate from 1 to "
                f"{SSHD_MAX_RATE}; a single number is refused, because sshd -T prints it with a "
                f"rate the value does not name, got {shown(raw)}"
            )
            raise ValueOverrideError(message)
        return cast("str", raw)

    def read_profile(self, text: str, /) -> str:
        """Return the canonical text of a profile's value, as :meth:`validate` does."""
        return self.validate(text)

    def _read(self, text: str) -> tuple[int, int, int]:
        found = self._components(text)
        if found is None:
            message = f"cannot judge {shown(text)}: it is not a valid start:rate:full"
            raise ValueOverrideError(message)
        return found

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether every component of ``candidate`` is at least as strict."""
        start, rate, full = self._read(candidate)
        wanted_start, wanted_rate, wanted_full = self._read(profile)
        return start <= wanted_start and rate >= wanted_rate and full <= wanted_full

    def stricter(self, first: str, second: str, /) -> str:
        """Return the stricter component of each, which is a valid value as strict as both."""
        one, other = self._read(first), self._read(second)
        return f"{min(one[0], other[0])}:{max(one[1], other[1])}:{min(one[2], other[2])}"


def _members(text: str, separator: str, pattern: str, limit: int) -> list[str] | None:
    """Return the members of a list without empty or repeated members, or None."""
    if len(text) > MAX_TEXT_LENGTH:
        return None
    members = text.split(separator)
    if len(members) > limit or len(set(members)) != len(members):
        return None
    if any(re.fullmatch(pattern, member) is None for member in members):
        return None
    return members


@dataclass(frozen=True)
class AlgorithmSubset:
    """An sshd algorithm list that meets the profile when it holds only algorithms of its list.

    The order is ignored, so a list is as strict as each of its reorderings. ``+``, ``-`` and
    ``^`` (append to, remove from or put before the defaults of sshd) are refused, because
    the list sshd then uses is not the list written; so are wildcards, empty members and repeated
    members. sshd refuses an algorithm that it does not know, which the family's ``sshd -T``
    validation catches before anything is written.
    """

    def validate(self, raw: object, /) -> str:
        """Return a comma-separated list of algorithm names, or raise."""
        members = (
            _members(raw, ALGORITHM_SEPARATOR, ALGORITHM, MAX_ALGORITHMS)
            if isinstance(raw, str)
            else None
        )
        if members is None:
            message = (
                f"needs a string of at most {MAX_ALGORITHMS} different algorithm names separated "
                f"by commas, at most {MAX_TEXT_LENGTH} characters, without a leading +, - or ^, "
                f"a wildcard or a space, got {shown(raw)}"
            )
            raise ValueOverrideError(message)
        return cast("str", raw)

    def read_profile(self, text: str, /) -> str:
        """Return the canonical text of a profile's value, as :meth:`validate` does."""
        return self.validate(text)

    def _read(self, text: str) -> list[str]:
        try:
            self.validate(text)
        except ValueOverrideError as error:
            message = f"cannot judge {shown(text)}: {error}"
            raise ValueOverrideError(message) from error
        return text.split(ALGORITHM_SEPARATOR)

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether every algorithm of ``candidate`` is one of ``profile``."""
        return set(self._read(candidate)) <= set(self._read(profile))

    def stricter(self, first: str, second: str, /) -> str:
        """Return the algorithms of ``first`` that ``second`` holds too, in the first's order."""
        kept = set(self._read(second))
        common = [name for name in self._read(first) if name in kept]
        if not common:
            message = f"{shown(first)} and {shown(second)} have no algorithm in common"
            raise ValueOverrideError(message)
        return ALGORITHM_SEPARATOR.join(common)


@dataclass(frozen=True)
class ChoiceSet:
    """A keyword of a setting's own vocabulary that meets the profile when it is a choice of it.

    A profile's value may name several choices (``syslog|single|halt``), each of which the check
    accepts; an operator's value is one keyword, which the family writes as it is. The reader
    compares the keywords without regard to case, so the canonical text is in lower case. A set
    meets another when each of its keywords is one of the other's, so a keyword meets a profile
    exactly when it is one of its choices.

    A profile's set may also name a choice that is not a value of its own: ``exec`` of the four
    disk space and disk error actions, which auditd takes only with a further word, a program,
    that the collection never writes and whose line its reader does not read. Such a choice is
    taken in a profile's set, but never as an operator's value or as a value in force.

    Attributes:
        setting: The setting whose vocabulary is taken, for the messages.
        choices: The keywords, in lower case, that the reader accepts for the setting.
        profile_only: Further keywords that only a profile's set may name.
    """

    setting: str
    choices: frozenset[str]
    profile_only: frozenset[str] = frozenset()

    def validate(self, raw: object, /) -> str:
        """Return one keyword of the vocabulary in lower case, or raise."""
        word = raw.lower() if isinstance(raw, str) else None
        if word is None or word not in self.choices:
            message = (
                f"needs one keyword that auditd accepts for {self.setting}, one of "
                f"{', '.join(sorted(self.choices))}, not a set of them, got {shown(raw)}"
            )
            raise ValueOverrideError(message)
        return word

    def _read(self, text: object, allowed: frozenset[str]) -> list[str]:
        words = (
            _members(text.lower(), CHOICE_SEPARATOR, r"[a-z_]{1,32}", MAX_CHOICES)
            if isinstance(text, str)
            else None
        )
        if words is None or not set(words) <= allowed:
            message = (
                f"cannot judge {shown(text)}: it is not one keyword or a set of different "
                f"keywords separated by | that auditd accepts for {self.setting}"
            )
            raise ValueOverrideError(message)
        return words

    def _profile_words(self) -> frozenset[str]:
        return self.choices | self.profile_only

    def read_profile(self, text: str, /) -> str:
        """Return a profile's set of choices in lower case, or raise."""
        return CHOICE_SEPARATOR.join(self._read(text, self._profile_words()))

    def meets(self, candidate: str, profile: str, /) -> bool:
        """Return whether every keyword of ``candidate`` is one of the profile's choices."""
        held = self._read(candidate, self.choices)
        return set(held) <= set(self._read(profile, self._profile_words()))

    def stricter(self, first: str, second: str, /) -> str:
        """Return the keywords of ``first`` that ``second`` holds too and a host can hold."""
        kept = set(self._read(second, self._profile_words()))
        common = [
            word
            for word in self._read(first, self._profile_words())
            if word in kept and word in self.choices
        ]
        if not common:
            message = f"{shown(first)} and {shown(second)} have no choice in common"
            raise ValueOverrideError(message)
        return CHOICE_SEPARATOR.join(common)


def auditd_choices(setting: str) -> ChoiceSet:
    """Return the choice set of an auditd setting, with the vocabulary that auditd accepts.

    The four keywords of :data:`auditconf.OPTION_KEYWORDS` also take ``exec`` with a program,
    which only a profile's set may name.
    """
    profile_only = (
        frozenset({AUDITD_EXEC_ACTION})
        if setting in auditconf.OPTION_KEYWORDS
        else frozenset[str]()
    )
    return ChoiceSet(setting, frozenset(auditconf.KEYWORDS[setting].choices), profile_only)


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
        "sshd_interval": SshdInteger(AT_MOST, zero_loosest=True, seconds=True),
        "sshd_count_max": SshdInteger(AT_MOST, zero_loosest=True),
        "sshd_grace_time": SshdInteger(AT_MOST, zero_loosest=True, seconds=True),
        "sshd_at_most": SshdInteger(AT_MOST),
        "sshd_maxstartups": SshdMaxStartups(),
        "sshd_algorithms": AlgorithmSubset(),
        "sudo_timeout": IntegerOrder(AT_MOST, 0, SUDO_TIMEOUT_MAXIMUM),
        "sudo_path": Exact(SUDO_LOGFILE),
        "sysctl_exact": Exact(sysctl_config.KERNEL_INTEGER),
        "auditd_exact": Exact(AUDITD_MAIL_ACCOUNT),
        "auditd_minimum": IntegerOrder(AT_LEAST, 0, AUDITD_NUMBER_MAXIMUM),
        "auditd_percent": IntegerOrder(AT_LEAST, 0, AUDITD_MAX_PERCENT),
        "auditd_number": Exact(AUDITD_NUMBER),
        **{
            f"auditd_choice_{setting}": auditd_choices(setting)
            for setting in AUDITD_CHOICE_SETTINGS
        },
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
