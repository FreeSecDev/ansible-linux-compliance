"""Version-controlled exceptions (waivers) for compliance findings.

An exceptions file records accepted risks: which rule may fail, where, why, who
owns and approved the decision, and until when. This module parses and
validates such a file and applies it to a :class:`model.ScanRun`. It uses only
the standard library and runs on Python 3.9 and newer, so it can be used by
controller plugins and by the reporting package alike. The policy and the file
format are documented in ``docs/exceptions.md``.

Rules applied here:

* Every entry needs ``id``, ``rule``, ``framework``, ``scope``,
  ``justification``, ``owner``, ``approval`` (``approver`` and ``date``),
  ``created``, ``expires`` and ``risk``; none may be null or empty.
* ``created`` must not be in the future, ``approval.date`` lies between
  ``created`` and today and before ``expires``, and ``expires`` is after
  ``created`` by at most :data:`MAX_VALIDITY_DAYS` days. Owner and approver are
  email addresses or handles and must be different people. Identifiers are
  unique, ignoring case.
* A scope that names a benchmark must also name the profiles it covers, because
  the profiles of one benchmark (for example CIS and STIG) share its identifier.
* An exception is in effect from ``approval.date`` 00:00:00 UTC up to, but not
  including, ``expires`` 00:00:00 UTC. Expiry is judged at the later of the
  scan start and the controller time, so a host clock that runs behind cannot
  keep a lapsed waiver alive; a scan start in the future is refused.
* Only a ``fail`` finding of a completed run is waived. Every other outcome,
  and every finding of a run that did not complete, stays as it is.
* An expired exception never suppresses a failure: the finding stays ``fail``.
* Every exception gets a result per scan run, so unused (stale), expired and
  superseded exceptions are reported rather than dropped.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Final, NoReturn, TypeVar, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    yamlsubset,
)

E = TypeVar("E", bound=Enum)

FILE_SCHEMA_VERSION: Final[str] = "1.0"
SUPPORTED_FILE_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({FILE_SCHEMA_VERSION})
EVALUATION_SCHEMA_VERSION: Final[str] = "1.0"
MAX_VALIDITY_DAYS: Final[int] = 365
MAX_EXCEPTIONS: Final[int] = 1000
MAX_SCOPE_ITEMS: Final[int] = 256
MAX_ID_LENGTH: Final[int] = 64
MAX_PERSON_LENGTH: Final[int] = 254
MAX_HOST_LENGTH: Final[int] = 253
MAX_GROUP_LENGTH: Final[int] = 128
MAX_VERSION_LENGTH: Final[int] = 64
MAX_JUSTIFICATION_LENGTH: Final[int] = 4096
MAX_EVALUATIONS: Final[int] = 100000
FUTURE_TOLERANCE: Final[timedelta] = timedelta(minutes=5)
DEFAULT_MAX_SCAN_LAG: Final[timedelta] = timedelta(hours=24)
LONGEST_MAX_SCAN_LAG: Final[timedelta] = timedelta(days=MAX_VALIDITY_DAYS)

ID_PATTERN: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._-]*"
HOST_PATTERN: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._:-]*"
GROUP_PATTERN: Final[str] = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
DATE_PATTERN: Final[str] = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
TRIMMED_PATTERN: Final[str] = r"\S(?:.*\S)?"
HANDLE_PATTERN: Final[str] = r"[a-z0-9][a-z0-9._-]{0,63}"
EMAIL_PATTERN: Final[str] = (
    r"[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
PERSON_PATTERN: Final[str] = f"(?:{HANDLE_PATTERN}|{EMAIL_PATTERN})"
RESERVED_GROUPS: Final[frozenset[str]] = frozenset({"all", "ungrouped"})

DOCUMENT_KEYS: Final[tuple[str, ...]] = ("schema_version", "exceptions")
ENTRY_KEYS: Final[tuple[str, ...]] = (
    "id",
    "rule",
    "framework",
    "scope",
    "justification",
    "owner",
    "approval",
    "created",
    "expires",
    "risk",
)
SCOPE_KEYS: Final[tuple[str, ...]] = ("hosts", "groups", "benchmark", "profiles")
APPROVAL_KEYS: Final[tuple[str, ...]] = ("approver", "date")
BENCHMARK_KEYS: Final[tuple[str, ...]] = ("id", "version")

_TIMESTAMP_SUFFIX: Final[str] = "T00:00:00Z"


class ExceptionsError(ValueError):
    """Raised when an exceptions file, a target or an evaluation is invalid."""


class Risk(Enum):
    """Residual risk accepted by an exception."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Status(Enum):
    """What an exception did for one scan run."""

    WAIVED = "waived"
    EXPIRED = "expired"
    NOT_YET_EFFECTIVE = "not_yet_effective"
    NOT_FAILING = "not_failing"
    SUPERSEDED = "superseded"
    UNMATCHED = "unmatched"


_PRECEDENCE: Final[dict[Status, int]] = {
    Status.WAIVED: 0,
    Status.EXPIRED: 1,
    Status.NOT_YET_EFFECTIVE: 2,
}


def _fail(message: str) -> NoReturn:
    raise ExceptionsError(message)


def _mapping(
    value: object, where: str, keys: tuple[str, ...], *, required: bool
) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{where} must be a mapping")
    data = cast("dict[str, object]", value)
    unknown = sorted(repr(str(key)[:64]) for key in data if key not in keys)
    if unknown:
        _fail(f"{where} has unknown keys: {', '.join(unknown[:5])}")
    missing = [key for key in keys if key not in data]
    if required and missing:
        _fail(f"{where} is missing keys: {', '.join(missing)}")
    for key, item in data.items():
        if item is None:
            _fail(f"{where}.{key} must not be null or empty")
    return data


def _tuple(value: object, where: str) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        _fail(f"{where} must be a tuple")
    return cast("tuple[object, ...]", value)


def _string(value: object, message: str) -> str:
    if not isinstance(value, str):
        _fail(message)
    return value


def _text(value: object, where: str, *, max_length: int, pattern: str | None = None) -> str:
    return model.validate_text(value, where, max_length=max_length, pattern=pattern)


def _date(value: object, where: str) -> date:
    text = _text(value, where, max_length=10, pattern=DATE_PATTERN)
    try:
        return date.fromisoformat(text)
    except ValueError:
        _fail(f"{where} is not a valid calendar date")


def _names(value: object, where: str, *, max_length: int, pattern: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(f"{where} must be a sequence")
    items = cast("list[object]", value)
    if not items:
        _fail(f"{where} must not be empty")
    if len(items) > MAX_SCOPE_ITEMS:
        _fail(f"{where} has more than {MAX_SCOPE_ITEMS} items")
    names = tuple(
        _text(item, f"{where}[{index}]", max_length=max_length, pattern=pattern)
        for index, item in enumerate(items)
    )
    if len(set(names)) != len(names):
        _fail(f"{where} contains duplicates")
    return tuple(sorted(names))


def normalize_person(value: object, where: str) -> str:
    """Return the canonical form of an owner or approver.

    The value is NFKC-normalised, trimmed and case-folded, and must then be an
    email address or a handle (``[a-z0-9][a-z0-9._-]{0,63}``), ASCII only.

    Args:
        value: The owner or approver as written in the file.
        where: The field name used in error messages.

    Returns:
        The canonical form.

    Raises:
        ExceptionsError: If the value is not an email address or a handle.
        model.ModelError: If the value is not valid text.
    """
    raw = _text(value, where, max_length=MAX_PERSON_LENGTH)
    canonical = unicodedata.normalize("NFKC", raw).strip().casefold()
    if len(canonical) > MAX_PERSON_LENGTH or re.fullmatch(PERSON_PATTERN, canonical) is None:
        _fail(f"{where} must be an email address or a handle such as platform-team")
    return canonical


def same_person(first: str, second: str) -> bool:
    """Return whether two canonical owner or approver names may denote one person.

    They match when they are equal, or when one is a handle and the other an
    email address whose local part is that handle (``alice`` and
    ``alice@example.com``).
    """
    if first == second:
        return True
    handle, email = (first, second) if "@" in second else (second, first)
    return "@" not in handle and "@" in email and email.split("@", 1)[0] == handle


@dataclass(frozen=True)
class BenchmarkScope:
    """A benchmark and content version to which an exception is limited."""

    benchmark_id: str
    version: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping in the file format."""
        return {"id": self.benchmark_id, "version": self.version}


@dataclass(frozen=True)
class Scope:
    """Where an exception applies. Every dimension that is set must match."""

    hosts: tuple[str, ...]
    groups: tuple[str, ...]
    benchmark: BenchmarkScope | None
    profiles: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping that lists only the dimensions that are set."""
        result: dict[str, object] = {}
        if self.hosts:
            result["hosts"] = list(self.hosts)
        if self.groups:
            result["groups"] = list(self.groups)
        if self.benchmark is not None:
            result["benchmark"] = self.benchmark.to_dict()
        if self.profiles:
            result["profiles"] = list(self.profiles)
        return result


@dataclass(frozen=True)
class Target:
    """The controller's view of the host a scan run belongs to.

    ``host`` is the inventory host name and ``groups`` the inventory groups of
    that host. Both come from the controller, never from the scanned host.
    """

    host: str
    groups: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate the target."""
        _text(self.host, "target.host", max_length=MAX_HOST_LENGTH)
        groups = _tuple(self.groups, "target.groups")
        if len(groups) > MAX_SCOPE_ITEMS * 16:
            _fail("target.groups has too many items")
        for index, group in enumerate(groups):
            _text(group, f"target.groups[{index}]", max_length=MAX_GROUP_LENGTH)
        object.__setattr__(self, "groups", tuple(sorted(set(self.groups))))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"groups": list(self.groups), "host": self.host}


@dataclass(frozen=True)
class ExceptionRecord:
    """One validated exception. Build it with :func:`parse_exceptions`."""

    exception_id: str
    rule_id: str
    framework: model.FrameworkId
    scope: Scope
    justification: str
    owner: str
    approver: str
    approved_on: date
    created: date
    expires: date
    risk: Risk

    @property
    def expires_at(self) -> str:
        """Return the expiry as the model's UTC timestamp, at 00:00:00 of ``expires``."""
        return self.expires.isoformat() + _TIMESTAMP_SUFFIX

    def is_expired_at(self, instant: datetime) -> bool:
        """Return whether the exception has expired at a UTC instant."""
        return instant >= _midnight(self.expires)

    def is_effective_at(self, instant: datetime) -> bool:
        """Return whether the exception was approved before a UTC instant."""
        return instant >= _midnight(self.approved_on)

    def reason(self) -> str:
        """Return the text recorded on every finding the exception applies to."""
        return (
            f"{self.justification} (risk: {self.risk.value}; framework: "
            f"{self.framework.value}; owner: {self.owner}; approved by {self.approver} "
            f"on {self.approved_on.isoformat()}; created {self.created.isoformat()}; "
            f"expires {self.expires.isoformat()})"
        )

    def matches(self, run: model.ScanRun, target: Target) -> bool:
        """Return whether the scope covers a scan run of a target."""
        scope = self.scope
        if scope.hosts and target.host not in scope.hosts:
            return False
        if scope.groups and not set(scope.groups) & set(target.groups):
            return False
        if scope.profiles and run.profile_id not in scope.profiles:
            return False
        benchmark = scope.benchmark
        return benchmark is None or (
            run.benchmark_id == benchmark.benchmark_id
            and run.content.content_version == benchmark.version
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping of the record and its effective expiry."""
        return {
            "approval": {"approver": self.approver, "date": self.approved_on.isoformat()},
            "created": self.created.isoformat(),
            "expires": self.expires.isoformat(),
            "expires_at": self.expires_at,
            "framework": self.framework.value,
            "id": self.exception_id,
            "justification": self.justification,
            "owner": self.owner,
            "risk": self.risk.value,
            "rule": self.rule_id,
            "scope": self.scope.to_dict(),
        }


@dataclass(frozen=True)
class ExceptionSet:
    """The validated content of one exceptions file."""

    records: tuple[ExceptionRecord, ...]
    source_sha256: str


@dataclass(frozen=True)
class ExceptionResult:
    """What one exception did for one scan run."""

    record: ExceptionRecord
    status: Status
    outcome: model.Outcome | None
    superseded_by: str | None
    expired: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        result = self.record.to_dict()
        result["expired"] = self.expired
        result["outcome"] = None if self.outcome is None else self.outcome.value
        result["status"] = self.status.value
        result["superseded_by"] = self.superseded_by
        return result


@dataclass(frozen=True)
class Timing:
    """The instants an evaluation used.

    ``evaluated_at`` is the later of the scan start and the controller time and
    is the instant at which expiry is judged. ``scan_lag_exceeded`` is set when
    the scan started more than ``max_scan_lag`` before the controller time.
    """

    scan_started_at: datetime
    controller_time: datetime
    max_scan_lag: timedelta

    @property
    def evaluated_at(self) -> datetime:
        """Return the instant at which expiry is judged."""
        return max(self.scan_started_at, self.controller_time)

    @property
    def scan_lag(self) -> timedelta:
        """Return how long before the controller time the scan started."""
        return self.controller_time - self.scan_started_at

    @property
    def scan_lag_exceeded(self) -> bool:
        """Return whether the scan started longer ago than the allowed lag."""
        return self.scan_lag > self.max_scan_lag

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "controller_time": _format(self.controller_time),
            "evaluated_at": _format(self.evaluated_at),
            "max_scan_lag_seconds": int(self.max_scan_lag.total_seconds()),
            "scan_lag_exceeded": self.scan_lag_exceeded,
            "scan_lag_seconds": int(self.scan_lag.total_seconds()),
            "scan_started_at": _format(self.scan_started_at),
        }


@dataclass(frozen=True)
class Evaluation:
    """A scan run with exceptions applied, and the result of every exception."""

    run: model.ScanRun
    target: Target
    source_sha256: str
    results: tuple[ExceptionResult, ...]
    timing: Timing

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping (the evaluation document)."""
        counts = {status.value: 0 for status in Status}
        for result in self.results:
            counts[result.status.value] += 1
        document: dict[str, object] = {
            "exceptions": [result.to_dict() for result in self.results],
            "max_validity_days": MAX_VALIDITY_DAYS,
            "scan_run": self.run.to_dict(),
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "source_sha256": self.source_sha256,
            "summary": counts,
            "target": self.target.to_dict(),
        }
        document.update(self.timing.to_dict())
        return document


def _midnight(day: date) -> datetime:
    return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)


def _format(instant: datetime) -> str:
    return instant.strftime(model.TIMESTAMP_FORMAT)


def _utc(now: object) -> datetime:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        _fail("the current time must be a timezone-aware datetime")
    return now.astimezone(timezone.utc).replace(microsecond=0)


def _utc_today(now: object) -> date:
    return _utc(now).date()


def _parse_scope(value: object, where: str) -> Scope:
    data = _mapping(value, where, SCOPE_KEYS, required=False)
    if not data:
        _fail(f"{where} must name hosts, groups, profiles or a benchmark")
    hosts: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ()
    benchmark = None
    if "hosts" in data:
        hosts = _names(
            data["hosts"], f"{where}.hosts", max_length=MAX_HOST_LENGTH, pattern=HOST_PATTERN
        )
    if "groups" in data:
        groups = _names(
            data["groups"], f"{where}.groups", max_length=MAX_GROUP_LENGTH, pattern=GROUP_PATTERN
        )
        reserved = sorted(RESERVED_GROUPS.intersection(groups))
        if reserved:
            _fail(f"{where}.groups must not name the implicit group {reserved[0]!r}")
    if "profiles" in data:
        profiles = _names(
            data["profiles"],
            f"{where}.profiles",
            max_length=model.MAX_ID_LENGTH,
            pattern=model.XCCDF_ID_PATTERNS["profile"],
        )
    if "benchmark" in data:
        if not profiles:
            _fail(f"{where}.profiles is required when {where}.benchmark is set")
        bench = _mapping(data["benchmark"], f"{where}.benchmark", BENCHMARK_KEYS, required=True)
        benchmark = BenchmarkScope(
            model.validate_xccdf_id(bench["id"], f"{where}.benchmark.id", "benchmark"),
            _text(
                bench["version"],
                f"{where}.benchmark.version",
                max_length=MAX_VERSION_LENGTH,
                pattern=TRIMMED_PATTERN,
            ),
        )
    return Scope(hosts, groups, benchmark, profiles)


def _parse_enum(value: object, where: str, kind: type[E]) -> E:
    text = _text(value, where, max_length=32)
    try:
        return kind(text)
    except ValueError:
        allowed = ", ".join(str(member.value) for member in kind)
        _fail(f"{where} must be one of: {allowed}")


def _check_dates(record: ExceptionRecord, where: str, today: date) -> None:
    if record.created > today:
        _fail(f"{where}.created is in the future")
    if record.expires <= record.created:
        _fail(f"{where}.expires must be after {where}.created")
    if record.expires - record.created > timedelta(days=MAX_VALIDITY_DAYS):
        _fail(f"{where} is valid for more than {MAX_VALIDITY_DAYS} days")
    if record.approved_on < record.created:
        _fail(f"{where}.approval.date is before {where}.created")
    if record.approved_on > today:
        _fail(f"{where}.approval.date is in the future")
    if record.approved_on >= record.expires:
        _fail(f"{where}.approval.date must be before {where}.expires")
    if same_person(record.approver, record.owner):
        _fail(f"{where}.approval.approver must not be the owner")


def _parse_entry(value: object, where: str, today: date) -> ExceptionRecord:
    data = _mapping(value, where, ENTRY_KEYS, required=True)
    approval = _mapping(data["approval"], f"{where}.approval", APPROVAL_KEYS, required=True)
    justification = model.validate_text(
        data["justification"],
        f"{where}.justification",
        max_length=MAX_JUSTIFICATION_LENGTH,
        multiline=True,
    )
    record = ExceptionRecord(
        exception_id=_text(data["id"], f"{where}.id", max_length=MAX_ID_LENGTH, pattern=ID_PATTERN),
        rule_id=model.validate_xccdf_id(data["rule"], f"{where}.rule", "rule"),
        framework=_parse_enum(data["framework"], f"{where}.framework", model.FrameworkId),
        scope=_parse_scope(data["scope"], f"{where}.scope"),
        justification=justification.strip(),
        owner=normalize_person(data["owner"], f"{where}.owner"),
        approver=normalize_person(approval["approver"], f"{where}.approval.approver"),
        approved_on=_date(approval["date"], f"{where}.approval.date"),
        created=_date(data["created"], f"{where}.created"),
        expires=_date(data["expires"], f"{where}.expires"),
        risk=_parse_enum(data["risk"], f"{where}.risk", Risk),
    )
    _check_dates(record, where, today)
    return record


def parse_document(document: object, now: datetime) -> tuple[ExceptionRecord, ...]:
    """Validate an exceptions document that is already loaded.

    :func:`parse_exceptions` is the normal entry point. This function lets a
    caller that loaded the document by other means apply the same validation;
    such a caller is responsible for rejecting duplicate keys.

    Args:
        document: The loaded document, made of ``dict``, ``list``, ``str`` and ``None``.
        now: The current time, timezone-aware.

    Returns:
        The validated exceptions, sorted by identifier.

    Raises:
        ExceptionsError: If the document is not a valid exceptions document.
    """
    today = _utc_today(now)
    try:
        return _parse_document(document, today)
    except model.ModelError as error:
        raise ExceptionsError(str(error)) from error


def _parse_document(document: object, today: date) -> tuple[ExceptionRecord, ...]:
    data = _mapping(document, "document", DOCUMENT_KEYS, required=True)
    version = _text(data["schema_version"], "schema_version", max_length=16)
    if version not in SUPPORTED_FILE_SCHEMA_VERSIONS:
        _fail(f"unsupported schema_version {version[:16]!r}")
    entries = data["exceptions"]
    if not isinstance(entries, list):
        _fail("exceptions must be a sequence")
    items = cast("list[object]", entries)
    if len(items) > MAX_EXCEPTIONS:
        _fail(f"exceptions has more than {MAX_EXCEPTIONS} entries")
    records = tuple(
        _parse_entry(item, f"exceptions[{index}]", today) for index, item in enumerate(items)
    )
    seen: dict[str, str] = {}
    for record in records:
        key = record.exception_id.casefold()
        if key in seen:
            _fail(f"duplicate exception id {record.exception_id!r} (also {seen[key]!r})")
        seen[key] = record.exception_id
    return tuple(sorted(records, key=lambda record: record.exception_id))


def parse_exceptions(text: str, now: datetime) -> ExceptionSet:
    """Parse and validate an exceptions file.

    Args:
        text: The file content, in the YAML subset of :mod:`yamlsubset`.
        now: The current time, timezone-aware. Its UTC date is "today" for the
            checks on ``created`` and ``approval.date``.

    Returns:
        The validated exceptions, sorted by identifier, with the SHA-256 of the text.

    Raises:
        ExceptionsError: If the text is not a valid exceptions file. The whole
            file is rejected; no entry is applied from an invalid file.
    """
    _utc_today(now)
    _string(text, "the exceptions file must be text")
    try:
        document = yamlsubset.load(text)
    except yamlsubset.YamlSubsetError as error:
        message = f"exceptions file: {error}"
        raise ExceptionsError(message) from error
    records = parse_document(document, now)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return ExceptionSet(records, digest)


def _mark(
    finding: model.Finding, status: Status, record: ExceptionRecord, started: datetime
) -> model.Finding:
    if status is Status.WAIVED:
        exception = model.ExceptionStatus(
            model.ExceptionState.ACTIVE, record.exception_id, record.reason(), record.expires_at
        )
        return replace(finding, outcome=model.Outcome.WAIVED, exception=exception)
    if status is Status.EXPIRED and record.is_expired_at(started):
        exception = model.ExceptionStatus(
            model.ExceptionState.EXPIRED, record.exception_id, record.reason(), record.expires_at
        )
        return replace(finding, exception=exception)
    return finding


def _candidate_status(record: ExceptionRecord, timing: Timing) -> Status:
    if record.is_expired_at(timing.evaluated_at):
        return Status.EXPIRED
    if not record.is_effective_at(timing.scan_started_at):
        return Status.NOT_YET_EFFECTIVE
    return Status.WAIVED


def _timing(run: model.ScanRun, now: datetime, max_scan_lag: object) -> Timing:
    controller = _utc(now)
    if not isinstance(max_scan_lag, timedelta) or not (
        timedelta(0) < max_scan_lag <= LONGEST_MAX_SCAN_LAG
    ):
        _fail(f"the maximum scan lag must be positive and at most {MAX_VALIDITY_DAYS} days")
    started = datetime.strptime(run.started_at, model.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    if started > controller + FUTURE_TOLERANCE:
        _fail(
            f"scan_run.started_at {run.started_at} is later than the controller time "
            f"{_format(controller)} by more than {int(FUTURE_TOLERANCE.total_seconds())} "
            "seconds; check the clock of the scanned host"
        )
    return Timing(started, controller, max_scan_lag)


def evaluate_run(
    run: model.ScanRun,
    exceptions: ExceptionSet,
    target: Target,
    now: datetime,
    *,
    max_scan_lag: timedelta = DEFAULT_MAX_SCAN_LAG,
) -> Evaluation:
    """Apply exceptions to the findings of one scan run.

    The scan start comes from the scanned host and is not trusted to extend a
    waiver: expiry is judged at the later of the scan start and ``now`` (the
    controller time), and a scan start more than :data:`FUTURE_TOLERANCE`
    after ``now`` is refused. Whether an exception was already approved is
    judged at the scan start. A scan that started more than ``max_scan_lag``
    before ``now`` is still evaluated and is flagged in the evaluation.

    Args:
        run: A scan run whose findings carry no exception data yet.
        exceptions: The validated exceptions file.
        target: The inventory host and groups the run belongs to.
        now: The controller's current time, timezone-aware.
        max_scan_lag: The scan age above which the evaluation is flagged.

    Returns:
        The evaluation: the run with waived and expired findings marked, and one
        result per exception.

    Raises:
        ExceptionsError: If the run already carries exception data, starts in
            the future, or ``now`` or ``max_scan_lag`` is invalid.
    """
    for finding in run.findings:
        if finding.exception.state is not model.ExceptionState.NONE:
            _fail(f"finding {finding.rule_id} already carries exception data")
    timing = _timing(run, now, max_scan_lag)
    results, candidates = _classify(run, exceptions, target, timing)
    marked: list[model.Finding] = []
    for finding in run.findings:
        options = candidates.get(finding.rule_id)
        if options is None:
            marked.append(finding)
            continue
        status, chosen = _choose(options, results)
        marked.append(_mark(finding, status, chosen, timing.scan_started_at))
    ordered = tuple(results[record.exception_id] for record in exceptions.records)
    return Evaluation(
        replace(run, findings=tuple(marked)), target, exceptions.source_sha256, ordered, timing
    )


def _classify(
    run: model.ScanRun, exceptions: ExceptionSet, target: Target, timing: Timing
) -> tuple[dict[str, ExceptionResult], dict[str, list[tuple[Status, ExceptionRecord]]]]:
    completed = run.status is model.ScanStatus.COMPLETED
    findings = {finding.rule_id: finding for finding in run.findings}
    results: dict[str, ExceptionResult] = {}
    candidates: dict[str, list[tuple[Status, ExceptionRecord]]] = {}
    for record in exceptions.records:
        expired = record.is_expired_at(timing.evaluated_at)
        finding = findings.get(record.rule_id)
        if finding is None or not record.matches(run, target):
            results[record.exception_id] = ExceptionResult(
                record, Status.UNMATCHED, None, None, expired
            )
        elif finding.outcome is not model.Outcome.FAIL or not completed:
            results[record.exception_id] = ExceptionResult(
                record, Status.NOT_FAILING, finding.outcome, None, expired
            )
        else:
            candidates.setdefault(record.rule_id, []).append(
                (_candidate_status(record, timing), record)
            )
    return results, candidates


def _choose(
    options: list[tuple[Status, ExceptionRecord]], results: dict[str, ExceptionResult]
) -> tuple[Status, ExceptionRecord]:
    ranked = sorted(
        options,
        key=lambda option: (_PRECEDENCE[option[0]], option[1].expires, option[1].exception_id),
    )
    status, chosen = ranked[0]
    results[chosen.exception_id] = ExceptionResult(
        chosen, status, model.Outcome.FAIL, None, status is Status.EXPIRED
    )
    for other_status, other in ranked[1:]:
        results[other.exception_id] = ExceptionResult(
            other,
            Status.SUPERSEDED,
            model.Outcome.FAIL,
            chosen.exception_id,
            other_status is Status.EXPIRED,
        )
    return status, chosen


def _evaluation_statuses(value: object, where: str) -> tuple[str, dict[str, str]]:
    if not isinstance(value, dict):
        _fail(f"{where} must be a mapping")
    data = cast("dict[str, object]", value)
    digest = data.get("source_sha256")
    entries = data.get("exceptions")
    if not isinstance(digest, str) or not isinstance(entries, list):
        _fail(f"{where} is not an exceptions evaluation")
    known = {member.value for member in Status}
    statuses: dict[str, str] = {}
    for entry in cast("list[object]", entries):
        if not isinstance(entry, dict):
            _fail(f"{where}.exceptions must contain mappings")
        item = cast("dict[str, object]", entry)
        identifier = item.get("id")
        status = item.get("status")
        if not isinstance(identifier, str) or not isinstance(status, str) or status not in known:
            _fail(f"{where}.exceptions entries need an id and a known status")
        if identifier in statuses:
            _fail(f"{where}.exceptions lists {identifier[:64]!r} twice")
        statuses[identifier] = status
    return digest, statuses


def stale_exception_ids(evaluations: object) -> list[str]:
    """Return the exceptions that matched no finding in any evaluation.

    Args:
        evaluations: Evaluation documents (:meth:`Evaluation.to_dict`) of the
            same exceptions file, typically one per host of a play.

    Returns:
        The sorted identifiers whose status is ``unmatched`` in every evaluation.

    Raises:
        ExceptionsError: If there is no evaluation, if one is malformed, or if
            they were produced from different exceptions files.
    """
    if not isinstance(evaluations, (list, tuple)):
        _fail("evaluations must be a list")
    documents = list(cast("list[object] | tuple[object, ...]", evaluations))
    if not documents:
        _fail("at least one evaluation is required to report stale exceptions")
    if len(documents) > MAX_EVALUATIONS:
        _fail(f"more than {MAX_EVALUATIONS} evaluations")
    parsed = [
        _evaluation_statuses(document, f"evaluations[{index}]")
        for index, document in enumerate(documents)
    ]
    digest, first = parsed[0]
    for other_digest, statuses in parsed[1:]:
        if other_digest != digest or set(statuses) != set(first):
            _fail("evaluations come from different exceptions files")
    unmatched = Status.UNMATCHED.value
    tables = [statuses for _digest, statuses in parsed]
    return sorted(
        identifier
        for identifier in first
        if all(table[identifier] == unmatched for table in tables)
    )


def make_target(host: object, groups: object) -> Target:
    """Build a target from inventory values.

    Args:
        host: The inventory host name.
        groups: The inventory group names of the host, as a list or tuple.

    Returns:
        The validated target.

    Raises:
        ExceptionsError: If the host or a group is not a valid name.
    """
    if not isinstance(groups, (list, tuple)):
        _fail("groups must be a list of inventory group names")
    try:
        names = cast("list[str] | tuple[str, ...]", groups)
        return Target(cast("str", host), tuple(names))
    except model.ModelError as error:
        raise ExceptionsError(str(error)) from error


def load_scan_run(value: object) -> model.ScanRun:
    """Read a scan run from its JSON text or from its JSON-compatible mapping.

    Args:
        value: The output of :func:`model.dumps` or of :meth:`model.ScanRun.to_dict`.

    Returns:
        The validated scan run.

    Raises:
        ExceptionsError: If the value is not a valid scan run.
    """
    if not isinstance(value, (str, dict)):
        _fail("the scan run must be a mapping or JSON text")
    try:
        text = value if isinstance(value, str) else json.dumps(value, allow_nan=False)
        return model.loads(text)
    except (TypeError, ValueError) as error:
        message = f"invalid scan run: {error}"
        raise ExceptionsError(message) from error
