"""Orchestration of one read-only compliance audit on a managed host.

This module is the logic behind the ``compliance_scan`` module. It never runs a
process itself and never imports a concrete backend: content is verified with
:mod:`catalog`, the scan runs through a backend from :func:`backends.default_registry`
(the OpenSCAP backend runs ``oscap xccdf eval`` through :mod:`process` only), and
the result is a :class:`model.ScanRun` (ADR 0013).

An audit has two steps. :func:`plan` validates every input, verifies the datastream
against its pinned SHA-256, resolves the profile and the disabled rules and inspects
the output directory without creating anything. :func:`execute` then creates the
run directory, writes the tailoring file for disabled rules, runs the backend and
stores the evidence.

Check mode runs the same read-only scan, because operators expect real findings
from ``--check``, but keeps nothing: :meth:`Auditor.preview` scans into a private
temporary directory below the existing output root and removes it, and every file
in it, before it returns, also on failure. Check mode never creates the output root;
when it does not exist no scan runs and the run status is ``not_run``.

Disabled rules (ADR 0011) are excluded from the scan through a generated XCCDF
tailoring file whose profile extends the requested one and deselects them. They are
reported as ``disabled`` findings that name the controlling variable, never dropped
and never counted as passing. When the scanner did not complete they are ``error``
findings like every other rule of the profile, because the model allows nothing
else in such a run.

A backend in :data:`POST_SCAN_DISABLE_BACKENDS` cannot apply a per-run tailoring
file: SCC 5.15 reads tailoring only from its own installation directory, which an
audit never changes (ADR 0019, amendment of FREES-170). For such a backend the
whole profile is scanned and every disabled rule is then reported as ``disabled``
with its ``disabled_by``. The scanner's own result for the rule stays in the raw
results of the evidence and in the finding's evidence, and is never counted.

Control placements (``control_placement``) give findings the control family, topic
and tags of the ComplianceAsCode rules they map to (:class:`placement.ControlPlacement`);
the audit role computes them for SCC with the ``scc_toggles`` filter.

Evidence is written below an output root that must be owned by root (the expected
owner), with no group or world permissions, reached without symlinks through
ancestors that are owned by root or the expected owner and not writable by group or
others unless the sticky bit is set. Each run gets a new directory (mode 0700) that
is never reused, and every file in it has mode 0600.

The datastream is read as root, so :func:`plan` first resolves its real path and
vets the way to it with :func:`catalog.vetted_content_path`, the check that the
discover modules use too: every directory of the resolved chain must be owned by
root or the expected owner and not be writable by group or others unless the
sticky bit is set, every symlink followed must be owned by root or the expected
owner, and the file itself must be owned by root or the expected owner and not be
writable by group or others. No other user can then replace the file, for example
with a FIFO whose ``open`` would block the audit. The private copy is made from the
resolved path.

Writing evidence is not a change to the configuration of the host: the module always
reports ``changed: false`` and reports the evidence separately (``evidence_written``).
"""

from __future__ import annotations

import hashlib
import os.path
import re
import stat
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, NoReturn, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    backends,
    catalog,
    model,
    placement,
    process,
    scanner,
    xmlsafe,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

ROOT_UID: Final[int] = 0
DEFAULT_BACKEND: Final[str] = "openscap"
DEFAULT_OUTPUT_ROOT: Final[str] = "/var/lib/freesecdev/linux_compliance/evidence"
DIRECTORY_MODE: Final[int] = 0o700
FILE_MODE: Final[int] = 0o600
SCAN_DIRECTORY_NAME: Final[str] = "scan"
TAILORING_FILE_NAME: Final[str] = "tailoring.xml"
SCAN_RUN_FILE_NAME: Final[str] = "scan-run.json"
TAILORING_ID: Final[str] = "xccdf_org.freesecdev_tailoring_linux_compliance_audit"
TAILORED_PROFILE_SUFFIX: Final[str] = "_freesecdev_audit_tailored"
TAILORING_TITLE: Final[str] = "Rules disabled by freesecdev.linux_compliance toggles excluded"
XCCDF_NAMESPACE: Final[str] = "http://checklists.nist.gov/xccdf/1.2"
MAX_PATH_LENGTH: Final[int] = 4096
MAX_DISABLED_RULES: Final[int] = model.MAX_ITEMS
MAX_EVIDENCE_ENTRIES: Final[int] = 64
MAX_MESSAGE_LENGTH: Final[int] = 4096
MAX_ECHO_LENGTH: Final[int] = 64
HASH_CHUNK_BYTES: Final[int] = 1024 * 1024
RUN_STATUS_NOT_RUN: Final[str] = "not_run"
RULE_TOGGLE_PREFIX: Final[str] = "linux_compliance_rule_"
RULE_TOGGLE_SUFFIX: Final[str] = "_enabled"

_CONTENT_NAME: Final[str] = r"[A-Za-z0-9._+-]{1,64}"
_LONG_CONTENT_NAME: Final[str] = r"[A-Za-z0-9._+-]{1,128}"
LONG_CONTENT_NAME_BACKENDS: Final[frozenset[str]] = frozenset({"scc"})
OFF_PLATFORM_BACKENDS: Final[frozenset[str]] = frozenset({"scc"})
OS_RELEASE_BACKENDS: Final[frozenset[str]] = frozenset({"scc"})
POST_SCAN_DISABLE_BACKENDS: Final[frozenset[str]] = frozenset({"scc"})
MAX_PLACEMENTS: Final[int] = model.MAX_ITEMS
PLACEMENT_KEYS: Final[frozenset[str]] = frozenset(
    {"rule_id", "family", "topic", "tags", "stig_id", "mapped_rules", "partially_disabled_by"}
)
SCANNER_RESULT_EVIDENCE: Final[str] = "scanner_result"
DISABLE_BY_TAILORING: Final[str] = "tailoring"
DISABLE_AFTER_SCAN: Final[str] = "post_scan"
DISABLE_NOTHING: Final[str] = "none"
OS_RELEASE_PATH: Final[str] = "/etc/os-release"
OS_RELEASE_FALLBACK_PATH: Final[str] = "/usr/lib/os-release"
MAX_OS_RELEASE_BYTES: Final[int] = 64 * 1024
_RUN_ID: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_OS_RELEASE_KEY: Final[str] = r"[A-Z][A-Z0-9_]*"
_QUOTES: Final[tuple[str, ...]] = ('"', "'")
_BACKEND: Final[str] = r"[a-z][a-z0-9_-]{0,63}"
_TOGGLE: Final[str] = r"linux_compliance_[a-z0-9_]{1,100}_enabled"
_SHORT_RULE: Final[str] = r"[a-z0-9_]{1,100}"
_RULE_MARKER: Final[str] = "_rule_"
_RUN_ID_FORMAT: Final[str] = "%Y%m%dT%H%M%S.%fZ"
_FIRST_PRINTABLE: Final[int] = 32
_DELETE: Final[int] = 127
_GROUP_OR_OTHER_WRITE: Final[int] = stat.S_IWGRP | stat.S_IWOTH
_GROUP_OR_OTHER_ANY: Final[int] = 0o077

ERROR_INVALID_ARGUMENT: Final[str] = "invalid_argument"
ERROR_UNSAFE_OUTPUT: Final[str] = "unsafe_output_dir"
ERROR_UNSAFE_CONTENT: Final[str] = catalog.ERROR_UNSAFE_CONTENT
ERROR_OUTPUT_EXISTS: Final[str] = "output_exists"
ERROR_NOTHING_TO_SCAN: Final[str] = "nothing_to_scan"
ERROR_UNKNOWN_BACKEND: Final[str] = "unknown_backend"
ERROR_INVALID_REQUEST: Final[str] = "invalid_request"
ERROR_EVIDENCE: Final[str] = "evidence_write_failed"
ERROR_CLEANUP: Final[str] = "cleanup_failed"
ERROR_DIGEST_MISMATCH: Final[str] = "digest_mismatch"
ERROR_INVALID_CONTENT: Final[str] = "invalid_content"
ERROR_SCRIPT_CHECK: Final[str] = catalog.ERROR_SCRIPT_CHECK
ERROR_HOST_MISMATCH: Final[str] = "host_mismatch"
CONTENT_DIRECTORY_NAME: Final[str] = "content"
PREVIEW_PREFIX: Final[str] = ".check-"
MAX_DISCARD_DEPTH: Final[int] = 10


class AuditError(ValueError):
    """Raised when an audit cannot be planned or executed.

    Attributes:
        error_type: Stable identifier that the module reports as ``error_type``.
        evidence_dir: Run directory that was created before the failure, if any.
    """

    def __init__(self, error_type: str, message: str, evidence_dir: str | None = None) -> None:
        """Create the error with its stable type."""
        super().__init__(message)
        self.error_type = error_type
        self.evidence_dir = evidence_dir


def _matches(pattern: str, value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _safe(value: object) -> str:
    return repr(str(value)[:MAX_ECHO_LENGTH])


def _invalid(message: str) -> NoReturn:
    raise AuditError(ERROR_INVALID_ARGUMENT, message)


def _unsafe(message: str) -> NoReturn:
    raise AuditError(ERROR_UNSAFE_OUTPUT, message)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class DisabledRule:
    """A rule of the profile that an operator toggle excludes (ADR 0011).

    Attributes:
        rule_id: Full XCCDF rule identifier.
        disabled_by: Name of the controlling toggle variable.
    """

    rule_id: str
    disabled_by: str

    def __post_init__(self) -> None:
        """Validate both fields."""
        try:
            scanner.check_xccdf_id(self.rule_id, "rule", "disabled rule_id")
        except scanner.ScanRequestError as error:
            _invalid(str(error))
        if not _matches(_TOGGLE, self.disabled_by):
            _invalid(
                "disabled_by must be a toggle variable named linux_compliance_<name>_enabled: "
                f"{_safe(self.disabled_by)}"
            )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"disabled_by": self.disabled_by, "rule_id": self.rule_id}


def rule_toggle(rule_id: str) -> str:
    """Return the per-rule toggle variable of ADR 0011 for a rule identifier.

    The variable is ``linux_compliance_rule_<short id>_enabled``, where the short
    identifier is the part after ``_rule_``.

    Raises:
        AuditError: If the identifier is invalid or its short form cannot be a
            variable name; the caller must then name the variable explicitly.
    """
    try:
        scanner.check_xccdf_id(rule_id, "rule", "disabled rule_id")
    except scanner.ScanRequestError as error:
        _invalid(str(error))
    short = rule_id.split(_RULE_MARKER, 1)[1]
    if re.fullmatch(_SHORT_RULE, short) is None:
        _invalid(
            f"no toggle variable can be derived from {_safe(rule_id)}; set disabled_by explicitly"
        )
    return f"{RULE_TOGGLE_PREFIX}{short}{RULE_TOGGLE_SUFFIX}"


def parse_disabled_rules(items: object) -> tuple[DisabledRule, ...]:
    """Validate the ``disabled_rules`` argument.

    Args:
        items: A list whose elements are mappings with ``rule_id`` and an optional
            ``disabled_by``; a missing or empty ``disabled_by`` is derived with
            :func:`rule_toggle`.

    Returns:
        The rules sorted by identifier.

    Raises:
        AuditError: If the value is not such a list, has too many items, contains
            an invalid item or names a rule twice.
    """
    if items is None:
        return ()
    if not isinstance(items, list):
        _invalid("disabled_rules must be a list")
    entries = cast("list[object]", items)
    if len(entries) > MAX_DISABLED_RULES:
        _invalid(f"disabled_rules exceeds {MAX_DISABLED_RULES} items")
    rules: list[DisabledRule] = []
    for entry in entries:
        if not isinstance(entry, dict):
            _invalid("every disabled_rules item must be a mapping")
        fields = cast("dict[object, object]", entry)
        unknown = set(fields) - {"rule_id", "disabled_by"}
        if unknown:
            _invalid(f"unknown disabled_rules keys: {_safe(sorted(map(str, unknown)))}")
        rule_id = fields.get("rule_id")
        if not isinstance(rule_id, str):
            _invalid("every disabled_rules item needs a rule_id string")
        variable = fields.get("disabled_by")
        if variable is None or variable == "":
            variable = rule_toggle(rule_id)
        rules.append(DisabledRule(rule_id, cast("str", variable)))
    identifiers = [rule.rule_id for rule in rules]
    if len(set(identifiers)) != len(identifiers):
        _invalid("disabled_rules names a rule more than once")
    return tuple(sorted(rules, key=lambda rule: rule.rule_id))


@dataclass(frozen=True)
class RulePlacement:
    """The control placement of one rule of the profile.

    Attributes:
        rule_id: Full XCCDF identifier of a rule that the profile selects.
        control: Where its findings belong among the control families.
    """

    rule_id: str
    control: placement.ControlPlacement


def _placement_tuple(fields: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = fields.get(key, [])
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) for item in cast("list[object]", value)
    ):
        _invalid(f"control_placement {key} must be a list of strings")
    return tuple(cast("list[str]", value))


def parse_control_placement(items: object) -> tuple[RulePlacement, ...]:
    """Validate the ``control_placement`` argument.

    Args:
        items: ``None`` or a list of mappings with ``rule_id``, ``family`` and ``topic`` and the
            optional ``tags``, ``stig_id``, ``mapped_rules`` and ``partially_disabled_by``.

    Raises:
        AuditError: With ``invalid_argument``.
    """
    if items is None:
        return ()
    if not isinstance(items, list):
        _invalid("control_placement must be a list")
    entries = cast("list[object]", items)
    if len(entries) > MAX_PLACEMENTS:
        _invalid(f"control_placement exceeds {MAX_PLACEMENTS} items")
    parsed: list[RulePlacement] = []
    for item in entries:
        if not isinstance(item, dict):
            _invalid("every control_placement item must be a mapping")
        fields = cast("dict[str, object]", item)
        unknown = set(fields) - PLACEMENT_KEYS
        if unknown:
            _invalid(f"unknown control_placement keys: {_safe(sorted(map(str, unknown)))}")
        rule_id = fields.get("rule_id")
        try:
            scanner.check_xccdf_id(rule_id, "rule", "control_placement rule_id")
            placed = placement.ControlPlacement(
                family=cast("str", fields.get("family")),
                topic=cast("str", fields.get("topic")),
                tags=_placement_tuple(fields, "tags"),
                stig_id=cast("str | None", fields.get("stig_id")),
                mapped_rules=_placement_tuple(fields, "mapped_rules"),
                partially_disabled_by=_placement_tuple(fields, "partially_disabled_by"),
            )
        except (scanner.ScanRequestError, placement.PlacementError) as error:
            _invalid(f"control_placement: {error}")
        parsed.append(RulePlacement(cast("str", rule_id), placed))
    if len({item.rule_id for item in parsed}) != len(parsed):
        _invalid("control_placement names a rule more than once")
    return tuple(parsed)


def default_run_id(moment: datetime) -> str:
    """Return a run identifier from a UTC time with microseconds."""
    return moment.astimezone(timezone.utc).strftime(_RUN_ID_FORMAT)


def check_run_id(value: object) -> str:
    """Validate a run identifier, which also names the run directory.

    Raises:
        AuditError: Unless the value matches ``[A-Za-z0-9][A-Za-z0-9._-]{0,63}``.
    """
    if not isinstance(value, str) or re.fullmatch(_RUN_ID, value) is None:
        _invalid(f"run_id must match {_RUN_ID}: {_safe(value)}")
    return value


def check_output_root(value: object) -> str:
    """Validate the syntax of the output root.

    The path must be absolute, normalised (no ``.``, ``..``, repeated or trailing
    separators), free of control characters, not ``/`` and at most 4096 characters.

    Raises:
        AuditError: If any of these does not hold.
    """
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LENGTH:
        _unsafe(f"output_dir must be a path of 1 to {MAX_PATH_LENGTH} characters")
    if any(ord(character) < _FIRST_PRINTABLE or ord(character) == _DELETE for character in value):
        _unsafe("output_dir contains a control character")
    if not value.startswith("/") or value == "/":
        _unsafe(f"output_dir must be an absolute path below /: {_safe(value)}")
    if os.path.normpath(value) != value or value.startswith("//"):
        _unsafe(f"output_dir must be normalised, without '.', '..' or repeated '/': {_safe(value)}")
    return value


@dataclass(frozen=True)
class _Status:
    mode: int
    uid: int


@dataclass(frozen=True)
class _Subject:
    name: str
    ancestor: str
    error_type: str

    def refuse(self, message: str) -> NoReturn:
        raise AuditError(self.error_type, message)


_OUTPUT: Final[_Subject] = _Subject("output_dir", "an ancestor of output_dir", ERROR_UNSAFE_OUTPUT)


def _vet_component(path: Path, info: _Status, subject: _Subject) -> None:
    if stat.S_ISLNK(info.mode):
        subject.refuse(f"{subject.name} must not pass through a symlink: {_safe(path)}")
    if not stat.S_ISDIR(info.mode):
        subject.refuse(f"{subject.name} component is not a directory: {_safe(path)}")


def _vet_ancestor(path: Path, info: _Status, subject: _Subject, *, owner_uid: int) -> None:
    _vet_component(path, info, subject)
    if info.uid not in {ROOT_UID, owner_uid}:
        subject.refuse(f"{subject.ancestor} has an unexpected owner: {_safe(path)}")
    if info.mode & _GROUP_OR_OTHER_WRITE and not info.mode & stat.S_ISVTX:
        subject.refuse(f"{subject.ancestor} is writable by group or others: {_safe(path)}")


def _vet_directory(path: Path, info: _Status, *, owner_uid: int, final: bool) -> None:
    if not final:
        _vet_ancestor(path, info, _OUTPUT, owner_uid=owner_uid)
        return
    _vet_component(path, info, _OUTPUT)
    if info.uid != owner_uid:
        _unsafe(f"output_dir is not owned by uid {owner_uid}: {_safe(path)}")
    if stat.S_IMODE(info.mode) & _GROUP_OR_OTHER_ANY:
        _unsafe(f"output_dir must not grant group or other permissions: {_safe(path)}")


def _lstat(path: Path, subject: _Subject = _OUTPUT) -> _Status | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        subject.refuse(
            f"{subject.name} cannot be inspected: {error.strerror or type(error).__name__}"
        )
    return _Status(info.st_mode, info.st_uid)


def _make_directory(path: Path) -> None:
    try:
        path.mkdir(mode=DIRECTORY_MODE)
    except FileExistsError:
        return
    except OSError as error:
        _unsafe(f"output_dir cannot be created: {error.strerror or type(error).__name__}")


def inspect_output_root(path: str, *, owner_uid: int = ROOT_UID, create: bool) -> bool:
    """Walk the output root from ``/`` and vet every component.

    Args:
        path: Output root, validated with :func:`check_output_root`.
        owner_uid: Expected owner of the output root. Keyword-only and root by
            default; only tests change it.
        create: Create missing components with mode 0700.

    Returns:
        Whether the output root exists afterwards.

    Raises:
        AuditError: With ``unsafe_output_dir`` for a symlink, a component that is
            not a directory, a wrong owner or unsafe permissions. An existing
            directory is never repaired.
    """
    parts = Path(check_output_root(path)).parts
    for index in range(len(parts)):
        current = Path(*parts[: index + 1])
        info = _lstat(current)
        if info is None:
            if not create:
                return False
            _make_directory(current)
            info = _lstat(current)
            if info is None:
                _unsafe(f"output_dir vanished while it was created: {_safe(current)}")
        _vet_directory(current, info, owner_uid=owner_uid, final=index == len(parts) - 1)
    return True


def _check_instances(host: object, disabled_rules: object, placements: object) -> None:
    if not isinstance(host, model.HostIdentity):
        _invalid("host must be a HostIdentity")
    if not isinstance(disabled_rules, tuple) or not all(
        isinstance(rule, DisabledRule) for rule in cast("tuple[object, ...]", disabled_rules)
    ):
        _invalid("disabled_rules must be a tuple of DisabledRule")
    if not isinstance(placements, tuple) or not all(
        isinstance(item, RulePlacement) for item in cast("tuple[object, ...]", placements)
    ):
        _invalid("control_placement must be a tuple of RulePlacement")


def _check_timeout(value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 < value <= process.MAX_TIMEOUT_SECONDS
    ):
        _invalid(f"scan_timeout must be above 0 and at most {process.MAX_TIMEOUT_SECONDS} seconds")


def _check_size(value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= scanner.MAX_RESULT_BYTES_LIMIT
    ):
        _invalid(f"max_result_bytes must be between 1 and {scanner.MAX_RESULT_BYTES_LIMIT}")


def _check_off_platform(value: object, backend: str) -> None:
    if not isinstance(value, bool):
        _invalid("allow_off_platform_benchmark must be a boolean")
    if value and backend not in OFF_PLATFORM_BACKENDS:
        _invalid(
            "allow_off_platform_benchmark applies only to the backend "
            f"{', '.join(sorted(OFF_PLATFORM_BACKENDS))}, not to {_safe(backend)}"
        )


@dataclass(frozen=True)
class AuditJob:
    """The validated arguments of one audit.

    Attributes:
        backend: Name of the scanner backend.
        content_path: Datastream file, or a directory that holds exactly one.
        expected_sha256: Pinned SHA-256 of the datastream.
        profile_id: Full XCCDF profile identifier.
        output_root: Directory below which each run gets its own directory.
        run_id: Identifier of the run and name of its directory.
        host: Identity of the scanned host.
        timeout_seconds: Wall-clock limit of the scan.
        max_result_bytes: Largest results document that is parsed.
        disabled_rules: Rules that operator toggles exclude.
        allow_off_platform_benchmark: Explicit opt-in to the off-platform pairs
            of the backend (ADR 0019, amendment of FREES-161). Only the backends
            in :data:`OFF_PLATFORM_BACKENDS` accept it.
        control_placement: The control placement of rules of the profile, which
            their findings carry (ADR 0019, amendment of FREES-170).
    """

    backend: str
    content_path: str
    expected_sha256: str
    profile_id: str
    output_root: str
    run_id: str
    host: model.HostIdentity
    timeout_seconds: float
    max_result_bytes: int
    disabled_rules: tuple[DisabledRule, ...]
    allow_off_platform_benchmark: bool = False
    control_placement: tuple[RulePlacement, ...] = ()

    def __post_init__(self) -> None:
        """Validate the fields that do not need the file system."""
        if not _matches(_BACKEND, self.backend):
            _invalid(f"backend must match {_BACKEND}: {_safe(self.backend)}")
        _check_off_platform(self.allow_off_platform_benchmark, self.backend)
        try:
            scanner.check_xccdf_id(self.profile_id, "profile", "profile_id")
        except scanner.ScanRequestError as error:
            _invalid(str(error))
        _check_timeout(self.timeout_seconds)
        _check_size(self.max_result_bytes)
        _check_instances(self.host, self.disabled_rules, self.control_placement)
        check_output_root(self.output_root)
        check_run_id(self.run_id)


def build_job(params: Mapping[str, object], moment: datetime) -> AuditJob:
    """Build and validate an :class:`AuditJob` from module parameters.

    Args:
        params: The module parameters.
        moment: Current UTC time, used for the default run identifier.

    Raises:
        AuditError: With ``invalid_argument`` or ``unsafe_output_dir``.
    """
    host = params.get("host")
    if not isinstance(host, dict):
        _invalid("host must be a mapping")
    fields = cast("dict[str, object]", host)
    try:
        identity = model.HostIdentity(
            cast("str", fields.get("hostname")),
            cast("str", fields.get("distribution_id")),
            cast("str", fields.get("distribution_version")),
            cast("str", fields.get("architecture")),
            cast("str | None", fields.get("machine_id") or None),
        )
    except model.ModelError as error:
        _invalid(str(error))
    run_id = params.get("run_id") or default_run_id(moment)
    timeout = params.get("scan_timeout")
    size = params.get("max_result_bytes")
    return AuditJob(
        backend=cast("str", params.get("backend")),
        content_path=cast("str", params.get("content_path")),
        expected_sha256=cast("str", params.get("expected_sha256")),
        profile_id=cast("str", params.get("profile_id")),
        output_root=cast("str", params.get("output_dir")),
        run_id=cast("str", run_id),
        host=identity,
        timeout_seconds=cast("float", timeout),
        max_result_bytes=cast("int", size),
        disabled_rules=parse_disabled_rules(params.get("disabled_rules")),
        allow_off_platform_benchmark=cast(
            "bool", params.get("allow_off_platform_benchmark", False)
        ),
        control_placement=parse_control_placement(params.get("control_placement")),
    )


@dataclass(frozen=True)
class AuditPlan:
    """What an audit will do, computed without writing anything.

    Attributes:
        job: The validated job.
        content_path: The datastream file that was verified.
        benchmark: The benchmark of the datastream.
        rules: The rules that the profile selects, sorted by identifier.
        expected_rule_ids: The selected rules that are not disabled.
        evaluated_profile_id: The profile the scanner evaluates: the requested one,
            or the tailored profile when rules are disabled.
        run_dir: The run directory that will be created.
        output_root_exists: Whether the output root exists already.
    """

    job: AuditJob
    content_path: str
    benchmark: catalog.Benchmark
    rules: tuple[catalog.Rule, ...]
    expected_rule_ids: tuple[str, ...]
    evaluated_profile_id: str
    run_dir: str
    output_root_exists: bool

    @property
    def tailored(self) -> bool:
        """Whether disabled rules require a tailoring file."""
        return self.disable_method == DISABLE_BY_TAILORING

    @property
    def disable_method(self) -> str:
        """How disabled rules are excluded: ``tailoring``, ``post_scan`` or ``none``."""
        if not self.job.disabled_rules:
            return DISABLE_NOTHING
        if self.job.backend in POST_SCAN_DISABLE_BACKENDS:
            return DISABLE_AFTER_SCAN
        return DISABLE_BY_TAILORING

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible description of the planned scan."""
        return {
            "allow_off_platform_benchmark": self.job.allow_off_platform_benchmark,
            "backend": self.job.backend,
            "benchmark_id": self.benchmark.benchmark_id,
            "benchmark_version": self.benchmark.version,
            "content_path": self.content_path,
            "content_sha256": self.job.expected_sha256.lower(),
            "control_placement_count": len(self.job.control_placement),
            "disable_method": self.disable_method,
            "disabled_rule_count": len(self.job.disabled_rules),
            "evaluated_profile_id": self.evaluated_profile_id,
            "expected_rule_count": len(self.expected_rule_ids),
            "output_dir": self.job.output_root,
            "output_root_exists": self.output_root_exists,
            "profile_id": self.job.profile_id,
            "rule_count": len(self.rules),
            "run_dir": self.run_dir,
            "run_id": self.job.run_id,
            "scan_timeout": self.job.timeout_seconds,
            "tailoring": self.tailored,
        }


def _mismatch(message: str) -> NoReturn:
    raise AuditError(ERROR_HOST_MISMATCH, message)


def read_os_release(path: str) -> dict[str, str]:
    """Return the ``KEY=VALUE`` assignments of an os-release file, unquoted.

    Raises:
        AuditError: With ``host_mismatch`` if the file cannot be read or is too large.
    """
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_OS_RELEASE_BYTES + 1)
    except OSError as error:
        _mismatch(
            f"the release of the host cannot be read from {path}: {error.strerror or 'error'}"
        )
    if len(data) > MAX_OS_RELEASE_BYTES:
        _mismatch(f"{path} exceeds {MAX_OS_RELEASE_BYTES} bytes")
    values: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        key, separator, value = line.strip().partition("=")
        if separator and re.fullmatch(_OS_RELEASE_KEY, key) is not None:
            text = value.strip()
            quoted = len(text) > 1 and text[0] in _QUOTES and text[-1] == text[0]
            values[key] = text[1:-1] if quoted else text
    return values


def resolve_os_release(primary: str, fallback: str) -> str:
    """Return the os-release file to read, as os-release(5) orders them.

    ``primary`` is used when it exists, even if it cannot be read, so an unreadable
    file never silently yields to ``fallback``. When neither exists, ``primary`` is
    returned and reading it fails closed with ``host_mismatch``.
    """
    if Path(primary).exists() or not Path(fallback).exists():
        return primary
    return fallback


def check_host_release(host: model.HostIdentity, path: str) -> None:
    """Refuse a host whose ``ID`` and ``VERSION_ID`` in ``path`` differ from ``host``.

    The SCC backend chooses between its on-platform and off-platform rules by the
    asserted distribution and version, so the module compares them with what the
    managed host itself reports before anything is created.

    Raises:
        AuditError: With ``host_mismatch``.
    """
    values = read_os_release(path)
    reported = (values.get("ID", ""), values.get("VERSION_ID", ""))
    asserted = (host.distribution_id, host.distribution_version)
    if reported != asserted:
        _mismatch(
            f"the host reports ID {_safe(reported[0])} and VERSION_ID {_safe(reported[1])} in "
            f"{path}, but host.distribution_id and host.distribution_version are "
            f"{_safe(asserted[0])} and {_safe(asserted[1])}"
        )


def _verified_profile(
    job: AuditJob, *, owner_uid: int
) -> tuple[str, catalog.Benchmark, tuple[catalog.Rule, ...]]:
    try:
        content = catalog.vetted_content_path(job.content_path, owner_uid=owner_uid)
        benchmark = catalog.single_benchmark(catalog.read_benchmarks(content, job.expected_sha256))
        profile = catalog.find_profile(benchmark, job.profile_id)
    except catalog.CatalogError as error:
        raise AuditError(catalog.error_type(error), str(error)) from error
    return content, benchmark, catalog.profile_rules(benchmark, profile)


def _tailored_profile_id(profile_id: str) -> str:
    candidate = f"{profile_id}{TAILORED_PROFILE_SUFFIX}"
    try:
        return scanner.check_xccdf_id(candidate, "profile", "tailored profile_id")
    except scanner.ScanRequestError as error:
        _invalid(f"profile_id is too long to be tailored: {error}")


def _scanned_rules(job: AuditJob, rules: tuple[catalog.Rule, ...]) -> tuple[tuple[str, ...], str]:
    """Return the rules the scanner must report on and the profile it evaluates.

    Every disabled and every placed rule must be selected by the profile, and at
    least one rule must stay enabled. A backend in :data:`POST_SCAN_DISABLE_BACKENDS`
    scans the requested profile and reports on every rule; any other backend
    scans the tailored profile when rules are disabled and reports on the enabled
    rules only.
    """
    selected = {rule.rule_id for rule in rules}
    outside = [rule.rule_id for rule in job.disabled_rules if rule.rule_id not in selected]
    if outside:
        _invalid(
            f"{len(outside)} disabled rule(s) are not selected by the profile, "
            f"for example {_safe(outside[0])}"
        )
    unplaced = [item.rule_id for item in job.control_placement if item.rule_id not in selected]
    if unplaced:
        _invalid(
            f"{len(unplaced)} control_placement rule(s) are not selected by the profile, "
            f"for example {_safe(unplaced[0])}"
        )
    disabled = {rule.rule_id for rule in job.disabled_rules}
    enabled = tuple(rule.rule_id for rule in rules if rule.rule_id not in disabled)
    if not enabled:
        raise AuditError(
            ERROR_NOTHING_TO_SCAN, "the profile selects no rule that is enabled, nothing to scan"
        )
    if job.backend in POST_SCAN_DISABLE_BACKENDS:
        return tuple(rule.rule_id for rule in rules), job.profile_id
    evaluated = _tailored_profile_id(job.profile_id) if disabled else job.profile_id
    return enabled, evaluated


def plan(job: AuditJob, *, owner_uid: int = ROOT_UID) -> AuditPlan:
    """Validate an audit against the host without writing anything.

    Resolves the real path of the datastream and vets it and the way to it with
    :func:`catalog.vetted_content_path` before it is opened, verifies the datastream
    digest and the profile and the datastream file name, checks that every
    disabled rule is selected by the profile and that at least one rule stays
    enabled, and inspects the output root and the run directory. Everything the
    backend would refuse about the request is refused here, before anything is
    created.

    Args:
        job: The validated job.
        owner_uid: Expected owner of the output root, and the only owner besides
            root that the datastream and its directories may have. Keyword-only
            and root by default; only tests change it.

    Raises:
        AuditError: For every problem, with a stable ``error_type``. A backend in
            :data:`OS_RELEASE_BACKENDS` also needs the host's ``/etc/os-release``
            (or ``/usr/lib/os-release`` when that is missing) to report the asserted
            distribution and version (``host_mismatch``).
    """
    if job.backend in OS_RELEASE_BACKENDS:
        check_host_release(job.host, resolve_os_release(OS_RELEASE_PATH, OS_RELEASE_FALLBACK_PATH))
    content, benchmark, rules = _verified_profile(job, owner_uid=owner_uid)
    pattern = _LONG_CONTENT_NAME if job.backend in LONG_CONTENT_NAME_BACKENDS else _CONTENT_NAME
    if re.fullmatch(pattern, Path(content).name) is None:
        _invalid(
            f"the datastream file name must match {pattern}, because it labels the "
            f"provenance: {_safe(Path(content).name)}"
        )
    expected, evaluated = _scanned_rules(job, rules)
    exists = inspect_output_root(job.output_root, owner_uid=owner_uid, create=False)
    run_dir = str(Path(job.output_root) / job.run_id)
    if exists and _lstat(Path(run_dir)) is not None:
        raise AuditError(ERROR_OUTPUT_EXISTS, f"the run directory already exists: {_safe(run_dir)}")
    return AuditPlan(job, content, benchmark, rules, expected, evaluated, run_dir, exists)


def xml_escape(value: str) -> str:
    """Escape ``&``, ``<``, ``>``, ``"`` and ``'`` for XML text and attribute values."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def tailoring_document(audit_plan: AuditPlan, moment: datetime) -> str:
    """Return the XCCDF 1.2 tailoring document that deselects the disabled rules.

    Every identifier in it has been validated against the XCCDF identifier
    alphabet, which contains no XML markup characters; every value is escaped
    with :func:`xml_escape` anyway, so a later change of the alphabet cannot
    inject markup. The document references no file: the scanner gets the
    datastream (the private copy) on its command line.
    """
    stamp = moment.astimezone(timezone.utc).strftime(model.TIMESTAMP_FORMAT)
    profile = xml_escape(audit_plan.job.profile_id)
    tailored = xml_escape(audit_plan.evaluated_profile_id)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<xccdf:Tailoring xmlns:xccdf="{XCCDF_NAMESPACE}" id="{xml_escape(TAILORING_ID)}">',
        f'  <xccdf:version time="{xml_escape(stamp)}">1</xccdf:version>',
        f'  <xccdf:Profile id="{tailored}" extends="{profile}">',
        f"    <xccdf:title>{xml_escape(TAILORING_TITLE)}</xccdf:title>",
    ]
    lines.extend(
        f'    <xccdf:select idref="{xml_escape(rule.rule_id)}" selected="false"/>'
        for rule in audit_plan.job.disabled_rules
    )
    lines.extend(["  </xccdf:Profile>", "</xccdf:Tailoring>", ""])
    return "\n".join(lines)


@dataclass(frozen=True)
class EvidenceFile:
    """One file of the evidence of a run.

    Attributes:
        path: Absolute path of the file.
        kind: ``scanner_output``, ``tailoring`` or ``scan_run``.
        sha256: SHA-256 of the file when it was recorded.
        size: Size in bytes.
    """

    path: str
    kind: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"kind": self.kind, "path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class AuditOutcome:
    """The result of an executed audit.

    Attributes:
        plan: The plan that was executed.
        run: The normalized scan run.
        evidence: The evidence files, sorted by path.
        skipped: Entries of the scanner output directory that are not regular
            files and were therefore neither recorded nor changed.
        content: The private copy of the datastream that the scanner read.
    """

    plan: AuditPlan
    run: model.ScanRun
    evidence: tuple[EvidenceFile, ...]
    skipped: tuple[SkippedEntry, ...]
    content: ContentCopy


@dataclass(frozen=True)
class SkippedEntry:
    """An entry of the scanner output directory that is not a regular file.

    Attributes:
        path: Absolute path of the entry.
        type: ``symlink``, ``directory``, ``fifo``, ``socket`` or ``other``.
    """

    path: str
    type: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {"path": self.path, "type": self.type}


@dataclass(frozen=True)
class ContentCopy:
    """The private copy of the datastream that the scanner reads.

    Attributes:
        source_path: The verified datastream on the host.
        copy_path: The copy in the run directory, the only file the scanner reads.
        sha256: SHA-256 of exactly the bytes written to the copy; equal to the pin.
        size: Size of the copy in bytes.
    """

    source_path: str
    copy_path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping; the copy is always removed after the scan."""
        return {
            "copy_removed": True,
            "private_copy": self.copy_path,
            "sha256": self.sha256,
            "size": self.size,
            "source_path": self.source_path,
        }


def _write_new_file(path: Path, text: str) -> None:
    staging = path.with_name(f".{path.name}.tmp")
    with staging.open("xb") as handle:
        staging.chmod(FILE_MODE)
        handle.write(text.encode("utf-8"))
        handle.flush()
    staging.replace(path)


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record(path: Path, kind: str) -> EvidenceFile:
    return EvidenceFile(str(path), kind, _digest(path), path.lstat().st_size)


def entry_type(mode: int) -> str:
    """Return the evidence listing type of a non-regular directory entry."""
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "other"


def _scanner_files(directory: Path) -> tuple[list[EvidenceFile], list[SkippedEntry]]:
    info = _lstat(directory)
    if info is None or not stat.S_ISDIR(info.mode):
        return [], []
    entries = sorted(directory.iterdir())
    if len(entries) > MAX_EVIDENCE_ENTRIES:
        message = f"the scanner wrote more than {MAX_EVIDENCE_ENTRIES} entries"
        raise AuditError(ERROR_EVIDENCE, message, str(directory.parent))
    recorded: list[EvidenceFile] = []
    skipped: list[SkippedEntry] = []
    for entry in entries:
        mode = entry.lstat().st_mode
        if not stat.S_ISREG(mode):
            skipped.append(SkippedEntry(str(entry), entry_type(mode)))
            continue
        entry.chmod(FILE_MODE)
        recorded.append(_record(entry, "scanner_output"))
    return recorded, skipped


class _CopiedChunks:
    """The chunks of a datastream, hashed and written to its private copy as they are parsed."""

    def __init__(self, handle: BinaryIO, copy: BinaryIO) -> None:
        self.handle = handle
        self.copy = copy
        self.digest = hashlib.sha256()
        self.size = 0

    def __iter__(self) -> Iterator[bytes]:
        for chunk in xmlsafe.iter_handle_chunks(self.handle, catalog.DEFAULT_MAX_BYTES):
            self.digest.update(chunk)
            self.size += len(chunk)
            self.copy.write(chunk)
            yield chunk


def copy_content(source: str, directory: Path, pinned: str) -> ContentCopy:
    """Copy the datastream into a new private directory and verify the copy.

    The source is opened once as a regular file that is not a symlink and is at
    most :data:`catalog.DEFAULT_MAX_BYTES` long. The SHA-256 is computed over
    exactly the bytes written to the copy (mode 0600, same file name), in one pass,
    so the copy has the pinned content or the audit stops. The same bytes are parsed
    while they are copied, and a copy that holds a check or script that would make the
    scanner run a script of the content is refused (:func:`catalog.refuse_script_check`,
    FREES-191), whatever its digest. A copy that does not match is deleted. ``directory``
    is created with mode 0700 and must not exist.

    Raises:
        AuditError: ``digest_mismatch`` if the bytes are not the pinned content,
            ``script_check_content`` if they hold a script check, ``invalid_content`` if
            the source cannot be read or parsed safely, and ``evidence_write_failed`` if the
            copy cannot be written.
    """
    target = directory / Path(source).name
    try:
        directory.mkdir(mode=DIRECTORY_MODE)
    except OSError as error:
        message = f"the private copy cannot be created: {error.strerror or type(error).__name__}"
        raise AuditError(ERROR_EVIDENCE, message) from error
    try:
        with (
            xmlsafe.RegularFile(source, catalog.DEFAULT_MAX_BYTES) as handle,
            target.open("xb") as copy,
        ):
            target.chmod(FILE_MODE)
            copied = _CopiedChunks(handle, copy)
            xmlsafe.parse_chunks(copied, catalog.ScriptCheckScanner())
            copy.flush()
    except catalog.ScriptCheckError as error:
        _discard_copy(directory)
        raise AuditError(ERROR_SCRIPT_CHECK, str(error)) from error
    except xmlsafe.XmlSafetyError as error:
        _discard_copy(directory)
        raise AuditError(
            ERROR_INVALID_CONTENT, f"the datastream cannot be copied: {error}"
        ) from error
    except OSError as error:
        _discard_copy(directory)
        message = f"the datastream cannot be copied: {error.strerror or type(error).__name__}"
        raise AuditError(ERROR_EVIDENCE, message) from error
    actual = copied.digest.hexdigest()
    if actual != pinned:
        _discard_copy(directory)
        message = f"the datastream changed after verification: expected {pinned}, copied {actual}"
        raise AuditError(ERROR_DIGEST_MISMATCH, message)
    return ContentCopy(source, str(target), actual, copied.size)


def _discard_copy(directory: Path) -> None:
    try:
        _discard_tree(directory)
    except OSError as error:
        message = (
            "the private copy of the datastream could not be removed: "
            f"{error.strerror or type(error).__name__}"
        )
        raise AuditError(ERROR_CLEANUP, message, str(directory)) from error


def _truncate(text: str) -> str:
    return text[:MAX_MESSAGE_LENGTH]


def _severity(rule: catalog.Rule) -> model.Severity:
    return model.Severity(rule.severity)


def _disabled_finding(rule: catalog.Rule, toggle: DisabledRule) -> model.Finding:
    return model.Finding(
        rule_id=rule.rule_id,
        outcome=model.Outcome.DISABLED,
        evaluated_outcome=model.Outcome.DISABLED,
        severity=_severity(rule),
        message=(
            f"disabled by {toggle.disabled_by}; excluded from the scan through the generated "
            "tailoring file and never counted as passing"
        ),
        evidence=(),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=toggle.disabled_by,
        flags=(),
    )


def _scanned_disabled_finding(
    rule: catalog.Rule, toggle: DisabledRule, scanned: model.Finding | None, scanner_name: str
) -> model.Finding:
    result = "none" if scanned is None else scanned.outcome.value
    return model.Finding(
        rule_id=rule.rule_id,
        outcome=model.Outcome.DISABLED,
        evaluated_outcome=model.Outcome.DISABLED,
        severity=_severity(rule),
        message=(
            f"disabled by {toggle.disabled_by}; {scanner_name} cannot exclude a rule from a scan "
            "without changing its own installation, so the rule was scanned and its result "
            f"{result!r} is kept only in the raw results and this finding's evidence, never "
            "counted as passing"
        ),
        evidence=(model.Evidence(SCANNER_RESULT_EVIDENCE, scanner_name, result),),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=toggle.disabled_by,
        flags=(),
    )


def _error_finding(rule: catalog.Rule, message: str) -> model.Finding:
    return model.Finding(
        rule_id=rule.rule_id,
        outcome=model.Outcome.ERROR,
        evaluated_outcome=model.Outcome.ERROR,
        severity=_severity(rule),
        message=_truncate(message),
        evidence=(),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=None,
        flags=(),
    )


def finalize_run(audit_plan: AuditPlan, run: model.ScanRun) -> model.ScanRun:
    """Turn the backend run into the run that the module reports.

    The run is reported under the requested profile, with the tailoring recorded
    in the provenance by the backend. A completed run whose content digest is not
    the pinned one becomes ``failed``. Disabled rules are added as ``disabled``
    findings on a completed run and as ``error`` findings otherwise, so every rule
    of the profile is accounted for exactly once. For a backend in
    :data:`POST_SCAN_DISABLE_BACKENDS` the disabled rules were scanned, and their
    findings are replaced in the same way, the scanner's result kept as evidence.
    Every finding of a rule with a control placement then carries it.
    """
    toggles = {rule.rule_id: rule for rule in audit_plan.job.disabled_rules}
    by_id = {rule.rule_id: rule for rule in audit_plan.rules}
    status = run.status
    message = run.error_message
    findings = run.findings
    pinned = audit_plan.job.expected_sha256.lower()
    if status is model.ScanStatus.COMPLETED and run.content.content_sha256 != pinned:
        status = model.ScanStatus.FAILED
        message = (
            f"the scanned content has SHA-256 {run.content.content_sha256}, not the pinned {pinned}"
        )
        findings = tuple(_error_finding(by_id[item.rule_id], message) for item in findings)
    scanned = {item.rule_id: item for item in findings if item.rule_id in toggles}
    findings = tuple(item for item in findings if item.rule_id not in toggles)
    if status is model.ScanStatus.COMPLETED and audit_plan.disable_method == DISABLE_AFTER_SCAN:
        added = tuple(
            _scanned_disabled_finding(by_id[key], toggle, scanned.get(key), run.scanner.name)
            for key, toggle in toggles.items()
        )
    elif status is model.ScanStatus.COMPLETED:
        added = tuple(_disabled_finding(by_id[key], toggle) for key, toggle in toggles.items())
    else:
        reason = f"the scan did not complete: {message}"
        added = tuple(
            _error_finding(by_id[key], f"{reason}; the rule was disabled by {toggle.disabled_by}")
            for key, toggle in toggles.items()
        )
    placed = {item.rule_id: item.control for item in audit_plan.job.control_placement}
    return replace(
        run,
        profile_id=audit_plan.job.profile_id,
        status=status,
        error_message=None if message is None else _truncate(message),
        findings=tuple(
            replace(item, control=placed.get(item.rule_id, item.control))
            for item in (*findings, *added)
        ),
    )


def _secure_directory(path: Path, *, owner_uid: int) -> None:
    try:
        path.mkdir(mode=DIRECTORY_MODE)
    except FileExistsError as error:
        message = f"the run directory already exists: {_safe(path)}"
        raise AuditError(ERROR_OUTPUT_EXISTS, message) from error
    except OSError as error:
        _unsafe(f"the run directory cannot be created: {error.strerror or type(error).__name__}")
    info = _lstat(path)
    if info is None:
        _unsafe(f"the run directory vanished: {_safe(path)}")
    _vet_directory(path, info, owner_uid=owner_uid, final=True)


def _run_backend(
    audit_plan: AuditPlan,
    run_dir: Path,
    content: ContentCopy,
    *,
    registry: scanner.BackendRegistry,
) -> model.ScanRun:
    tailoring = str(run_dir / TAILORING_FILE_NAME) if audit_plan.tailored else None
    try:
        settings = scanner.ScanSettings(
            str(run_dir),
            str(run_dir),
            audit_plan.job.timeout_seconds,
            audit_plan.job.max_result_bytes,
        )
        backend = registry.create(audit_plan.job.backend, settings)
        request = scanner.ScanRequest(
            run_id=audit_plan.job.run_id,
            host=audit_plan.job.host,
            benchmark_id=audit_plan.benchmark.benchmark_id,
            profile_id=audit_plan.evaluated_profile_id,
            content_path=content.copy_path,
            output_dir=SCAN_DIRECTORY_NAME,
            expected_rule_ids=audit_plan.expected_rule_ids,
            tailoring_path=tailoring,
            allow_off_platform_benchmark=audit_plan.job.allow_off_platform_benchmark,
        )
        return backend.audit(request)
    except scanner.UnknownBackendError as error:
        raise AuditError(ERROR_UNKNOWN_BACKEND, str(error), str(run_dir)) from error
    except scanner.ScanRequestError as error:
        raise AuditError(ERROR_INVALID_REQUEST, str(error), str(run_dir)) from error


def summarize(run: model.ScanRun | None) -> dict[str, object] | None:
    """Count the findings of a run by outcome, with the run status first.

    The summary never states compliance (AGENTS.md rule 9): it holds ``run_status``, the
    number of findings per outcome, the total and ``off_platform``, the off-platform
    marker of the run or ``None``. A run that did not complete has only ``error``
    findings, so it can never look compliant.
    """
    if run is None:
        return None
    counts: dict[str, object] = {outcome.value: 0 for outcome in model.Outcome}
    for finding in run.findings:
        key = finding.outcome.value
        counts[key] = cast("int", counts[key]) + 1
    counts["total"] = len(run.findings)
    counts["run_status"] = run.status.value
    counts["off_platform"] = None if run.off_platform is None else run.off_platform.to_dict()
    return counts


def report(
    audit_plan: AuditPlan,
    run: model.ScanRun | None,
    kept: AuditOutcome | None,
    content: ContentCopy | None,
    message: str,
) -> dict[str, object]:
    """Return the module result for an audit.

    Args:
        audit_plan: The plan of the audit.
        run: The scan run, or ``None`` when no scanner ran.
        kept: The executed audit whose evidence was kept, or ``None`` (check mode,
            or no scan).
        content: The private copy of the datastream that the scanner read, or
            ``None`` when no scanner ran.
        message: Human-readable summary returned as ``msg``.

    ``changed`` is always false: an audit never changes the configuration of the
    host. Evidence files are reported in ``evidence`` and ``evidence_written``.
    """
    return {
        "changed": False,
        "content": None if content is None else content.to_dict(),
        "disabled_rules": [rule.to_dict() for rule in audit_plan.job.disabled_rules],
        "evidence": {
            "directory": None if kept is None else audit_plan.run_dir,
            "files": [] if kept is None else [item.to_dict() for item in kept.evidence],
            "skipped": [] if kept is None else [item.to_dict() for item in kept.skipped],
        },
        "evidence_written": kept is not None,
        "msg": message,
        "planned": audit_plan.to_dict(),
        "run_id": audit_plan.job.run_id,
        "run_status": RUN_STATUS_NOT_RUN if run is None else run.status.value,
        "scan_run": None if run is None else run.to_dict(),
        "summary": summarize(run),
    }


def _discard_tree(path: Path, depth: int = 0) -> None:
    if depth > MAX_DISCARD_DEPTH:
        message = f"the temporary directory is nested too deeply: {_safe(path)}"
        raise AuditError(ERROR_CLEANUP, message, str(path))
    entries = sorted(path.iterdir())
    if len(entries) > MAX_EVIDENCE_ENTRIES:
        message = f"the temporary directory has too many entries: {_safe(path)}"
        raise AuditError(ERROR_CLEANUP, message, str(path))
    for entry in entries:
        if stat.S_ISDIR(entry.lstat().st_mode):
            _discard_tree(entry, depth + 1)
        else:
            entry.unlink()
    path.rmdir()


def discard_preview(path: Path) -> None:
    """Remove a temporary check-mode run directory and everything in it.

    Symlinks inside it are removed, never followed. Nesting is bounded.

    Raises:
        AuditError: With ``cleanup_failed`` and the directory as
            ``evidence_dir`` if anything cannot be removed.
    """
    try:
        _discard_tree(path)
    except OSError as error:
        message = (
            "the temporary check-mode directory could not be removed: "
            f"{error.strerror or type(error).__name__}"
        )
        raise AuditError(ERROR_CLEANUP, message, str(path)) from error


class Auditor:
    """Plans and executes audits.

    ``owner_uid``, ``registry`` and ``clock`` are seams for unit tests and are
    keyword-only. Production code constructs ``Auditor()``: the output root must
    then be owned by root, the backends come from :func:`backends.default_registry`
    and the time from the system clock. The repository guard bans the
    ``owner_uid``, ``registry`` and ``clock`` keywords in plugin code.
    """

    def __init__(
        self,
        *,
        owner_uid: int = ROOT_UID,
        registry: scanner.BackendRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Create an auditor."""
        self._owner_uid = owner_uid
        self._registry = backends.default_registry() if registry is None else registry
        self._clock = _utc_now if clock is None else clock

    def _scan(self, audit_plan: AuditPlan, run_dir: Path) -> tuple[model.ScanRun, ContentCopy]:
        content = copy_content(
            audit_plan.content_path,
            run_dir / CONTENT_DIRECTORY_NAME,
            audit_plan.job.expected_sha256.lower(),
        )
        try:
            if audit_plan.tailored:
                tailoring = run_dir / TAILORING_FILE_NAME
                _write_new_file(tailoring, tailoring_document(audit_plan, self._clock()))
            run = _run_backend(audit_plan, run_dir, content, registry=self._registry)
        finally:
            _discard_copy(run_dir / CONTENT_DIRECTORY_NAME)
        return finalize_run(audit_plan, run), content

    def execute(self, audit_plan: AuditPlan) -> AuditOutcome:
        """Create the run directory, run the backend and store the evidence.

        The scanner reads only a private, verified copy of the datastream in the
        run directory (:func:`copy_content`), which is removed after the scan; its
        source path and SHA-256 are reported in ``content``.

        Raises:
            AuditError: For every problem that prevents a scan run from existing.
                Scanner failures are not errors: they are a run whose status is
                ``failed`` or ``timed_out`` and whose findings are all ``error``.
        """
        inspect_output_root(audit_plan.job.output_root, owner_uid=self._owner_uid, create=True)
        run_dir = Path(audit_plan.run_dir)
        _secure_directory(run_dir, owner_uid=self._owner_uid)
        try:
            run, content = self._scan(audit_plan, run_dir)
            evidence: list[EvidenceFile] = []
            if audit_plan.tailored:
                evidence.append(_record(run_dir / TAILORING_FILE_NAME, "tailoring"))
            recorded, skipped = _scanner_files(run_dir / SCAN_DIRECTORY_NAME)
            evidence.extend(recorded)
            record = run_dir / SCAN_RUN_FILE_NAME
            _write_new_file(record, model.dumps(run) + "\n")
            evidence.append(_record(record, "scan_run"))
        except AuditError as error:
            raise AuditError(error.error_type, str(error), str(run_dir)) from error
        except OSError as error:
            message = f"evidence could not be written: {error.strerror or type(error).__name__}"
            raise AuditError(ERROR_EVIDENCE, message, str(run_dir)) from error
        return AuditOutcome(
            audit_plan,
            run,
            tuple(sorted(evidence, key=lambda item: item.path)),
            tuple(skipped),
            content,
        )

    def preview(self, audit_plan: AuditPlan) -> tuple[model.ScanRun, ContentCopy]:
        """Run the scan for check mode and keep nothing.

        The scan runs into a new private directory ``<output_dir>/.check-<run_id>``
        (mode 0700, vetted like a run directory) below the existing, vetted output
        root, on a private copy of the datastream in that directory. The directory
        and every file in it are removed before this returns, also when the scan or
        anything else fails. The output root is never created. Errors never name the
        removed directory, so nothing claims that evidence exists.

        Raises:
            AuditError: As :meth:`execute`, and ``cleanup_failed`` (naming the
                directory) if the temporary directory cannot be removed.
        """
        inspect_output_root(audit_plan.job.output_root, owner_uid=self._owner_uid, create=False)
        scratch = Path(audit_plan.job.output_root) / f"{PREVIEW_PREFIX}{audit_plan.job.run_id}"
        _secure_directory(scratch, owner_uid=self._owner_uid)
        try:
            return self._scan(audit_plan, scratch)
        except AuditError as error:
            if error.error_type == ERROR_CLEANUP:
                raise
            raise AuditError(error.error_type, str(error)) from error
        except OSError as error:
            message = f"the check-mode scan failed: {error.strerror or type(error).__name__}"
            raise AuditError(ERROR_EVIDENCE, message) from error
        finally:
            discard_preview(scratch)

    def run(self, job: AuditJob, *, check_mode: bool) -> dict[str, object]:
        """Plan an audit and run it.

        Outside check mode the evidence is kept in the run directory. In check
        mode the scan runs through :meth:`preview` and nothing is kept; when the
        output root does not exist, check mode does not create it and no scan
        runs (``run_status`` ``not_run``).

        Returns:
            The module result from :func:`report`.

        Raises:
            AuditError: For every problem that prevents a scan run from existing,
                including ``unknown_backend`` before anything is inspected.
        """
        names = self._registry.names()
        if job.backend not in names:
            message = f"unknown scanner backend {_safe(job.backend)}; known: {', '.join(names)}"
            raise AuditError(ERROR_UNKNOWN_BACKEND, message)
        planned = plan(job, owner_uid=self._owner_uid)
        if check_mode and not planned.output_root_exists:
            message = (
                f"check mode: output_dir {job.output_root} does not exist and check mode does "
                "not create it, so no scan ran"
            )
            return report(planned, None, None, None, message)
        if check_mode:
            run, content = self.preview(planned)
            message = (
                f"check mode: scan finished with run_status {run.status.value}; it ran on a "
                "private copy of the datastream in a temporary directory that was removed, and "
                "no evidence was kept"
            )
            return report(planned, run, None, content, message)
        outcome = self.execute(planned)
        message = (
            f"scan finished with run_status {outcome.run.status.value} on a private copy of the "
            f"datastream; evidence in {planned.run_dir}"
        )
        return report(planned, outcome.run, outcome, outcome.content, message)
