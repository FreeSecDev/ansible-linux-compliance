"""Evidence bundles of one audit run: plan, build and verify (FREES-51).

An evidence bundle is a directory on the controller that holds the evidence of one
audit run of one host, the manifest ``bundle.json`` and a ``SHA256SUMS`` file. The
``evidence`` role fetches the files that the audit recorded on the host, and this
module decides which files those are, checks every digest and writes the documents
of the bundle. The reporting package verifies a bundle with
:func:`evidence_check.check_bundle` before it reads anything from it. The format
is documented in ``docs/evidence.md``.

Only a fixed vocabulary of files can enter a bundle. A host file is collected only
when its path is directly inside the run directory that the audit reported and its
name is one of :data:`HOST_SOURCES`; any other path inside the run directory is
recorded as excluded, and a path outside it refuses the whole bundle. Nothing from
the host's facts, the environment, the inventory or the state ledger is written, so
the only host data in a bundle is the scanner output, the scan run and, when
exceptions were applied, the evaluation, the exceptions file and the stale result.

The bundle is not signed (ADR 0018 is proposed). Its checksums detect a file that
changed or went missing after collection; they do not prove who wrote the bundle,
because whoever can edit a file can also edit the checksums.

The module uses only the Python standard library and runs on Python 3.9.
"""

from __future__ import annotations

import hashlib
import json
import os.path
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, NoReturn, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

BUNDLE_SCHEMA_VERSION: Final[str] = "1.0"
SUPPORTED_BUNDLE_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({BUNDLE_SCHEMA_VERSION})
STALE_SCHEMA_VERSION: Final[str] = "1.0"
BUNDLE_KIND: Final[str] = "freesecdev.linux_compliance.evidence_bundle"
STALE_KIND: Final[str] = "freesecdev.linux_compliance.stale_exceptions"
COLLECTION_NAME: Final[str] = "freesecdev.linux_compliance"
MANIFEST_NAME: Final[str] = "bundle.json"
CHECKSUMS_NAME: Final[str] = "SHA256SUMS"
SCAN_RUN_PATH: Final[str] = "raw/scan-run.json"
EVALUATION_PATH: Final[str] = "exceptions/evaluation.json"
EXCEPTIONS_FILE_PATH: Final[str] = "exceptions/exceptions.yml"
STALE_PATH: Final[str] = "exceptions/stale.json"
EVALUATION_SOURCE: Final[str] = "linux_compliance_audited.exceptions.evaluation"
STALE_SOURCE: Final[str] = "linux_compliance_audit_stale_exceptions"

KIND_SCAN_RUN: Final[str] = "scan_run"
KIND_XCCDF: Final[str] = "xccdf"
KIND_ARF: Final[str] = "arf"
KIND_TAILORING: Final[str] = "tailoring"
KIND_EVALUATION: Final[str] = "exceptions_evaluation"
KIND_EXCEPTIONS_FILE: Final[str] = "exceptions_file"
KIND_STALE: Final[str] = "stale_exceptions"

REASON_NOT_ALLOW_LISTED: Final[str] = "not_allow_listed"
REASON_ARF_NOT_REQUESTED: Final[str] = "arf_not_requested"
EXCLUSION_REASONS: Final[frozenset[str]] = frozenset(
    {REASON_NOT_ALLOW_LISTED, REASON_ARF_NOT_REQUESTED}
)

EXCEPTIONS_NOT_REQUESTED: Final[str] = "not_requested"
EXCEPTIONS_APPLIED: Final[str] = "applied"
EXCEPTIONS_STATUSES: Final[frozenset[str]] = frozenset(
    {EXCEPTIONS_NOT_REQUESTED, EXCEPTIONS_APPLIED, "not_run", "not_completed"}
)


@dataclass(frozen=True)
class HostSource:
    """A file of the run directory that may enter a bundle.

    Attributes:
        audit_kind: The kind the audit module records for it.
        path: The path of the copy in the bundle.
        kind: The kind of the copy in the bundle manifest.
    """

    audit_kind: str
    path: str
    kind: str


HOST_SOURCES: Final[Mapping[str, HostSource]] = MappingProxyType(
    {
        "scan-run.json": HostSource("scan_run", SCAN_RUN_PATH, KIND_SCAN_RUN),
        "tailoring.xml": HostSource("tailoring", "raw/tailoring.xml", KIND_TAILORING),
        "scan/results.xml": HostSource("scanner_output", "raw/scan/results.xml", KIND_XCCDF),
        "scan/results-arf.xml": HostSource("scanner_output", "raw/scan/results-arf.xml", KIND_ARF),
        "scan/results.off-platform.xml": HostSource(
            "scanner_output", "raw/scan/results.off-platform.xml", KIND_XCCDF
        ),
        "scan/results-arf.off-platform.xml": HostSource(
            "scanner_output", "raw/scan/results-arf.off-platform.xml", KIND_ARF
        ),
    }
)
DOCUMENT_PATHS: Final[Mapping[str, str]] = MappingProxyType(
    {
        EVALUATION_PATH: KIND_EVALUATION,
        EXCEPTIONS_FILE_PATH: KIND_EXCEPTIONS_FILE,
        STALE_PATH: KIND_STALE,
    }
)
BUNDLE_PATHS: Final[Mapping[str, str]] = MappingProxyType(
    dict(
        [(source.path, source.kind) for source in HOST_SOURCES.values()]
        + list(DOCUMENT_PATHS.items())
    )
)
SIGNATURE_SUFFIXES: Final[tuple[str, ...]] = (
    ".sig",
    ".pem",
    ".crt",
    ".sigstore",
    ".sigstore.json",
    ".intoto.jsonl",
    ".att",
)

MAX_FILE_BYTES: Final[int] = 256 * 1024 * 1024
MAX_HOST_FILES: Final[int] = 64
MAX_MANIFEST_BYTES: Final[int] = 1024 * 1024
MAX_PATH_LENGTH: Final[int] = 4096
MAX_HOSTS: Final[int] = 100000
MAX_ECHO: Final[int] = 64

_SHA256: Final[str] = r"[0-9a-f]{64}"
_RUN_ID: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_MACHINE_ID: Final[str] = r"[0-9a-f]{32}"
_VERSION: Final[str] = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?"
_TIMESTAMP: Final[str] = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
_EXCEPTION_ID: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._-]*"

_MANIFEST_KEYS: Final[tuple[str, ...]] = (
    "checksums",
    "collected_at",
    "collection",
    "content",
    "exceptions",
    "excluded",
    "files",
    "gate",
    "host",
    "kind",
    "run",
    "scanner",
    "schema_version",
)
_GATE_KEYS: Final[tuple[str, ...]] = ("decision", "deferred", "enforced")
_DECISION_KEYS: Final[tuple[str, ...]] = (
    "after_waivers",
    "basis",
    "counted",
    "enabled",
    "error",
    "fail",
    "waived",
)
_GATE_BASES: Final[frozenset[str]] = frozenset({"raw", "waived"})
NOT_ENFORCED: Final[str] = (
    "the result gate of this run was deferred and never enforced; a bundle is only written after "
    "the gate ran (playbooks/evidence.yml runs the enforce.yml entry point of the audit role first)"
)
_COLLECTION_KEYS: Final[tuple[str, ...]] = ("name", "version")
_HOST_KEYS: Final[tuple[str, ...]] = ("inventory_hostname", "machine_id", "reported")
_RUN_KEYS: Final[tuple[str, ...]] = (
    "benchmark_id",
    "finished_at",
    "profile_id",
    "run_id",
    "started_at",
    "status",
)
_EXCEPTIONS_KEYS: Final[tuple[str, ...]] = (
    "evaluation",
    "file",
    "source_sha256",
    "stale",
    "status",
)
_FILE_KEYS: Final[tuple[str, ...]] = ("kind", "path", "sha256", "size", "source")
_EXCLUDED_KEYS: Final[tuple[str, ...]] = ("audit_kind", "reason", "sha256", "size", "source")
_CHECKSUMS_KEYS: Final[tuple[str, ...]] = ("path", "sha256", "size")
_AUDIT_FILE_KEYS: Final[tuple[str, ...]] = ("kind", "path", "sha256", "size")
STALE_KEYS: Final[tuple[str, ...]] = (
    "audited_hosts",
    "complete",
    "computed",
    "evaluated_hosts",
    "not_evaluated_hosts",
    "source_sha256",
    "stale",
    "target_hosts",
    "unmatched",
)
STALE_DOCUMENT_KEYS: Final[tuple[str, ...]] = ("kind", "result", "schema_version")
_COLLECTED_KEYS: Final[tuple[str, ...]] = (
    "collection_version",
    "controller_uid",
    "exceptions_text",
    "host",
    "include_arf",
    "machine_id",
    "observed",
    "scan_run_text",
    "stale",
)
_STAT_KEYS: Final[tuple[str, ...]] = ("checksum", "isreg", "islnk", "mode", "size", "uid")
_FILE_MODE: Final[str] = "0600"


class EvidenceError(ValueError):
    """Raised when evidence cannot be collected into a bundle or a bundle does not verify."""


def _fail(message: str) -> NoReturn:
    raise EvidenceError(message)


def _echo(value: object) -> str:
    return repr(str(value)[:MAX_ECHO])


def _mapping(value: object, where: str, keys: tuple[str, ...] | None = None) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{where} must be a mapping")
    data = cast("dict[object, object]", value)
    if any(not isinstance(key, str) for key in data):
        _fail(f"{where} has a key that is not a string")
    result = {cast("str", key): item for key, item in data.items()}
    if keys is not None:
        unknown = sorted(set(result) - set(keys))
        missing = sorted(set(keys) - set(result))
        if unknown:
            _fail(f"{where} has unknown keys: {', '.join(_echo(key) for key in unknown[:5])}")
        if missing:
            _fail(f"{where} is missing keys: {', '.join(missing)}")
    return result


def _list(value: object, where: str, max_items: int) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{where} must be a list")
    items = cast("list[object]", value)
    if len(items) > max_items:
        _fail(f"{where} has more than {max_items} items")
    return items


def _text(value: object, where: str, *, max_length: int, pattern: str | None = None) -> str:
    try:
        return model.validate_text(value, where, max_length=max_length, pattern=pattern)
    except model.ModelError as error:
        raise EvidenceError(str(error)) from None


def _optional_text(
    value: object, where: str, *, max_length: int, pattern: str | None = None
) -> str | None:
    if value is None:
        return None
    return _text(value, where, max_length=max_length, pattern=pattern)


def _digest(value: object, where: str) -> str:
    return _text(value, where, max_length=64, pattern=_SHA256)


def _size(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_FILE_BYTES:
        _fail(f"{where} must be an integer from 0 to {MAX_FILE_BYTES}")
    return value


def _flag(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{where} must be a boolean")
    return value


def _host(value: object, where: str) -> str:
    return _text(
        value, where, max_length=exceptions.MAX_HOST_LENGTH, pattern=exceptions.HOST_PATTERN
    )


def _source(value: object, where: str) -> str:
    return _text(value, where, max_length=MAX_PATH_LENGTH)


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 of ``data`` as lower-case hex."""
    return hashlib.sha256(data).hexdigest()


def canonical_json(document: object) -> str:
    """Serialize a bundle document: sorted keys, two-space indent, ASCII, trailing newline."""
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def load_json(data: bytes, where: str) -> object:
    """Parse strict JSON: UTF-8, no duplicate keys, no ``NaN`` or ``Infinity``.

    ``where`` names the document in every error, for example ``bundle.json`` or
    ``the collection summary``.
    """

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                _fail(f"{where} contains a duplicate key")
            result[key] = value
        return result

    def no_constant(_constant: str) -> NoReturn:
        _fail(f"{where} contains a non-finite number")

    try:
        text = data.decode("utf-8")
        return json.loads(text, object_pairs_hook=no_duplicates, parse_constant=no_constant)
    except EvidenceError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        _fail(f"{where} is not valid JSON")


@dataclass(frozen=True)
class BundleFile:
    """One file of a bundle, listed in the manifest.

    Attributes:
        path: Path inside the bundle, one of :data:`BUNDLE_PATHS`.
        kind: The kind that belongs to the path.
        sha256: SHA-256 of the file.
        size: Size in bytes.
        source: Where the file came from: the path on the host, the exceptions file
            on the controller, or the fact the document was written from.
    """

    path: str
    kind: str
    sha256: str
    size: int
    source: str

    def __post_init__(self) -> None:
        """Validate the entry."""
        if self.path not in BUNDLE_PATHS:
            _fail(f"bundle file {_echo(self.path)} is not a known bundle path")
        if BUNDLE_PATHS[self.path] != self.kind:
            _fail(f"bundle file {self.path} must have kind {BUNDLE_PATHS[self.path]}")
        _digest(self.sha256, f"{self.path}.sha256")
        _size(self.size, f"{self.path}.size")
        _source(self.source, f"{self.path}.source")

    def to_dict(self) -> dict[str, object]:
        """Return the manifest mapping."""
        return {
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, value: object) -> BundleFile:
        """Build an entry from its manifest mapping."""
        data = _mapping(value, "manifest file", _FILE_KEYS)
        return cls(
            _text(data["path"], "manifest file path", max_length=64),
            _text(data["kind"], "manifest file kind", max_length=64),
            _digest(data["sha256"], "manifest file sha256"),
            _size(data["size"], "manifest file size"),
            _source(data["source"], "manifest file source"),
        )


@dataclass(frozen=True)
class ExcludedFile:
    """A file that the audit recorded on the host and that was not collected.

    Attributes:
        source: The path on the host.
        audit_kind: The kind the audit recorded.
        sha256: The SHA-256 the audit recorded.
        size: The size the audit recorded.
        reason: ``not_allow_listed`` or ``arf_not_requested``.
    """

    source: str
    audit_kind: str
    sha256: str
    size: int
    reason: str

    def __post_init__(self) -> None:
        """Validate the entry."""
        _source(self.source, "excluded source")
        _text(self.audit_kind, "excluded audit_kind", max_length=64, pattern=r"[a-z_]+")
        _digest(self.sha256, "excluded sha256")
        _size(self.size, "excluded size")
        if self.reason not in EXCLUSION_REASONS:
            _fail(f"excluded reason {_echo(self.reason)} is unknown")

    def to_dict(self) -> dict[str, object]:
        """Return the manifest mapping."""
        return {
            "audit_kind": self.audit_kind,
            "reason": self.reason,
            "sha256": self.sha256,
            "size": self.size,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExcludedFile:
        """Build an entry from its manifest mapping."""
        data = _mapping(value, "manifest excluded file", _EXCLUDED_KEYS)
        return cls(
            _source(data["source"], "excluded source"),
            _text(data["audit_kind"], "excluded audit_kind", max_length=64),
            _digest(data["sha256"], "excluded sha256"),
            _size(data["size"], "excluded size"),
            _text(data["reason"], "excluded reason", max_length=64),
        )


@dataclass(frozen=True)
class ExceptionsRecord:
    """Whether exceptions were applied to the run, and which bundle files hold them.

    Attributes:
        status: The ``status`` of ``linux_compliance_audited.exceptions``.
        source_sha256: SHA-256 of the exceptions file, or ``None`` without one.
        evaluation: Path of the evaluation document, set exactly when applied.
        file: Path of the exceptions file, set exactly when applied.
        stale: Path of the stale result, or ``None`` when none was supplied.
    """

    status: str
    source_sha256: str | None
    evaluation: str | None
    file: str | None
    stale: str | None

    def __post_init__(self) -> None:
        """Validate the record."""
        if self.status not in EXCEPTIONS_STATUSES:
            _fail(f"exceptions status {_echo(self.status)} is unknown")
        if self.source_sha256 is not None:
            _digest(self.source_sha256, "exceptions source_sha256")
        if (self.source_sha256 is None) != (self.status == EXCEPTIONS_NOT_REQUESTED):
            _fail("exceptions source_sha256 is set exactly when an exceptions file was requested")
        applied = self.status == EXCEPTIONS_APPLIED
        expected = (EVALUATION_PATH, EXCEPTIONS_FILE_PATH) if applied else (None, None)
        if (self.evaluation, self.file) != expected:
            _fail("the evaluation and the exceptions file are in a bundle exactly when applied")
        if self.stale not in ((STALE_PATH, None) if applied else (None,)):
            _fail("a stale result is only in a bundle whose exceptions were applied")

    def to_dict(self) -> dict[str, object]:
        """Return the manifest mapping."""
        return {
            "evaluation": self.evaluation,
            "file": self.file,
            "source_sha256": self.source_sha256,
            "stale": self.stale,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExceptionsRecord:
        """Build the record from its manifest mapping."""
        data = _mapping(value, "manifest exceptions", _EXCEPTIONS_KEYS)
        return cls(
            _text(data["status"], "exceptions status", max_length=32),
            _optional_text(data["source_sha256"], "exceptions source_sha256", max_length=64),
            _optional_text(data["evaluation"], "exceptions evaluation", max_length=64),
            _optional_text(data["file"], "exceptions file", max_length=64),
            _optional_text(data["stale"], "exceptions stale", max_length=64),
        )


def _gate_counts(record: GateRecord) -> None:
    for where, value in (
        ("gate fail", record.fail),
        ("gate error", record.error),
        ("gate waived", record.waived),
    ):
        if not record.counted:
            if value is not None:
                _fail(f"{where} must be null when the gate counted nothing")
        elif isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _fail(f"{where} must be a non-negative integer")


@dataclass(frozen=True)
class GateRecord:
    """Whether and how the result gates of the audit ran before the bundle was written.

    A bundle is only written after the gates were enforced, so ``enforced`` is always
    true; ``deferred`` says that the gates ran in a later play than the scan (the
    deferred.yml and enforce.yml entry points of the audit role), after which the
    evidence was collected.

    Attributes:
        deferred: Whether the gates were deferred and enforced later.
        enforced: Whether the gates were enforced; always true in a bundle.
        enabled: Whether linux_compliance_audit_fail_on_noncompliant was true.
        after_waivers: Whether the gate counted the waived result.
        basis: ``raw`` or ``waived``.
        counted: Whether the run completed, so that the gate counted rules.
        fail: The failed rules the gate counted, or ``None``.
        error: The errored rules the gate counted, or ``None``.
        waived: The waived rules of the counted result, or ``None``.
    """

    deferred: bool
    enforced: bool
    enabled: bool
    after_waivers: bool
    basis: str
    counted: bool
    fail: int | None
    error: int | None
    waived: int | None

    def __post_init__(self) -> None:
        """Validate the record."""
        _flag(self.deferred, "gate deferred")
        _flag(self.enforced, "gate enforced")
        _flag(self.enabled, "gate enabled")
        _flag(self.after_waivers, "gate after_waivers")
        _flag(self.counted, "gate counted")
        if not self.enforced:
            _fail(NOT_ENFORCED)
        if self.basis not in _GATE_BASES:
            _fail(f"gate basis {_echo(self.basis)} is unknown")
        _gate_counts(self)

    def to_dict(self) -> dict[str, object]:
        """Return the manifest mapping."""
        return {
            "decision": {
                "after_waivers": self.after_waivers,
                "basis": self.basis,
                "counted": self.counted,
                "enabled": self.enabled,
                "error": self.error,
                "fail": self.fail,
                "waived": self.waived,
            },
            "deferred": self.deferred,
            "enforced": self.enforced,
        }

    @classmethod
    def from_dict(cls, value: object) -> GateRecord:
        """Build the record from its manifest mapping."""
        data = _mapping(value, "manifest gate", _GATE_KEYS)
        if data["decision"] is None:
            _fail(NOT_ENFORCED)
        decision = _mapping(data["decision"], "manifest gate decision", _DECISION_KEYS)
        return cls.from_values(data["deferred"], data["enforced"], decision)

    @classmethod
    def from_audit(cls, value: object) -> GateRecord:
        """Build the record from ``linux_compliance_audited.gate``."""
        if value is None:
            _fail(
                "linux_compliance_audited has no gate record; collect the evidence after the "
                "result gates of the audit role ran (main, evaluate.yml or enforce.yml)"
            )
        where = "linux_compliance_audited.gate"
        if _mapping(value, where).get("enforced") is False:
            _fail(
                "the result gate of this run was deferred and not enforced yet; run the "
                "enforce.yml entry point of the audit role before collecting "
                "(playbooks/evidence.yml does)"
            )
        data = _mapping(value, where, (*_DECISION_KEYS, "deferred", "enforced"))
        return cls.from_values(data["deferred"], data["enforced"], data)

    @classmethod
    def from_values(
        cls, deferred: object, enforced: object, decision: dict[str, object]
    ) -> GateRecord:
        """Build the record from the two flags and the decision mapping."""
        return cls(
            deferred=cast("bool", deferred),
            enforced=cast("bool", enforced),
            enabled=cast("bool", decision["enabled"]),
            after_waivers=cast("bool", decision["after_waivers"]),
            basis=cast("str", decision["basis"]),
            counted=cast("bool", decision["counted"]),
            fail=cast("int | None", decision["fail"]),
            error=cast("int | None", decision["error"]),
            waived=cast("int | None", decision["waived"]),
        )


@dataclass(frozen=True)
class ManifestParts:
    """The parts of a manifest that come from the controller rather than the scan run.

    Attributes:
        collection_version: Version of the collection that collects the bundle.
        collected_at: Controller time, UTC.
        machine_id: The machine ID from the gathered facts, or ``None``.
    """

    collection_version: str
    collected_at: str
    machine_id: str | None


@dataclass(frozen=True)
class Manifest:
    """The manifest ``bundle.json`` of one evidence bundle.

    Attributes:
        collection_version: Version of the collection that collected the bundle.
        collected_at: Controller time at which the manifest was written, UTC.
        inventory_host: The inventory host name, the controller's name for the host.
        machine_id: The machine ID from the host's gathered facts, or ``None``.
        reported_host: The host identity that the scan run reports (self-asserted).
        run_id: The audit run identifier.
        run_status: The scan run status.
        started_at: Scan start reported by the host.
        finished_at: Scan end reported by the host.
        benchmark_id: The benchmark of the scan run.
        profile_id: The profile of the scan run.
        scanner: Scanner name and version.
        content: Datastream source, content version and SHA-256.
        waivers: Whether and how exceptions were applied.
        gate: Whether the result gates were deferred, and the decision they enforced.
        files: Every file of the bundle except the manifest and the checksums file.
        excluded: The host files that the audit recorded and that were not collected.
        checksums_sha256: SHA-256 of ``SHA256SUMS``.
        checksums_size: Size of ``SHA256SUMS``.
    """

    collection_version: str
    collected_at: str
    inventory_host: str
    machine_id: str | None
    reported_host: model.HostIdentity
    run_id: str
    run_status: model.ScanStatus
    started_at: str
    finished_at: str
    benchmark_id: str
    profile_id: str
    scanner: model.ScannerInfo
    content: model.Provenance
    waivers: ExceptionsRecord
    gate: GateRecord
    files: tuple[BundleFile, ...]
    excluded: tuple[ExcludedFile, ...]
    checksums_sha256: str
    checksums_size: int

    def __post_init__(self) -> None:
        """Validate the manifest and the coupling between its parts."""
        _text(self.collection_version, "collection version", max_length=64, pattern=_VERSION)
        _text(self.collected_at, "collected_at", max_length=20, pattern=_TIMESTAMP)
        _host(self.inventory_host, "host inventory_hostname")
        _optional_text(self.machine_id, "host machine_id", max_length=32, pattern=_MACHINE_ID)
        _text(self.run_id, "run run_id", max_length=64, pattern=_RUN_ID)
        _text(self.started_at, "run started_at", max_length=20, pattern=_TIMESTAMP)
        _text(self.finished_at, "run finished_at", max_length=20, pattern=_TIMESTAMP)
        _xccdf(self.benchmark_id, "run benchmark_id", "benchmark")
        _xccdf(self.profile_id, "run profile_id", "profile")
        paths = [item.path for item in self.files]
        if paths != sorted(set(paths)):
            _fail("manifest files must be unique and sorted by path")
        if SCAN_RUN_PATH not in paths:
            _fail(f"the bundle has no {SCAN_RUN_PATH}")
        documents = {path for path in paths if path in DOCUMENT_PATHS}
        recorded = {
            path
            for path in (self.waivers.evaluation, self.waivers.file, self.waivers.stale)
            if path is not None
        }
        if documents != recorded:
            _fail("manifest files and the exceptions record name different documents")
        sources = [item.source for item in self.excluded]
        if sources != sorted(set(sources)):
            _fail("manifest excluded files must be unique and sorted by source")
        _digest(self.checksums_sha256, "checksums sha256")
        _size(self.checksums_size, "checksums size")

    def file(self, path: str) -> BundleFile | None:
        """Return the entry of ``path``, or ``None`` when the bundle has no such file."""
        for item in self.files:
            if item.path == path:
                return item
        return None

    def to_dict(self) -> dict[str, object]:
        """Return the manifest document."""
        return {
            "checksums": {
                "path": CHECKSUMS_NAME,
                "sha256": self.checksums_sha256,
                "size": self.checksums_size,
            },
            "collected_at": self.collected_at,
            "collection": {"name": COLLECTION_NAME, "version": self.collection_version},
            "content": self.content.to_dict(),
            "exceptions": self.waivers.to_dict(),
            "gate": self.gate.to_dict(),
            "excluded": [item.to_dict() for item in self.excluded],
            "files": [item.to_dict() for item in self.files],
            "host": {
                "inventory_hostname": self.inventory_host,
                "machine_id": self.machine_id,
                "reported": self.reported_host.to_dict(),
            },
            "kind": BUNDLE_KIND,
            "run": {
                "benchmark_id": self.benchmark_id,
                "finished_at": self.finished_at,
                "profile_id": self.profile_id,
                "run_id": self.run_id,
                "started_at": self.started_at,
                "status": self.run_status.value,
            },
            "scanner": self.scanner.to_dict(),
            "schema_version": BUNDLE_SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: object) -> Manifest:
        """Build the manifest from its document, rejecting unknown and missing keys."""
        data = _mapping(value, "manifest", _MANIFEST_KEYS)
        version = data["schema_version"]
        if not isinstance(version, str) or version not in SUPPORTED_BUNDLE_SCHEMA_VERSIONS:
            _fail(f"the manifest has an unsupported schema_version {_echo(version)}")
        if data["kind"] != BUNDLE_KIND:
            _fail(f"the manifest kind must be {BUNDLE_KIND}")
        collection = _mapping(data["collection"], "manifest collection", _COLLECTION_KEYS)
        if collection["name"] != COLLECTION_NAME:
            _fail(f"the manifest collection name must be {COLLECTION_NAME}")
        host = _mapping(data["host"], "manifest host", _HOST_KEYS)
        run = _mapping(data["run"], "manifest run", _RUN_KEYS)
        checksums = _mapping(data["checksums"], "manifest checksums", _CHECKSUMS_KEYS)
        if checksums["path"] != CHECKSUMS_NAME:
            _fail(f"the manifest checksums path must be {CHECKSUMS_NAME}")
        try:
            reported = model.HostIdentity.from_dict(host["reported"])
            scanner = model.ScannerInfo.from_dict(data["scanner"])
            content = model.Provenance.from_dict(data["content"])
            status = model.ScanStatus(run["status"])
        except (model.ModelError, ValueError) as error:
            message = f"the manifest is invalid: {error}"
            raise EvidenceError(message) from None
        return cls(
            collection_version=_text(collection["version"], "collection version", max_length=64),
            collected_at=_text(data["collected_at"], "collected_at", max_length=20),
            inventory_host=_host(host["inventory_hostname"], "host inventory_hostname"),
            machine_id=_optional_text(host["machine_id"], "host machine_id", max_length=32),
            reported_host=reported,
            run_id=_text(run["run_id"], "run run_id", max_length=64),
            run_status=status,
            started_at=_text(run["started_at"], "run started_at", max_length=20),
            finished_at=_text(run["finished_at"], "run finished_at", max_length=20),
            benchmark_id=_text(run["benchmark_id"], "run benchmark_id", max_length=256),
            profile_id=_text(run["profile_id"], "run profile_id", max_length=256),
            scanner=scanner,
            content=content,
            waivers=ExceptionsRecord.from_dict(data["exceptions"]),
            gate=GateRecord.from_dict(data["gate"]),
            files=tuple(
                BundleFile.from_dict(item)
                for item in _list(data["files"], "manifest files", len(BUNDLE_PATHS))
            ),
            excluded=tuple(
                ExcludedFile.from_dict(item)
                for item in _list(data["excluded"], "manifest excluded", MAX_HOST_FILES)
            ),
            checksums_sha256=_digest(checksums["sha256"], "checksums sha256"),
            checksums_size=_size(checksums["size"], "checksums size"),
        )


def _xccdf(value: object, where: str, kind: str) -> str:
    try:
        return model.validate_xccdf_id(value, where, kind)
    except model.ModelError as error:
        raise EvidenceError(str(error)) from None


def parse_manifest(data: bytes) -> Manifest:
    """Parse and validate ``bundle.json``.

    Raises:
        EvidenceError: If the document is oversized, not strict JSON or not a valid manifest.
    """
    if len(data) > MAX_MANIFEST_BYTES:
        _fail(f"{MANIFEST_NAME} is larger than {MAX_MANIFEST_BYTES} bytes")
    return Manifest.from_dict(load_json(data, MANIFEST_NAME))


def checksums_text(files: tuple[BundleFile, ...]) -> str:
    """Return ``SHA256SUMS`` for ``files``, in the format that ``sha256sum --check`` reads."""
    return "".join(f"{item.sha256}  {item.path}\n" for item in sorted(files, key=_path_of))


def _path_of(item: BundleFile) -> str:
    return item.path


@dataclass(frozen=True)
class HostFile:
    """A file of the run directory that the bundle collects.

    Attributes:
        source: The absolute path on the host.
        path: The path of the copy in the bundle.
        kind: The kind of the copy.
        sha256: The SHA-256 that the audit recorded on the host.
        size: The size that the audit recorded on the host.
    """

    source: str
    path: str
    kind: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "source": self.source,
        }


@dataclass(frozen=True)
class BundlePlan:
    """What the bundle of one audit run will hold.

    Attributes:
        host: The inventory host name.
        run_id: The audit run identifier.
        run: The raw scan run that the audit published.
        files: The host files to fetch, sorted by bundle path.
        excluded: The host files that are recorded but not collected.
        exceptions_status: The status of the exceptions of the run.
        exceptions_source: The SHA-256 of the exceptions file, or ``None``.
        exceptions_file: The controller path of the exceptions file, or ``None``.
        evaluation: The evaluation document when the exceptions were applied.
        gate: The result gate record of the audit, which must have been enforced.
    """

    host: str
    run_id: str
    run: model.ScanRun
    files: tuple[HostFile, ...]
    excluded: tuple[ExcludedFile, ...]
    exceptions_status: str
    exceptions_source: str | None
    exceptions_file: str | None
    evaluation: object
    gate: GateRecord

    @property
    def applied(self) -> bool:
        """Whether exceptions were applied, so the bundle carries the evaluation."""
        return self.exceptions_status == EXCEPTIONS_APPLIED

    @property
    def directory(self) -> str:
        """The bundle directory relative to the evidence output directory."""
        return f"{self.host}/{self.run_id}"

    def directories(self) -> list[str]:
        """Return the subdirectories of the bundle, parents first."""
        names = {"raw"}
        if any(item.path.startswith("raw/scan/") for item in self.files):
            names.add("raw/scan")
        if self.applied:
            names.add("exceptions")
        return sorted(names)

    def to_dict(self) -> dict[str, object]:
        """Return the plan for the role: directories, files to fetch and exclusions."""
        return {
            "applied": self.applied,
            "directories": self.directories(),
            "directory": self.directory,
            "excluded": [item.to_dict() for item in self.excluded],
            "exceptions_file": self.exceptions_file,
            "fetch": [item.to_dict() for item in self.files],
            "host": self.host,
            "run_id": self.run_id,
        }


def _run_directory(evidence: dict[str, object], run_id: str) -> str:
    directory = _text(evidence.get("directory"), "evidence.directory", max_length=MAX_PATH_LENGTH)
    if (
        not directory.startswith("/")
        or os.path.normpath(directory) != directory
        or directory.startswith("//")
        or PurePosixPath(directory).name != run_id
    ):
        _fail(
            f"evidence.directory {_echo(directory)} must be an absolute, normalised path whose "
            f"last component is the run ID {run_id}"
        )
    return directory


def _host_file(
    value: object, directory: str, withheld: frozenset[str]
) -> tuple[HostFile | None, ExcludedFile | None]:
    data = _mapping(value, "evidence file", _AUDIT_FILE_KEYS)
    path = _source(data["path"], "evidence file path")
    kind = _text(data["kind"], "evidence file kind", max_length=64, pattern=r"[a-z_]+")
    digest = _digest(data["sha256"], f"evidence file {path} sha256")
    size = _size(data["size"], f"evidence file {path} size")
    prefix = f"{directory}/"
    if not path.startswith(prefix) or os.path.normpath(path) != path:
        _fail(f"evidence file {_echo(path)} is not inside the run directory {directory}")
    name = path[len(prefix) :]
    source = HOST_SOURCES.get(name)
    if source is None:
        return None, ExcludedFile(path, kind, digest, size, REASON_NOT_ALLOW_LISTED)
    if source.audit_kind != kind:
        _fail(f"evidence file {name} must have kind {source.audit_kind}, not {_echo(kind)}")
    if source.kind in withheld:
        return None, ExcludedFile(path, kind, digest, size, REASON_ARF_NOT_REQUESTED)
    return HostFile(path, source.path, source.kind, digest, size), None


def _exceptions_of(
    audited: dict[str, object], host: str
) -> tuple[str, str | None, str | None, object]:
    value = audited.get("exceptions")
    if value is None:
        return EXCEPTIONS_NOT_REQUESTED, None, None, None
    data = _mapping(value, "linux_compliance_audited.exceptions")
    status = data.get("status")
    if not isinstance(status, str) or status not in EXCEPTIONS_STATUSES:
        _fail(f"linux_compliance_audited.exceptions.status {_echo(status)} is unknown")
    applied = _flag(data.get("applied"), "linux_compliance_audited.exceptions.applied")
    if applied != (status == EXCEPTIONS_APPLIED):
        _fail("linux_compliance_audited.exceptions.applied contradicts its status")
    if status == EXCEPTIONS_NOT_REQUESTED:
        return status, None, None, None
    source = _digest(data.get("source_sha256"), "linux_compliance_audited.exceptions.source_sha256")
    if not applied:
        return status, source, None, None
    path = _source(data.get("file"), "linux_compliance_audited.exceptions.file")
    if not path.startswith("/"):
        _fail("linux_compliance_audited.exceptions.file must be an absolute controller path")
    evaluation = _mapping(data.get("evaluation"), "linux_compliance_audited.exceptions.evaluation")
    target = _mapping(evaluation.get("target"), "the evaluation target")
    if target.get("host") != host:
        _fail(f"the evaluation was made for {_echo(target.get('host'))}, not for {host}")
    if evaluation.get("source_sha256") != source:
        _fail(
            "the evaluation names another exceptions file than linux_compliance_audited.exceptions"
        )
    return status, source, path, evaluation


def plan_bundle(audited: object, host: object, include_arf: object) -> BundlePlan:
    """Decide which host files the bundle of an audit run collects.

    Args:
        audited: The fact ``linux_compliance_audited`` that the audit role published.
        host: The inventory host name, normally ``inventory_hostname``.
        include_arf: Whether to collect the ARF results, which hold the system
            characteristics that OVAL collected and can contain credential material.

    Returns:
        The plan.

    Raises:
        EvidenceError: If the fact is malformed, no evidence was written, a file is
            outside the run directory, a kind is wrong or the scan run file is missing.
    """
    name = _host(host, "the inventory host name")
    arf = _flag(include_arf, "include_arf")
    data = _mapping(audited, "linux_compliance_audited")
    if data.get("evidence_written") is not True:
        _fail(
            "no evidence was written on the host (check mode, or no scan ran); "
            "there is nothing to collect"
        )
    run_id, run = _audited_run(data)
    evidence = _mapping(data.get("evidence"), "linux_compliance_audited.evidence")
    collected, excluded = _host_files(
        evidence,
        _run_directory(evidence, run_id),
        frozenset() if arf else frozenset({KIND_ARF}),
    )
    status, source, path, evaluation = _exceptions_of(data, name)
    return BundlePlan(
        host=name,
        run_id=run_id,
        run=run,
        files=collected,
        excluded=excluded,
        exceptions_status=status,
        exceptions_source=source,
        exceptions_file=path,
        evaluation=evaluation,
        gate=GateRecord.from_audit(data.get("gate")),
    )


def _audited_run(data: dict[str, object]) -> tuple[str, model.ScanRun]:
    run_id = _text(
        data.get("run_id"), "linux_compliance_audited.run_id", max_length=64, pattern=_RUN_ID
    )
    try:
        run = exceptions.load_scan_run(data.get("scan_run"))
    except exceptions.ExceptionsError as error:
        message = f"linux_compliance_audited.scan_run is invalid: {error}"
        raise EvidenceError(message) from None
    if run.run_id != run_id:
        _fail("linux_compliance_audited.scan_run belongs to another run ID")
    if data.get("run_status") != run.status.value:
        _fail("linux_compliance_audited.run_status contradicts the scan run")
    return run_id, run


def _host_files(
    evidence: dict[str, object], directory: str, withheld: frozenset[str]
) -> tuple[tuple[HostFile, ...], tuple[ExcludedFile, ...]]:
    items = _list(evidence.get("files"), "linux_compliance_audited.evidence.files", MAX_HOST_FILES)
    collected: list[HostFile] = []
    excluded: list[ExcludedFile] = []
    for item in items:
        kept, dropped = _host_file(item, directory, withheld)
        if kept is not None:
            collected.append(kept)
        if dropped is not None:
            excluded.append(dropped)
    paths = [entry.path for entry in collected]
    sources = [entry.source for entry in excluded]
    if len(set(paths)) != len(paths) or len(set(sources)) != len(sources):
        _fail("linux_compliance_audited.evidence.files lists a file twice")
    if SCAN_RUN_PATH not in paths:
        _fail("linux_compliance_audited.evidence.files has no scan-run.json")
    return (
        tuple(sorted(collected, key=lambda entry: entry.path)),
        tuple(sorted(excluded, key=lambda entry: entry.source)),
    )


def _uid(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail("controller_uid must be a non-negative integer")
    return value


def _observed(observed: object, path: str, controller_uid: int) -> dict[str, object]:
    stats = _mapping(observed, "the observed files")
    if path not in stats:
        _fail(f"{path} was not found in the bundle on the controller")
    data = _mapping(stats[path], f"the controller stat of {path}")
    missing = [key for key in _STAT_KEYS if key not in data]
    if missing or data.get("isreg") is not True or data.get("islnk") is not False:
        _fail(f"{path} in the bundle is not a regular file")
    if data.get("mode") != _FILE_MODE:
        _fail(f"{path} in the bundle has mode {_echo(data.get('mode'))}, not {_FILE_MODE}")
    if data.get("uid") != controller_uid:
        _fail(f"{path} in the bundle is not owned by the controller user")
    return data


def _check_received(item: HostFile, observed: object, controller_uid: int) -> None:
    data = _observed(observed, item.path, controller_uid)
    if data.get("checksum") != item.sha256 or data.get("size") != item.size:
        _fail(
            f"checksum mismatch for {item.source}: the audit recorded SHA-256 {item.sha256} "
            f"({item.size} bytes) on the host, the controller received "
            f"{_echo(data.get('checksum'))} ({_echo(data.get('size'))} bytes); "
            "the bundle was not written"
        )


def _stale_document(stale: object, plan: BundlePlan) -> dict[str, object] | None:
    if stale is None or stale == {}:
        return None
    data = _mapping(stale, STALE_SOURCE, STALE_KEYS)
    computed = _flag(data["computed"], "stale computed")
    complete = _flag(data["complete"], "stale complete")
    if not computed:
        _fail(f"{STALE_SOURCE} was not computed")
    if data["source_sha256"] != plan.exceptions_source:
        _fail(f"{STALE_SOURCE} was computed from another exceptions file")
    hosts: dict[str, list[str]] = {}
    for key in ("target_hosts", "audited_hosts", "evaluated_hosts", "not_evaluated_hosts"):
        names = [
            _host(name, f"stale {key}") for name in _list(data[key], f"stale {key}", MAX_HOSTS)
        ]
        hosts[key] = names
    if plan.host not in hosts["evaluated_hosts"]:
        _fail(f"{STALE_SOURCE} does not include the evaluation of {plan.host}")
    unmatched = [
        _text(item, "stale unmatched", max_length=exceptions.MAX_ID_LENGTH, pattern=_EXCEPTION_ID)
        for item in _list(data["unmatched"], "stale unmatched", exceptions.MAX_EXCEPTIONS)
    ]
    if data["stale"] != (unmatched if complete else None):
        _fail("stale must equal unmatched when coverage is complete and be null otherwise")
    result: dict[str, object] = dict(hosts)
    result.update(
        {
            "complete": complete,
            "computed": computed,
            "source_sha256": plan.exceptions_source,
            "stale": unmatched if complete else None,
            "unmatched": unmatched,
        }
    )
    return {"kind": STALE_KIND, "result": result, "schema_version": STALE_SCHEMA_VERSION}


def _evaluation_text(plan: BundlePlan, exceptions_text: object) -> tuple[str, str]:
    if not isinstance(exceptions_text, str):
        _fail("the exceptions file text is required because exceptions were applied")
    if sha256_hex(exceptions_text.encode("utf-8")) != plan.exceptions_source:
        _fail(
            "the exceptions file on the controller is no longer the file that was applied "
            "(its SHA-256 changed); the bundle was not written"
        )
    try:
        verified = exceptions.verify_evaluation(plan.evaluation, exceptions_text)
    except exceptions.ExceptionsError as error:
        message = f"the evaluation does not verify: {error}"
        raise EvidenceError(message) from None
    if model.dumps(exceptions.unmarked(verified.run)) != model.dumps(plan.run):
        _fail("the evaluation was not made from the raw scan run of this audit")
    return canonical_json(verified.to_dict()), exceptions_text


def _document(path: str, text: str, source: str) -> BundleFile:
    data = text.encode("utf-8")
    return BundleFile(path, DOCUMENT_PATHS[path], sha256_hex(data), len(data), source)


@dataclass(frozen=True)
class Collected:
    """What the role observed on the controller after fetching the host files.

    Attributes:
        host: The inventory host name.
        include_arf: Whether the ARF results were collected.
        observed: Bundle path to the controller ``stat`` result of each fetched file
            (``checksum`` as SHA-256, ``size``, ``mode``, ``uid``, ``isreg``, ``islnk``).
        scan_run_text: The text of the fetched ``scan-run.json``.
        exceptions_text: The text of the exceptions file, read byte for byte, or ``None``.
        stale: The fact ``linux_compliance_audit_stale_exceptions``, or an empty mapping.
        machine_id: The machine ID from the gathered facts of the host, or ``None``.
        collection_version: The version of this collection.
        controller_uid: The user ID of the controller user that owns the bundle.
    """

    host: object
    include_arf: object
    observed: object
    scan_run_text: object
    exceptions_text: object
    stale: object
    machine_id: object
    collection_version: object
    controller_uid: object

    @classmethod
    def from_dict(cls, value: object) -> Collected:
        """Build the record from the mapping the role passes, rejecting unknown and missing keys."""
        data = _mapping(value, "the collected evidence", _COLLECTED_KEYS)
        return cls(
            host=data["host"],
            include_arf=data["include_arf"],
            observed=data["observed"],
            scan_run_text=data["scan_run_text"],
            exceptions_text=data["exceptions_text"],
            stale=data["stale"],
            machine_id=data["machine_id"],
            collection_version=data["collection_version"],
            controller_uid=data["controller_uid"],
        )


def build_documents(audited: object, collected: Collected, now: datetime) -> dict[str, object]:
    """Check the fetched files and return the documents of the bundle.

    The plan is computed again from ``audited``, so nothing the role passed between
    tasks is trusted. Every fetched file must be a regular ``0600`` file of the
    controller user with exactly the SHA-256 and size that the audit recorded on the
    host. ``scan-run.json`` must be the scan run of the fact. When exceptions were
    applied, the exceptions file must still have the applied SHA-256, the evaluation
    must verify against it and must have been made from the raw scan run.

    Returns:
        ``documents`` (bundle path to text, written before the manifest, including
        ``SHA256SUMS``), ``manifest`` (the text of ``bundle.json``),
        ``manifest_sha256`` and ``expected`` (bundle path to SHA-256 and size of every
        file except the manifest).

    Raises:
        EvidenceError: On any mismatch; nothing of the bundle may then be kept.
    """
    plan = plan_bundle(audited, collected.host, collected.include_arf)
    controller_uid = _uid(collected.controller_uid)
    for item in plan.files:
        _check_received(item, collected.observed, controller_uid)
    _check_scan_run_text(plan, collected.scan_run_text)
    machine = _optional_text(collected.machine_id, "machine_id", max_length=32, pattern=_MACHINE_ID)
    if machine is not None and plan.run.host.machine_id not in (None, machine):
        _fail("the machine ID of the gathered facts differs from the one in the scan run")
    documents, files, stale_path = _exception_documents(plan, collected)
    ordered = tuple(sorted(files, key=_path_of))
    documents[CHECKSUMS_NAME] = checksums_text(ordered)
    manifest = _manifest(
        plan,
        ManifestParts(
            cast("str", collected.collection_version),
            now.astimezone(timezone.utc).strftime(model.TIMESTAMP_FORMAT),
            machine,
        ),
        ordered,
        stale_path,
    )
    text = canonical_json(manifest.to_dict())
    expected: dict[str, object] = {
        item.path: {"sha256": item.sha256, "size": item.size} for item in ordered
    }
    expected[CHECKSUMS_NAME] = {
        "sha256": manifest.checksums_sha256,
        "size": manifest.checksums_size,
    }
    return {
        "documents": documents,
        "expected": expected,
        "manifest": text,
        "manifest_sha256": sha256_hex(text.encode("utf-8")),
    }


def _check_scan_run_text(plan: BundlePlan, scan_run_text: object) -> None:
    if not isinstance(scan_run_text, str):
        _fail("the text of scan-run.json is required")
    recorded = next(item for item in plan.files if item.path == SCAN_RUN_PATH)
    if sha256_hex(scan_run_text.encode("utf-8")) != recorded.sha256:
        _fail("scan-run.json read on the controller is not the file whose digest was checked")
    try:
        fetched = model.loads(scan_run_text)
    except model.ModelError as error:
        message = f"scan-run.json is not a valid scan run: {error}"
        raise EvidenceError(message) from None
    if model.dumps(fetched) != model.dumps(plan.run):
        _fail("scan-run.json is not the scan run of linux_compliance_audited")


def _exception_documents(
    plan: BundlePlan, collected: Collected
) -> tuple[dict[str, str], list[BundleFile], str | None]:
    files = [
        BundleFile(item.path, item.kind, item.sha256, item.size, item.source) for item in plan.files
    ]
    documents: dict[str, str] = {}
    if not plan.applied:
        return documents, files, None
    evaluation, text = _evaluation_text(plan, collected.exceptions_text)
    documents[EVALUATION_PATH] = evaluation
    documents[EXCEPTIONS_FILE_PATH] = text
    files.append(_document(EVALUATION_PATH, evaluation, EVALUATION_SOURCE))
    files.append(_document(EXCEPTIONS_FILE_PATH, text, cast("str", plan.exceptions_file)))
    stale_document = _stale_document(collected.stale, plan)
    if stale_document is None:
        return documents, files, None
    documents[STALE_PATH] = canonical_json(stale_document)
    files.append(_document(STALE_PATH, documents[STALE_PATH], STALE_SOURCE))
    return documents, files, STALE_PATH


def _manifest(
    plan: BundlePlan, parts: ManifestParts, ordered: tuple[BundleFile, ...], stale_path: str | None
) -> Manifest:
    sums = checksums_text(ordered).encode("utf-8")
    run = plan.run
    return Manifest(
        collection_version=parts.collection_version,
        collected_at=parts.collected_at,
        inventory_host=plan.host,
        machine_id=parts.machine_id,
        reported_host=run.host,
        run_id=plan.run_id,
        run_status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        benchmark_id=run.benchmark_id,
        profile_id=run.profile_id,
        scanner=run.scanner,
        content=run.content,
        waivers=ExceptionsRecord(
            plan.exceptions_status,
            plan.exceptions_source,
            EVALUATION_PATH if plan.applied else None,
            EXCEPTIONS_FILE_PATH if plan.applied else None,
            stale_path,
        ),
        gate=plan.gate,
        files=ordered,
        excluded=plan.excluded,
        checksums_sha256=sha256_hex(sums),
        checksums_size=len(sums),
    )


def check_host_files(
    audited: object, host: object, include_arf: object, observed: object
) -> list[str]:
    """Check the host files of a bundle on the host, before anything is transferred.

    The plan is computed again from ``audited``. Each planned file must exist on the
    host as a regular file that is not a symbolic link (``stat`` with ``follow: false``)
    and must have exactly the size that the audit recorded, which the plan bounds by
    :data:`MAX_FILE_BYTES`. A symbolic link would otherwise be followed by the fetch,
    as root, and an oversized file would be transferred before its digest is compared.

    Args:
        audited: The fact ``linux_compliance_audited``.
        host: The inventory host name.
        include_arf: Whether the ARF results are collected.
        observed: Bundle path to the result of ``ansible.builtin.stat`` on the host.

    Returns:
        The checked bundle paths, sorted.

    Raises:
        EvidenceError: If a file is missing, a symbolic link, not a regular file or has
            another size than the audit recorded.
    """
    plan = plan_bundle(audited, host, include_arf)
    stats = _mapping(observed, "the files observed on the host")
    for item in plan.files:
        if item.path not in stats:
            _fail(f"{item.source} was not inspected on the host")
        data = _mapping(stats[item.path], f"the host stat of {item.source}")
        if data.get("exists") is not True:
            _fail(f"{item.source} does not exist on the host; nothing was fetched")
        if data.get("islnk") is not False:
            _fail(f"{item.source} is a symbolic link on the host; it is not followed or fetched")
        if data.get("isreg") is not True:
            _fail(f"{item.source} is not a regular file on the host; it is not fetched")
        if data.get("size") != item.size:
            _fail(
                f"{item.source} has {_echo(data.get('size'))} bytes on the host, but the audit "
                f"recorded {item.size}; it is not fetched"
            )
    return sorted(item.path for item in plan.files)


def check_written(expected: object, observed: object, controller_uid: object) -> list[str]:
    """Check every written file of a bundle against the digests the manifest will record.

    Args:
        expected: The ``expected`` mapping of :func:`build_documents`.
        observed: Bundle path to the controller ``stat`` result of each file.
        controller_uid: The user ID of the controller user.

    Returns:
        The checked paths, sorted.

    Raises:
        EvidenceError: If a file is missing, not a regular ``0600`` file of the
            controller user, or differs from the expected SHA-256 or size.
    """
    uid = _uid(controller_uid)
    wanted = _mapping(expected, "the expected files")
    for path in sorted(wanted):
        entry = _mapping(wanted[path], f"the expected entry of {path}", ("sha256", "size"))
        data = _observed(observed, path, uid)
        if data.get("checksum") != entry["sha256"] or data.get("size") != entry["size"]:
            _fail(f"{path} in the bundle differs from what was written; the bundle was not kept")
    return sorted(wanted)
