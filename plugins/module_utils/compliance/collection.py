"""The evidence collection summary of one run of ``playbooks/evidence.yml`` (FREES-142).

A fleet report built from evidence bundles alone cannot see the target hosts that have no
bundle: hosts that were unreachable, limited out, failed before any evidence was written or
whose collection failed. The ``evidence`` role therefore writes one collection summary per
run next to the bundles, ``collection-<collection_id>.json``. It names every target host of
the run with its status and, for each collected host, the run ID and the SHA-256 of its
manifest ``bundle.json``.

:func:`summarize` classifies the target hosts from what the playbook observed and builds the
document; :func:`parse_collection` reads one back for the reporting package. The target
hosts are the inventory hosts of the run's host pattern, so they come from the controller's
inventory, never from a managed host. The summary is not signed (ADR 0018 is proposed): it
names the hosts a report must account for and binds each collected bundle to its digest,
and whoever can write the evidence directory can rewrite it consistently.

The module uses only the Python standard library and runs on Python 3.9.
"""

from __future__ import annotations

import os.path
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Final, NoReturn, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
    exceptions,
    model,
)

COLLECTION_SCHEMA_VERSION: Final[str] = "1.0"
SUPPORTED_COLLECTION_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({COLLECTION_SCHEMA_VERSION})
COLLECTION_KIND: Final[str] = "freesecdev.linux_compliance.evidence_collection"
FILE_PREFIX: Final[str] = "collection-"
FILE_SUFFIX: Final[str] = ".json"
COLLECTION_ID_FORMAT: Final[str] = "%Y%m%dT%H%M%S.%fZ"

COLLECTED: Final[str] = "collected"
UNREACHABLE: Final[str] = "unreachable"
LIMITED_OUT: Final[str] = "limited_out"
NO_AUDIT_RESULT: Final[str] = "no_audit_result"
NO_EVIDENCE_WRITTEN: Final[str] = "no_evidence_written"
COLLECTION_FAILED: Final[str] = "collection_failed"
HOST_STATUSES: Final[tuple[str, ...]] = (
    COLLECTED,
    UNREACHABLE,
    LIMITED_OUT,
    NO_AUDIT_RESULT,
    NO_EVIDENCE_WRITTEN,
    COLLECTION_FAILED,
)
MAX_HOSTS: Final[int] = evidence.MAX_HOSTS
MAX_ECHO: Final[int] = 64

RUN_ID_PATTERN: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
COLLECTION_ID_PATTERN: Final[str] = r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z"
_TIMESTAMP: Final[str] = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
_SHA256: Final[str] = r"[0-9a-f]{64}"
_VERSION: Final[str] = r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?"
_DOCUMENT_KEYS: Final[tuple[str, ...]] = (
    "collected_at",
    "collection",
    "collection_id",
    "hosts",
    "kind",
    "schema_version",
)
_COLLECTION_KEYS: Final[tuple[str, ...]] = ("name", "version")
_HOST_KEYS: Final[tuple[str, ...]] = ("bundle", "inventory_hostname", "status")
_BUNDLE_KEYS: Final[tuple[str, ...]] = ("manifest_sha256", "run_id")
_OBSERVED_KEYS: Final[tuple[str, ...]] = (
    "audited",
    "bundles",
    "collection_version",
    "evidence_written",
    "output_dir",
    "play_hosts",
    "reached",
    "targets",
)
BUNDLE_FACT_KEYS: Final[tuple[str, ...]] = (
    "directory",
    "exceptions_applied",
    "excluded",
    "files",
    "manifest_sha256",
    "run_id",
)


class CollectionError(ValueError):
    """Raised when a collection summary cannot be built or does not validate."""


def _fail(message: str) -> NoReturn:
    raise CollectionError(message)


def _echo(value: object) -> str:
    return repr(str(value)[:MAX_ECHO])


def _object(value: object, where: str, keys: tuple[str, ...]) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{where} must be a mapping")
    data = cast("dict[object, object]", value)
    result = {str(key): item for key, item in data.items()}
    if len(result) != len(data) or sorted(result) != sorted(keys):
        _fail(f"{where} must have exactly the keys {', '.join(sorted(keys))}")
    return result


def _items(value: object, where: str) -> list[object]:
    if not isinstance(value, list) or len(cast("list[object]", value)) > MAX_HOSTS:
        _fail(f"{where} must be a list of at most {MAX_HOSTS} items")
    return cast("list[object]", value)


def _text(value: object, where: str, *, max_length: int, pattern: str) -> str:
    try:
        return model.validate_text(value, where, max_length=max_length, pattern=pattern)
    except model.ModelError as error:
        raise CollectionError(str(error)) from None


def _host(value: object, where: str) -> str:
    return _text(
        value, where, max_length=exceptions.MAX_HOST_LENGTH, pattern=exceptions.HOST_PATTERN
    )


def _hosts(value: object, where: str) -> tuple[str, ...]:
    hosts = tuple(_host(item, f"{where} entry") for item in _items(value, where))
    if len(set(hosts)) != len(hosts):
        _fail(f"{where} names a host twice")
    return hosts


def _absolute(value: object, where: str) -> str:
    path = _text(value, where, max_length=evidence.MAX_PATH_LENGTH, pattern=r"/.*")
    if path == "/" or path != os.path.normpath(path) or path.startswith("//"):
        _fail(f"{where} must be a normalised absolute path other than /")
    return path


@dataclass(frozen=True)
class CollectedBundle:
    """The bundle of a collected host.

    Attributes:
        run_id: The audit run ID, the last component of the bundle directory.
        manifest_sha256: SHA-256 of the bundle's ``bundle.json``.
    """

    run_id: str
    manifest_sha256: str

    def __post_init__(self) -> None:
        """Validate the run ID and the digest."""
        _text(self.run_id, "bundle run_id", max_length=64, pattern=RUN_ID_PATTERN)
        _text(self.manifest_sha256, "bundle manifest_sha256", max_length=64, pattern=_SHA256)

    def to_dict(self) -> dict[str, object]:
        """Return the document form."""
        return {"manifest_sha256": self.manifest_sha256, "run_id": self.run_id}

    @classmethod
    def from_fields(cls, fields: dict[str, object]) -> CollectedBundle:
        """Build the bundle from a mapping that has ``run_id`` and ``manifest_sha256``."""
        return cls(
            run_id=_text(fields["run_id"], "bundle run_id", max_length=64, pattern=RUN_ID_PATTERN),
            manifest_sha256=_text(
                fields["manifest_sha256"], "bundle manifest_sha256", max_length=64, pattern=_SHA256
            ),
        )


@dataclass(frozen=True)
class TargetHost:
    """One target host of the run and what became of its evidence.

    Attributes:
        inventory_host: The controller's name for the host.
        status: One of :data:`HOST_STATUSES`.
        bundle: The collected bundle; set exactly when the status is ``collected``.
    """

    inventory_host: str
    status: str
    bundle: CollectedBundle | None

    def __post_init__(self) -> None:
        """Validate the host name and the coupling between status and bundle."""
        _host(self.inventory_host, "host inventory_hostname")
        if self.status not in HOST_STATUSES:
            _fail(f"host status {_echo(self.status)} is unknown")
        if (self.status == COLLECTED) != (self.bundle is not None):
            _fail(f"host {self.inventory_host} must have a bundle exactly when it was collected")

    def to_dict(self) -> dict[str, object]:
        """Return the document form."""
        return {
            "bundle": None if self.bundle is None else self.bundle.to_dict(),
            "inventory_hostname": self.inventory_host,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, value: object) -> TargetHost:
        """Build a target host from its document, rejecting unknown and missing keys."""
        data = _object(value, "collection host", _HOST_KEYS)
        bundle = None
        if data["bundle"] is not None:
            bundle = CollectedBundle.from_fields(
                _object(data["bundle"], "collection host bundle", _BUNDLE_KEYS)
            )
        return cls(
            inventory_host=_host(data["inventory_hostname"], "host inventory_hostname"),
            status=_text(data["status"], "host status", max_length=32, pattern=r"[a-z_]+"),
            bundle=bundle,
        )


@dataclass(frozen=True)
class Collection:
    """The collection summary of one run.

    Attributes:
        collection_id: Controller time at which the summary was built, as an identifier.
        collected_at: The same time as a UTC timestamp.
        collection_version: Version of the collection that wrote the summary.
        hosts: Every target host of the run, sorted by name.
    """

    collection_id: str
    collected_at: str
    collection_version: str
    hosts: tuple[TargetHost, ...]

    def __post_init__(self) -> None:
        """Validate the identity and the host list."""
        _text(self.collection_id, "collection_id", max_length=23, pattern=COLLECTION_ID_PATTERN)
        _text(self.collected_at, "collected_at", max_length=20, pattern=_TIMESTAMP)
        _text(self.collection_version, "collection version", max_length=64, pattern=_VERSION)
        try:
            instant = datetime.strptime(self.collection_id, COLLECTION_ID_FORMAT).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            _fail("collection_id is not a valid controller time")
        if self.collected_at != instant.strftime(model.TIMESTAMP_FORMAT):
            _fail("collected_at must be the time of the collection_id")
        names = [host.inventory_host for host in self.hosts]
        if not names:
            _fail("a collection summary names at least one target host")
        if len(names) > MAX_HOSTS:
            _fail(f"a collection summary names at most {MAX_HOSTS} target hosts")
        if names != sorted(set(names)):
            _fail("collection hosts must be unique and sorted by inventory_hostname")

    @property
    def file_name(self) -> str:
        """Return the file name of the summary, ``collection-<collection_id>.json``."""
        return f"{FILE_PREFIX}{self.collection_id}{FILE_SUFFIX}"

    def to_dict(self) -> dict[str, object]:
        """Return the document."""
        return {
            "collected_at": self.collected_at,
            "collection": {"name": evidence.COLLECTION_NAME, "version": self.collection_version},
            "collection_id": self.collection_id,
            "hosts": [host.to_dict() for host in self.hosts],
            "kind": COLLECTION_KIND,
            "schema_version": COLLECTION_SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: object) -> Collection:
        """Build the summary from its document, rejecting unknown and missing keys."""
        data = _object(value, "collection summary", _DOCUMENT_KEYS)
        version = data["schema_version"]
        if not isinstance(version, str) or version not in SUPPORTED_COLLECTION_SCHEMA_VERSIONS:
            _fail(f"the collection summary has an unsupported schema_version {_echo(version)}")
        if data["kind"] != COLLECTION_KIND:
            _fail(f"the collection summary kind must be {COLLECTION_KIND}")
        collection = _object(data["collection"], "collection summary collection", _COLLECTION_KEYS)
        if collection["name"] != evidence.COLLECTION_NAME:
            _fail(f"the collection summary collection name must be {evidence.COLLECTION_NAME}")
        return cls(
            collection_id=_text(
                data["collection_id"], "collection_id", max_length=23, pattern=COLLECTION_ID_PATTERN
            ),
            collected_at=_text(
                data["collected_at"], "collected_at", max_length=20, pattern=_TIMESTAMP
            ),
            collection_version=_text(
                collection["version"], "collection version", max_length=64, pattern=_VERSION
            ),
            hosts=tuple(
                TargetHost.from_dict(item) for item in _items(data["hosts"], "collection hosts")
            ),
        )


def parse_collection(data: bytes) -> Collection:
    """Parse and validate the bytes of a collection summary.

    Raises:
        CollectionError: If the bytes are not strict JSON or not a valid summary.
    """
    try:
        document = evidence.load_json(data, "the collection summary")
    except evidence.EvidenceError as error:
        raise CollectionError(str(error)) from None
    return Collection.from_dict(document)


def _status(
    host: str,
    observed: dict[str, frozenset[str]],
    play_hosts: frozenset[str] | None,
    collected: dict[str, CollectedBundle],
) -> str:
    if host in collected:
        return COLLECTED
    if play_hosts is not None and host not in play_hosts:
        return LIMITED_OUT
    if play_hosts is not None and host not in observed["reached"]:
        return UNREACHABLE
    if host not in observed["audited"]:
        return NO_AUDIT_RESULT
    if host not in observed["evidence_written"]:
        return NO_EVIDENCE_WRITTEN
    return COLLECTION_FAILED


def _bundles(value: object, targets: frozenset[str]) -> tuple[dict[str, CollectedBundle], str]:
    if not isinstance(value, dict):
        _fail("bundles must be a mapping")
    facts = cast("dict[object, object]", value)
    collected: dict[str, CollectedBundle] = {}
    roots: set[str] = set()
    for name, fact in facts.items():
        host = _host(name, "bundles key")
        if host not in targets:
            _fail(f"bundles names a host that is not a target host: {_echo(host)}")
        data = _object(fact, f"the bundle of {host}", BUNDLE_FACT_KEYS)
        bundle = CollectedBundle.from_fields(data)
        directory = _absolute(data["directory"], f"the bundle directory of {host}")
        root = str(PurePosixPath(directory).parent.parent)
        if root == "/" or directory != f"{root}/{host}/{bundle.run_id}":
            _fail(f"the bundle directory of {host} is not <output directory>/{host}/<run_id>")
        roots.add(root)
        collected[host] = bundle
    if len(roots) > 1:
        _fail(
            "the collected bundles are in more than one output directory; set "
            "linux_compliance_evidence_output_dir once for the whole run"
        )
    return collected, roots.pop() if roots else ""


def summarize(value: object, now: datetime) -> dict[str, object]:
    """Classify every target host of a run and build its collection summary.

    Args:
        value: What the playbook observed, a mapping with exactly these keys:
            ``targets`` (the inventory hosts of the run's host pattern), ``play_hosts``
            (the hosts of the audit play, or ``None`` when they were not recorded),
            ``reached``, ``audited`` and ``evidence_written`` (the target hosts that
            completed fact gathering, have an audit result and wrote evidence),
            ``bundles`` (inventory host to its ``linux_compliance_evidence_bundle``
            fact, of which ``directory``, ``run_id`` and ``manifest_sha256`` are used),
            ``output_dir`` (the resolved output directory, used when nothing was
            collected) and ``collection_version``.
        now: The controller time.

    Returns:
        The host lists per status, the status of each host, the summary document, its
        SHA-256, its path and the output directory it is written to.

    Raises:
        CollectionError: If an observation is malformed or the bundles are not in one
            output directory.
    """
    data = _object(value, "the observed collection", _OBSERVED_KEYS)
    targets = tuple(sorted(_hosts(data["targets"], "targets")))
    observed = {
        name: frozenset(_hosts(data[name], name))
        for name in ("reached", "audited", "evidence_written")
    }
    play_hosts = (
        None if data["play_hosts"] is None else frozenset(_hosts(data["play_hosts"], "play_hosts"))
    )
    collected, root = _bundles(data["bundles"], frozenset(targets))
    root = root or _absolute(data["output_dir"], "output_dir")
    hosts = tuple(
        TargetHost(host, _status(host, observed, play_hosts, collected), collected.get(host))
        for host in targets
    )
    collection_id = now.strftime(COLLECTION_ID_FORMAT)
    summary = Collection(
        collection_id=collection_id,
        collected_at=now.strftime(model.TIMESTAMP_FORMAT),
        collection_version=_text(
            data["collection_version"], "collection_version", max_length=64, pattern=_VERSION
        ),
        hosts=hosts,
    )
    document = evidence.canonical_json(summary.to_dict())
    result: dict[str, object] = {
        status: [host.inventory_host for host in hosts if host.status == status]
        for status in HOST_STATUSES
        if status != COLLECTED
    }
    result.update(
        {
            "target_hosts": list(targets),
            "collected_hosts": sorted(collected),
            "missing_hosts": [host for host in targets if host not in collected],
            "statuses": {host.inventory_host: host.status for host in hosts},
            "bundles": [
                {"inventory_hostname": host, **collected[host].to_dict()}
                for host in sorted(collected)
            ],
            "collection_id": collection_id,
            "document": document,
            "sha256": evidence.sha256_hex(document.encode("ascii")),
            "output_dir": root,
            "path": f"{root}/{summary.file_name}",
        }
    )
    return result
