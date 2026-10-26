"""Host coverage of a report built from evidence bundles (FREES-142).

A report over evidence bundles alone cannot see a target host that has no bundle. The
collection summary that ``playbooks/evidence.yml`` writes next to the bundles
(``--evidence-collection``) names every target host of the run, so the report can
account for each of them:

- Every supplied bundle that verified must be listed in the summary as ``collected``,
  with its inventory host, run ID and manifest SHA-256. A bundle that is not is an input
  ``error`` (:func:`bundle.refuse`): the summary binds each bundle to its digest.
- Every target host without such a bundle in the report is a missing input: an
  ``unavailable`` compliance item and, when the report has exceptions evaluations, an
  ``unavailable`` evaluation too, so that no exception is called stale on the strength of
  the hosts that are present. The compliance section is therefore never ``available``
  while a host is missing, so it has no summary, group or pooled figure, and the command
  exits with status 1.
- ``host_coverage`` names every target host with its status and counts them.

Without ``--evidence-collection`` the coverage is ``unknown``: the report cannot tell
whether a host is missing, and says so. The summary is written by the controller, but a
file supplied to the report is untrusted, so it is read with the common bounds and every
field is validated; a summary that cannot be read refuses the report.
"""

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    collection,
)
from tools.reporting.bundle import BundleIdentity, BundleInput, missing_input, refuse
from tools.reporting.common import (
    ArtifactRef,
    InvalidInputError,
    Json,
    ParseResult,
    SectionStatus,
    clean_text,
    run_parser,
)

FORMAT: Final[str] = "evidence_collection"
UNKNOWN: Final[str] = "unknown"
COMPLETE: Final[str] = "complete"
INCOMPLETE: Final[str] = "incomplete"
UNKNOWN_REASON: Final[str] = (
    "no --evidence-collection was supplied, so the report cannot tell whether a target host "
    "without an input is missing"
)
MISSING_REASONS: Final[dict[str, str]] = {
    collection.UNREACHABLE: "it was unreachable (it did not complete fact gathering)",
    collection.LIMITED_OUT: "it was limited out of the run",
    collection.NO_AUDIT_RESULT: "it has no audit result (it failed before the scan)",
    collection.NO_EVIDENCE_WRITTEN: "its audit wrote no evidence (check mode or no scan)",
    collection.COLLECTION_FAILED: "the collection of its evidence bundle failed",
}


@dataclass(frozen=True)
class Coverage:
    """The bundles after the summary check, the missing inputs and the coverage document.

    Attributes:
        bundles: The supplied bundles; those that the summary does not list are refused.
        missing: One missing input per target host without a bundle in the report.
        document: The ``host_coverage`` object of the compliance section.
    """

    bundles: list[BundleInput]
    missing: list[BundleInput]
    document: dict[str, Json]


def _parse(data: bytes) -> collection.Collection:
    try:
        return collection.parse_collection(data)
    except collection.CollectionError as error:
        message = f"evidence collection summary rejected: {clean_text(str(error), 300)}"
        raise InvalidInputError(message) from None


def parse_collection_file(path: Path, max_bytes: int) -> ParseResult[collection.Collection]:
    """Read and validate a collection summary, bounded like every input."""
    return run_parser(path, FORMAT, max_bytes, _parse)


def unknown(bundles: list[BundleInput]) -> Coverage:
    """Return the coverage of a report without a collection summary."""
    document: dict[str, Json] = {
        "collection": None,
        "hosts": [],
        "reason": UNKNOWN_REASON,
        "status": UNKNOWN,
        "summary": None,
    }
    return Coverage(bundles, [], document)


def _listed(identity: BundleIdentity, summary: collection.Collection) -> bool:
    return any(
        host.inventory_host == identity.inventory_host
        and host.bundle is not None
        and host.bundle.run_id == identity.run_id
        and host.bundle.manifest_sha256 == identity.manifest.sha256
        for host in summary.hosts
    )


def _checked(
    bundles: list[BundleInput], summary: collection.Collection
) -> tuple[list[BundleInput], set[str]]:
    checked: list[BundleInput] = []
    present: set[str] = set()
    for item in bundles:
        identity = item.identity
        if identity is None:
            checked.append(item)
        elif _listed(identity, summary):
            checked.append(item)
            present.add(identity.inventory_host)
        else:
            reason = (
                f"the collection summary {summary.collection_id} does not list run "
                f"{identity.run_id} of {identity.inventory_host} with the SHA-256 of this "
                "bundle.json"
            )
            checked.append(refuse(identity, reason))
    return checked, present


def _missing(host: collection.TargetHost, directory: str, *, holds_exceptions: bool) -> BundleInput:
    name = host.inventory_host
    if host.bundle is None:
        path = f"{directory}/{name}"
        reason = f"target host {name} has no evidence bundle: {MISSING_REASONS[host.status]}"
    else:
        path = f"{directory}/{name}/{host.bundle.run_id}"
        reason = (
            f"target host {name} was collected as run {host.bundle.run_id}, but no bundle of "
            "that run that verified and matches the collection summary was supplied"
        )
    return missing_input(
        ArtifactRef(path, None, None),
        SectionStatus.UNAVAILABLE,
        reason,
        holds_exceptions=holds_exceptions,
    )


def account(
    bundles: list[BundleInput],
    artifact: ArtifactRef,
    summary: collection.Collection,
    *,
    holds_exceptions: bool,
) -> Coverage:
    """Check the bundles against a collection summary and account for every target host.

    Args:
        bundles: The supplied bundles.
        artifact: The artifact reference of the collection summary.
        summary: The validated collection summary.
        holds_exceptions: Whether missing hosts are also missing exceptions evaluations.

    Returns:
        The checked bundles, one missing input per absent target host and the coverage.
    """
    checked, present = _checked(bundles, summary)
    directory = str(PurePosixPath(artifact.path).parent)
    absent = [host for host in summary.hosts if host.inventory_host not in present]
    missing = [_missing(host, directory, holds_exceptions=holds_exceptions) for host in absent]
    by_status: dict[str, Json] = {
        status: sum(1 for host in summary.hosts if host.status == status)
        for status in collection.HOST_STATUSES
    }
    document: dict[str, Json] = {
        "collection": {
            "collected_at": summary.collected_at,
            "collection_id": summary.collection_id,
            "path": artifact.path,
            "sha256": artifact.sha256,
            "size": artifact.size,
        },
        "hosts": [
            {
                "host": host.inventory_host,
                "in_report": host.inventory_host in present,
                "manifest_sha256": None if host.bundle is None else host.bundle.manifest_sha256,
                "run_id": None if host.bundle is None else host.bundle.run_id,
                "status": host.status,
            }
            for host in summary.hosts
        ],
        "reason": None
        if not absent
        else f"{len(absent)} of {len(summary.hosts)} target host(s) have no evidence bundle "
        "in this report",
        "status": INCOMPLETE if absent else COMPLETE,
        "summary": {
            "by_status": by_status,
            "in_report": len(summary.hosts) - len(absent),
            "missing": len(absent),
            "target_hosts": len(summary.hosts),
        },
    }
    return Coverage(checked, missing, document)
