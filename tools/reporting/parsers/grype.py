"""Grype JSON vulnerability reports."""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    MAX_DETAIL_ITEMS,
    MAX_SUBENTRIES,
    SEVERITY_ORDER,
    InvalidInputError,
    ParseResult,
    as_list,
    as_object,
    as_text,
    bounded,
    dig,
    load_json,
    maybe_text,
    optional_list,
    optional_object,
    require,
    run_parser,
    severity_counts,
)

SEVERITY_NAMES: Final[dict[str, str]] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "info",
}


@dataclass(frozen=True)
class Vulnerability:
    """One vulnerable package and its fix state."""

    vulnerability_id: str
    severity: str
    package: str
    version: str
    fix_state: str | None
    fixed_versions: tuple[str, ...]


@dataclass(frozen=True)
class VulnerabilityData:
    """Scanner identity, database date, totals and the most severe matches."""

    scanner: str
    scanner_version: str
    database_built: str | None
    total: int
    by_severity: dict[str, int]
    vulnerabilities: tuple[Vulnerability, ...]
    truncated: bool


def _severity(vulnerability: dict[str, object], match: dict[str, object]) -> str:
    related = [
        dig(item, "severity") for item in optional_list(match, "relatedVulnerabilities", "match")
    ]
    names = [
        SEVERITY_NAMES.get((maybe_text(value) or "").lower(), "unknown")
        for value in [vulnerability.get("severity"), *related]
    ]
    return min(names, key=SEVERITY_ORDER.index)


def _match(raw: object) -> Vulnerability:
    match = as_object(raw, "match")
    vulnerability = as_object(require(match, "vulnerability", "match"), "vulnerability")
    artifact = as_object(require(match, "artifact", "match"), "artifact")
    fix = optional_object(vulnerability, "fix", "vulnerability")
    return Vulnerability(
        vulnerability_id=as_text(require(vulnerability, "id", "vulnerability"), "vulnerability.id"),
        severity=_severity(vulnerability, match),
        package=as_text(require(artifact, "name", "artifact"), "artifact.name"),
        version=as_text(require(artifact, "version", "artifact"), "artifact.version"),
        fix_state=maybe_text(fix.get("state")),
        fixed_versions=tuple(
            sorted(
                {
                    as_text(item, "fix.versions")
                    for item in bounded(
                        optional_list(fix, "versions", "fix"), MAX_SUBENTRIES, "fix.versions"
                    )
                }
            )
        ),
    )


def _build(data: bytes) -> VulnerabilityData:
    document = as_object(load_json(data), "grype report")
    descriptor = as_object(require(document, "descriptor", "grype report"), "descriptor")
    if descriptor.get("name") != "grype":
        message = "descriptor.name is not grype"
        raise InvalidInputError(message)
    matches = as_list(require(document, "matches", "grype report"), "matches")
    unique: dict[tuple[str, str, str], Vulnerability] = {}
    for item in (_match(raw) for raw in matches):
        key = (item.vulnerability_id, item.package, item.version)
        current = unique.get(key)
        if current is None or SEVERITY_ORDER.index(item.severity) < SEVERITY_ORDER.index(
            current.severity
        ):
            unique[key] = item
    ordered = sorted(
        unique.values(),
        key=lambda item: (
            SEVERITY_ORDER.index(item.severity),
            item.vulnerability_id,
            item.package,
            item.version,
        ),
    )
    built = dig(descriptor, "db", "status", "built") or dig(descriptor, "db", "built")
    return VulnerabilityData(
        scanner="grype",
        scanner_version=as_text(require(descriptor, "version", "descriptor"), "descriptor.version"),
        database_built=maybe_text(built),
        total=len(ordered),
        by_severity=severity_counts([item.severity for item in ordered]),
        vulnerabilities=tuple(ordered[:MAX_DETAIL_ITEMS]),
        truncated=len(ordered) > MAX_DETAIL_ITEMS,
    )


def parse_grype(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[VulnerabilityData]:
    """Parse a Grype JSON report. Unlisted severities become ``unknown``, never ``info``."""
    return run_parser(path, "grype", max_bytes, _build)
