"""Assemble the normalized, versioned report document (schema ``report-v1.json``).

Every section has an explicit status. A section with no input is ``unavailable``, a
section with any unreadable or invalid input is ``error``, and a section is
``available`` only when every input parsed. Nothing is ever defaulted to a pass, and
no timestamp is generated: metadata times are supplied by the caller.
"""

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    Json,
    ParseResult,
    SectionStatus,
    dig,
    to_json,
)
from tools.reporting.compliance import ComplianceData, rollup, summarize_rollup
from tools.reporting.parsers.cobertura import CoverageData, parse_cobertura
from tools.reporting.parsers.codebuild import CodeBuildData, parse_codebuild
from tools.reporting.parsers.grype import VulnerabilityData, parse_grype
from tools.reporting.parsers.junit import TestsData, parse_junit
from tools.reporting.parsers.lint import LintData, parse_lint
from tools.reporting.parsers.molecule import MoleculeData, parse_molecule
from tools.reporting.parsers.packer import PackerData, parse_packer
from tools.reporting.parsers.pytest_json import parse_pytest_json
from tools.reporting.parsers.sbom import SbomData, parse_sbom
from tools.reporting.parsers.scanrun import parse_scan_run
from tools.reporting.parsers.xccdf import parse_arf, parse_xccdf

SCHEMA_VERSION: Final[str] = "1.0"
SECTION_NAMES: Final[tuple[str, ...]] = (
    "codebuild",
    "compliance",
    "coverage",
    "lint",
    "molecule",
    "packer",
    "sbom",
    "tests",
    "vulnerabilities",
)
_STATUS_BADNESS: Final[tuple[SectionStatus, ...]] = (
    SectionStatus.ERROR,
    SectionStatus.UNAVAILABLE,
    SectionStatus.AVAILABLE,
)
_COMMIT: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{7,64}")
_PULL_REQUEST: Final[re.Pattern[str]] = re.compile(r"[1-9][0-9]{0,8}")
_WORKFLOW_RUN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9._:/@#-]{1,256}")
_TIMESTAMP: Final[re.Pattern[str]] = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)


class ReportError(ValueError):
    """Raised when the caller supplies invalid report metadata."""


class Scope(Enum):
    """What the statistics of a report describe. Scopes are never combined."""

    SINGLE_HOST = "single_host"
    MULTI_HOST = "multi_host"
    BENCHMARK = "benchmark"
    FLEET = "fleet"


def _checked(value: str | None, name: str, pattern: re.Pattern[str]) -> str | None:
    if value is not None and pattern.fullmatch(value) is None:
        message = f"{name} has an invalid format"
        raise ReportError(message)
    return value


def _checked_time(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    message = f"{name} must be a UTC timestamp like 2026-10-25T10:00:00Z"
    if _TIMESTAMP.fullmatch(value) is None:
        raise ReportError(message)
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise ReportError(message) from None
    return value


@dataclass(frozen=True)
class RunMetadata:
    """Identity of the run that produced the inputs. Every value is supplied, never generated."""

    commit: str | None = None
    pull_request: str | None = None
    workflow_run: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    generated_at: str | None = None

    def __post_init__(self) -> None:
        """Validate the supplied values."""
        _checked(self.commit, "commit", _COMMIT)
        _checked(self.pull_request, "pull_request", _PULL_REQUEST)
        _checked(self.workflow_run, "workflow_run", _WORKFLOW_RUN)
        for name in ("started_at", "finished_at", "generated_at"):
            _checked_time(getattr(self, name), name)


@dataclass(frozen=True)
class ReportInputs:
    """Scope, metadata and the input files of every format."""

    scope: Scope
    metadata: RunMetadata = field(default_factory=RunMetadata)
    xccdf: tuple[Path, ...] = ()
    arf: tuple[Path, ...] = ()
    scan_run: tuple[Path, ...] = ()
    junit: tuple[Path, ...] = ()
    pytest_json: tuple[Path, ...] = ()
    cobertura: tuple[Path, ...] = ()
    lint: tuple[Path, ...] = ()
    grype: tuple[Path, ...] = ()
    sbom: tuple[Path, ...] = ()
    packer: tuple[Path, ...] = ()
    codebuild: tuple[Path, ...] = ()
    molecule: tuple[Path, ...] = ()
    max_bytes: int = DEFAULT_MAX_BYTES


def _item(result: ParseResult[object]) -> dict[str, Json]:
    return {
        "artifact": to_json(result.artifact),
        "data": to_json(result.data),
        "format": result.format,
        "reason": result.reason,
        "status": result.status.value,
    }


def _worst(statuses: Sequence[SectionStatus]) -> SectionStatus:
    if not statuses:
        return SectionStatus.UNAVAILABLE
    return min(statuses, key=_STATUS_BADNESS.index)


def _section[T](
    results: Sequence[ParseResult[T]], summarize: Callable[[list[T]], Json] | None = None
) -> dict[str, Json]:
    status = _worst([result.status for result in results])
    problems = sum(1 for result in results if result.status is not SectionStatus.AVAILABLE)
    if not results:
        reason: str | None = "no input was supplied"
    elif problems:
        reason = f"{problems} of {len(results)} input(s) are unavailable or invalid"
    else:
        reason = None
    summary: Json = None
    if status is SectionStatus.AVAILABLE and summarize is not None:
        summary = summarize([result.data for result in results if result.data is not None])
    return {
        "items": [_item(result) for result in results],
        "reason": reason,
        "status": status.value,
        "summary": summary,
    }


def _sum_counts(items: Sequence[object], names: tuple[str, ...]) -> dict[str, Json]:
    return {name: sum(getattr(item, name) for item in items) for name in names}


def _tests_summary(items: list[TestsData]) -> Json:
    return _sum_counts(items, ("total", "passed", "failed", "errors", "skipped"))


def _molecule_summary(items: list[MoleculeData]) -> Json:
    return _sum_counts(items, ("total", "passed", "failed", "skipped", "error"))


def _severity_summary(items: Sequence[LintData | VulnerabilityData]) -> Json:
    severities: dict[str, Json] = {
        name: sum(item.by_severity[name] for item in items) for name in items[0].by_severity
    }
    return {"by_severity": severities, "total": sum(item.total for item in items)}


def _compliance_section(results: Sequence[ParseResult[ComplianceData]]) -> dict[str, Json]:
    section = _section(results)
    section["rules"] = []
    if section["status"] != SectionStatus.AVAILABLE.value:
        return section
    entries = [(result.artifact.path, result.data) for result in results if result.data is not None]
    rules = rollup(entries)
    statuses = [data.scan_status for _, data in entries]
    section["summary"] = to_json(summarize_rollup(rules, statuses))
    section["rules"] = [to_json(rule) for rule in rules]
    return section


def _parse_all[T](
    paths: Sequence[Path], parser: Callable[[Path, int], ParseResult[T]], max_bytes: int
) -> list[ParseResult[T]]:
    return [parser(path, max_bytes) for path in paths]


def _raw_artifacts(sections: dict[str, list[ParseResult[object]]]) -> list[Json]:
    references: list[dict[str, Json]] = [
        {
            "format": result.format,
            "path": result.artifact.path,
            "sha256": result.artifact.sha256,
            "size": result.artifact.size,
            "status": result.status.value,
        }
        for results in sections.values()
        for result in results
    ]
    ordered = sorted(references, key=lambda ref: (str(ref["path"]), str(ref["format"])))
    return list[Json](ordered)


def _metadata(metadata: RunMetadata) -> Json:
    return {
        "commit": metadata.commit,
        "finished_at": metadata.finished_at,
        "generated_at": metadata.generated_at,
        "pull_request": metadata.pull_request,
        "started_at": metadata.started_at,
        "workflow_run": metadata.workflow_run,
    }


def build_report(inputs: ReportInputs) -> dict[str, Json]:
    """Parse every input and assemble the report document.

    The result is plain JSON data that validates against ``schema/report-v1.json``.
    Equal inputs give equal documents.
    """
    size = inputs.max_bytes
    compliance = (
        _parse_all(inputs.xccdf, parse_xccdf, size)
        + _parse_all(inputs.arf, parse_arf, size)
        + _parse_all(inputs.scan_run, parse_scan_run, size)
    )
    tests = _parse_all(inputs.junit, parse_junit, size) + _parse_all(
        inputs.pytest_json, parse_pytest_json, size
    )
    coverage: list[ParseResult[CoverageData]] = _parse_all(inputs.cobertura, parse_cobertura, size)
    lint = _parse_all(inputs.lint, parse_lint, size)
    vulnerabilities = _parse_all(inputs.grype, parse_grype, size)
    sbom: list[ParseResult[SbomData]] = _parse_all(inputs.sbom, parse_sbom, size)
    packer: list[ParseResult[PackerData]] = _parse_all(inputs.packer, parse_packer, size)
    codebuild: list[ParseResult[CodeBuildData]] = _parse_all(
        inputs.codebuild, parse_codebuild, size
    )
    molecule = _parse_all(inputs.molecule, parse_molecule, size)
    sections: dict[str, dict[str, Json]] = {
        "codebuild": _section(codebuild),
        "compliance": _compliance_section(compliance),
        "coverage": _section(coverage),
        "lint": _section(lint, _severity_summary),
        "molecule": _section(molecule, _molecule_summary),
        "packer": _section(packer),
        "sbom": _section(sbom),
        "tests": _section(tests, _tests_summary),
        "vulnerabilities": _section(vulnerabilities, _severity_summary),
    }
    every_result: dict[str, list[ParseResult[object]]] = {
        "compliance": [*compliance],
        "tests": [*tests],
        "coverage": [*coverage],
        "lint": [*lint],
        "vulnerabilities": [*vulnerabilities],
        "sbom": [*sbom],
        "packer": [*packer],
        "codebuild": [*codebuild],
        "molecule": [*molecule],
    }
    overview: dict[str, Json] = {
        status.value: [name for name in SECTION_NAMES if sections[name]["status"] == status.value]
        for status in SectionStatus
    }
    return {
        "metadata": _metadata(inputs.metadata),
        "overview": overview,
        "raw_artifacts": _raw_artifacts(every_result),
        "schema_version": SCHEMA_VERSION,
        "scope": inputs.scope.value,
        "sections": dict(sections),
    }


def has_error(report: dict[str, Json]) -> bool:
    """Return whether any section of ``report`` is in the ``error`` state."""
    return bool(dig(report, "overview", "error"))
