"""Assemble the normalized, versioned report document (schema ``report-v2.json``).

Every section has an explicit status. A section with no input is ``unavailable``, a
section with any unreadable or invalid input is ``error``, and a section is
``available`` only when every input parsed. Nothing is ever defaulted to a pass, and
no timestamp is generated: metadata times are supplied by the caller.

Exceptions evaluations are inputs of two sections: their scan runs feed
``compliance`` and their exception statuses feed ``exceptions``. They are listed once
in ``raw_artifacts``. An evidence bundle (``--evidence-bundle``) is verified first and
contributes its evaluation, or its raw scan run when no exceptions were applied, and
its exceptions file. More than one completed ScanRun for one host, benchmark, content
version and profile is refused unless ``allow_repeated_scans`` is set.

With an evidence collection summary (``--evidence-collection``) every target host of the
run is accounted for in ``sections.compliance.host_coverage`` (schema 2.1): a bundle that
the summary does not list is an input error, and a target host without a bundle in the
report is a missing input, so the section cannot be ``available`` while a host is missing.
Without a summary the coverage is ``unknown``.
"""

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Final, cast

from tools.reporting import host_coverage
from tools.reporting.bundle import BundleInput, parse_bundle
from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    Json,
    ParseResult,
    SectionStatus,
    dig,
    to_json,
)
from tools.reporting.compliance import (
    ComplianceData,
    Entry,
    aggregate_figures,
    figure,
    figured,
    group_figures,
    host_key,
    input_notes,
    repeated_scan_runs,
    rollup,
)
from tools.reporting.parsers.cobertura import CoverageData, parse_cobertura
from tools.reporting.parsers.codebuild import CodeBuildData, parse_codebuild
from tools.reporting.parsers.evaluation import (
    EvaluationData,
    compliance_result,
    parse_evaluation,
    parse_exceptions_file,
)
from tools.reporting.parsers.grype import VulnerabilityData, parse_grype
from tools.reporting.parsers.junit import TestsData, parse_junit
from tools.reporting.parsers.lint import LintData, parse_lint
from tools.reporting.parsers.molecule import MoleculeData, parse_molecule
from tools.reporting.parsers.packer import PackerData, parse_packer
from tools.reporting.parsers.pytest_json import parse_pytest_json
from tools.reporting.parsers.sbom import SbomData, parse_sbom
from tools.reporting.parsers.scanrun import parse_scan_run
from tools.reporting.parsers.xccdf import parse_arf, parse_xccdf
from tools.reporting.waivers import exception_entries

SCHEMA_VERSION: Final[str] = "2.1"
SECTION_NAMES: Final[tuple[str, ...]] = (
    "codebuild",
    "compliance",
    "coverage",
    "exceptions",
    "lint",
    "molecule",
    "packer",
    "sbom",
    "tests",
    "vulnerabilities",
)
SECTION_INPUTS: Final[dict[str, tuple[str, ...]]] = {
    "codebuild": ("codebuild",),
    "compliance": ("xccdf", "arf", "scan_run", "exceptions_evaluation", "evidence_bundle"),
    "coverage": ("cobertura",),
    "exceptions": ("exceptions_evaluation", "evidence_bundle"),
    "lint": ("lint",),
    "molecule": ("molecule",),
    "packer": ("packer",),
    "sbom": ("sbom",),
    "tests": ("junit", "pytest_json"),
    "vulnerabilities": ("grype",),
}
MAX_INPUTS: Final[int] = 1000
SHARED_INPUT_SECTIONS: Final[frozenset[str]] = frozenset({"exceptions"})
REFERENCE_FILES: Final[tuple[str, ...]] = ("exceptions_file", "evidence_collection")
MAX_RAW_ARTIFACTS: Final[int] = (
    len(SECTION_NAMES) - len(SHARED_INPUT_SECTIONS)
) * MAX_INPUTS + len(REFERENCE_FILES)
BUNDLE_ONLY_INPUTS: Final[tuple[str, ...]] = ("xccdf", "arf", "scan_run", "exceptions_evaluation")
MAX_RULES: Final[int] = 1_000_000
MAX_GROUPS: Final[int] = 100_000
FAILED_BUILD_STATUSES: Final[frozenset[str]] = frozenset(
    {"FAILED", "FAULT", "TIMED_OUT", "STOPPED"}
)
COMMIT_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{7,64}")
PULL_REQUEST_PATTERN: Final[re.Pattern[str]] = re.compile(r"[1-9][0-9]{0,8}")
WORKFLOW_RUN_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9._:/@#-]{1,256}")
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
        _checked(self.commit, "commit", COMMIT_PATTERN)
        _checked(self.pull_request, "pull_request", PULL_REQUEST_PATTERN)
        _checked(self.workflow_run, "workflow_run", WORKFLOW_RUN_PATTERN)
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
    exceptions_evaluation: tuple[Path, ...] = ()
    evidence_bundle: tuple[Path, ...] = ()
    exceptions_file: Path | None = None
    evidence_collection: Path | None = None
    max_bytes: int = DEFAULT_MAX_BYTES
    allow_repeated_scans: bool = False


def _item(result: ParseResult[object]) -> dict[str, Json]:
    return {
        "artifact": to_json(result.artifact),
        "data": to_json(result.data),
        "format": result.format,
        "reason": result.reason,
        "status": result.status.value,
    }


def _section_status(statuses: Sequence[SectionStatus]) -> SectionStatus:
    """Return the section state: error beats partial, partial beats unavailable."""
    if not statuses:
        return SectionStatus.UNAVAILABLE
    if SectionStatus.ERROR in statuses:
        return SectionStatus.ERROR
    if all(status is SectionStatus.AVAILABLE for status in statuses):
        return SectionStatus.AVAILABLE
    if SectionStatus.AVAILABLE in statuses:
        return SectionStatus.PARTIAL
    return SectionStatus.UNAVAILABLE


def _reason(results: Sequence[ParseResult[object]]) -> str | None:
    if not results:
        return "no input was supplied"
    missing = sum(1 for result in results if result.status is SectionStatus.UNAVAILABLE)
    invalid = sum(1 for result in results if result.status is SectionStatus.ERROR)
    if not missing and not invalid:
        return None
    return f"{missing} of {len(results)} input(s) are missing and {invalid} are invalid"


def _section[T](
    results: Sequence[ParseResult[T]], summarize: Callable[[list[T]], Json] | None = None
) -> dict[str, Json]:
    status = _section_status([result.status for result in results])
    summary: Json = None
    if status is SectionStatus.AVAILABLE and summarize is not None:
        summary = summarize([result.data for result in results if result.data is not None])
    gaps: list[Json] = [
        {"artifact": result.artifact.path, "reason": result.reason, "status": result.status.value}
        for result in results
        if result.status is not SectionStatus.AVAILABLE
    ]
    return {
        "gaps": gaps,
        "items": [_item(result) for result in results],
        "reason": _reason(results),
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


def _codebuild_summary(items: list[CodeBuildData]) -> Json:
    statuses = [build.status for item in items for build in item.builds]
    return {
        "failed": sum(1 for status in statuses if status in FAILED_BUILD_STATUSES),
        "in_progress": statuses.count("IN_PROGRESS"),
        "succeeded": statuses.count("SUCCEEDED"),
        "total": len(statuses),
    }


def check_scope(scope: Scope, entries: list[Entry]) -> None:
    """Reject a declared scope that the data contradicts.

    Raises:
        ReportError: If ``single_host`` covers several hosts or ``benchmark`` covers
            several benchmarks, content versions or profiles.
    """
    hosts = {host_key(entry[1]) for entry in entries}
    if scope is Scope.SINGLE_HOST and len(hosts) > 1:
        message = f"scope single_host, but the inputs describe {len(hosts)} hosts"
        raise ReportError(message)
    versions = figured(entries)
    if scope is Scope.BENCHMARK and len(versions) > 1:
        message = (
            f"scope benchmark, but the inputs cover {len(versions)} benchmark, content version "
            "and profile combinations"
        )
        raise ReportError(message)


def _unique[T](results: Sequence[ParseResult[T]]) -> list[tuple[str, T, str]]:
    seen: set[str] = set()
    inputs: list[tuple[str, T, str]] = []
    for result in results:
        digest = result.artifact.sha256
        if result.data is not None and digest is not None and digest not in seen:
            seen.add(digest)
            inputs.append((result.artifact.path, result.data, digest))
    return inputs


def check_repeated_scans(entries: list[Entry], *, allowed: bool) -> None:
    """Refuse several completed ScanRuns of one host, benchmark version and profile.

    Raises:
        ReportError: If such runs exist and ``allowed`` is false.
    """
    repeated = repeated_scan_runs(entries)
    if repeated and not allowed:
        message = (
            f"{repeated} host, benchmark version and profile combination(s) have more than one "
            "completed scan run; pass --allow-repeated-scans to merge them rule by rule"
        )
        raise ReportError(message)


def _compliance_section(
    results: Sequence[ParseResult[ComplianceData]],
    scope: Scope,
    coverage: dict[str, Json],
    *,
    allow_repeated: bool,
) -> dict[str, Json]:
    section = _section(results)
    entries: list[Entry] = [(path, data) for path, data, _ in _unique(results)]
    check_scope(scope, entries)
    check_repeated_scans(entries, allowed=allow_repeated)
    section.update(
        {"aggregates": [], "groups": [], "host_coverage": coverage, "notes": [], "rules": []}
    )
    if section["status"] != SectionStatus.AVAILABLE.value:
        return section
    rules = rollup(entries)
    groups = group_figures(entries)
    if len(rules) > MAX_RULES or len(groups) > MAX_GROUPS:
        message = "the compliance data exceeds the report size limits"
        raise ReportError(message)
    versions = figured(entries)
    section["notes"] = to_json(input_notes(entries))
    section["rules"] = [to_json(rule) for rule in rules]
    section["groups"] = [to_json(group) for group in groups]
    if scope is not Scope.SINGLE_HOST:
        section["aggregates"] = [to_json(a) for a in aggregate_figures(entries, scope.value)]
    if len(versions) == 1:
        section["summary"] = to_json(figure(entries))
    return section


def _exceptions_file(
    inputs: ReportInputs, bundles: Sequence[BundleInput]
) -> ParseResult[str] | None:
    """Return the reviewed exceptions file that every evaluation must be verified against.

    It is always ``--exceptions-file``, the file the operator supplies. A bundle is not
    signed, so its own copy of the exceptions file is never the reference: a bundle
    built consistently from a made-up file would otherwise turn failures into waivers.
    Every bundle whose exceptions were applied carries a copy, and each copy must be
    byte-identical to ``--exceptions-file``.

    Raises:
        ReportError: If evaluations or bundles with applied exceptions are supplied
            without ``--exceptions-file``, the file without any evaluation, the file
            cannot be read, or a bundle carries another exceptions file.
    """
    copies = [bundle.exceptions_file for bundle in bundles if bundle.exceptions_file is not None]
    evaluated = bool(inputs.exceptions_evaluation) or any(
        bundle.evaluation is not None for bundle in bundles
    )
    if inputs.exceptions_file is None:
        if inputs.exceptions_evaluation:
            message = "--exceptions-evaluation requires --exceptions-file"
            raise ReportError(message)
        if copies:
            message = (
                "an --evidence-bundle whose exceptions were applied requires --exceptions-file: "
                "the bundle is not signed, so its own copy of the exceptions file is not trusted"
            )
            raise ReportError(message)
        return None
    if not evaluated:
        message = (
            "--exceptions-file is only used with --exceptions-evaluation or with evidence "
            "bundles whose exceptions were applied"
        )
        raise ReportError(message)
    source = parse_exceptions_file(inputs.exceptions_file, inputs.max_bytes)
    if source.data is None:
        message = f"the exceptions file cannot be used: {source.reason}"
        raise ReportError(message)
    foreign = [copy for copy in copies if copy.artifact.sha256 != source.artifact.sha256]
    if foreign:
        message = (
            f"{len(foreign)} evidence bundle(s) carry an exceptions file that is not "
            "byte-identical to --exceptions-file; report the runs of each exceptions file "
            "separately, each with its reviewed file"
        )
        raise ReportError(message)
    return source


def _evaluations(
    inputs: ReportInputs, bundles: Sequence[BundleInput]
) -> tuple[ParseResult[str] | None, list[ParseResult[EvaluationData]]]:
    source = _exceptions_file(inputs, bundles)
    text = "" if source is None else source.data or ""
    paths = inputs.exceptions_evaluation
    supplied = [parse_evaluation(path, text, inputs.max_bytes) for path in paths]
    bundled = [bundle.evaluation for bundle in bundles if bundle.evaluation is not None]
    return source, supplied + bundled


def _exceptions_section(
    results: Sequence[ParseResult[EvaluationData]], source: ParseResult[str] | None
) -> dict[str, Json]:
    section = _section(results)
    section.update({"exceptions": [], "exceptions_file": None, "source_sha256": None})
    if section["status"] != SectionStatus.AVAILABLE.value or source is None:
        return section
    evaluated = [(digest, data) for _, data, digest in _unique(results)]
    entries, summary = exception_entries(evaluated)
    section["exceptions"] = to_json(entries)
    section["exceptions_file"] = {
        "path": source.artifact.path,
        "sha256": source.artifact.sha256,
        "verified": True,
    }
    section["source_sha256"] = to_json(summary["source_sha256"])
    section["summary"] = to_json(summary)
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


def _check_input_counts(inputs: ReportInputs) -> None:
    for names in SECTION_INPUTS.values():
        if sum(len(getattr(inputs, name)) for name in names) > MAX_INPUTS:
            message = f"more than {MAX_INPUTS} inputs for one section"
            raise ReportError(message)


def _overview(sections: dict[str, dict[str, Json]]) -> dict[str, Json]:
    overview: dict[str, Json] = {
        status.value: [name for name in SECTION_NAMES if sections[name]["status"] == status.value]
        for status in SectionStatus
    }
    overview["exceptions"] = sections["exceptions"]["summary"]
    return overview


def _compliance_inputs(
    inputs: ReportInputs,
    evaluations: Sequence[ParseResult[EvaluationData]],
    bundles: Sequence[BundleInput],
) -> list[ParseResult[ComplianceData]]:
    size = inputs.max_bytes
    return (
        _parse_all(inputs.xccdf, parse_xccdf, size)
        + _parse_all(inputs.arf, parse_arf, size)
        + _parse_all(inputs.scan_run, parse_scan_run, size)
        + [compliance_result(result) for result in evaluations]
        + [bundle.compliance for bundle in bundles if bundle.evaluation is None]
    )


@dataclass(frozen=True)
class ScanInputs:
    """The scan inputs of a report after the exceptions file and the collection checks."""

    exceptions_file: ParseResult[str] | None
    evaluations: list[ParseResult[EvaluationData]]
    compliance: list[ParseResult[ComplianceData]]
    collection: ParseResult[object] | None
    coverage: dict[str, Json]


def _coverage(
    inputs: ReportInputs, bundles: list[BundleInput]
) -> tuple[host_coverage.Coverage, ParseResult[object] | None]:
    """Account for the target hosts of ``--evidence-collection``, or label coverage unknown.

    Raises:
        ReportError: If the summary is supplied with inputs that are not evidence bundles,
            cannot be read or used, or names more target hosts than a section can hold.
    """
    if inputs.evidence_collection is None:
        return host_coverage.unknown(bundles), None
    direct = [name for name in BUNDLE_ONLY_INPUTS if getattr(inputs, name)]
    if direct:
        message = (
            "--evidence-collection accounts for evidence bundles only; supply the scans as "
            f"--evidence-bundle, not --{direct[0].replace('_', '-')}"
        )
        raise ReportError(message)
    source = host_coverage.parse_collection_file(inputs.evidence_collection, inputs.max_bytes)
    if source.data is None:
        message = f"the evidence collection summary cannot be used: {source.reason}"
        raise ReportError(message)
    if len(source.data.hosts) > MAX_INPUTS:
        message = f"the evidence collection summary names more than {MAX_INPUTS} target hosts"
        raise ReportError(message)
    coverage = host_coverage.account(
        bundles,
        source.artifact,
        source.data,
        holds_exceptions=any(bundle.evaluation is not None for bundle in bundles),
    )
    return coverage, ParseResult(source.format, source.status, source.reason, source.artifact, None)


def _scan_inputs(inputs: ReportInputs) -> ScanInputs:
    parsed = [parse_bundle(path, inputs.max_bytes) for path in inputs.evidence_bundle]
    coverage, collection = _coverage(inputs, parsed)
    bundles = coverage.bundles + coverage.missing
    source, evaluations = _evaluations(inputs, bundles)
    compliance = _compliance_inputs(inputs, evaluations, bundles)
    if max(len(compliance), len(evaluations)) > MAX_INPUTS:
        message = f"more than {MAX_INPUTS} inputs for one section, counting the missing hosts"
        raise ReportError(message)
    return ScanInputs(source, evaluations, compliance, collection, coverage.document)


def build_report(inputs: ReportInputs) -> dict[str, Json]:
    """Parse every input and assemble the report document.

    The result is plain JSON data that validates against ``schema/report-v2.json``.
    Equal inputs give equal documents.

    Raises:
        ReportError: If the declared scope contradicts the data or a limit is exceeded.
    """
    _check_input_counts(inputs)
    size = inputs.max_bytes
    scan = _scan_inputs(inputs)
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
        "codebuild": _section(codebuild, _codebuild_summary),
        "compliance": _compliance_section(
            scan.compliance, inputs.scope, scan.coverage, allow_repeated=inputs.allow_repeated_scans
        ),
        "coverage": _section(coverage),
        "exceptions": _exceptions_section(scan.evaluations, scan.exceptions_file),
        "lint": _section(lint, _severity_summary),
        "molecule": _section(molecule, _molecule_summary),
        "packer": _section(packer),
        "sbom": _section(sbom),
        "tests": _section(tests, _tests_summary),
        "vulnerabilities": _section(vulnerabilities, _severity_summary),
    }
    every_result: dict[str, list[ParseResult[object]]] = {
        "compliance": [*scan.compliance],
        "tests": [*tests],
        "coverage": [*coverage],
        "lint": [*lint],
        "vulnerabilities": [*vulnerabilities],
        "sbom": [*sbom],
        "packer": [*packer],
        "codebuild": [*codebuild],
        "molecule": [*molecule],
        "exceptions": [] if scan.exceptions_file is None else [scan.exceptions_file],
        "host_coverage": [] if scan.collection is None else [scan.collection],
    }
    return {
        "metadata": _metadata(inputs.metadata),
        "overview": _overview(sections),
        "raw_artifacts": _raw_artifacts(every_result),
        "schema_version": SCHEMA_VERSION,
        "scope": inputs.scope.value,
        "sections": dict(sections),
    }


def has_error(report: dict[str, Json]) -> bool:
    """Return whether any section of ``report`` is in the ``error`` state."""
    return bool(dig(report, "overview", "error"))


def has_gap(report: dict[str, Json]) -> bool:
    """Return whether a supplied input is missing or invalid in any section."""
    return any(
        bool(dig(section, "gaps"))
        for section in cast("dict[str, Json]", report["sections"]).values()
    )
