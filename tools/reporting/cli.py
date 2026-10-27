"""Command line: parse report inputs, write the normalized JSON report and the dashboard.

``--html`` also writes the single-file HTML dashboard of the same document. Both files
are written atomically: to a temporary file in the target directory, synced, then
renamed over the target, with mode 0600 because a report can hold host evidence.

Exit status: 0 when the report was written and every supplied input parsed, 1 when it
was written but a supplied input is missing or invalid (a section is ``partial`` or
``error``), 2 for invalid arguments or metadata, ``--html`` naming the same file as
``--output``, a scope that the data contradicts, or an output that cannot be written,
and 3 when the JSON report was written but the dashboard was not, because the report
is above the dashboard size cap; a dashboard left from an earlier run at that path is
removed. Status 3 takes precedence over 1. A section without any input is
``unavailable`` and is not an error. Several completed ScanRuns of one host,
benchmark version and profile are refused with status 2 unless
``--allow-repeated-scans`` is given.

``--evidence-collection`` names every target host of an evidence run: a target host
without a bundle in the report is a missing input (status 1), a bundle that the summary
does not list is an invalid input (status 1), and a summary that cannot be read, or one
supplied with scan inputs that are not evidence bundles, is refused with status 2.

``--require-host-coverage`` (FREES-154) turns a host coverage other than ``complete`` into
status 1: ``incomplete`` already gives status 1, and ``unknown`` (no
``--evidence-collection``) does too with the option. The report is still written, and the
reason is printed on standard error. Status 3 still takes precedence.

``--export-ckl DIR`` and ``--export-cklb DIR`` (FREES-147) also write one STIG Viewer
checklist per host and DISA STIG benchmark, from the same scan inputs, with the status
mapping of ADR 0020. ``--checklist-content FILE`` names DISA content for runs whose
evidence bundle holds no XCCDF results, and for ScanRun JSON and evaluations. When an
input that parsed cannot be exported honestly (for example ComplianceAsCode findings of a
profile that the STIG mapping of FREES-146 does not cover), nothing is written and the
status is 2. ComplianceAsCode findings of a mapped STIG profile are exported through
``--stig-mapping FILE`` (default ``content/stig-mapping.json``) with the DISA content of
``--checklist-content``. ``--compare-stig FILE`` writes, from the same inputs, a JSON
comparison of an SCC run and an OpenSCAP run of each host by DISA STIG rule. Checklists
and the comparison are written atomically with mode 0600 into directories created with
mode 0700.
"""

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, cast

from tools.reporting.checklist import ChecklistError
from tools.reporting.checklist_export import PRIVATE_OUTPUTS, ExportRequest
from tools.reporting.checklist_export import outputs as checklist_outputs
from tools.reporting.common import DEFAULT_MAX_BYTES, Json, dig, dumps
from tools.reporting.dashboard import DashboardError, render_dashboard
from tools.reporting.host_coverage import COMPLETE
from tools.reporting.report import (
    ReportError,
    ReportInputs,
    RunMetadata,
    ScanInputs,
    Scope,
    build_report_and_inputs,
    has_error,
    has_gap,
)
from tools.reporting.stig_mapping import DEFAULT_PATH as STIG_MAPPING

EXIT_OK: Final[int] = 0
EXIT_SECTION_ERROR: Final[int] = 1
EXIT_USAGE: Final[int] = 2
EXIT_DASHBOARD_SKIPPED: Final[int] = 3
INPUT_OPTIONS: Final[tuple[str, ...]] = (
    "xccdf",
    "arf",
    "scan_run",
    "junit",
    "pytest_json",
    "cobertura",
    "lint",
    "grype",
    "sbom",
    "packer",
    "codebuild",
    "molecule",
    "exceptions_evaluation",
    "evidence_bundle",
)
METADATA_OPTIONS: Final[tuple[str, ...]] = (
    "commit",
    "pull_request",
    "workflow_run",
    "started_at",
    "finished_at",
    "generated_at",
)


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m tools.reporting",
        description="Write the normalized JSON report (schema report-v2) and, with "
        "--html, the single-file HTML dashboard.",
    )
    parser.add_argument("--scope", required=True, choices=[scope.value for scope in Scope])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--html", type=Path, default=None)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument(
        "--exceptions-file",
        type=Path,
        default=None,
        help="the exceptions file that every --exceptions-evaluation was made from; required "
        "with --exceptions-evaluation unless an --evidence-bundle carries it",
    )
    parser.add_argument(
        "--evidence-collection",
        type=Path,
        default=None,
        help="the collection summary that playbooks/evidence.yml wrote next to the bundles; the "
        "report then names every target host without a bundle, and refuses a bundle that the "
        "summary does not list",
    )
    parser.add_argument(
        "--require-host-coverage",
        action="store_true",
        help="exit with status 1 unless the report accounts for every target host, that is "
        "unless sections.compliance.host_coverage.status is complete; without "
        "--evidence-collection the coverage is unknown, so this also requires the summary",
    )
    parser.add_argument(
        "--allow-repeated-scans",
        action="store_true",
        help="merge several completed scan runs of one host, benchmark version and profile "
        "rule by rule instead of refusing them; each merge is noted in the report",
    )
    parser.add_argument(
        "--export-ckl",
        type=Path,
        default=None,
        help="also write one STIG Viewer 2 checklist (CKL) per host and DISA STIG benchmark "
        "into this directory",
    )
    parser.add_argument(
        "--export-cklb",
        type=Path,
        default=None,
        help="also write one STIG Viewer 3 checklist (CKLB) per host and DISA STIG benchmark "
        "into this directory",
    )
    parser.add_argument(
        "--checklist-content",
        action="append",
        default=[],
        type=Path,
        help="DISA STIG content (XCCDF 1.2 benchmark or results, or a SCAP source data stream) "
        "for the checklists of runs whose evidence bundle holds no XCCDF results, and of "
        "ComplianceAsCode runs exported through the STIG mapping",
    )
    parser.add_argument(
        "--stig-mapping",
        type=Path,
        default=STIG_MAPPING,
        help="the STIG to ComplianceAsCode mapping that ComplianceAsCode STIG profile runs are "
        "exported through (default: content/stig-mapping.json of this repository)",
    )
    parser.add_argument(
        "--compare-stig",
        type=Path,
        default=None,
        help="also write a JSON comparison of an SCC run and an OpenSCAP run of each host by "
        "DISA STIG rule, listing every rule whose checklist statuses differ",
    )
    for name in INPUT_OPTIONS:
        parser.add_argument(
            f"--{name.replace('_', '-')}", dest=name, action="append", default=[], type=Path
        )
    for name in METADATA_OPTIONS:
        parser.add_argument(f"--{name.replace('_', '-')}", dest=name, default=None)
    return parser


def write_atomic(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` through a synced temporary file and a rename.

    A crash or a full disk leaves either the previous file or the new one, never a
    truncated file, and no temporary file is left behind.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def coverage_shortfall(report: dict[str, Json]) -> str | None:
    """Return why the host coverage of ``report`` is not ``complete``, or ``None`` if it is."""
    status = dig(report, "sections", "compliance", "host_coverage", "status")
    if status == COMPLETE:
        return None
    reason = dig(report, "sections", "compliance", "host_coverage", "reason")
    return (
        f"--require-host-coverage: the host coverage is {status}, not {COMPLETE}: {reason}; "
        "the report was written, but it does not account for every target host"
    )


def _render(report: dict[str, Json], html: Path) -> str | None:
    try:
        return render_dashboard(report)
    except DashboardError as error:
        print(f"warning: the dashboard was not written: {error}", file=sys.stderr)
    try:
        html.unlink(missing_ok=True)
    except OSError as error:
        print(f"warning: cannot remove the earlier dashboard: {error.strerror}", file=sys.stderr)
    return None


def _checklists(
    arguments: dict[str, object], scan: ScanInputs, max_bytes: int
) -> list[tuple[Path, str, str]] | None:
    ckl = cast("Path | None", arguments["export_ckl"])
    cklb = cast("Path | None", arguments["export_cklb"])
    comparison = cast("Path | None", arguments["compare_stig"])
    content = tuple(cast("list[Path]", arguments["checklist_content"]))
    if ckl is None and cklb is None and comparison is None:
        return []
    mapping = cast("Path", arguments["stig_mapping"])
    request = ExportRequest(ckl, cklb, content, max_bytes, mapping, comparison)
    try:
        return checklist_outputs(request, scan)
    except ChecklistError as error:
        print(f"error: no checklist was written: {error}", file=sys.stderr)
        return None


def _write(outputs: list[tuple[Path, str, str]]) -> bool:
    for path, content, name in outputs:
        try:
            if name in PRIVATE_OUTPUTS:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_atomic(path, content)
        except OSError as error:
            print(f"error: cannot write the {name}: {error.strerror}", file=sys.stderr)
            return False
        print(f"{name} written to {path}")
    return True


def _inputs(arguments: dict[str, Any]) -> ReportInputs | str:
    output: Path = arguments["output"]
    html: Path | None = arguments["html"]
    if html is not None and html.resolve() == output.resolve():
        return "--html and --output must name different files"
    exporting = any(
        arguments[name] is not None for name in ("export_ckl", "export_cklb", "compare_stig")
    )
    if arguments["checklist_content"] and not exporting:
        return "--checklist-content needs --export-ckl, --export-cklb or --compare-stig"
    try:
        metadata = RunMetadata(**{name: arguments[name] for name in METADATA_OPTIONS})
    except ReportError as error:
        return str(error)
    return ReportInputs(
        scope=Scope(arguments["scope"]),
        metadata=metadata,
        max_bytes=arguments["max_bytes"],
        allow_repeated_scans=arguments["allow_repeated_scans"],
        exceptions_file=arguments["exceptions_file"],
        evidence_collection=arguments["evidence_collection"],
        **{name: tuple(arguments[name]) for name in INPUT_OPTIONS},
    )


def main(argv: Sequence[str]) -> int:
    """Run the command line and return the exit status."""
    arguments = vars(build_parser().parse_args(argv))
    output: Path = arguments["output"]
    html: Path | None = arguments["html"]
    inputs = _inputs(arguments)
    if isinstance(inputs, str):
        print(f"error: {inputs}", file=sys.stderr)
        return EXIT_USAGE
    try:
        report, scan = build_report_and_inputs(inputs)
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    checklists = _checklists(arguments, scan, inputs.max_bytes)
    if checklists is None:
        return EXIT_USAGE
    outputs = [(output, dumps(report), "report"), *checklists]
    dashboard = None if html is None else _render(report, html)
    if html is not None and dashboard is not None:
        outputs.append((html, dashboard, "dashboard"))
    if not _write(outputs):
        return EXIT_USAGE
    shortfall = coverage_shortfall(report) if arguments["require_host_coverage"] else None
    if shortfall is not None:
        print(f"error: {shortfall}", file=sys.stderr)
    if html is not None and dashboard is None:
        return EXIT_DASHBOARD_SKIPPED
    incomplete = has_error(report) or has_gap(report) or shortfall is not None
    return EXIT_SECTION_ERROR if incomplete else EXIT_OK
