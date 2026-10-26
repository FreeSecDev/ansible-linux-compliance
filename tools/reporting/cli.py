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
"""

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from tools.reporting.common import DEFAULT_MAX_BYTES, Json, dumps
from tools.reporting.dashboard import DashboardError, render_dashboard
from tools.reporting.report import (
    ReportError,
    ReportInputs,
    RunMetadata,
    Scope,
    build_report,
    has_error,
    has_gap,
)

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
        "with --exceptions-evaluation",
    )
    parser.add_argument(
        "--allow-repeated-scans",
        action="store_true",
        help="merge several completed scan runs of one host, benchmark version and profile "
        "rule by rule instead of refusing them; each merge is noted in the report",
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


def _write(outputs: list[tuple[Path, str, str]]) -> bool:
    for path, content, name in outputs:
        try:
            write_atomic(path, content)
        except OSError as error:
            print(f"error: cannot write the {name}: {error.strerror}", file=sys.stderr)
            return False
        print(f"{name} written to {path}")
    return True


def main(argv: Sequence[str]) -> int:
    """Run the command line and return the exit status."""
    arguments = vars(build_parser().parse_args(argv))
    output: Path = arguments["output"]
    html: Path | None = arguments["html"]
    if html is not None and html.resolve() == output.resolve():
        print("error: --html and --output must name different files", file=sys.stderr)
        return EXIT_USAGE
    try:
        metadata = RunMetadata(**{name: arguments[name] for name in METADATA_OPTIONS})
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    inputs = ReportInputs(
        scope=Scope(arguments["scope"]),
        metadata=metadata,
        max_bytes=arguments["max_bytes"],
        allow_repeated_scans=arguments["allow_repeated_scans"],
        exceptions_file=arguments["exceptions_file"],
        **{name: tuple(arguments[name]) for name in INPUT_OPTIONS},
    )
    try:
        report = build_report(inputs)
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    outputs = [(output, dumps(report), "report")]
    dashboard = None if html is None else _render(report, html)
    if html is not None and dashboard is not None:
        outputs.append((html, dashboard, "dashboard"))
    if not _write(outputs):
        return EXIT_USAGE
    if html is not None and dashboard is None:
        return EXIT_DASHBOARD_SKIPPED
    return EXIT_SECTION_ERROR if has_error(report) or has_gap(report) else EXIT_OK
