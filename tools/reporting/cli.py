"""Command line: parse report inputs, write the normalized JSON report and the dashboard.

``--html`` also writes the single-file HTML dashboard of the same document. Nothing
is written when the dashboard cannot be rendered.

Exit status: 0 when the report was written and every supplied input parsed, 1 when it
was written but a supplied input is missing or invalid (a section is ``partial`` or
``error``), 2 for invalid arguments or metadata, a scope that the data contradicts,
a report that the dashboard cannot render, or an output that cannot be written. A
section without any input is ``unavailable`` and is not an error.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from tools.reporting.common import DEFAULT_MAX_BYTES, dumps
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
        description="Write the normalized JSON report (schema report-v1) and, with "
        "--html, the single-file HTML dashboard.",
    )
    parser.add_argument("--scope", required=True, choices=[scope.value for scope in Scope])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--html", type=Path, default=None)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    for name in INPUT_OPTIONS:
        parser.add_argument(
            f"--{name.replace('_', '-')}", dest=name, action="append", default=[], type=Path
        )
    for name in METADATA_OPTIONS:
        parser.add_argument(f"--{name.replace('_', '-')}", dest=name, default=None)
    return parser


def main(argv: Sequence[str]) -> int:
    """Run the command line and return the exit status."""
    arguments = vars(build_parser().parse_args(argv))
    try:
        metadata = RunMetadata(**{name: arguments[name] for name in METADATA_OPTIONS})
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    inputs = ReportInputs(
        scope=Scope(arguments["scope"]),
        metadata=metadata,
        max_bytes=arguments["max_bytes"],
        **{name: tuple(arguments[name]) for name in INPUT_OPTIONS},
    )
    try:
        report = build_report(inputs)
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    outputs: list[tuple[Path, str, str]] = [(arguments["output"], dumps(report), "report")]
    html_output: Path | None = arguments["html"]
    if html_output is not None:
        try:
            outputs.append((html_output, render_dashboard(report), "dashboard"))
        except DashboardError as error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_USAGE
    for path, content, name in outputs:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except OSError as error:
            print(f"error: cannot write the {name}: {error.strerror}", file=sys.stderr)
            return EXIT_USAGE
        print(f"{name} written to {path}")
    return EXIT_SECTION_ERROR if has_error(report) or has_gap(report) else EXIT_OK
