"""pytest JSON reports (pytest-json-report layout)."""

from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    MAX_DETAIL_ITEMS,
    InvalidInputError,
    ParseResult,
    as_count,
    as_list,
    as_object,
    as_text,
    load_json,
    require,
    run_parser,
)
from tools.reporting.parsers.junit import FailedCase, TestsData

COUNTED: Final[tuple[str, ...]] = ("passed", "failed", "error", "skipped", "xfailed", "xpassed")
FAILED_OUTCOMES: Final[frozenset[str]] = frozenset({"failed", "error", "xpassed"})


def _failed_cases(document: dict[str, object]) -> list[FailedCase]:
    cases: list[FailedCase] = []
    for index, raw in enumerate(as_list(document.get("tests", []), "tests")):
        entry = as_object(raw, f"tests[{index}]")
        outcome = as_text(require(entry, "outcome", f"tests[{index}]"), "outcome")
        if outcome in FAILED_OUTCOMES:
            name = as_text(require(entry, "nodeid", f"tests[{index}]"), "nodeid")
            cases.append(FailedCase(name, None, outcome, None))
    return cases


def _build(data: bytes) -> TestsData:
    document = as_object(load_json(data), "pytest report")
    summary = as_object(require(document, "summary", "pytest report"), "summary")
    counts = {name: as_count(summary.get(name, 0), f"summary.{name}") for name in COUNTED}
    total = as_count(require(summary, "total", "summary"), "summary.total")
    if total == 0 or total != sum(counts.values()):
        message = "summary.total is zero or does not equal the sum of the outcome counts"
        raise InvalidInputError(message)
    failed_cases = _failed_cases(document)
    return TestsData(
        total=total,
        passed=counts["passed"],
        failed=counts["failed"] + counts["xpassed"],
        errors=counts["error"],
        skipped=counts["skipped"] + counts["xfailed"],
        failed_cases=tuple(failed_cases[:MAX_DETAIL_ITEMS]),
        truncated=len(failed_cases) > MAX_DETAIL_ITEMS,
    )


def parse_pytest_json(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[TestsData]:
    """Parse a pytest JSON report. ``xpassed`` counts as failed, ``xfailed`` as skipped."""
    return run_parser(path, "pytest_json", max_bytes, _build)
