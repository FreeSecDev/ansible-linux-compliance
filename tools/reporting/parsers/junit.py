"""JUnit XML test reports."""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    MAX_DETAIL_ITEMS,
    InvalidInputError,
    ParseResult,
    clean_text,
    run_parser,
)
from tools.reporting.xmlsafe import XmlNode, parse_xml

ROOT_NAMES: Final[frozenset[str]] = frozenset({"testsuite", "testsuites"})


@dataclass(frozen=True)
class FailedCase:
    """A failed or errored test case."""

    name: str
    classname: str | None
    kind: str
    message: str | None


@dataclass(frozen=True)
class TestsData:
    """Test totals and the first failed cases of one report."""

    __test__ = False

    total: int
    passed: int
    failed: int
    errors: int
    skipped: int
    failed_cases: tuple[FailedCase, ...]
    truncated: bool


def _case(node: XmlNode) -> tuple[str, FailedCase | None]:
    name = clean_text(node.attributes.get("name", "")) or "unnamed"
    classname = clean_text(node.attributes.get("classname", "")) or None
    kinds = {child.local: child for child in node.children}
    for kind in ("error", "failure"):
        if kind in kinds:
            message = clean_text(kinds[kind].attributes.get("message", "")) or None
            return kind, FailedCase(name, classname, kind, message)
    if "skipped" in kinds:
        return "skipped", None
    return "passed", None


def _check_suite(node: XmlNode) -> None:
    cases = [child for child in node.children if child.local == "testcase"]
    actual = {
        "tests": len(cases),
        "failures": sum(1 for c in cases if any(k.local == "failure" for k in c.children)),
        "errors": sum(1 for c in cases if any(k.local == "error" for k in c.children)),
    }
    for attribute, count in actual.items():
        stated = node.attributes.get(attribute)
        if stated is not None and stated != str(count):
            message = f"the testsuite {attribute} attribute does not match its test cases"
            raise InvalidInputError(message)


def _build(data: bytes) -> TestsData:
    root = parse_xml(data)
    if root.local not in ROOT_NAMES:
        message = "the root element is not testsuite or testsuites"
        raise InvalidInputError(message)
    totals = {"passed": 0, "failure": 0, "error": 0, "skipped": 0}
    failed_cases: list[FailedCase] = []
    for node in root.descendants():
        if node.local == "testsuite":
            _check_suite(node)
        if node.local != "testcase":
            continue
        kind, failed = _case(node)
        totals[kind] += 1
        if failed is not None:
            failed_cases.append(failed)
    total = sum(totals.values())
    if total == 0:
        message = "the report contains no test cases"
        raise InvalidInputError(message)
    return TestsData(
        total=total,
        passed=totals["passed"],
        failed=totals["failure"],
        errors=totals["error"],
        skipped=totals["skipped"],
        failed_cases=tuple(failed_cases[:MAX_DETAIL_ITEMS]),
        truncated=len(failed_cases) > MAX_DETAIL_ITEMS,
    )


def parse_junit(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[TestsData]:
    """Parse a JUnit XML report. Totals are counted from test cases, not from attributes."""
    return run_parser(path, "junit", max_bytes, _build)
