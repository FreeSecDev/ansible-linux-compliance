"""Cobertura coverage XML (also produced by coverage.py)."""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    MAX_DETAIL_ITEMS,
    InvalidInputError,
    ParseResult,
    as_count,
    as_rate,
    clean_text,
    run_parser,
)
from tools.reporting.xmlsafe import XmlNode, parse_xml

COUNT_ATTRIBUTES: Final[tuple[str, ...]] = (
    "lines-valid",
    "lines-covered",
    "branches-valid",
    "branches-covered",
)


@dataclass(frozen=True)
class PackageCoverage:
    """Coverage rates of one package."""

    name: str
    line_rate: float
    branch_rate: float


@dataclass(frozen=True)
class CoverageData:
    """Overall coverage rates, optional absolute counts and per-package rates."""

    line_rate: float
    branch_rate: float
    lines_valid: int | None
    lines_covered: int | None
    branches_valid: int | None
    branches_covered: int | None
    packages: tuple[PackageCoverage, ...]
    truncated: bool


def _rate(node: XmlNode, attribute: str) -> float:
    raw = node.attributes.get(attribute)
    try:
        number = float(raw) if raw is not None else None
    except ValueError:
        number = None
    return as_rate(number, f"{node.local} {attribute}")


def _optional_count(node: XmlNode, attribute: str) -> int | None:
    raw = node.attributes.get(attribute)
    if raw is None:
        return None
    if not raw.isascii() or not raw.isdigit():
        message = f"{attribute} is not a non-negative integer"
        raise InvalidInputError(message)
    return as_count(int(raw), attribute)


def _packages(root: XmlNode) -> list[PackageCoverage]:
    packages = [
        PackageCoverage(
            clean_text(node.attributes.get("name", "")) or ".",
            _rate(node, "line-rate"),
            _rate(node, "branch-rate"),
        )
        for node in root.descendants()
        if node.local == "package"
    ]
    return sorted(packages, key=lambda package: package.name)


def _build(data: bytes) -> CoverageData:
    root = parse_xml(data)
    if root.local != "coverage":
        message = "the root element is not coverage"
        raise InvalidInputError(message)
    counts = {name: _optional_count(root, name) for name in COUNT_ATTRIBUTES}
    packages = _packages(root)
    return CoverageData(
        line_rate=_rate(root, "line-rate"),
        branch_rate=_rate(root, "branch-rate"),
        lines_valid=counts["lines-valid"],
        lines_covered=counts["lines-covered"],
        branches_valid=counts["branches-valid"],
        branches_covered=counts["branches-covered"],
        packages=tuple(packages[:MAX_DETAIL_ITEMS]),
        truncated=len(packages) > MAX_DETAIL_ITEMS,
    )


def parse_cobertura(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[CoverageData]:
    """Parse a Cobertura report. Rates must lie in 0..1; a missing rate is an error."""
    return run_parser(path, "cobertura", max_bytes, _build)
