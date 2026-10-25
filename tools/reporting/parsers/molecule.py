"""Molecule results summary, a small JSON format defined by this project.

Document layout (``format`` and ``version`` are required and exact)::

    {
        "format": "freesecdev-molecule-summary",
        "version": 1,
        "scenarios": [{"name": "default", "platform": "debian-12", "result": "passed"}],
    }

``result`` is one of ``passed``, ``failed``, ``skipped`` or ``error``. A scenario and
platform pair may appear only once.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    MAX_ENTRIES,
    InvalidInputError,
    ParseResult,
    as_list,
    as_object,
    as_text,
    bounded,
    load_json,
    require,
    run_parser,
)

FORMAT_NAME: Final[str] = "freesecdev-molecule-summary"
FORMAT_VERSION: Final[int] = 1
RESULTS: Final[tuple[str, ...]] = ("passed", "failed", "skipped", "error")


@dataclass(frozen=True)
class MoleculeScenario:
    """The outcome of one scenario on one platform."""

    name: str
    platform: str
    result: str


@dataclass(frozen=True)
class MoleculeData:
    """Scenario outcomes and totals per result."""

    total: int
    passed: int
    failed: int
    skipped: int
    error: int
    scenarios: tuple[MoleculeScenario, ...]


def _scenario(raw: object) -> MoleculeScenario:
    entry = as_object(raw, "scenario")
    result = as_text(require(entry, "result", "scenario"), "scenario.result")
    if result not in RESULTS:
        message = "scenario.result is not passed, failed, skipped or error"
        raise InvalidInputError(message)
    return MoleculeScenario(
        as_text(require(entry, "name", "scenario"), "scenario.name"),
        as_text(require(entry, "platform", "scenario"), "scenario.platform"),
        result,
    )


def _build(data: bytes) -> MoleculeData:
    document = as_object(load_json(data), "molecule summary")
    version = document.get("version")
    if (
        document.get("format") != FORMAT_NAME
        or version != FORMAT_VERSION
        or isinstance(version, bool)
    ):
        message = f"not a {FORMAT_NAME} version {FORMAT_VERSION} document"
        raise InvalidInputError(message)
    listed = bounded(
        as_list(require(document, "scenarios", "document"), "scenarios"), MAX_ENTRIES, "scenarios"
    )
    scenarios = [_scenario(raw) for raw in listed]
    if not scenarios:
        message = "the summary lists no scenarios"
        raise InvalidInputError(message)
    keys = {(item.name, item.platform) for item in scenarios}
    if len(keys) != len(scenarios):
        message = "a scenario and platform pair appears more than once"
        raise InvalidInputError(message)
    counts = {result: sum(1 for item in scenarios if item.result == result) for result in RESULTS}
    return MoleculeData(
        total=len(scenarios),
        passed=counts["passed"],
        failed=counts["failed"],
        skipped=counts["skipped"],
        error=counts["error"],
        scenarios=tuple(sorted(scenarios, key=lambda item: (item.name, item.platform))),
    )


def parse_molecule(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[MoleculeData]:
    """Parse a Molecule results summary. Zero scenarios is an error."""
    return run_parser(path, "molecule_summary", max_bytes, _build)
