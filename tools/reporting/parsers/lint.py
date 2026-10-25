"""ansible-lint output in SARIF 2.1.0 or JSON (code-climate) format."""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    MAX_DETAIL_ITEMS,
    SEVERITY_ORDER,
    InvalidInputError,
    ParseResult,
    as_list,
    as_object,
    as_text,
    dig,
    is_object,
    load_json,
    maybe_count,
    maybe_text,
    optional_list,
    require,
    run_parser,
    severity_counts,
)

SARIF_VERSION: Final[str] = "2.1.0"
EXPECTED_TOOL: Final[str] = "ansible-lint"
SARIF_LEVELS: Final[dict[str, str]] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}
JSON_SEVERITIES: Final[dict[str, str]] = {
    "blocker": "critical",
    "critical": "critical",
    "major": "high",
    "minor": "medium",
    "info": "info",
}


@dataclass(frozen=True)
class LintIssue:
    """One lint finding."""

    rule_id: str
    severity: str
    message: str
    path: str | None
    line: int | None


@dataclass(frozen=True)
class LintData:
    """Lint totals, severity counts and the first issues."""

    format: str
    total: int
    by_severity: dict[str, int]
    issues: tuple[LintIssue, ...]
    truncated: bool


def _sarif_issue(raw: object) -> LintIssue:
    result = as_object(raw, "result")
    level = maybe_text(result.get("level")) or "warning"
    return LintIssue(
        rule_id=as_text(require(result, "ruleId", "result"), "ruleId"),
        severity=SARIF_LEVELS.get(level, "unknown"),
        message=as_text(dig(result, "message", "text"), "message.text"),
        path=maybe_text(dig(result, "locations", 0, "physicalLocation", "artifactLocation", "uri")),
        line=maybe_count(dig(result, "locations", 0, "physicalLocation", "region", "startLine")),
    )


def _check_invocations(run: dict[str, object]) -> None:
    for invocation in optional_list(run, "invocations", "run"):
        item = as_object(invocation, "invocation")
        if item.get("executionSuccessful") is False:
            message = "the SARIF invocation reports that the tool did not run successfully"
            raise InvalidInputError(message)
        for note in optional_list(item, "toolExecutionNotifications", "invocation"):
            if dig(note, "level") == "error":
                message = "the SARIF invocation reports a tool execution error"
                raise InvalidInputError(message)


def _sarif_issues(document: dict[str, object]) -> list[LintIssue]:
    if document.get("version") != SARIF_VERSION:
        message = f"unsupported SARIF version, expected {SARIF_VERSION}"
        raise InvalidInputError(message)
    runs = as_list(require(document, "runs", "SARIF document"), "runs")
    if not runs:
        message = "SARIF document contains no runs"
        raise InvalidInputError(message)
    issues: list[LintIssue] = []
    for run in runs:
        driver = as_text(dig(run, "tool", "driver", "name"), "tool.driver.name")
        if driver != EXPECTED_TOOL:
            message = f"the SARIF run was produced by a different tool than {EXPECTED_TOOL}"
            raise InvalidInputError(message)
        _check_invocations(as_object(run, "run"))
        issues.extend(_sarif_issue(raw) for raw in as_list(dig(run, "results"), "results"))
    return issues


def _json_issue(raw: object) -> LintIssue:
    item = as_object(raw, "issue")
    severity = (maybe_text(item.get("severity")) or "").lower()
    return LintIssue(
        rule_id=as_text(require(item, "check_name", "issue"), "check_name"),
        severity=JSON_SEVERITIES.get(severity, "unknown"),
        message=as_text(require(item, "description", "issue"), "description"),
        path=maybe_text(dig(item, "location", "path")),
        line=maybe_count(dig(item, "location", "lines", "begin")),
    )


def _build(data: bytes) -> LintData:
    document = load_json(data)
    if is_object(document):
        name = "sarif"
        issues = _sarif_issues(as_object(document, "lint report"))
    else:
        name = "json"
        issues = [_json_issue(raw) for raw in as_list(document, "lint report")]
    ordered = sorted(
        issues,
        key=lambda issue: (
            SEVERITY_ORDER.index(issue.severity),
            issue.rule_id,
            issue.path or "",
            issue.line or 0,
            issue.message,
        ),
    )
    return LintData(
        format=name,
        total=len(ordered),
        by_severity=severity_counts([issue.severity for issue in ordered]),
        issues=tuple(ordered[:MAX_DETAIL_ITEMS]),
        truncated=len(ordered) > MAX_DETAIL_ITEMS,
    )


def parse_lint(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[LintData]:
    """Parse ansible-lint SARIF 2.1.0 or JSON output. An empty issue list is a clean run."""
    return run_parser(path, "ansible_lint", max_bytes, _build)
