"""The workflows that can write issues, and the permission forms the guard refuses (FREES-149).

Only the scheduled SCC release watch may write issues (ADR 0019, FREES-176). A permission
written as a string (``write-all``, ``read-all``) hides what a job can do, and a write at
workflow level reaches every job that does not set its own permissions, so both are refused.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIRECTORY = REPOSITORY_ROOT / ".github" / "workflows"
WATCH_JOB = "scc-release-watch.yml:scc-release-watch"
WRITES = " can write issues"


def permission_findings(name: str, text: str) -> list[str]:
    """Name every job that can write issues, and every permission form the guard refuses.

    Refused are permissions written as a string (``write-all``, ``read-all``) at either
    level, and any ``write`` at workflow level. A job without its own ``permissions`` that
    inherits an issue write is a writer too.
    """
    workflow = cast("dict[str, object]", yaml.safe_load(text))
    top = workflow.get("permissions", {})
    findings: list[str] = []
    top_writes_issues = False
    if isinstance(top, str):
        findings.append(f"{name}: string-form workflow permissions")
    else:
        top_permissions = cast("dict[str, str]", top)
        if "write" in top_permissions.values():
            findings.append(f"{name}: workflow-level write permissions")
        top_writes_issues = top_permissions.get("issues") == "write"
    for job_name, job in cast("dict[str, dict[str, object]]", workflow["jobs"]).items():
        own = job.get("permissions")
        if isinstance(own, str):
            findings.append(f"{name}:{job_name}: string-form job permissions")
        elif "issues" in cast("dict[str, str]", own or {}) or (own is None and top_writes_issues):
            findings.append(f"{name}:{job_name} can write issues")
    return findings


@pytest.mark.parametrize(
    ("header", "job_permissions", "expected"),
    [
        ("permissions: {}", "permissions: {contents: read}", []),
        ("permissions: {}", "permissions: {issues: write}", ["w.yml:j can write issues"]),
        (
            "permissions: write-all",
            "permissions: {contents: read}",
            ["w.yml: string-form workflow permissions"],
        ),
        (
            "permissions: read-all",
            "permissions: {contents: read}",
            ["w.yml: string-form workflow permissions"],
        ),
        (
            "permissions: {contents: write}",
            "permissions: {contents: read}",
            ["w.yml: workflow-level write permissions"],
        ),
        (
            "permissions: {issues: write}",
            "permissions: {contents: read}",
            ["w.yml: workflow-level write permissions"],
        ),
        (
            "permissions: {issues: write}",
            "runs-on: x",
            ["w.yml: workflow-level write permissions", "w.yml:j can write issues"],
        ),
        ("permissions: {}", "permissions: write-all", ["w.yml:j: string-form job permissions"]),
        ("permissions: {}", "permissions: read-all", ["w.yml:j: string-form job permissions"]),
    ],
)
def test_the_writers_check_refuses_string_form_and_workflow_level_write_permissions(
    header: str, job_permissions: str, expected: list[str]
) -> None:
    text = f"on: push\n{header}\njobs:\n  j:\n    {job_permissions}\n"
    assert permission_findings("w.yml", text) == expected


def test_only_the_release_watch_job_can_write_issues_and_no_workflow_widens_permissions() -> None:
    writers: list[str] = []
    for path in sorted(WORKFLOW_DIRECTORY.glob("*.y*ml")):
        found = permission_findings(path.name, path.read_text(encoding="utf-8"))
        assert [item for item in found if not item.endswith(WRITES)] == []
        writers += [item.removesuffix(WRITES) for item in found]
    assert writers == [WATCH_JOB]
