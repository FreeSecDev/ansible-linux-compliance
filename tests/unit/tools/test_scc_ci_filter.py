"""The SCC path filter and ``ci-gate`` (ADR 0019 decision 7, FREES-152).

``scc-changes`` runs the base revision's copy of ``tools/scc/needs-smoke.sh`` as a
separate ``bash`` process, so a pull request that edits the filter cannot exempt
itself. Anything but an exact ``false`` from it means the smoke test runs, and the
filter diffs with ``--no-renames``, so a rename out of an SCC path counts.
``ci-gate`` accepts a skipped ``scc-smoke`` only for a pull request or a merge group
whose filter output is exactly ``false``. The never-publish guard is in
``test_scc_image.py``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
FILTER_SCRIPT = REPOSITORY_ROOT / "tools" / "scc" / "needs-smoke.sh"
SMOKE_SCRIPT = REPOSITORY_ROOT / "tools" / "scc" / "smoke-test.sh"
FILTER_RELATIVE = "tools/scc/needs-smoke.sh"
FALSE_FILTER = "#!/usr/bin/env bash\nprintf 'false\\n'\n"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
TIMEOUT_SECONDS = 60


def run_script(
    arguments: list[str], environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        cwd=REPOSITORY_ROOT,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **(environment or {})},
    )


def gate_script() -> str:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    gate = cast("dict[str, dict[str, object]]", workflow["jobs"])["ci-gate"]
    steps = cast("list[dict[str, str]]", gate["steps"])
    assert len(steps) == 1
    return steps[0]["run"]


def git() -> str:
    path = shutil.which("git")
    assert path is not None, "git is required to run the path filter"
    return path


def gate_needs(changes: str, scc: str, smoke: str, other: str = "success") -> str:
    return json.dumps(
        {
            "lint": {"result": other, "outputs": {}},
            "scc-changes": {"result": changes, "outputs": {"scc": scc}},
            "scc-smoke": {"result": smoke, "outputs": {}},
        }
    )


@pytest.mark.parametrize(
    ("event", "needs", "passes"),
    [
        ("pull_request", ("success", "false", "skipped", "success"), True),
        ("pull_request", ("success", "true", "success", "success"), True),
        ("pull_request", ("success", "false", "success", "success"), True),
        ("pull_request", ("success", "true", "skipped", "success"), False),
        ("pull_request", ("success", "", "skipped", "success"), False),
        ("pull_request", ("failure", "false", "skipped", "success"), False),
        ("pull_request", ("success", "false", "skipped", "failure"), False),
        ("pull_request", ("success", "true", "failure", "success"), False),
        ("pull_request", ("success", "true", "cancelled", "success"), False),
        ("merge_group", ("success", "false", "skipped", "success"), True),
        ("merge_group", ("success", "true", "skipped", "success"), False),
        ("merge_group", ("success", "", "skipped", "success"), False),
        ("merge_group", ("failure", "false", "skipped", "success"), False),
        ("push", ("success", "false", "skipped", "success"), False),
        ("workflow_dispatch", ("success", "false", "skipped", "success"), False),
        ("schedule", ("success", "false", "skipped", "success"), False),
        ("merge_group", ("success", "true", "success", "success"), True),
        ("push", ("success", "true", "success", "success"), True),
    ],
)
def test_ci_gate_accepts_a_skipped_smoke_only_without_scc_changes_in_a_pr_or_the_queue(
    event: str, needs: tuple[str, str, str, str], passes: bool
) -> None:
    bash = shutil.which("bash")
    assert bash is not None
    assert shutil.which("jq") is not None, "jq is required to run the ci-gate script"
    result = run_script(
        [bash, "-euo", "pipefail", "-c", gate_script()],
        {"NEEDS": gate_needs(*needs), "EVENT_NAME": event},
    )
    assert (result.returncode == 0) is passes, result.stdout + result.stderr


def test_the_path_filter_runs_the_smoke_test_unless_a_pull_request_changes_nothing_scc() -> None:
    head = subprocess.run(
        [git(), "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
    ).stdout.strip()
    cases = [
        (["push", head, head], "true"),
        (["schedule", head, head], "true"),
        (["workflow_dispatch", head, head], "true"),
        (["pull_request", ""], "true"),
        (["pull_request", "not-a-sha"], "true"),
        (["pull_request", "0" * 40], "true"),
        (["pull_request", EMPTY_TREE], "true"),
        (["pull_request", head, "not-a-sha"], "true"),
        (["pull_request", head], "false"),
        (["pull_request", head, head], "false"),
        (["merge_group", head, head], "false"),
        (["merge_group", EMPTY_TREE, head], "true"),
        (["merge_group", head, ""], "true"),
        (["merge_group", head, "not-a-sha"], "true"),
        (["merge_group", "not-a-sha", head], "true"),
        (["merge_group", "", head], "true"),
        (["merge_group", "0" * 40, head], "true"),
        (["merge_group", head, "0" * 40], "true"),
    ]
    for arguments, expected in cases:
        result = run_script([str(FILTER_SCRIPT), *arguments])
        assert result.stdout.strip() == expected, (arguments, result.stdout, result.stderr)


def _isolated_git_environment(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "FREES-152 test",
        "GIT_AUTHOR_EMAIL": "frees-152@example.invalid",
        "GIT_COMMITTER_NAME": "FREES-152 test",
        "GIT_COMMITTER_EMAIL": "frees-152@example.invalid",
    }


def filter_step_script() -> str:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    job = cast("dict[str, dict[str, object]]", workflow["jobs"])["scc-changes"]
    steps = [
        step for step in cast("list[dict[str, str]]", job["steps"]) if step.get("id") == "filter"
    ]
    assert len(steps) == 1
    assert "shell" not in steps[0]
    assert "defaults" not in workflow
    assert "defaults" not in job
    assert job["runs-on"] == "ubuntu-24.04"
    return steps[0]["run"]


@dataclass
class _Scratch:
    root: Path

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            [git(), "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            env=_isolated_git_environment(self.root.parent),
        ).stdout.strip()

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "--all")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def run(self, arguments: list[str], environment: dict[str, str]) -> str:
        bash = shutil.which("bash")
        assert bash is not None
        result = subprocess.run(
            [bash, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            cwd=self.root,
            env={**_isolated_git_environment(self.root.parent), **environment},
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    def filter_step(self, event: str, base: str, head: str = "") -> str:
        output = self.root.parent / "github-output"
        output.write_text("", encoding="utf-8")
        self.run(
            ["--noprofile", "--norc", "-e", "-c", filter_step_script()],
            {"EVENT_NAME": event, "BASE_SHA": base, "HEAD_SHA": head, "GITHUB_OUTPUT": str(output)},
        )
        lines = output.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1, lines
        assert lines[0].startswith("scc=")
        return lines[0].removeprefix("scc=")


@pytest.fixture
def scratch(tmp_path: Path) -> _Scratch:
    repository = _Scratch(tmp_path / "repository")
    repository.root.mkdir()
    repository.git("init", "--quiet", "--initial-branch=main")
    repository.write(FILTER_RELATIVE, FILTER_SCRIPT.read_text(encoding="utf-8"))
    repository.write("tools/scc/smoke-test.sh", SMOKE_SCRIPT.read_text(encoding="utf-8"))
    repository.write("README.txt", "base\n")
    repository.commit("base")
    return repository


def test_the_path_filter_sees_a_rename_out_of_an_scc_path(scratch: _Scratch) -> None:
    base = scratch.git("rev-parse", "HEAD")
    (scratch.root / "other").mkdir()
    scratch.git("mv", "tools/scc/smoke-test.sh", "other/smoke.sh")
    head = scratch.commit("rename out of the SCC path")
    detected = scratch.git("-c", "diff.renames=true", "diff", "--name-only", base, head)
    assert detected == "other/smoke.sh"
    for arguments in (["pull_request", base], ["merge_group", base, head]):
        assert scratch.run([str(FILTER_SCRIPT), *arguments], {}) == "true"
    assert scratch.filter_step("pull_request", base) == "true"
    assert scratch.filter_step("merge_group", base, head) == "true"


def test_the_filter_step_skips_the_smoke_test_without_an_scc_change(scratch: _Scratch) -> None:
    base = scratch.git("rev-parse", "HEAD")
    scratch.write("README.txt", "changed\n")
    head = scratch.commit("unrelated change")
    assert scratch.filter_step("pull_request", base) == "false"
    assert scratch.filter_step("merge_group", base, head) == "false"
    for event in ("push", "schedule", "workflow_dispatch", "", "pull", "merge_grou"):
        assert scratch.filter_step(event, base, head) == "true"


@pytest.mark.parametrize(
    "relative",
    [
        "tools/reporting/checklist.py",
        "tools/reporting/checklist_export.py",
        "tools/reporting/checklist_formats.py",
        "tools/reporting/stig_content.py",
        "tools/reporting/stig_mapping.py",
        "tools/reporting/stig_compare.py",
        "content/stig-mapping.json",
        "extensions/ci/oscap/Containerfile",
        "docs/adr/0020-stig-viewer-checklist-export.md",
    ],
)
def test_a_change_to_the_checklist_exporter_runs_the_smoke_test(
    scratch: _Scratch, relative: str
) -> None:
    base = scratch.git("rev-parse", "HEAD")
    scratch.write(relative, "changed\n")
    head = scratch.commit("checklist exporter change")
    assert scratch.filter_step("pull_request", base) == "true"
    assert scratch.filter_step("merge_group", base, head) == "true"


def test_other_reporting_changes_do_not_run_the_smoke_test(scratch: _Scratch) -> None:
    base = scratch.git("rev-parse", "HEAD")
    scratch.write("tools/reporting/dashboard.py", "changed\n")
    head = scratch.commit("dashboard change")
    assert scratch.filter_step("merge_group", base, head) == "false"


def test_a_pull_request_cannot_exempt_itself_by_editing_the_filter(scratch: _Scratch) -> None:
    base = scratch.git("rev-parse", "HEAD")
    scratch.write(FILTER_RELATIVE, FALSE_FILTER)
    head = scratch.commit("the filter says false")
    assert scratch.run([FILTER_RELATIVE, "pull_request", base], {}) == "false"
    assert scratch.filter_step("pull_request", base) == "true"
    assert scratch.filter_step("merge_group", base, head) == "true"


def test_the_base_revision_filter_decides_until_a_change_is_merged(scratch: _Scratch) -> None:
    scratch.write(FILTER_RELATIVE, FALSE_FILTER)
    base = scratch.commit("a merged filter that says false")
    scratch.write(FILTER_RELATIVE, FILTER_SCRIPT.read_text(encoding="utf-8"))
    scratch.write("tools/scc/smoke-test.sh", "#!/bin/sh\nexit 0\n")
    head = scratch.commit("restore the filter and change an SCC path")
    assert scratch.run([FILTER_RELATIVE, "pull_request", base], {}) == "true"
    assert scratch.filter_step("pull_request", base) == "false"
    assert scratch.filter_step("merge_group", base, head) == "false"


@pytest.mark.parametrize(
    "base_filter",
    [
        None,
        "#!/usr/bin/env bash\nprintf 'false\\n'\nexit 3\n",
        "#!/usr/bin/env bash\nprintf 'fals\\n'\n",
        "#!/usr/bin/env bash\nprintf ''\n",
        "#!/usr/bin/env bash\nprintf 'false\\nfalse\\n'\n",
    ],
)
def test_the_filter_step_fails_safe_without_a_usable_base_filter(
    scratch: _Scratch, base_filter: str | None
) -> None:
    if base_filter is None:
        scratch.git("rm", "--quiet", FILTER_RELATIVE)
    else:
        scratch.write(FILTER_RELATIVE, base_filter)
    base = scratch.commit("base filter")
    scratch.write(FILTER_RELATIVE, FALSE_FILTER)
    scratch.write("README.txt", "changed\n")
    head = scratch.commit("the pull request")
    assert scratch.filter_step("pull_request", base) == "true"
    assert scratch.filter_step("merge_group", base, head) == "true"


@pytest.mark.parametrize("base", ["", "not-a-sha", "0" * 40, "HEAD", "main", "HEAD~1"])
def test_the_filter_step_fails_safe_without_a_valid_base_sha(scratch: _Scratch, base: str) -> None:
    scratch.write(FILTER_RELATIVE, FALSE_FILTER)
    head = scratch.commit("the pull request")
    assert scratch.filter_step("pull_request", base) == "true"
    assert scratch.filter_step("merge_group", base, head) == "true"


def test_the_filter_step_runs_the_base_filter_as_a_separate_bash_process() -> None:
    script = filter_step_script()
    assert 'git show "$BASE_SHA:tools/scc/needs-smoke.sh" > "$filter"' in script
    assert 'bash "$filter"' in script
    assert not re.search(r"(?:^|[\s;&|(])(?:source|\.)\s", script)
    assert "| bash" not in script


@pytest.mark.parametrize(
    ("event", "scc", "smoke"),
    [
        ("pull_request", "", "success"),
        ("pull_request", "ru", "success"),
        ("pull_request", "fals", "success"),
        ("pull_request", "ru", "skipped"),
        ("pull_request", "fals", "skipped"),
        ("", "false", "skipped"),
        ("pull", "false", "skipped"),
        ("merge", "false", "skipped"),
        ("merge_grou", "false", "skipped"),
        ("_", "false", "skipped"),
        ("pull_requests", "false", "skipped"),
    ],
)
def test_ci_gate_matches_the_event_and_the_filter_output_exactly(
    event: str, scc: str, smoke: str
) -> None:
    bash = shutil.which("bash")
    assert bash is not None
    result = run_script(
        [bash, "-euo", "pipefail", "-c", gate_script()],
        {"NEEDS": gate_needs("success", scc, smoke), "EVENT_NAME": event},
    )
    assert result.returncode != 0, result.stdout + result.stderr


def test_ci_gate_uses_no_substring_matching() -> None:
    script = gate_script()
    assert "inside(" not in script
    assert "contains(" not in script
    assert 'IN("true", "false")' in script
    assert 'IN("pull_request", "merge_group")' in script
