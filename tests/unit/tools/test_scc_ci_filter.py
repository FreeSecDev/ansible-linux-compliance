"""The SCC path filter and ``ci-gate`` (ADR 0019 decision 7, FREES-152).

``scc-changes`` runs the base revision's copy of ``tools/scc/needs-smoke.sh`` as a
separate ``bash`` process, so a pull request that edits the filter cannot exempt
itself. Anything but an exact ``false`` from it means the smoke test runs, and the
filter diffs with ``--no-renames``, so a rename out of an SCC path counts.
``ci-gate`` accepts a skipped ``scc-smoke`` only for a pull request or a merge group
whose filter output is exactly ``false``, or whose expiry output is exactly
``expired`` (FREES-176). That output comes from the base revision's
``tools/scc/expiry-state.sh`` and pins, so a pull request cannot fabricate an expiry,
and it is ``expired`` only while both pins name the same release past its hard stop,
so a newer pin is smoke-tested again. The gate then names the skip in a warning. The
never-publish guard is in ``test_scc_image.py``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import date, timedelta
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


def gate_needs(
    changes: str, scc: str, smoke: str, other: str = "success", expiry: str | None = "current"
) -> str:
    outputs = {"scc": scc} if expiry is None else {"scc": scc, "expiry": expiry}
    return json.dumps(
        {
            "lint": {"result": other, "outputs": {}},
            "scc-changes": {"result": changes, "outputs": outputs},
            "scc-smoke": {"result": smoke, "outputs": {}},
            "molecule-plan": {
                "result": "success",
                "outputs": {"scope": "full", "lifecycle_legs": "1"},
            },
            "molecule-lifecycle": {"result": "success", "outputs": {}},
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


EXPIRY_STATE = REPOSITORY_ROOT / "tools" / "scc" / "expiry-state.sh"
EXPIRY_RELATIVE = "tools/scc/expiry-state.sh"
PINS_RELATIVE = "extensions/ci/scc/scc.pins"
PINS = REPOSITORY_ROOT / PINS_RELATIVE
CHECK_EXPIRY = REPOSITORY_ROOT / "tools" / "scc" / "check-expiry.sh"
EXPIRED_STATE = "#!/usr/bin/env bash\nprintf 'expired\\n'\n"
WARNING = "::warning title=SCC not built or run::"


def pins_text(version: str = "5.15", expires: str = "2026-11-25") -> str:
    return f"SCC_VERSION := {version}\nSCC_PUBLISHED := 2026-09-09\nSCC_EXPIRES := {expires}\n"


def expiry_state(base: Path, head: Path, today: str | None = None) -> str:
    bash = shutil.which("bash")
    assert bash is not None
    arguments = [bash, str(EXPIRY_STATE), str(base), str(head)]
    result = run_script(arguments if today is None else [*arguments, today])
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    return result.stdout


@pytest.mark.parametrize(
    ("event", "scc", "smoke", "expiry", "passes"),
    [
        ("pull_request", "true", "skipped", "expired", True),
        ("merge_group", "true", "skipped", "expired", True),
        ("pull_request", "false", "skipped", "expired", True),
        ("pull_request", "true", "success", "expired", True),
        ("push", "true", "skipped", "expired", False),
        ("schedule", "true", "skipped", "expired", False),
        ("workflow_dispatch", "true", "skipped", "expired", False),
        ("pull_request", "true", "failure", "expired", False),
        ("merge_group", "true", "cancelled", "expired", False),
        ("pull_request", "true", "skipped", "current", False),
        ("merge_group", "true", "skipped", "current", False),
        ("pull_request", "true", "skipped", "", False),
        ("pull_request", "true", "skipped", "expire", False),
        ("pull_request", "true", "skipped", "expired ", False),
        ("pull_request", "false", "skipped", "", False),
        ("pull_request", "true", "skipped", None, False),
        ("pull_request", "false", "skipped", None, False),
        ("pull_request", "true", "success", None, False),
    ],
)
def test_ci_gate_accepts_an_expired_skip_only_in_a_pr_or_the_queue(
    event: str, scc: str, smoke: str, expiry: str | None, passes: bool
) -> None:
    bash = shutil.which("bash")
    assert bash is not None
    result = run_script(
        [bash, "-euo", "pipefail", "-c", gate_script()],
        {"NEEDS": gate_needs("success", scc, smoke, expiry=expiry), "EVENT_NAME": event},
    )
    assert (result.returncode == 0) is passes, result.stdout + result.stderr
    named = passes and scc == "true" and smoke == "skipped" and expiry == "expired"
    assert (WARNING in result.stdout) is named, result.stdout


def test_the_gate_names_the_expired_skip_and_never_calls_it_a_pass() -> None:
    script = gate_script()
    assert 'IN("current", "expired")' in script
    assert "skipped, not passed" in script
    assert "neither built nor run" in script


@pytest.mark.parametrize(
    ("today", "state"),
    [
        ("2026-10-30", "current"),
        ("2026-11-17", "current"),
        ("2026-11-18", "expired"),
        ("2026-11-25", "expired"),
        ("2026-11-26", "expired"),
        ("2027-06-01", "expired"),
    ],
)
def test_the_expiry_state_turns_on_the_hard_stop_day(
    tmp_path: Path, today: str, state: str
) -> None:
    pins = tmp_path / "scc.pins"
    pins.write_text(pins_text(), encoding="utf-8")
    assert expiry_state(pins, pins, today) == f"{state}\n"


def test_the_expiry_state_of_the_tracked_pins_matches_the_expiry_check() -> None:
    expires = date.fromisoformat(
        next(
            line.split(" := ", 1)[1]
            for line in PINS.read_text(encoding="utf-8").splitlines()
            if line.startswith("SCC_EXPIRES := ")
        )
    )
    stop = expires - timedelta(days=7)
    for today, state in ((stop - timedelta(days=1), "current"), (stop, "expired")):
        assert expiry_state(PINS, PINS, today.isoformat()) == f"{state}\n"
        result = run_script([str(CHECK_EXPIRY), expires.isoformat(), today.isoformat()])
        assert (result.returncode == 0) is (state == "current"), result.stderr


@pytest.mark.parametrize(
    ("base", "head"),
    [
        (pins_text(), pins_text("5.16", "2027-03-01")),
        (pins_text(), pins_text("5.16", "2026-11-25")),
        (pins_text(), pins_text("5.15", "2027-03-01")),
        (pins_text("5.15", "2027-03-01"), pins_text()),
        (pins_text(), pins_text() + "SCC_BUNDLE_SHA256 := " + "0" * 64 + "\n"),
        (
            pins_text() + "SCC_DEB_SHA256 := " + "a" * 64 + "\n",
            pins_text() + "SCC_DEB_SHA256 := " + "b" * 64 + "\n",
        ),
        (pins_text() + "SCC_CONTENT_FILE := a.zip\n", pins_text() + "SCC_CONTENT_FILE := b.zip\n"),
        (pins_text() + "SCC_SIZE := 1\n", pins_text() + "SCC_SIZE := 2\n"),
        (pins_text(), pins_text() + "\n"),
        (pins_text(), pins_text() + "SCC_VERSION := 5.15\n"),
        (pins_text() + "SCC_EXPIRES := 2026-11-25\n", pins_text()),
        (pins_text("5.15; true"), pins_text("5.15; true")),
        (pins_text("5"), pins_text("5")),
        (pins_text(expires="2026-11-31"), pins_text(expires="2026-11-31")),
        (pins_text(expires="25.11.2026"), pins_text(expires="25.11.2026")),
        ("", pins_text()),
        (pins_text(), ""),
    ],
)
def test_the_expiry_state_is_current_unless_both_pins_name_the_same_expired_release(
    tmp_path: Path, base: str, head: str
) -> None:
    (tmp_path / "base").write_text(base, encoding="utf-8")
    (tmp_path / "head").write_text(head, encoding="utf-8")
    assert expiry_state(tmp_path / "base", tmp_path / "head", "2026-11-20") == "current\n"


def test_the_expiry_state_requires_byte_identical_pins(tmp_path: Path) -> None:
    pins = pins_text() + "SCC_CONTENT_SHA256 := " + "c" * 64 + "\n"
    (tmp_path / "base").write_text(pins, encoding="utf-8")
    (tmp_path / "head").write_text(pins, encoding="utf-8")
    assert expiry_state(tmp_path / "base", tmp_path / "head", "2026-11-20") == "expired\n"
    (tmp_path / "head").write_text(pins.replace("c" * 64, "d" * 64), encoding="utf-8")
    assert expiry_state(tmp_path / "base", tmp_path / "head", "2026-11-20") == "current\n"


def test_the_expiry_state_fails_safe_without_usable_inputs(tmp_path: Path) -> None:
    pins = tmp_path / "scc.pins"
    pins.write_text(pins_text(), encoding="utf-8")
    link = tmp_path / "link.pins"
    link.symlink_to(pins)
    assert expiry_state(pins, pins, "2026-11-20") == "expired\n"
    for base, head, today in (
        (pins, tmp_path / "missing", "2026-11-20"),
        (tmp_path / "missing", pins, "2026-11-20"),
        (link, pins, "2026-11-20"),
        (pins, link, "2026-11-20"),
        (tmp_path, pins, "2026-11-20"),
        (pins, pins, "2026-02-30"),
        (pins, pins, "tomorrow"),
        (pins, pins, "2026-11-20; true"),
    ):
        assert expiry_state(base, head, today) == "current\n", (base, head, today)
    bash = shutil.which("bash")
    assert bash is not None
    assert run_script([bash, str(EXPIRY_STATE)]).stdout == "current\n"


def expiry_step_script() -> str:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    job = cast("dict[str, dict[str, object]]", workflow["jobs"])["scc-changes"]
    steps = [
        step for step in cast("list[dict[str, str]]", job["steps"]) if step.get("id") == "expiry"
    ]
    assert len(steps) == 1
    assert "shell" not in steps[0]
    outputs = cast("dict[str, str]", job["outputs"])
    assert outputs["expiry"] == "${{ steps.expiry.outputs.expiry }}"
    return steps[0]["run"]


def run_expiry_step(scratch: _Scratch, event: str, base: str) -> str:
    output = scratch.root.parent / "github-output"
    output.write_text("", encoding="utf-8")
    scratch.run(
        ["--noprofile", "--norc", "-e", "-c", expiry_step_script()],
        {"EVENT_NAME": event, "BASE_SHA": base, "GITHUB_OUTPUT": str(output)},
    )
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, lines
    assert lines[0].startswith("expiry=")
    return lines[0].removeprefix("expiry=")


def expiry_base(scratch: _Scratch, pins: str, state: str | None = None) -> str:
    script = EXPIRY_STATE.read_text(encoding="utf-8") if state is None else state
    scratch.write(EXPIRY_RELATIVE, script)
    scratch.write(PINS_RELATIVE, pins)
    return scratch.commit("base pins")


def test_an_expired_base_pin_skips_the_smoke_test_in_a_pr_and_the_queue(
    scratch: _Scratch,
) -> None:
    base = expiry_base(scratch, pins_text(expires="2020-01-01"))
    scratch.write("tools/scc/smoke-test.sh", "#!/bin/sh\nexit 0\n")
    scratch.commit("an SCC change without a newer pin")
    assert run_expiry_step(scratch, "pull_request", base) == "expired"
    assert run_expiry_step(scratch, "merge_group", base) == "expired"
    for event in ("push", "schedule", "workflow_dispatch", "", "pull", "merge_grou"):
        assert run_expiry_step(scratch, event, base) == "current"


def test_a_newer_pin_runs_the_smoke_test_again(scratch: _Scratch) -> None:
    base = expiry_base(scratch, pins_text(expires="2020-01-01"))
    scratch.write(PINS_RELATIVE, pins_text("5.16", "2099-01-01"))
    scratch.commit("bump the pin")
    assert run_expiry_step(scratch, "pull_request", base) == "current"
    assert run_expiry_step(scratch, "merge_group", base) == "current"


def test_a_pull_request_cannot_fabricate_an_expiry(scratch: _Scratch) -> None:
    base = expiry_base(scratch, pins_text(expires="2099-01-01"))
    scratch.write(PINS_RELATIVE, pins_text(expires="2020-01-01"))
    scratch.write(EXPIRY_RELATIVE, EXPIRED_STATE)
    scratch.commit("claim that the pin expired")
    assert run_expiry_step(scratch, "pull_request", base) == "current"
    assert run_expiry_step(scratch, "merge_group", base) == "current"


@pytest.mark.parametrize(
    "state",
    [
        None,
        "#!/usr/bin/env bash\nprintf 'expired\\n'\nexit 3\n",
        "#!/usr/bin/env bash\nprintf 'expire\\n'\n",
        "#!/usr/bin/env bash\nprintf 'expired\\nexpired\\n'\n",
        "#!/usr/bin/env bash\nprintf ''\n",
    ],
)
def test_the_expiry_step_fails_safe_without_a_usable_base_script(
    scratch: _Scratch, state: str | None
) -> None:
    if state is None:
        scratch.write(PINS_RELATIVE, pins_text(expires="2020-01-01"))
        base = scratch.commit("no expiry script on the base")
    else:
        base = expiry_base(scratch, pins_text(expires="2020-01-01"), state)
    scratch.write(EXPIRY_RELATIVE, EXPIRED_STATE)
    scratch.commit("the pull request")
    assert run_expiry_step(scratch, "pull_request", base) == "current"
    assert run_expiry_step(scratch, "merge_group", base) == "current"


def test_the_expiry_step_fails_safe_without_base_pins(scratch: _Scratch) -> None:
    scratch.write(EXPIRY_RELATIVE, EXPIRY_STATE.read_text(encoding="utf-8"))
    base = scratch.commit("no pins on the base")
    scratch.write(PINS_RELATIVE, pins_text(expires="2020-01-01"))
    scratch.commit("the pull request")
    assert run_expiry_step(scratch, "pull_request", base) == "current"


@pytest.mark.parametrize("base", ["", "not-a-sha", "0" * 40, "HEAD", "main"])
def test_the_expiry_step_fails_safe_without_a_valid_base_sha(scratch: _Scratch, base: str) -> None:
    expiry_base(scratch, pins_text(expires="2020-01-01"))
    assert run_expiry_step(scratch, "pull_request", base) == "current"
    assert run_expiry_step(scratch, "merge_group", base) == "current"


def test_the_expiry_step_runs_the_base_script_as_a_separate_bash_process() -> None:
    script = expiry_step_script()
    assert 'git show "$BASE_SHA:tools/scc/expiry-state.sh" > "$state"' in script
    assert 'git show "$BASE_SHA:extensions/ci/scc/scc.pins" > "$pins"' in script
    assert 'bash "$state" "$pins" extensions/ci/scc/scc.pins' in script
    assert not re.search(r"(?:^|[\s;&|(])(?:source|\.)\s", script)
    assert "| bash" not in script
