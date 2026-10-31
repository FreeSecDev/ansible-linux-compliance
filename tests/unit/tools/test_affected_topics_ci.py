"""The affected-legs plan of ``molecule-plan`` and its check in ``ci-gate`` (FREES-189).

``molecule-plan`` plans the full matrices with the head revision's ``make molecule-matrix``, then
runs the base revision's copy of ``tools/molecule/plan-lifecycle.sh`` as a separate ``bash``
process, which runs the base revision's ``make molecule-affected`` over the head checkout. The
step uses its answer only when it is a well-formed plan whose legs all come from the full
matrices and that keeps every leg without a topic; anything else, any other event and a base
revision without the planner run the full matrices. ``ci-gate`` accepts a skipped
``molecule-lifecycle`` only for a pull request or a merge group whose plan has the scope
``affected`` and exactly zero lifecycle legs, and accepts the scope ``affected`` only for those
events.

The tests run the script and the step scripts of ``ci.yml`` with bash, git and jq in a scratch
Git repository, with a fake ``make`` that records what it was asked to run.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
PLANNER = REPOSITORY_ROOT / "tools" / "molecule" / "plan-lifecycle.sh"
PLANNER_RELATIVE = "tools/molecule/plan-lifecycle.sh"
TIMEOUT_SECONDS = 60
UBUNTU_BASE = {"platform": "ubuntu", "scenario": "libvirt-ubuntu", "topic": "", "mode": ""}
SELFTEST = {"platform": "ubuntu", "scenario": "libvirt-selftest", "topic": "", "mode": ""}
SUDO_TOPIC = {
    "platform": "ubuntu",
    "scenario": "docker-ubuntu-lifecycle",
    "topic": "sudo",
    "mode": "topic",
}
SUDO_RULE = {
    "platform": "ubuntu",
    "scenario": "docker-ubuntu-lifecycle",
    "topic": "sudo",
    "mode": "rule",
}
BANNERS_TOPIC = {
    "platform": "ubuntu",
    "scenario": "docker-ubuntu-lifecycle",
    "topic": "banners",
    "mode": "topic",
}
DOCKER = {"include": [SUDO_TOPIC, SUDO_RULE, BANNERS_TOPIC]}
LIBVIRT = {"include": [UBUNTU_BASE, SELFTEST]}
FAKE_MAKE = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$FAKE_RECORD/arguments"
ls -A "$2" > "$FAKE_RECORD/listing"
for argument in "$@"; do
  case "$argument" in
    MOLECULE_AFFECTED_CHANGED=*) tr '\\0' '\\n' < "${argument#*=}" > "$FAKE_RECORD/changed" ;;
  esac
done
printf '%s\\n' "${FAKE_OUTPUT:-planned}"
exit "${FAKE_STATUS:-0}"
"""


def executable(name: str) -> str:
    path = shutil.which(name)
    assert path is not None, f"{name} is required for these tests"
    return path


def _environment(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "FREES-189 test",
        "GIT_AUTHOR_EMAIL": "frees-189@example.invalid",
        "GIT_COMMITTER_NAME": "FREES-189 test",
        "GIT_COMMITTER_EMAIL": "frees-189@example.invalid",
    }


def jobs() -> dict[str, dict[str, object]]:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    return cast("dict[str, dict[str, object]]", workflow["jobs"])


def plan_step() -> str:
    steps = cast("list[dict[str, str]]", jobs()["molecule-plan"]["steps"])
    found = [step for step in steps if step.get("id") == "plan"]
    assert len(found) == 1
    assert "shell" not in found[0]
    return found[0]["run"]


def gate_script() -> str:
    steps = cast("list[dict[str, str]]", jobs()["ci-gate"]["steps"])
    assert len(steps) == 1
    return steps[0]["run"]


@dataclass
class Scratch:
    """A scratch Git repository with a fake make on the PATH that records its arguments."""

    root: Path

    @property
    def home(self) -> Path:
        return self.root.parent

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            [executable("git"), "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            env=_environment(self.home),
        ).stdout.strip()

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "--all")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def bash(
        self, arguments: list[str], environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        base = _environment(self.home)
        bin_directory = self.home / "bin"
        base["PATH"] = f"{bin_directory}:{base['PATH']}"
        return subprocess.run(
            [executable("bash"), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            cwd=self.root,
            env={**base, **environment},
        )

    def record(self, name: str) -> str:
        return (self.home / "record" / name).read_text(encoding="utf-8")


@pytest.fixture
def scratch(tmp_path: Path) -> Scratch:
    repository = Scratch(tmp_path / "repository")
    repository.root.mkdir()
    (tmp_path / "record").mkdir()
    (tmp_path / "bin").mkdir()
    make = tmp_path / "bin" / "make"
    make.write_text(FAKE_MAKE, encoding="utf-8")
    make.chmod(0o755)
    repository.git("init", "--quiet", "--initial-branch=main")
    repository.write(PLANNER_RELATIVE, PLANNER.read_text(encoding="utf-8"))
    repository.write("base-only.txt", "base\n")
    repository.write("moved/file.txt", "moved\n")
    repository.commit("base")
    return repository


def write_matrices(directory: Path) -> tuple[Path, Path]:
    docker = directory / "docker.json"
    libvirt = directory / "libvirt.json"
    docker.write_text(json.dumps(DOCKER), encoding="utf-8")
    libvirt.write_text(json.dumps(LIBVIRT), encoding="utf-8")
    return docker, libvirt


def run_planner(
    scratch: Scratch, arguments: list[str], environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    docker, libvirt = write_matrices(scratch.home)
    return scratch.bash(
        [PLANNER_RELATIVE, *arguments[:3], *(arguments[3:] or [str(docker), str(libvirt)])],
        {"FAKE_RECORD": str(scratch.home / "record"), **(environment or {})},
    )


def test_the_planner_runs_the_base_revision_s_make_target_over_the_head(scratch: Scratch) -> None:
    base = scratch.git("rev-parse", "HEAD")
    (scratch.root / "base-only.txt").unlink()
    scratch.write("head-only.txt", "head\n")
    scratch.git("mv", "moved/file.txt", "renamed.txt")
    head = scratch.commit("head")
    for arguments in (
        ["pull_request", base, ""],
        ["pull_request", base, head],
        ["merge_group", base, head],
    ):
        result = run_planner(scratch, arguments)
        assert result.returncode == 0, result.stderr
        assert result.stdout == "planned\n"
        recorded = scratch.record("arguments").splitlines()
        assert recorded[0] == "-C"
        assert recorded[2:5] == ["--no-print-directory", "-s", "molecule-affected"]
        assert f"MOLECULE_AFFECTED_HEAD={scratch.root}" in recorded
        assert any(item.startswith("MOLECULE_AFFECTED_DOCKER=/") for item in recorded)
        assert any(item.startswith("MOLECULE_AFFECTED_LIBVIRT=/") for item in recorded)
        listing = scratch.record("listing").split()
        assert "base-only.txt" in listing
        assert "head-only.txt" not in listing
        assert ".git" not in listing
        assert sorted(scratch.record("changed").split()) == [
            "base-only.txt",
            "head-only.txt",
            "moved/file.txt",
            "renamed.txt",
        ]
    assert not list(scratch.home.glob("tmp.*"))


@pytest.mark.parametrize(
    ("event", "base", "head", "message"),
    [
        ("push", "base", "head", "the push event always runs the full matrix"),
        ("schedule", "base", "head", "the schedule event"),
        ("workflow_dispatch", "base", "head", "the workflow_dispatch event"),
        ("", "base", "head", "the unnamed event"),
        ("pull_request", "not-a-sha", "", "the base revision is not a commit SHA"),
        ("pull_request", "", "", "the base revision is not a commit SHA"),
        ("merge_group", "base", "", "the head revision is not a commit SHA"),
        ("merge_group", "base", "not-a-sha", "the head revision is not a commit SHA"),
        ("pull_request", "base", "0" * 40, "the checkout is not the head revision"),
        ("pull_request", "0" * 40, "", "the base revision is not in the clone"),
    ],
)
def test_the_planner_refuses_anything_but_a_pull_request_or_queue_of_known_revisions(
    scratch: Scratch, event: str, base: str, head: str, message: str
) -> None:
    sha = scratch.git("rev-parse", "HEAD")
    values = {"base": sha, "head": sha}
    result = run_planner(scratch, [event, values.get(base, base), values.get(head, head)])
    assert result.returncode == 1
    assert message in result.stderr
    assert "plan the full matrix" in result.stderr
    assert result.stdout == ""


def test_the_planner_refuses_missing_matrices_and_a_failing_base_planner(scratch: Scratch) -> None:
    sha = scratch.git("rev-parse", "HEAD")
    result = run_planner(scratch, ["pull_request", sha, sha, "missing.json", "missing.json"])
    assert result.returncode == 1
    assert "usage: plan-lifecycle.sh" in result.stderr
    result = run_planner(scratch, ["pull_request", sha, sha], {"FAKE_STATUS": "2"})
    assert result.returncode == 1
    assert "the base revision's planner failed" in result.stderr


def full_plan() -> dict[str, object]:
    return {
        "scope": "full",
        "topics": [],
        "reasons": ["the full matrix runs"],
        "docker": DOCKER,
        "libvirt": LIBVIRT,
    }


def affected_plan(docker: list[dict[str, str]], libvirt: list[dict[str, str]]) -> dict[str, object]:
    return {
        "scope": "affected",
        "topics": sorted({leg["topic"] for leg in docker if leg["topic"]}),
        "reasons": ["roles/remediate/tasks/sudo.yml: topic file: sudo"],
        "lifecycle_legs": len(docker),
        "docker": {"include": docker},
        "libvirt": {"include": libvirt},
    }


def fake_base_planner(output: str, status: int = 0) -> str:
    return f"#!/usr/bin/env bash\ncat <<'PLAN'\n{output}\nPLAN\nexit {status}\n"


def run_step(scratch: Scratch, event: str, base: str, head: str = "") -> dict[str, str]:
    runner = scratch.home / "runner"
    runner.mkdir(exist_ok=True)
    write_matrices(runner)
    output = scratch.home / "github-output"
    output.write_text("", encoding="utf-8")
    result = scratch.bash(
        ["--noprofile", "--norc", "-e", "-c", plan_step()],
        {
            "EVENT_NAME": event,
            "BASE_SHA": base,
            "HEAD_SHA": head,
            "BASE_REF": "refs/heads/main" if event == "merge_group" else "",
            "RUNNER_TEMP": str(runner),
            "GITHUB_OUTPUT": str(output),
        },
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("scope: ")
    found: dict[str, str] = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        found[key] = value
    assert set(found) == {"matrix", "libvirt", "scope", "lifecycle_legs"}
    return found


def assert_full(found: dict[str, str]) -> None:
    assert found["scope"] == "full"
    assert json.loads(found["matrix"]) == DOCKER
    assert json.loads(found["libvirt"]) == LIBVIRT
    assert found["lifecycle_legs"] == str(len(DOCKER["include"]))


def commit_base_planner(scratch: Scratch, plan: object, status: int = 0) -> str:
    text = plan if isinstance(plan, str) else json.dumps(plan)
    scratch.write(PLANNER_RELATIVE, fake_base_planner(text, status))
    return scratch.commit("base planner")


def test_the_step_keeps_the_legs_that_the_base_planner_selects(scratch: Scratch) -> None:
    base = commit_base_planner(
        scratch, affected_plan([SUDO_TOPIC, SUDO_RULE], [UBUNTU_BASE, SELFTEST])
    )
    head = scratch.commit("head")
    scratch.git("update-ref", "refs/remotes/origin/main", base)
    for event, head_sha in (("pull_request", ""), ("merge_group", head)):
        found = run_step(scratch, event, base, head_sha)
        assert found["scope"] == "affected"
        assert json.loads(found["matrix"]) == {"include": [SUDO_TOPIC, SUDO_RULE]}
        assert json.loads(found["libvirt"]) == LIBVIRT
        assert found["lifecycle_legs"] == "2"


def test_the_queue_decides_with_the_planner_and_diff_of_the_target_branch(scratch: Scratch) -> None:
    main = commit_base_planner(scratch, full_plan())
    scratch.git("update-ref", "refs/remotes/origin/main", main)
    earlier = commit_base_planner(scratch, affected_plan([], [UBUNTU_BASE, SELFTEST]))
    head = scratch.commit("a later pull request in the queue")
    assert_full(run_step(scratch, "merge_group", earlier, head))
    scratch.git("update-ref", "-d", "refs/remotes/origin/main")
    assert_full(run_step(scratch, "merge_group", earlier, head))
    scratch.git("update-ref", "refs/remotes/origin/main", earlier)
    found = run_step(scratch, "merge_group", main, head)
    assert found["scope"] == "affected"


def test_the_step_may_plan_no_lifecycle_leg(scratch: Scratch) -> None:
    base = commit_base_planner(scratch, affected_plan([], [UBUNTU_BASE, SELFTEST]))
    found = run_step(scratch, "pull_request", base)
    assert found["scope"] == "affected"
    assert json.loads(found["matrix"]) == {"include": []}
    assert found["lifecycle_legs"] == "0"


@pytest.mark.parametrize(
    "plan",
    [
        affected_plan([SUDO_TOPIC, {**SUDO_RULE, "mode": "invented"}], [UBUNTU_BASE, SELFTEST]),
        affected_plan([SUDO_TOPIC], [SELFTEST]),
        affected_plan([SUDO_TOPIC], [UBUNTU_BASE]),
        {**affected_plan([SUDO_TOPIC], [UBUNTU_BASE, SELFTEST]), "scope": "partial"},
        {**affected_plan([SUDO_TOPIC], [UBUNTU_BASE, SELFTEST]), "topics": "sudo"},
        {**affected_plan([SUDO_TOPIC], [UBUNTU_BASE, SELFTEST]), "reasons": None},
        {**affected_plan([SUDO_TOPIC], [UBUNTU_BASE, SELFTEST]), "docker": {"include": "legs"}},
        {**affected_plan([SUDO_TOPIC], [UBUNTU_BASE, SELFTEST]), "libvirt": {}},
        {**full_plan(), "docker": {"include": [SUDO_TOPIC]}},
        "not json",
        "",
    ],
)
def test_the_step_runs_the_full_matrix_unless_the_plan_is_a_subset_that_keeps_the_standard_legs(
    scratch: Scratch, plan: object
) -> None:
    base = commit_base_planner(scratch, plan)
    assert_full(run_step(scratch, "pull_request", base))


def test_the_step_runs_the_full_matrix_when_the_base_planner_fails(scratch: Scratch) -> None:
    base = commit_base_planner(scratch, affected_plan([SUDO_TOPIC], [UBUNTU_BASE, SELFTEST]), 1)
    assert_full(run_step(scratch, "pull_request", base))


def test_the_step_accepts_a_full_plan_from_the_base_planner(scratch: Scratch) -> None:
    base = commit_base_planner(scratch, full_plan())
    assert_full(run_step(scratch, "pull_request", base))


@pytest.mark.parametrize(
    "event", ["push", "schedule", "workflow_dispatch", "", "pull", "merge_grou"]
)
def test_other_events_always_run_the_full_matrix(scratch: Scratch, event: str) -> None:
    base = commit_base_planner(scratch, affected_plan([], [UBUNTU_BASE, SELFTEST]))
    assert_full(run_step(scratch, event, base, base))


@pytest.mark.parametrize("base", ["", "not-a-sha", "0" * 40])
def test_an_unusable_base_revision_runs_the_full_matrix(scratch: Scratch, base: str) -> None:
    commit_base_planner(scratch, affected_plan([], [UBUNTU_BASE, SELFTEST]))
    assert_full(run_step(scratch, "pull_request", base))


def test_a_base_revision_without_the_planner_runs_the_full_matrix(scratch: Scratch) -> None:
    (scratch.root / PLANNER_RELATIVE).unlink()
    base = scratch.commit("no planner yet")
    commit_base_planner(scratch, affected_plan([], [UBUNTU_BASE, SELFTEST]))
    assert_full(run_step(scratch, "pull_request", base))


def test_a_pull_request_cannot_shrink_its_matrix_by_editing_the_planner(scratch: Scratch) -> None:
    base = commit_base_planner(scratch, full_plan())
    scratch.write(
        PLANNER_RELATIVE, fake_base_planner(json.dumps(affected_plan([], [UBUNTU_BASE, SELFTEST])))
    )
    scratch.commit("the head's planner plans nothing")
    assert_full(run_step(scratch, "pull_request", base))


def gate_needs(
    plan: str = "success",
    scope: str | None = "full",
    legs: str | None = "3",
    lifecycle: str = "success",
    libvirt: str = "success",
) -> str:
    outputs = {
        key: value
        for key, value in (("scope", scope), ("lifecycle_legs", legs))
        if value is not None
    }
    return json.dumps(
        {
            "lint": {"result": "success", "outputs": {}},
            "scc-changes": {"result": "success", "outputs": {"scc": "true", "expiry": "current"}},
            "scc-smoke": {"result": "success", "outputs": {}},
            "molecule-plan": {"result": plan, "outputs": outputs},
            "molecule-lifecycle": {"result": lifecycle, "outputs": {}},
            "molecule-libvirt": {"result": libvirt, "outputs": {}},
            "molecule-collections": {"result": "success", "outputs": {}},
            "molecule-images": {
                "result": "success",
                "outputs": {"ids": "ubuntu=sha256:" + "a" * 64},
            },
        }
    )


def with_inputs(needs: str, result: str) -> str:
    document = json.loads(needs)
    for job in ("molecule-collections", "molecule-images"):
        document[job]["result"] = result
    return json.dumps(document)


@pytest.mark.parametrize(
    ("event", "needs", "passes"),
    [
        ("pull_request", gate_needs(), True),
        ("pull_request", gate_needs(scope="affected", legs="2"), True),
        ("merge_group", gate_needs(scope="affected", legs="2"), True),
        ("pull_request", gate_needs(scope="affected", legs="0", lifecycle="skipped"), True),
        ("merge_group", gate_needs(scope="affected", legs="0", lifecycle="skipped"), True),
        ("pull_request", gate_needs(scope="affected", legs="2", lifecycle="skipped"), False),
        ("pull_request", gate_needs(scope="full", legs="0", lifecycle="skipped"), False),
        ("pull_request", gate_needs(scope="affected", legs="00", lifecycle="skipped"), False),
        ("pull_request", gate_needs(scope="affected", legs="", lifecycle="skipped"), False),
        ("pull_request", gate_needs(scope="affected", legs=None, lifecycle="skipped"), False),
        ("pull_request", gate_needs(scope="affected", legs="2", lifecycle="failure"), False),
        ("pull_request", gate_needs(scope="affected", legs="2", lifecycle="cancelled"), False),
        ("pull_request", gate_needs(scope="partial", legs="2"), False),
        ("pull_request", with_inputs(gate_needs(), "failure"), False),
        (
            "merge_group",
            with_inputs(gate_needs(scope="affected", legs="0", lifecycle="skipped"), "skipped"),
            False,
        ),
        ("pull_request", gate_needs(scope=None, legs="2"), False),
        (
            "pull_request",
            gate_needs(plan="failure", scope=None, legs=None, lifecycle="skipped"),
            False,
        ),
        (
            "pull_request",
            gate_needs(scope="affected", legs="0", lifecycle="skipped", libvirt="skipped"),
            False,
        ),
        ("push", gate_needs(), True),
        ("schedule", gate_needs(), True),
        ("workflow_dispatch", gate_needs(), True),
        ("push", gate_needs(scope="affected", legs="2"), False),
        ("schedule", gate_needs(scope="affected", legs="0", lifecycle="skipped"), False),
        ("workflow_dispatch", gate_needs(scope="affected", legs="2"), False),
        ("push", gate_needs(scope="full", legs="0", lifecycle="skipped"), False),
    ],
)
def test_ci_gate_accepts_a_skipped_lifecycle_only_when_the_plan_says_so(
    event: str, needs: str, passes: bool
) -> None:
    assert shutil.which("jq") is not None, "jq is required to run the ci-gate script"
    result = subprocess.run(
        [executable("bash"), "-euo", "pipefail", "-c", gate_script()],
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        cwd=REPOSITORY_ROOT,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "NEEDS": needs, "EVENT_NAME": event},
    )
    assert (result.returncode == 0) is passes, result.stdout + result.stderr


def test_the_lifecycle_job_runs_only_when_the_plan_has_legs() -> None:
    found = jobs()
    lifecycle = found["molecule-lifecycle"]
    assert lifecycle["needs"] == ["molecule-plan", "molecule-collections", "molecule-images"]
    assert lifecycle["if"] == "needs.molecule-plan.outputs.lifecycle_legs != '0'"
    assert "if" not in found["molecule-libvirt"]
    plan = found["molecule-plan"]
    assert plan["outputs"] == {
        "matrix": "${{ steps.plan.outputs.matrix }}",
        "libvirt": "${{ steps.plan.outputs.libvirt }}",
        "scope": "${{ steps.plan.outputs.scope }}",
        "lifecycle_legs": "${{ steps.plan.outputs.lifecycle_legs }}",
    }
    steps = cast("list[dict[str, object]]", plan["steps"])
    checkout = cast("dict[str, object]", steps[0]["with"])
    assert checkout == {"persist-credentials": False, "fetch-depth": 0}
    assert plan["permissions"] == {"contents": "read"}
    workflow = cast("dict[object, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    triggers = cast("dict[str, object]", workflow[True])
    assert {"pull_request", "push", "merge_group", "schedule", "workflow_dispatch"} <= set(triggers)


def test_the_makefile_target_runs_the_tool_of_its_own_revision() -> None:
    text = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "molecule-affected: require-uv collection-link\n" in text
    assert "python -m tools.roles.affected_topics --head-root '$(MOLECULE_AFFECTED_HEAD)'" in text
    assert "MOLECULE_AFFECTED_CHANGED ?=\n" in text
