"""The unit test jobs of ``ci.yml`` and the parallel coverage run (FREES-174).

``test`` runs only ``make test-coverage``, which runs pytest on ``PYTEST_WORKERS`` workers and
keeps both 100% gates on the combined data. ``test-suites`` runs the audit-exception, golden
content and browser tests alongside it. The check-mode playbooks of the former ``test-playbooks``
job run in ``test-playbooks-remediate`` (``make test-remediate-check-role``),
``test-playbooks-native`` (``make test-remediate-check-native``; FREES-214 split
``make test-remediate-check`` into these two targets, which it still runs) and
``test-playbooks-evidence`` (evidence, role guards and verify). Every one of these jobs runs on
every event without a condition, only the Molecule legs read the plan of ``molecule-plan``, so no
plan can skip them, and ``ci-gate`` needs every job of the workflow.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
MAXIMUM_TIMEOUT_MINUTES = 20
PYTEST_COMMAND = "$(RUN) pytest tests/unit $(PYTEST_PARALLEL)"
COVERAGE_OPTIONS = "--cov --cov-report=term-missing --cov-report=xml"
EXPECTED_COMMANDS = {
    "test": ["make test-coverage"],
    "test-suites": [
        "make test-audit-exceptions",
        "make test-content-golden",
        "make test-browser",
    ],
    "test-playbooks-remediate": ["make test-remediate-check-role"],
    "test-playbooks-native": ["make test-remediate-check-native"],
    "test-playbooks-evidence": [
        "make test-evidence",
        "make test-role-guards",
        "make test-verify",
    ],
}
PLANNED_JOBS = frozenset({"molecule-lifecycle", "molecule-libvirt"})
REMEDIATE_CHECK_PARTS = ("test-remediate-check-role", "test-remediate-check-native")
FORMER_REMEDIATE_CHECK = [
    "$(REMEDIATE_CHECK) --diff tests/playbooks/remediate-check-mode.yml",
    "$(REMEDIATE_CHECK) --skip-tags file_permissions tests/playbooks/remediate-check-mode.yml",
    "$(REMEDIATE_CHECK) --diff tests/playbooks/remediate-native-check.yml",
    "$(REMEDIATE_CHECK) --diff tests/playbooks/remediate-login-defs-check.yml",
    "$(REMEDIATE_CHECK) --diff tests/playbooks/remediate-pam-conf-check.yml",
    "$(REMEDIATE_CHECK) --skip-tags always tests/playbooks/remediate-skip-always.yml",
]
PLAYBOOKS = REPOSITORY_ROOT / "tests" / "playbooks"


def jobs() -> dict[str, dict[str, object]]:
    workflow = cast("dict[str, object]", yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8")))
    return cast("dict[str, dict[str, object]]", workflow["jobs"])


def commands(job: dict[str, object]) -> list[str]:
    steps = cast("list[dict[str, object]]", job["steps"])
    return [cast("str", step["run"]).strip() for step in steps if "run" in step]


def recipe(target: str) -> list[str]:
    lines = MAKEFILE.read_text(encoding="utf-8").splitlines()
    start = lines.index(next(line for line in lines if line.startswith(f"{target}:")))
    body: list[str] = []
    for line in lines[start + 1 :]:
        if not line.startswith("\t"):
            break
        body.append(line.strip())
    return body


@pytest.mark.parametrize("name", sorted(EXPECTED_COMMANDS))
def test_each_test_job_runs_its_targets_on_every_event(name: str) -> None:
    job = jobs()[name]
    assert commands(job) == EXPECTED_COMMANDS[name]
    assert "if" not in job
    assert "needs" not in job
    assert job["permissions"] == {"contents": "read"}
    timeout = job["timeout-minutes"]
    assert isinstance(timeout, int)
    assert 0 < timeout <= MAXIMUM_TIMEOUT_MINUTES


def test_every_former_test_target_runs_in_exactly_one_job() -> None:
    expected = [command for group in EXPECTED_COMMANDS.values() for command in group]
    found = [command for job in jobs().values() for command in commands(job)]
    for command in expected:
        assert found.count(command) == 1, command


def test_ci_gate_needs_every_job_of_the_workflow() -> None:
    workflow_jobs = jobs()
    needs = cast("list[str]", workflow_jobs["ci-gate"]["needs"])
    assert sorted(needs) == sorted(name for name in workflow_jobs if name != "ci-gate")
    assert len(needs) == len(set(needs))


def test_coverage_runs_in_parallel_and_keeps_both_gates_on_the_combined_data() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    assert re.search(r"^PYTEST_WORKERS \?= auto$", text, re.MULTILINE)
    assert re.search(r"^PYTEST_PARALLEL := -n \$\(PYTEST_WORKERS\) ", text, re.MULTILINE)
    assert recipe("test-coverage") == [
        f"{PYTEST_COMMAND} {COVERAGE_OPTIONS}",
        "$(RUN) coverage report --include='tools/*' --fail-under=100",
        "$(RUN) coverage report --include='plugins/*' --fail-under=100",
    ]


def prerequisites(target: str) -> list[str]:
    lines = MAKEFILE.read_text(encoding="utf-8").splitlines()
    line = next(line for line in lines if line.startswith(f"{target}:"))
    return line.partition(":")[2].split()


def test_the_remediate_check_targets_split_the_playbooks_without_loss() -> None:
    assert prerequisites("test-remediate-check") == list(REMEDIATE_CHECK_PARTS)
    assert recipe("test-remediate-check") == []
    assert "test-remediate-disruptive" in prerequisites("test-remediate-check-role")
    runs = [line for part in REMEDIATE_CHECK_PARTS for line in recipe(part)]
    assert sorted(runs) == sorted(FORMER_REMEDIATE_CHECK)
    run_playbooks = {PurePosixPath(line.split()[-1]).name for line in runs}
    assert "tests/playbooks/remediate-disruptive.yml" in MAKEFILE.read_text(encoding="utf-8")
    run_playbooks.add("remediate-disruptive.yml")
    assert run_playbooks == {path.name for path in PLAYBOOKS.glob("remediate-*.yml")}


def test_only_the_molecule_legs_depend_on_the_plan() -> None:
    workflow_jobs = jobs()
    readers = {
        name
        for name, job in workflow_jobs.items()
        if name not in {"molecule-plan", "ci-gate"} and "molecule-plan" in yaml.safe_dump(job)
    }
    assert readers == PLANNED_JOBS
    for name in EXPECTED_COMMANDS:
        assert "molecule-plan" not in yaml.safe_dump(workflow_jobs[name])
