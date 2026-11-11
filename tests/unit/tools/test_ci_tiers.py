"""The fast tier and the full matrix of ``ci.yml`` (FREES-215, ADR 0034).

``ci-tier`` decides the tier of a run. A pull request into ``integration``, the promotion pull
request of ``integration`` into ``main`` and a push to ``main`` run the fast tier: every job but
the Molecule jobs. Every other event runs the full matrix, among them every merge group and a
pull request into ``main`` from any other branch. ``ci-gate`` stays the one required check of
both tiers: it accepts the fast tier only for those events and only when every Molecule job was
skipped. The tests run the step scripts with bash and jq, and pin the rulesets that the
maintainer applies (``tools/ci/rulesets``).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
PR_BODY_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "pr-body.yml"
RULESETS = REPOSITORY_ROOT / "tools" / "ci" / "rulesets"
LIVE_MAIN = REPOSITORY_ROOT / ".github" / "rulesets" / "main.json"
ADR = REPOSITORY_ROOT / "docs" / "adr" / "0034-daily-integration-branch.md"
TIMEOUT_SECONDS = 30
REPOSITORY = "FreeSecDev/ansible-linux-compliance"
FULL_ONLY = frozenset(
    {
        "molecule-images",
        "molecule-docker",
        "molecule-plan",
        "molecule-lifecycle",
        "molecule-libvirt",
    }
)
TIER_CONDITION = "needs.ci-tier.outputs.tier == 'full'"
GITHUB_ACTIONS_APP = 15368


def workflow(path: Path = CI_WORKFLOW) -> dict[object, object]:
    return cast("dict[object, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


def jobs() -> dict[str, dict[str, object]]:
    return cast("dict[str, dict[str, object]]", workflow()["jobs"])


def needs_of(job: dict[str, object]) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else cast("list[str]", needs)


def only_run(name: str) -> str:
    steps = cast("list[dict[str, str]]", jobs()[name]["steps"])
    assert len(steps) == 1
    return steps[0]["run"]


def bash() -> str:
    path = shutil.which("bash")
    assert path is not None, "bash is required to run the step scripts"
    return path


def run_bash(script: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [bash(), "-euo", "pipefail", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        cwd=REPOSITORY_ROOT,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **environment},
    )


def event(
    name: str,
    base: str = "",
    head: str = "",
    head_repo: str = REPOSITORY,
    ref: str = "",
) -> dict[str, str]:
    return {
        "EVENT_NAME": name,
        "REF": ref,
        "BASE_REF": base,
        "HEAD_REF": head,
        "HEAD_REPO": head_repo if name == "pull_request" else "",
        "REPOSITORY": REPOSITORY,
    }


INTO_INTEGRATION = event("pull_request", "integration", "feat/FREES-1-x")
PROMOTION = event("pull_request", "main", "integration")
PUSH_MAIN = event("push", ref="refs/heads/main")
FAST_EVENTS = [INTO_INTEGRATION, PROMOTION, PUSH_MAIN]
FULL_EVENTS = [
    event("pull_request", "main", "fix/FREES-2-hotfix"),
    event("pull_request", "main", "integration", head_repo="someone/fork"),
    event("pull_request", "main", "integration", head_repo=""),
    event("pull_request", "release", "integration"),
    event("merge_group", ref="refs/heads/gh-readonly-queue/main/pr-1-" + "a" * 40),
    event("push", ref="refs/heads/integration"),
    event("schedule", ref="refs/heads/main"),
    event("workflow_dispatch", ref="refs/heads/integration"),
]


def decided_tier(environment: dict[str, str], tmp_path: Path) -> str:
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    result = run_bash(only_run("ci-tier"), {**environment, "GITHUB_OUTPUT": str(output)})
    assert result.returncode == 0, result.stderr
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("tier=")
    return lines[0].removeprefix("tier=")


@pytest.mark.parametrize("environment", FAST_EVENTS)
def test_these_events_run_the_fast_tier(environment: dict[str, str], tmp_path: Path) -> None:
    assert decided_tier(environment, tmp_path) == "fast"


@pytest.mark.parametrize("environment", FULL_EVENTS)
def test_every_other_event_runs_the_full_matrix(
    environment: dict[str, str], tmp_path: Path
) -> None:
    assert decided_tier(environment, tmp_path) == "full"


def test_the_tier_job_reads_the_event_through_the_environment_only() -> None:
    job = jobs()["ci-tier"]
    assert job["permissions"] == {}
    assert "needs" not in job
    assert "if" not in job
    assert job["outputs"] == {"tier": "${{ steps.tier.outputs.tier }}"}
    step = cast("list[dict[str, object]]", job["steps"])[0]
    assert "uses" not in step
    assert "${{" not in cast("str", step["run"])
    assert set(cast("dict[str, str]", step["env"])) == set(event("push"))


def test_only_the_molecule_jobs_belong_to_the_full_tier() -> None:
    found = jobs()
    for name in FULL_ONLY:
        job = found[name]
        assert "ci-tier" in needs_of(job), name
        assert cast("str", job["if"]).startswith(TIER_CONDITION), name
    for name, job in found.items():
        if name in FULL_ONLY or name in {"ci-tier", "ci-gate"}:
            continue
        assert "ci-tier" not in needs_of(job), name
        assert "ci-tier" not in yaml.safe_dump(job), name
    assert found["molecule-lifecycle"]["if"] == (
        f"{TIER_CONDITION} && needs.molecule-plan.outputs.lifecycle_legs != '0'"
    )


def test_the_docs_job_runs_make_docs_on_every_event() -> None:
    job = jobs()["docs"]
    steps = cast("list[dict[str, object]]", job["steps"])
    assert [step["run"] for step in steps if "run" in step] == ["make docs"]
    assert "if" not in job
    assert "needs" not in job
    assert job["permissions"] == {"contents": "read"}


def test_pull_requests_into_main_and_integration_run_ci_and_the_body_check() -> None:
    for path in (CI_WORKFLOW, PR_BODY_WORKFLOW):
        found = cast("dict[str, dict[str, object]]", workflow(path)[True])
        assert found["pull_request"]["branches"] == ["main", "integration"], path
    triggers = cast("dict[str, dict[str, object] | None]", workflow()[True])
    push = triggers["push"]
    assert push is not None
    assert push["branches"] == ["main"]
    assert "merge_group" in triggers


def gate_needs(tier: str | None, full_only: str, tier_result: str = "success") -> str:
    document: dict[str, dict[str, object]] = {
        name: {"result": "success", "outputs": {}} for name in jobs() if name != "ci-gate"
    }
    document["ci-tier"] = {
        "result": tier_result,
        "outputs": {} if tier is None else {"tier": tier},
    }
    document["scc-changes"]["outputs"] = {"scc": "true", "expiry": "current"}
    document["molecule-plan"]["outputs"] = {"scope": "full", "lifecycle_legs": "3"}
    for name in FULL_ONLY:
        document[name]["result"] = full_only
    if full_only == "skipped":
        document["molecule-plan"]["outputs"] = {}
    return json.dumps(document)


def gate_passes(needs: str, environment: dict[str, str]) -> bool:
    assert shutil.which("jq") is not None, "jq is required to run the ci-gate script"
    result = run_bash(only_run("ci-gate"), {**environment, "NEEDS": needs})
    return result.returncode == 0


@pytest.mark.parametrize("environment", FAST_EVENTS + FULL_EVENTS)
def test_the_gate_accepts_the_fast_tier_exactly_where_the_tier_job_decides_it(
    environment: dict[str, str], tmp_path: Path
) -> None:
    fast = decided_tier(environment, tmp_path) == "fast"
    assert gate_passes(gate_needs("fast", "skipped"), environment) is fast
    assert gate_passes(gate_needs("full", "success"), environment)


@pytest.mark.parametrize("environment", FAST_EVENTS)
@pytest.mark.parametrize(
    ("tier", "full_only", "tier_result"),
    [
        ("fast", "success", "success"),
        ("fast", "failure", "success"),
        ("fast", "cancelled", "success"),
        ("full", "skipped", "success"),
        ("fast", "skipped", "failure"),
        ("fast", "skipped", "skipped"),
        (None, "skipped", "success"),
        ("", "skipped", "success"),
        ("fast ", "skipped", "success"),
        ("partial", "skipped", "success"),
    ],
)
def test_the_gate_refuses_a_tier_that_does_not_match_its_jobs(
    environment: dict[str, str], tier: str | None, full_only: str, tier_result: str
) -> None:
    assert not gate_passes(gate_needs(tier, full_only, tier_result), environment)


def test_the_gate_still_needs_every_fast_job_in_the_fast_tier() -> None:
    document = cast("dict[str, object]", json.loads(gate_needs("fast", "skipped")))
    for name in ("lint", "docs", "test", "collection", "security"):
        broken: dict[str, object] = {**document, name: {"result": "skipped", "outputs": {}}}
        assert not gate_passes(json.dumps(broken), INTO_INTEGRATION), name


def read_json(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(path.read_text(encoding="utf-8")))


def rules_of(ruleset: dict[str, object]) -> dict[str, dict[str, object]]:
    rules = cast("list[dict[str, object]]", ruleset["rules"])
    found = {cast("str", rule["type"]): rule for rule in rules}
    assert len(found) == len(rules)
    return found


def parameters(ruleset: dict[str, object], kind: str) -> dict[str, object]:
    return cast("dict[str, object]", rules_of(ruleset)[kind]["parameters"])


def test_the_integration_ruleset_requires_the_gate_and_squash_without_a_queue() -> None:
    ruleset = read_json(RULESETS / "integration-protection.json")
    assert ruleset["name"] == "integration-protection"
    assert ruleset["target"] == "branch"
    assert ruleset["enforcement"] == "active"
    assert ruleset["bypass_actors"] == []
    assert ruleset["conditions"] == {
        "ref_name": {"exclude": [], "include": ["refs/heads/integration"]}
    }
    assert set(rules_of(ruleset)) == {
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "pull_request",
        "required_status_checks",
    }
    review = parameters(ruleset, "pull_request")
    assert review["required_approving_review_count"] == 0
    assert review["allowed_merge_methods"] == ["squash"]
    assert review["required_review_thread_resolution"] is True
    checks = parameters(ruleset, "required_status_checks")
    assert checks["strict_required_status_checks_policy"] is False
    assert checks["required_status_checks"] == [
        {"context": "ci-gate", "integration_id": GITHUB_ACTIONS_APP}
    ]


def test_the_main_ruleset_changes_only_the_merge_method_linear_history_and_strictness() -> None:
    live = read_json(LIVE_MAIN)
    target = read_json(RULESETS / "main-protection.json")
    live_rules = rules_of(live)
    target_rules = rules_of(target)
    assert "required_linear_history" in live_rules
    assert set(target_rules) == set(live_rules) - {"required_linear_history"}
    assert parameters(target, "merge_queue")["merge_method"] == "MERGE"
    assert parameters(target, "pull_request")["allowed_merge_methods"] == ["merge"]
    restored = json.loads(json.dumps(target))
    for rule in restored["rules"]:
        if rule["type"] == "merge_queue":
            rule["parameters"]["merge_method"] = "SQUASH"
        if rule["type"] == "pull_request":
            rule["parameters"]["allowed_merge_methods"] = ["squash"]
        if rule["type"] == "required_status_checks":
            rule["parameters"]["strict_required_status_checks_policy"] = True
    restored["rules"].insert(2, live_rules["required_linear_history"])
    assert restored == live
    checks = parameters(target, "required_status_checks")
    assert checks["strict_required_status_checks_policy"] is False
    assert checks["required_status_checks"] == [
        {"context": "ci-gate", "integration_id": GITHUB_ACTIONS_APP}
    ]


def test_the_repository_settings_title_merge_commits_with_the_pull_request() -> None:
    settings = read_json(RULESETS / "repository-merge-settings.json")
    assert settings == {
        "allow_merge_commit": True,
        "allow_squash_merge": True,
        "allow_rebase_merge": False,
        "merge_commit_title": "PR_TITLE",
        "merge_commit_message": "PR_BODY",
        "squash_merge_commit_title": "PR_TITLE",
        "squash_merge_commit_message": "PR_BODY",
    }


def test_the_adr_names_the_command_of_every_settings_file() -> None:
    text = ADR.read_text(encoding="utf-8")
    for path in sorted(RULESETS.glob("*.json")):
        assert f"--input tools/ci/rulesets/{path.name}" in text, path.name
