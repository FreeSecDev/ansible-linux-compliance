"""The Molecule legs that a branch runs on a Docker host before it merges (FREES-215, ADR 0034).

The plan comes from the base revision's planner, as in the ``molecule-plan`` job; the tool
checks it as that job's step does and lists the full matrices when it cannot be used. Every
worker leg of an ``affected`` plan is required; of a ``full`` plan only the standard scenarios
and the legs of the named topics are. The libvirt legs are left to the daily full run.
"""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from typing import cast

import pytest

from tools.ci import affected_legs

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPOSITORY_ROOT / "Makefile"

PWQ_RULE = {
    "platform": "ubuntu",
    "scenario": "docker-ubuntu-lifecycle",
    "topic": "pwquality",
    "mode": "rule",
}
PWQ_TOPIC = {**PWQ_RULE, "mode": "topic"}
SSH_RULE = {**PWQ_RULE, "topic": "ssh"}
LIBVIRT_UBUNTU = {"platform": "ubuntu", "scenario": "libvirt-ubuntu", "topic": "", "mode": ""}
LIBVIRT_SELFTEST = {"platform": "ubuntu", "scenario": "libvirt-selftest", "topic": "", "mode": ""}
LIBVIRT_SYSCTL = {
    "platform": "rhel_compatible",
    "scenario": "libvirt-rhel-compatible-lifecycle",
    "topic": "sysctl",
    "mode": "topic",
}
DOCKER = [PWQ_TOPIC, PWQ_RULE, SSH_RULE]
LIBVIRT = [LIBVIRT_UBUNTU, LIBVIRT_SELFTEST, LIBVIRT_SYSCTL]
SCENARIOS = ["docker-ubuntu", "docker-rhel-compatible", "docker-selftest"]
WORKFLOW = {"jobs": {"molecule-docker": {"strategy": {"matrix": {"scenario": SCENARIOS}}}}}


def plan_text(
    scope: str = "affected",
    topics: object = ("pwquality",),
    docker: object = (PWQ_TOPIC, PWQ_RULE),
    libvirt: object = (LIBVIRT_UBUNTU, LIBVIRT_SELFTEST),
    reasons: object = ("roles/remediate/tasks/pwquality.yml: topic file: pwquality",),
) -> str:
    def listed(value: object) -> object:
        if isinstance(value, tuple):
            return list(cast("tuple[object, ...]", value))
        return value

    def matrix(value: object) -> object:
        if isinstance(value, tuple):
            return {"include": listed(cast("tuple[object, ...]", value))}
        return value

    return json.dumps(
        {
            "scope": scope,
            "topics": listed(topics),
            "reasons": listed(reasons),
            "lifecycle_legs": 2,
            "docker": matrix(docker),
            "libvirt": matrix(libvirt),
        }
    )


def test_an_affected_plan_runs_the_standard_scenarios_and_its_legs_on_the_worker() -> None:
    plan = affected_legs.checked_plan(plan_text(), DOCKER, LIBVIRT)
    assert plan.scope == "affected"
    assert plan.topics == ("pwquality",)
    found = affected_legs.runs(plan, SCENARIOS)
    assert [(run.job, run.where) for run in found] == [
        ("molecule-docker (docker-ubuntu)", "worker"),
        ("molecule-docker (docker-rhel-compatible)", "worker"),
        ("molecule-docker (docker-selftest)", "worker"),
        ("molecule-lifecycle (ubuntu, pwquality, topic)", "worker"),
        ("molecule-lifecycle (ubuntu, pwquality, rule)", "worker"),
        ("molecule-libvirt (libvirt-ubuntu)", "daily full run"),
        ("molecule-libvirt (libvirt-selftest)", "daily full run"),
    ]
    assert found[0].make == (
        "test-molecule-docker",
        "MOLECULE_DOCKER_SCENARIOS=docker-ubuntu",
        "MOLECULE_DOCKER_SELFTEST=false",
    )
    assert found[2].make == ("test-molecule-docker-selftest",)
    assert found[4].make == (
        "test-molecule-docker",
        "MOLECULE_DOCKER_SCENARIOS=docker-ubuntu-lifecycle",
        "MOLECULE_DOCKER_SELFTEST=false",
        "MOLECULE_LIFECYCLE_TOPIC=pwquality",
        "MOLECULE_LIFECYCLE_MODE=rule",
    )
    assert found[5].make == (
        "test-molecule-libvirt",
        "MOLECULE_LIBVIRT_SCENARIOS=libvirt-ubuntu",
        "MOLECULE_LIBVIRT_PLATFORMS=ubuntu",
        "MOLECULE_LIBVIRT_SELFTEST=false",
    )
    assert found[6].make == ("test-molecule-libvirt-selftest", "MOLECULE_LIBVIRT_PLATFORMS=ubuntu")


def test_a_plan_without_lifecycle_legs_runs_nothing_on_the_worker() -> None:
    plan = affected_legs.checked_plan(plan_text(topics=(), docker=(), reasons=()), DOCKER, LIBVIRT)
    found = affected_legs.runs(plan, SCENARIOS)
    assert {run.where for run in found} == {"daily full run"}
    assert affected_legs.render_commands(found, "") == ""
    assert "- no path changed" in affected_legs.render_markdown(plan, found, "")


def test_a_full_plan_requires_the_named_topics_and_makes_the_rest_optional() -> None:
    text = plan_text(scope="full", docker=tuple(DOCKER), libvirt=tuple(LIBVIRT))
    plan = affected_legs.checked_plan(text, DOCKER, LIBVIRT)
    found = affected_legs.runs(plan, SCENARIOS)
    assert [(run.job, run.where) for run in found] == [
        ("molecule-docker (docker-ubuntu)", "worker"),
        ("molecule-docker (docker-rhel-compatible)", "worker"),
        ("molecule-docker (docker-selftest)", "worker"),
        ("molecule-lifecycle (ubuntu, pwquality, topic)", "worker"),
        ("molecule-lifecycle (ubuntu, pwquality, rule)", "worker"),
        ("molecule-lifecycle (ubuntu, ssh, rule)", "worker, optional"),
        ("molecule-libvirt (libvirt-ubuntu)", "daily full run"),
        ("molecule-libvirt (libvirt-selftest)", "daily full run"),
        ("molecule-libvirt (libvirt-rhel-compatible-lifecycle, sysctl, topic)", "daily full run"),
    ]
    assert found[-1].make[-2:] == (
        "MOLECULE_LIFECYCLE_TOPIC=sysctl",
        "MOLECULE_LIFECYCLE_MODE=topic",
    )
    assert len(affected_legs.render_commands(found, "").splitlines()) == 5


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "the base revision's planner gave no plan"),
        ("  \n", "the base revision's planner gave no plan"),
        ("{", "the plan is not JSON"),
        ("[]", "the plan is not a JSON object with a scope"),
        (plan_text(scope="partial"), "the plan is not a JSON object with a scope"),
        (plan_text(topics="pwquality"), "the plan is not a JSON object with a scope"),
        (plan_text(reasons=[1]), "the plan is not a JSON object with a scope"),
        (plan_text(docker={"legs": []}), "the plan's Docker matrix is not a matrix"),
        (plan_text(libvirt=[]), "the plan's libvirt matrix is not a matrix"),
        (
            plan_text(docker=({**PWQ_RULE, "topic": "invented"},)),
            "is not a subset of the full matrices",
        ),
        (plan_text(libvirt=(LIBVIRT_UBUNTU,)), "keeps every leg without a topic"),
        (plan_text(scope="full"), "the plan is full but does not hold the full matrices"),
        (
            plan_text(scope="full", docker=tuple(DOCKER)),
            "the plan is full but does not hold the full matrices",
        ),
    ],
)
def test_an_unusable_plan_lists_the_full_matrices(text: str, reason: str) -> None:
    plan = affected_legs.checked_plan(text, DOCKER, LIBVIRT)
    assert plan.scope == "full"
    assert plan.topics == ()
    assert plan.docker == tuple(DOCKER)
    assert plan.libvirt == tuple(LIBVIRT)
    assert len(plan.reasons) == 1
    assert reason in plan.reasons[0]
    optional = [run for run in affected_legs.runs(plan, SCENARIOS) if run.where != "worker"]
    assert [run.job for run in optional][:1] == ["molecule-lifecycle (ubuntu, pwquality, topic)"]


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        (None, "is not a matrix with an include list"),
        ({"include": "x"}, "is not a matrix with an include list"),
        ({"include": ["x"]}, "exactly the keys"),
        ({"include": [{"platform": "ubuntu"}]}, "exactly the keys"),
        ({"include": [{**PWQ_RULE, "mode": 1}]}, "must be a string"),
        ({"include": [{**PWQ_RULE, "scenario": ""}]}, "not a plain name"),
        ({"include": [{**PWQ_RULE, "topic": "a b"}]}, "not a plain name"),
        ({"include": [{**PWQ_RULE, "mode": "x;y"}]}, "not a plain name"),
        ({"include": [{**PWQ_RULE, "platform": "Ubuntu"}]}, "not a plain name"),
    ],
)
def test_a_matrix_holds_only_legs_of_plain_names(data: object, fragment: str) -> None:
    with pytest.raises(affected_legs.LegsError, match=fragment):
        affected_legs.matrix_legs(data, "the matrix")


def test_a_matrix_of_plain_names_is_read_in_key_order() -> None:
    leg = dict(reversed(list(LIBVIRT_UBUNTU.items())))
    assert affected_legs.matrix_legs({"include": [leg]}, "m") == [LIBVIRT_UBUNTU]


@pytest.mark.parametrize(
    "workflow",
    [
        None,
        {"jobs": []},
        {"jobs": {}},
        {"jobs": {"molecule-docker": {}}},
        {"jobs": {"molecule-docker": {"strategy": {}}}},
        {"jobs": {"molecule-docker": {"strategy": {"matrix": {}}}}},
        {"jobs": {"molecule-docker": {"strategy": {"matrix": {"scenario": []}}}}},
        {"jobs": {"molecule-docker": {"strategy": {"matrix": {"scenario": ["a b"]}}}}},
        {"jobs": {"molecule-docker": {"strategy": {"matrix": {"scenario": [1]}}}}},
    ],
)
def test_the_standard_scenarios_must_be_a_list_of_names(workflow: object) -> None:
    with pytest.raises(affected_legs.LegsError, match="no molecule-docker job"):
        affected_legs.standard_scenarios(workflow)


def test_the_standard_scenarios_are_those_of_the_molecule_docker_job_of_ci_yml() -> None:
    workflow = affected_legs.read_workflow(CI_WORKFLOW)
    assert affected_legs.standard_scenarios(workflow) == SCENARIOS
    assert affected_legs.standard_scenarios(WORKFLOW) == SCENARIOS


def test_the_commands_take_a_prefix_and_quote_nothing_they_do_not_need_to() -> None:
    run = affected_legs.Run("job", "worker", ("test-molecule-docker", "A=b c"))
    assert affected_legs.command(run, "") == "make test-molecule-docker 'A=b c'"
    assert affected_legs.command(run, "  ") == "make test-molecule-docker 'A=b c'"
    assert (
        affected_legs.command(run, " host-runner dir molecule -- ")
        == "host-runner dir molecule -- make test-molecule-docker 'A=b c'"
    )


def test_the_markdown_table_has_one_row_per_leg_and_a_result_to_fill_in() -> None:
    text = plan_text(scope="full", docker=tuple(DOCKER), libvirt=tuple(LIBVIRT))
    plan = affected_legs.checked_plan(text, DOCKER, LIBVIRT)
    found = affected_legs.runs(plan, SCENARIOS)
    rendered = affected_legs.render_markdown(plan, found, "p --")
    lines = rendered.splitlines()
    assert lines[0] == "Scope: `full`; topics: `pwquality`."
    assert lines[1] == (
        "Required on the worker: 5. Optional on the worker: 1. Left to the daily full run: 3."
    )
    rows = [line for line in lines if line.startswith("| `")]
    assert len(rows) == len(found)
    assert rows[0] == (
        "| `molecule-docker (docker-ubuntu)` | worker | `p -- make test-molecule-docker "
        "MOLECULE_DOCKER_SCENARIOS=docker-ubuntu MOLECULE_DOCKER_SELFTEST=false` | not run |"
    )
    assert rows[5].endswith("| not run |")
    assert rows[-1].endswith("| deferred |")
    assert lines[-1] == "- roles/remediate/tasks/pwquality.yml: topic file: pwquality"


def test_the_json_lists_the_plan_and_every_leg() -> None:
    plan = affected_legs.checked_plan(plan_text(), DOCKER, LIBVIRT)
    found = affected_legs.runs(plan, SCENARIOS)
    document = json.loads(affected_legs.render_json(plan, found, ""))
    assert document["scope"] == "affected"
    assert document["topics"] == ["pwquality"]
    assert len(document["legs"]) == len(found)
    assert document["legs"][2] == {
        "job": "molecule-docker (docker-selftest)",
        "where": "worker",
        "command": "make test-molecule-docker-selftest",
    }


def write_inputs(tmp_path: Path, plan: str | None = None) -> list[str]:
    (tmp_path / "docker.json").write_text(json.dumps({"include": DOCKER}), encoding="utf-8")
    (tmp_path / "libvirt.json").write_text(json.dumps({"include": LIBVIRT}), encoding="utf-8")
    if plan is not None:
        (tmp_path / "plan.json").write_text(plan, encoding="utf-8")
    return [
        "--plan",
        str(tmp_path / "plan.json"),
        "--docker",
        str(tmp_path / "docker.json"),
        "--libvirt",
        str(tmp_path / "libvirt.json"),
        "--workflow",
        str(CI_WORKFLOW),
    ]


@pytest.mark.parametrize(
    ("form", "expected"),
    [
        ("markdown", "Scope: `affected`; topics: `pwquality`."),
        ("commands", "make test-molecule-docker MOLECULE_DOCKER_SCENARIOS=docker-ubuntu"),
        ("json", '{"scope":"affected"'),
    ],
)
def test_the_command_line_prints_each_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], form: str, expected: str
) -> None:
    arguments = [*write_inputs(tmp_path, plan_text()), "--format", form]
    assert affected_legs.main(arguments) == 0
    assert capsys.readouterr().out.startswith(expected)


def test_a_missing_plan_lists_the_full_matrices(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert affected_legs.main(write_inputs(tmp_path)) == 0
    out = capsys.readouterr().out
    assert out.startswith("Scope: `full`; topics: none.")
    assert "- the base revision's planner gave no plan" in out


@pytest.mark.parametrize(
    ("name", "content", "fragment"),
    [
        ("docker.json", "{", "the Docker matrix"),
        ("libvirt.json", "[]", "the libvirt matrix is not a matrix"),
        ("docker.json", b"\xff", "cannot be read"),
        ("ci.yml", "jobs: [", "is not YAML"),
        ("ci.yml", "jobs: {}\n", "no molecule-docker job"),
    ],
)
def test_unusable_matrices_or_workflow_stop_with_status_2(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    content: str | bytes,
    fragment: str,
) -> None:
    arguments = write_inputs(tmp_path, plan_text())
    target = tmp_path / name
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    if name == "ci.yml":
        arguments[-1] = str(target)
    assert affected_legs.main(arguments) == 2
    assert fragment in capsys.readouterr().err


def test_the_module_runs_as_a_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = write_inputs(tmp_path, plan_text())
    monkeypatch.setattr(sys, "argv", ["affected_legs", *arguments, "--format", "commands"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(affected_legs.__file__, run_name="__main__")
    assert raised.value.code == 0
    assert len(capsys.readouterr().out.splitlines()) == 5


def test_the_makefile_target_plans_with_the_base_revision_and_falls_back_to_full() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "affected-legs: require-uv collection-link\n" in text
    assert (
        "@tools/molecule/plan-lifecycle.sh pull_request "
        "\"$$(git merge-base HEAD '$(AFFECTED_LEGS_BASE)')\" ''" in text
    )
    assert "|| : > '$(AFFECTED_LEGS_DIR)/plan.json'" in text
    assert "python -m tools.ci.affected_legs --plan '$(AFFECTED_LEGS_DIR)/plan.json'" in text
    assert "refs/remotes/origin/integration" in text
