from __future__ import annotations

from pathlib import Path
from typing import cast

import jinja2
import jinja2.meta
import yaml

from tools.roles import generate_role_guards as gen
from tools.roles import generate_toggles, run_start

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PLAYBOOKS = REPOSITORY_ROOT / "playbooks"
SHIPPED = ("audit.yml", "evidence.yml", "remediate.yml", "verify.yml")


def load(path: Path) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", yaml.safe_load(path.read_text(encoding="utf-8")))


def anything(value: object, *arguments: object) -> object:
    return (value, arguments)


def names_of(expression: str) -> set[str]:
    environment = jinja2.Environment(autoescape=True)
    environment.tests["match"] = anything
    for name in ("flatten", "zip", "dict2items", "ansible.builtin.subelements"):
        environment.filters[name] = anything
    return jinja2.meta.find_undeclared_variables(environment.parse("{{ " + expression + " }}"))


def the_task() -> dict[str, object]:
    plays = load(REPOSITORY_ROOT / run_start.RUN_START)
    assert len(plays) == 1
    assert plays[0]["hosts"] == "all:localhost"
    assert plays[0]["gather_facts"] is False
    assert "vars" not in plays[0]
    tasks = cast("list[dict[str, object]]", plays[0]["tasks"])
    assert len(tasks) == 1
    return tasks[0]


def test_the_check_reads_only_magic_variables_and_literals() -> None:
    task = the_task()
    assert "vars" not in task
    assert task["run_once"] is True
    assert task["tags"] == ["always"]
    assertion = cast("dict[str, object]", task["ansible.builtin.assert"])
    for item in cast("list[str]", assertion["that"]):
        assert names_of(item) <= {"groups", "hostvars"}, item
    message = str(assertion["fail_msg"])
    for part in message.split("{{")[1:]:
        assert names_of(part.split("}}")[0]) <= {"groups", "hostvars"}
    assert names_of(str(task["when"])) == {run_start.MARKER, "hostvars"}


def test_the_check_refuses_every_internal_name_and_role_output_by_its_name() -> None:
    assertion = cast("dict[str, object]", the_task()["ansible.builtin.assert"])
    that = [" ".join(item.split()) for item in cast("list[str]", assertion["that"])]
    outputs = gen.role_outputs(REPOSITORY_ROOT / "roles")
    exempt = ["__linux_compliance_verify_baseline_recorded"]
    assert that[0] == run_start.refused(outputs, exempt) + " | length == 0"
    for name in [*outputs, run_start.MARKER]:
        assert f"'{name}'" in that[0], name
    assert "select('match', '^__linux_compliance_')" in that[0]
    assert "map('extract', hostvars, 'inventory_hostname')" in that[1]
    assert "(groups['all'] + ['localhost']) | unique" in that[1]
    assert that[2] == run_start.memberships()
    stated, actual = that[2].split(" == ")
    assert "ansible.builtin.subelements('group_names')" in stated
    assert "map('extract', hostvars)" in stated
    assert actual.startswith("(groups | dict2items | rejectattr('key', 'equalto', 'all')")
    assert "hostvars" not in actual
    assert "group_names" in str(assertion["fail_msg"])


def test_the_play_is_folded_within_the_line_limit() -> None:
    text = run_start.play(["linux_compliance_" + "x" * 60], ["__linux_compliance_" + "y" * 60])
    assert all(len(line) <= generate_toggles.MAX_LINE for line in text.splitlines())
    assert text.startswith("---\n")


def test_every_shipped_playbook_runs_the_check_first() -> None:
    for name in SHIPPED:
        first = load(PLAYBOOKS / name)[0]
        assert first["ansible.builtin.import_playbook"] == "run_start.yml", name
        assert "vars" not in first, name


def test_a_shipped_playbook_that_imports_another_passes_the_marker_as_a_play_variable() -> None:
    imports = [
        (name, entry["ansible.builtin.import_playbook"], entry.get("vars"))
        for name in SHIPPED
        for entry in load(PLAYBOOKS / name)[1:]
        if "ansible.builtin.import_playbook" in entry
    ]
    marker = {run_start.MARKER: True}
    assert imports == [
        ("remediate.yml", "audit.yml", marker),
        ("remediate.yml", "verify.yml", marker),
        ("verify.yml", "audit.yml", marker),
    ]
    assert {path.name for path in PLAYBOOKS.glob("*.yml")} == {*SHIPPED, "run_start.yml"}
