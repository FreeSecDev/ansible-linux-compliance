from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.roles import check_role_specs as specs

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TASKS = REPOSITORY_ROOT / "roles" / "remediate" / "tasks"
NESTED = ("block", "rescue", "always")
INCLUDES = ("ansible.builtin.include_tasks", "ansible.builtin.import_tasks")
COMPLETENESS = "Remediate | Check that every planned rule has exactly one result"
DISPATCHED = "Remediate | Record that the dispatch completed"
DISPATCH = "Remediate | Dispatch every family with work, in registry order"


def load(path: Path) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", yaml.safe_load(path.read_text(encoding="utf-8")))


def walk(tasks: list[dict[str, object]]) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for task in tasks:
        found.append(task)
        for key in NESTED:
            found.extend(walk(cast("list[dict[str, object]]", task.get(key, []))))
    return found


def task_files() -> list[Path]:
    return sorted(TASKS.glob("*.yml"))


def by_name(name: str) -> dict[str, object]:
    return next(task for task in load(TASKS / "main.yml") if task["name"] == name)


@pytest.mark.parametrize("path", task_files(), ids=lambda path: path.name)
def test_every_task_of_the_role_is_tagged_exactly_always(path: Path) -> None:
    top_level = load(path)
    for task in walk(top_level):
        if path.name == "main.yml" and task in top_level and specs.is_guard_task("remediate", task):
            continue
        assert task.get("tags") == ["always"], (path.name, task.get("name"))


@pytest.mark.parametrize("path", task_files(), ids=lambda path: path.name)
def test_every_include_applies_exactly_always_and_stays_inside_the_role(path: Path) -> None:
    for task in walk(load(path)):
        for module in INCLUDES:
            if module not in task:
                continue
            options = cast("dict[str, object]", task[module])
            apply = cast("dict[str, object]", options["apply"])
            assert apply == {"tags": ["always"]}, (path.name, task.get("name"))
            assert str(options["file"]).startswith("{{ role_path }}/tasks/"), task.get("name")


def test_the_only_guard_tasks_are_the_two_of_main() -> None:
    guards = [
        task["name"] for task in load(TASKS / "main.yml") if specs.is_guard_task("remediate", task)
    ]
    assert guards == [
        "Remediate | Arm the guard against skipping the always-tagged tasks",
        "Remediate | Fail when the always-tagged tasks were skipped",
    ]
    assert specs.check_role(TASKS.parent) == []


def test_the_completeness_check_asserts_the_result_accounting_of_the_plan() -> None:
    task = by_name(COMPLETENESS)
    assertion = cast("dict[str, object]", task["ansible.builtin.assert"])
    assert assertion["that"] == ["__linux_compliance_remediate_unaccounted | length == 0"]
    unaccounted = str(
        cast("dict[str, object]", task["vars"])["__linux_compliance_remediate_unaccounted"]
    )
    assert "__linux_compliance_remediate_results" in unaccounted
    assert (
        "freesecdev.linux_compliance.remediation_unaccounted(__linux_compliance_remediate_plan)"
        in unaccounted
    )
    assert set(task) == {"name", "vars", "ansible.builtin.assert", "tags"}


def test_the_dispatch_is_marked_complete_only_after_the_completeness_check() -> None:
    names = [task["name"] for task in load(TASKS / "main.yml")]
    assert names.index(DISPATCH) < names.index(COMPLETENESS) < names.index(DISPATCHED)
    assert by_name(DISPATCHED)["ansible.builtin.set_fact"] == {
        "__linux_compliance_remediate_dispatched": True
    }
    assert names[-1] == "Remediate | Fail when the always-tagged tasks were skipped"
