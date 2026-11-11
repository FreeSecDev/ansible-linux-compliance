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
PLAN_ERRORS = "Remediate | Stop on unknown toggles, allow-list entries or catalogue errors"
VALUES = "Remediate | Resolve the target of every rule to apply, with the value overrides"
VALUES_SHAPE = "Remediate | Check the type and shape of the resolved values"
VALUES_ERRORS = (
    "Remediate | Stop on a value override that is unknown, not overridable yet or invalid"
)
PUBLISH = "Remediate | Publish the plan and the results"


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


def test_the_only_guard_tasks_are_the_three_of_main() -> None:
    guards = [
        task["name"] for task in load(TASKS / "main.yml") if specs.is_guard_task("remediate", task)
    ]
    assert guards == [
        "Remediate | Arm the guard against skipping the always-tagged tasks",
        "Remediate | Check that the guard is armed with the boolean false",
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


def test_pwquality_and_the_pam_conf_families_read_the_same_pam_directories() -> None:
    variables = cast(
        "dict[str, object]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "roles" / "remediate" / "vars" / "main.yml").read_text(
                encoding="utf-8"
            )
        ),
    )
    shared = "{{ __linux_compliance_remediate_pam_directories }}"
    pwquality = [
        task
        for task in walk(load(TASKS / "pwquality.yml"))
        if str(task.get("name", "")).startswith("Password quality | Inspect the PAM directories")
    ]
    pam_conf = [
        task for task in walk(load(TASKS / "pam_conf_prepare.yml")) if task.get("loop") == shared
    ]
    assert variables["__linux_compliance_remediate_pam_directories"] == [
        "/etc/pam.d",
        "/usr/lib/pam.d",
        "/usr/share/pam.d",
    ]
    assert "__linux_compliance_remediate_pwquality_pam_directories" not in variables
    assert [task.get("loop") for task in pwquality] == [shared]
    assert len(pam_conf) == 1


def test_the_value_overrides_are_validated_before_any_family_runs() -> None:
    names = [task["name"] for task in load(TASKS / "main.yml")]
    position = names.index(PLAN_ERRORS)
    assert names[position + 1 : position + 4] == [VALUES, VALUES_SHAPE, VALUES_ERRORS]
    assert names.index(VALUES_ERRORS) < names.index(DISPATCH)
    resolved = str(
        cast("dict[str, object]", by_name(VALUES)["ansible.builtin.set_fact"])[
            "__linux_compliance_remediate_values"
        ]
    )
    assert "__linux_compliance_remediate_rules | freesecdev.linux_compliance.value_overrides(" in (
        resolved
    )
    for option in ("overrides", "plan", "content_sha256", "profile"):
        assert f"'{option}':" in resolved
    assert "'overrides': linux_compliance_remediate_value_overrides," in resolved
    assertion = cast("dict[str, object]", by_name(VALUES_ERRORS)["ansible.builtin.assert"])
    assert assertion["that"] == ["__linux_compliance_remediate_values.errors | length == 0"]
    assert "no change was made to the host" in str(assertion["fail_msg"])


def test_the_value_overrides_must_be_a_mapping() -> None:
    assertion = cast(
        "dict[str, object]", by_name("Remediate | Validate inputs")["ansible.builtin.assert"]
    )
    assert "linux_compliance_remediate_value_overrides is mapping" in cast(
        "list[str]", assertion["that"]
    )


def test_the_results_publish_the_unused_overrides_and_their_notices() -> None:
    published = cast("dict[str, dict[str, object]]", by_name(PUBLISH)["ansible.builtin.set_fact"])[
        "linux_compliance_remediated"
    ]
    assert published["unused_overrides"] == (
        "{{ __linux_compliance_remediate_values.unused_overrides }}"
    )
    assert "+ __linux_compliance_remediate_values.notices" in str(published["notices"])
