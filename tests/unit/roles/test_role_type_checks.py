from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
import yaml

from tools.roles import generate_role_guards as gen

if TYPE_CHECKING:
    from collections.abc import Iterator

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
NESTED = ("block", "rescue", "always")
KEY_FACTS: dict[str, dict[str, str]] = {
    "audit": {
        "__linux_compliance_audit_toggle_names": (
            "__linux_compliance_audit_toggle_names is sequence"
        ),
        "__linux_compliance_audit_toggles": "__linux_compliance_audit_toggles is mapping",
        "__linux_compliance_audit_evaluation": (
            "__linux_compliance_audit_evaluation is none or "
            "__linux_compliance_audit_evaluation is mapping"
        ),
    },
    "evidence": {
        "__linux_compliance_evidence_root": "__linux_compliance_evidence_root is string",
        "__linux_compliance_evidence_plan": "__linux_compliance_evidence_plan is mapping",
    },
    "remediate": {
        "__linux_compliance_remediate_dispatched": (
            "__linux_compliance_remediate_dispatched is boolean"
        ),
        "__linux_compliance_remediate_toggle_names": (
            "__linux_compliance_remediate_toggle_names is sequence"
        ),
        "__linux_compliance_remediate_plan": "__linux_compliance_remediate_plan is mapping",
        "__linux_compliance_remediate_results": "__linux_compliance_remediate_results is sequence",
    },
    "verify": {
        "__linux_compliance_verify_dispatched": "__linux_compliance_verify_dispatched is boolean",
        "__linux_compliance_verify_comparison": "__linux_compliance_verify_comparison is mapping",
    },
}


def task_lists(value: object) -> Iterator[list[dict[str, object]]]:
    if not isinstance(value, list):
        return
    tasks = cast("list[dict[str, object]]", value)
    yield tasks
    for task in tasks:
        for key in NESTED:
            yield from task_lists(task.get(key))


def key_fact_sites(role: str) -> Iterator[tuple[str, str, dict[str, object], object]]:
    for path in sorted((REPOSITORY_ROOT / "roles" / role / "tasks").glob("*.yml")):
        if path.name == gen.GUARD_FILE:
            continue
        for tasks in task_lists(yaml.safe_load(path.read_text(encoding="utf-8"))):
            for index, task in enumerate(tasks):
                facts = task.get(gen.SET_FACT)
                if not isinstance(facts, dict):
                    continue
                following = tasks[index + 1] if index + 1 < len(tasks) else None
                for name, value in cast("dict[str, object]", facts).items():
                    if name in KEY_FACTS[role] and name not in str(value):
                        yield path.name, name, task, following


def leading_checks(task: object) -> list[str]:
    if not isinstance(task, dict):
        return []
    assertion = cast("dict[str, object]", task).get("ansible.builtin.assert")
    if not isinstance(assertion, dict):
        return []
    return [
        str(item) for item in cast("list[object]", cast("dict[str, object]", assertion)["that"])
    ]


@pytest.mark.parametrize("role", sorted(KEY_FACTS))
def test_every_key_fact_is_type_checked_right_after_the_role_sets_it(role: str) -> None:
    seen: set[str] = set()
    for file_name, name, task, following in key_fact_sites(role):
        seen.add(name)
        checks = leading_checks(following)
        assert checks, f"{file_name}: no assertion follows the set_fact of {name}"
        assert checks[0] == KEY_FACTS[role][name], f"{file_name}: {name}"
        tags = cast("dict[str, object]", following).get("tags")
        assert tags in (task.get("tags"), [f"linux_compliance_{role}_guard"]), name
    assert seen == set(KEY_FACTS[role])


def test_the_key_facts_are_internal_facts_of_guarded_roles() -> None:
    assert set(KEY_FACTS) == set(gen.GUARDED_ROLES)
    for role, facts in KEY_FACTS.items():
        found = gen.role_variables(REPOSITORY_ROOT / "roles" / role, {})
        assert set(facts) <= found.facts, role


def test_an_update_of_a_checked_fact_needs_no_second_check() -> None:
    updates = [
        str(value).split("+", 1)[0].strip()
        for file_name in ("file_permissions_apply.yml", "file_permissions_cleanup.yml")
        for tasks in task_lists(
            yaml.safe_load((REPOSITORY_ROOT / "roles/remediate/tasks" / file_name).read_text())
        )
        for task in tasks
        for name, value in cast("dict[str, object]", task.get(gen.SET_FACT, {})).items()
        if name == "__linux_compliance_remediate_results"
    ]
    assert updates == ["{{ __linux_compliance_remediate_results"] * 2
    assert all(
        site[0] == "main.yml"
        for site in key_fact_sites("remediate")
        if site[1] == "__linux_compliance_remediate_results"
    )


def test_a_set_fact_without_a_following_type_check_is_found() -> None:
    assert leading_checks(None) == []
    assert leading_checks({"ansible.builtin.debug": {"msg": "x"}}) == []
    assert leading_checks({"ansible.builtin.assert": {"that": ["a", "b"]}}) == ["a", "b"]
    assert list(task_lists({"not": "a list"})) == []
