from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

ROLE = Path(__file__).resolve().parents[3] / "roles" / "audit"
SCAN_MODULE = "freesecdev.linux_compliance.compliance_scan"
TOGGLE_RESULT = "{{ __linux_compliance_audit_toggles.disabled_rules }}"

Task = dict[str, object]


def tasks(name: str) -> list[Task]:
    loaded = yaml.safe_load((ROLE / "tasks" / name).read_text(encoding="utf-8"))
    return cast("list[Task]", loaded)


def index_of(items: list[Task], predicate: str) -> int:
    matches = [
        position
        for position, task in enumerate(items)
        if predicate in task or task.get("ansible.builtin.import_tasks") == predicate
    ]
    assert len(matches) == 1, predicate
    return matches[0]


def test_the_scan_uses_the_toggle_result_and_nothing_else() -> None:
    main = tasks("scan.yml")
    scan = cast("dict[str, object]", main[index_of(main, SCAN_MODULE)][SCAN_MODULE])
    assert scan["disabled_rules"] == TOGGLE_RESULT
    scans = [task for task in main if SCAN_MODULE in task]
    assert len(scans) == 1


def test_the_toggles_are_resolved_after_the_discover_check_and_before_the_scan() -> None:
    main = tasks("scan.yml")
    discover_check = next(
        position
        for position, task in enumerate(main)
        if "discover role verified the same profile" in str(task.get("name"))
    )
    toggles = index_of(main, "toggles.yml")
    scan = index_of(main, SCAN_MODULE)
    assert discover_check < toggles < scan
    assert main[toggles].get("tags") == ["always"]
    assert "when" not in main[toggles]


def test_the_toggle_file_resolves_with_the_shared_filter_and_fails_closed() -> None:
    steps = tasks("toggles.yml")
    resolve = next(
        task
        for task in steps
        if "__linux_compliance_audit_toggles"
        in cast("dict[str, object]", task.get("ansible.builtin.set_fact", {}))
    )
    facts = cast("dict[str, str]", resolve["ansible.builtin.set_fact"])
    expression = facts["__linux_compliance_audit_toggles"]
    assert "freesecdev.linux_compliance.audit_disabled_rules" in expression
    assert "linux_compliance_discovered.rule_ids" in expression
    assert "linux_compliance_audit_disabled_rules" in expression
    stop = next(task for task in steps if "ansible.builtin.assert" in task)
    assertion = cast("dict[str, list[str]]", stop["ansible.builtin.assert"])
    assert assertion["that"] == ["__linux_compliance_audit_toggles.errors | length == 0"]
    assert steps.index(resolve) < steps.index(stop)
    assert all(task.get("tags") == ["always"] for task in steps)
    assert all("when" not in task for task in steps if task is not steps[-1])
