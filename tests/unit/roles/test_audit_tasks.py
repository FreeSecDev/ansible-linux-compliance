from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

ROLE = Path(__file__).resolve().parents[3] / "roles" / "audit"
SCAN_MODULE = "freesecdev.linux_compliance.compliance_scan"
TOGGLE_RESULT = "{{ __linux_compliance_audit_toggles.disabled_rules }}"
OPENSCAP = "linux_compliance_audit_backend == 'openscap'"
SCC = "linux_compliance_audit_backend == 'scc'"

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
    scc = index_of(main, "scc.yml")
    scan = index_of(main, SCAN_MODULE)
    assert discover_check < toggles < scc < scan
    assert main[toggles].get("tags") == ["always"]
    assert main[scc].get("tags") == ["always"]
    assert main[discover_check]["when"] == OPENSCAP
    assert main[toggles]["when"] == OPENSCAP
    assert main[scc]["when"] == SCC


def test_the_scc_branch_reads_the_profile_and_maps_the_toggles_before_the_scan() -> None:
    steps = tasks("scc.yml")
    assert steps[0].get("ansible.builtin.import_tasks") == "toggle_names.yml"
    read = index_of(steps, "freesecdev.linux_compliance.profile_info")
    assert steps[read]["become"] is True
    resolve = next(
        position
        for position, task in enumerate(steps)
        if "__linux_compliance_audit_toggles"
        in cast("dict[str, object]", task.get("ansible.builtin.set_fact", {}))
    )
    facts = cast("dict[str, str]", steps[resolve]["ansible.builtin.set_fact"])
    expression = facts["__linux_compliance_audit_toggles"]
    assert "freesecdev.linux_compliance.scc_toggles" in expression
    assert "role_path ~ '/../../content/stig-mapping.json'" in expression
    assert "linux_compliance_audit_disabled_rules" in expression
    stop = next(
        position
        for position, task in enumerate(steps)
        if "Stop on invalid toggles" in str(task.get("name"))
    )
    assertion = cast("dict[str, list[str]]", steps[stop]["ansible.builtin.assert"])
    assert assertion["that"] == ["__linux_compliance_audit_toggles.errors | length == 0"]
    assert read < resolve < stop
    assert all(task.get("tags") == ["always"] for task in steps)


def test_the_scan_passes_the_scc_inputs() -> None:
    main = tasks("scan.yml")
    scan = cast("dict[str, str]", main[index_of(main, SCAN_MODULE)][SCAN_MODULE])
    assert "__linux_compliance_audit_toggles.control_placement" in scan["control_placement"]
    assert scan["allow_off_platform_benchmark"] == (
        "{{ linux_compliance_audit_allow_off_platform_benchmark }}"
    )
    assert "__linux_compliance_audit_scc_profile.content_path" in scan["content_path"]
    assert "__linux_compliance_audit_scc_profile.content_sha256" in scan["expected_sha256"]


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
    stop = next(
        task
        for task in steps
        if task.get("name") == "Audit | Stop on unknown or invalid toggles before any scan"
    )
    assertion = cast("dict[str, list[str]]", stop["ansible.builtin.assert"])
    assert assertion["that"] == ["__linux_compliance_audit_toggles.errors | length == 0"]
    assert steps.index(resolve) < steps.index(stop)
    assert all(task.get("tags") == ["always"] for task in steps)
    assert all("when" not in task for task in steps if task is not steps[-1])


READ_MARKER = "__linux_compliance_audit_exceptions_read_here"


def test_the_host_that_runs_the_read_is_marked_on_that_host_only() -> None:
    steps = tasks("exceptions_file.yml")
    read = next(
        position
        for position, task in enumerate(steps)
        if "__linux_compliance_audit_exceptions"
        in cast("dict[str, object]", task.get("ansible.builtin.set_fact", {}))
    )
    marker = steps[read + 1]
    assert marker["ansible.builtin.set_fact"] == {READ_MARKER: "{{ inventory_hostname }}"}
    assert marker["delegate_to"] == "{{ inventory_hostname }}"
    assert marker["delegate_facts"] is True
    assert marker["run_once"] is True
    assert marker["tags"] == ["always"]


def test_a_host_that_read_the_file_but_is_not_first_of_its_batch_fails() -> None:
    steps = tasks("exceptions_file.yml")
    check = next(task for task in steps if "read once for the batch" in str(task.get("name")))
    assertion = cast("dict[str, object]", check["ansible.builtin.assert"])
    conditions = [" ".join(str(item).split()) for item in cast("list[str]", assertion["that"])]
    assert (
        f"{READ_MARKER} != inventory_hostname or inventory_hostname == ansible_play_batch | first"
        in conditions
    )
    assert "does not support the free strategy" in str(assertion["fail_msg"])
    assert "run_once" not in check


def test_the_published_audit_result_is_checked_against_the_scan_right_after_it_is_set() -> None:
    main = tasks("scan.yml")
    publish = next(
        position
        for position, task in enumerate(main)
        if "linux_compliance_audited"
        in cast("dict[str, object]", task.get("ansible.builtin.set_fact", {}))
    )
    check = main[publish + 1]
    assertion = cast("dict[str, object]", check["ansible.builtin.assert"])
    conditions = [" ".join(str(item).split()) for item in cast("list[str]", assertion["that"])]
    run_id = "__linux_compliance_audit_scan.run_id"
    assert f"linux_compliance_audited.run_id | default(none) == {run_id}" in conditions
    assert (
        "hostvars[inventory_hostname]['linux_compliance_audited'].run_id | default(none)"
        f" == {run_id}" in conditions
    )
    assert "extra variable (-e)" in str(assertion["fail_msg"])
    assert check["tags"] == ["always"]
    assert "when" not in check


def test_the_exception_scope_uses_the_groups_magic_variable_not_group_names() -> None:
    steps = tasks("exceptions_apply.yml")
    apply = next(
        task
        for task in steps
        if "__linux_compliance_audit_evaluation"
        in cast("dict[str, object]", task.get("ansible.builtin.set_fact", {}))
    )
    facts = cast("dict[str, str]", apply["ansible.builtin.set_fact"])
    expression = " ".join(facts["__linux_compliance_audit_evaluation"].split())
    assert "group_names" not in expression
    assert (
        "inventory_hostname, groups | dict2items | rejectattr('key', 'equalto', 'all')"
        " | selectattr('value', 'ansible.builtin.contains', inventory_hostname)"
        " | map(attribute='key') | sort)" in expression
    )
    assert "group_names" not in str(apply.get("vars"))


def test_the_stig_mapping_that_the_scc_branch_reads_ships_with_the_collection() -> None:
    root = ROLE.parents[1]
    assert (ROLE / ".." / ".." / "content" / "stig-mapping.json").resolve().is_file()
    makefile = (root / "Makefile").read_text(encoding="utf-8")
    sources = makefile.split("\nCOLLECTION_SOURCES := ", 1)[1].split("\nTREE_SORT", 1)[0]
    assert "content/stig-mapping.json" in sources.split()
