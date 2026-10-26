from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    collection,
    evidence,
    openscap,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ROLE = REPOSITORY_ROOT / "roles" / "evidence"
CONTROLLER_MODULES = {"ansible.builtin.stat", "ansible.builtin.file", "ansible.builtin.copy"}
HOST_MODULES = {"ansible.builtin.fetch"}
LOCAL_MODULES = {
    "ansible.builtin.set_fact",
    "ansible.builtin.assert",
    "ansible.builtin.debug",
    "ansible.builtin.fail",
    "ansible.builtin.import_tasks",
}


def load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def tasks(path: Path) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for task in cast("list[dict[str, object]]", load(path)):
        found.append(task)
        for key in ("block", "rescue", "always"):
            found.extend(cast("list[dict[str, object]]", task.get(key, [])))
    return [task for task in found if not {"block", "rescue", "always"} & set(task)]


def module_of(task: dict[str, object]) -> str:
    return next(key for key in task if key.startswith("ansible.builtin."))


def test_the_recorded_collection_version_matches_galaxy() -> None:
    galaxy = cast("dict[str, object]", load(REPOSITORY_ROOT / "galaxy.yml"))
    role_vars = cast("dict[str, object]", load(ROLE / "vars" / "main.yml"))
    assert role_vars["__linux_compliance_evidence_collection_version"] == galaxy["version"]


def test_the_bundle_vocabulary_uses_the_file_names_of_the_audit() -> None:
    assert set(evidence.HOST_SOURCES) == {
        audit.SCAN_RUN_FILE_NAME,
        audit.TAILORING_FILE_NAME,
        f"{audit.SCAN_DIRECTORY_NAME}/{openscap.RESULTS_FILE_NAME}",
        f"{audit.SCAN_DIRECTORY_NAME}/{openscap.ARF_FILE_NAME}",
    }


def test_only_the_host_stat_and_fetch_reach_the_host_and_only_they_may_become() -> None:
    host_tasks: list[str] = []
    for path in sorted((ROLE / "tasks").glob("*.yml")):
        for task in tasks(path):
            module = module_of(task)
            if module in HOST_MODULES or (
                "delegate_to" not in task and module in CONTROLLER_MODULES
            ):
                assert module in {"ansible.builtin.fetch", "ansible.builtin.stat"}, task["name"]
                assert task.get("become") == "{{ linux_compliance_evidence_become }}"
                assert "delegate_to" not in task
                host_tasks.append(module)
            elif module in CONTROLLER_MODULES:
                assert task.get("delegate_to") == "localhost", task["name"]
                assert task.get("become") is False, task["name"]
            else:
                assert module in LOCAL_MODULES, task["name"]
                assert "become" not in task, task["name"]
    assert host_tasks == ["ansible.builtin.stat", "ansible.builtin.fetch"]


def test_bundle_files_are_written_with_mode_0600_and_directories_with_0700() -> None:
    for task in tasks(ROLE / "tasks" / "collect.yml"):
        module = module_of(task)
        arguments = cast("dict[str, object]", task[module])
        if module == "ansible.builtin.copy":
            assert arguments["mode"] == "0600"
            assert arguments["force"] is False
        if module == "ansible.builtin.file" and arguments["state"] == "directory":
            assert arguments["mode"] == "0700"
        if module == "ansible.builtin.file" and arguments["state"] == "file":
            assert arguments["mode"] == "0600"


def imports(path: Path) -> list[str]:
    return [
        cast("str", task["ansible.builtin.import_tasks"])
        for task in cast("list[dict[str, object]]", load(path))
        if "ansible.builtin.import_tasks" in task
    ]


def role_of(task: dict[str, object]) -> object:
    return task.get("ansible.builtin.include_role", task.get("ansible.builtin.import_role"))


def test_the_playbook_writes_the_summary_before_any_gate_or_collection_fails_a_host() -> None:
    plays = cast("list[dict[str, object]]", load(REPOSITORY_ROOT / "playbooks" / "evidence.yml"))
    assert len(plays) == 5
    reached = cast("list[dict[str, object]]", plays[0]["pre_tasks"])
    assert [role_of(task) for task in reached] == [
        {"name": "freesecdev.linux_compliance.evidence", "tasks_from": "reached.yml"}
    ]
    audit = cast("list[dict[str, object]]", plays[0]["tasks"])[0]
    assert audit["ansible.builtin.import_role"] == {
        "name": "freesecdev.linux_compliance.audit",
        "tasks_from": "deferred.yml",
    }
    assert audit["become"] is True
    assert "vars" not in plays[0]
    collect = cast("list[dict[str, object]]", plays[2]["tasks"])
    assert len(collect) == 1
    enforce = cast("list[dict[str, object]]", collect[0]["block"])
    assert [role_of(task) for task in enforce] == [
        {"name": "freesecdev.linux_compliance.audit", "tasks_from": "enforce.yml"}
    ]
    rescued = cast("list[dict[str, object]]", collect[0]["rescue"])
    assert [module_of(task) for task in rescued] == ["ansible.builtin.debug"]
    always = cast("list[dict[str, object]]", collect[0]["always"])
    assert len(always) == 1
    gather = cast("list[dict[str, object]]", always[0]["block"])
    assert [role_of(task) for task in gather] == [{"name": "freesecdev.linux_compliance.evidence"}]
    rescued = cast("list[dict[str, object]]", always[0]["rescue"])
    assert [module_of(task) for task in rescued] == ["ansible.builtin.debug"]
    summary = cast("list[dict[str, object]]", plays[3]["tasks"])
    assert [role_of(task) for task in summary] == [
        {"name": "freesecdev.linux_compliance.evidence", "tasks_from": "summary.yml"}
    ]
    assert plays[3]["hosts"] == "localhost"
    final = cast("list[dict[str, object]]", plays[4]["tasks"])
    assert plays[4]["hosts"] == plays[2]["hosts"] == plays[0]["hosts"]
    assert [role_of(task) for task in final] == [
        {"name": "freesecdev.linux_compliance.audit", "tasks_from": "enforce.yml"},
        {"name": "freesecdev.linux_compliance.evidence", "tasks_from": "collected.yml"},
    ]
    for play in plays:
        for task in cast("list[dict[str, object]]", play.get("tasks", [])):
            assert "ignore_errors" not in task
            assert "when" not in task


MARKER = "__linux_compliance_evidence_run_bundle"


def test_the_summary_reads_the_run_marker_that_the_role_publishes_with_the_bundle_fact() -> None:
    name = "Evidence | Publish the collected bundle and mark it as collected in this run"
    published = next(task for task in tasks(ROLE / "tasks" / "collect.yml") if task["name"] == name)
    fact = cast("dict[str, object]", published["ansible.builtin.set_fact"])
    source = "{{ __linux_compliance_evidence_published }}"
    assert fact == {"linux_compliance_evidence_bundle": source, MARKER: source}
    assert "cacheable" not in fact
    task_vars = cast("dict[str, object]", published["vars"])
    bundle = cast("dict[str, object]", task_vars["__linux_compliance_evidence_published"])
    assert tuple(sorted(bundle)) == collection.BUNDLE_FACT_KEYS


def test_only_the_run_marker_counts_a_host_as_collected() -> None:
    summary = (ROLE / "tasks" / "summary.yml").read_text(encoding="utf-8")
    assert f"selectattr('{MARKER}', 'defined')\n" in summary
    assert f"selectattr('{MARKER}', 'mapping')" in summary
    assert "linux_compliance_evidence_bundle" not in summary
    collected = tasks(ROLE / "tasks" / "collected.yml")
    assert len(collected) == 1
    condition = cast("dict[str, list[str]]", collected[0]["ansible.builtin.assert"])["that"]
    assert f"hostvars[inventory_hostname]['{MARKER}'] is defined" in condition[0]
    assert f"hostvars[inventory_hostname]['{MARKER}'] is mapping" in condition[0]
    assert "linux_compliance_evidence_bundle" not in condition[0]


def test_the_guard_runs_where_it_cannot_erase_the_marker_of_a_target_host() -> None:
    guard = {"ansible.builtin.import_tasks": "internal_variables.yml"}
    for name in ("main.yml", "summary.yml"):
        first = tasks(ROLE / "tasks" / name)[0]
        assert {key: first[key] for key in guard} == guard, name
    for name in ("reached.yml", "collected.yml"):
        text = (ROLE / "tasks" / name).read_text(encoding="utf-8")
        assert "internal_variables.yml" not in text, name
    for task in tasks(ROLE / "tasks" / "internal_variables.yml"):
        assert MARKER not in cast("dict[str, object]", task.get("ansible.builtin.set_fact", {}))
    assert MARKER not in (ROLE / "tasks" / "internal_variables.yml").read_text(encoding="utf-8")
    condition = cast(
        "dict[str, list[str]]", tasks(ROLE / "tasks" / "collected.yml")[0]["ansible.builtin.assert"]
    )["that"][0]
    assert "== linux_compliance_audited.run_id" in condition
    assert "is match('^[0-9a-f]{64}$')" in condition


def test_reached_refuses_internal_variables_from_outside_before_anything_else() -> None:
    first = tasks(ROLE / "tasks" / "reached.yml")[0]
    assert first["run_once"] is True
    assert "vars" not in first
    condition = cast("dict[str, list[str]]", first["ansible.builtin.assert"])["that"]
    assert "select('match', '__linux_compliance_evidence_')" in condition[0]
    assert "(groups['all'] + ['localhost'])" in condition[0]
    assert "map('extract', hostvars, 'inventory_hostname')" in condition[1]
    names = [str(task["name"]) for task in tasks(ROLE / "tasks" / "summary.yml")]
    assert names[2].startswith("Evidence | Check that the audit play ran reached.yml")


def test_the_summary_is_written_with_mode_0600_and_never_overwritten() -> None:
    written = [
        task
        for task in tasks(ROLE / "tasks" / "summary.yml")
        if module_of(task) in {"ansible.builtin.copy", "ansible.builtin.file"}
    ]
    assert [module_of(task) for task in written] == ["ansible.builtin.file", "ansible.builtin.copy"]
    directory = cast("dict[str, object]", written[0]["ansible.builtin.file"])
    summary = cast("dict[str, object]", written[1]["ansible.builtin.copy"])
    assert directory["mode"] == "0700"
    assert summary["mode"] == "0600"
    assert summary["force"] is False


def test_only_the_deferred_entry_points_skip_the_gates_and_no_variable_does() -> None:
    tasks = REPOSITORY_ROOT / "roles" / "audit" / "tasks"
    assert imports(tasks / "main.yml") == ["internal_variables.yml", "scan.yml", "gate.yml"]
    assert imports(tasks / "evaluate.yml") == [
        "internal_variables.yml",
        "evaluation.yml",
        "gate.yml",
    ]
    assert imports(tasks / "enforce.yml") == ["internal_variables.yml", "gate.yml"]
    assert imports(tasks / "deferred.yml") == ["internal_variables.yml", "scan.yml", "defer.yml"]
    assert imports(tasks / "evaluate_deferred.yml") == [
        "internal_variables.yml",
        "evaluation.yml",
        "defer.yml",
    ]
    for path in sorted(tasks.glob("*.yml")):
        for task in cast("list[dict[str, object]]", load(path)):
            if task.get("ansible.builtin.import_tasks") == "gate.yml":
                assert "when" not in task, path.name
        assert "defer_gate" not in path.read_text(encoding="utf-8"), path.name
    defaults = cast(
        "dict[str, object]", load(REPOSITORY_ROOT / "roles" / "audit" / "defaults" / "main.yml")
    )
    assert not [name for name in defaults if "defer" in name]
