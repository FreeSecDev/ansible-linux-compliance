from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
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


def test_the_playbook_collects_before_the_gates_and_names_the_missing_hosts() -> None:
    plays = cast("list[dict[str, object]]", load(REPOSITORY_ROOT / "playbooks" / "evidence.yml"))
    assert plays[0]["ansible.builtin.import_playbook"] == "audit.yml"
    assert plays[0]["vars"] == {"linux_compliance_audit_defer_gate": True}
    roles = [cast("list[dict[str, object]]", play["tasks"])[0] for play in plays[1:]]
    targets = [
        cast(
            "dict[str, str]",
            task.get("ansible.builtin.include_role") or task.get("ansible.builtin.import_role"),
        )
        for task in roles
    ]
    assert [(target["name"], target.get("tasks_from")) for target in targets] == [
        ("freesecdev.linux_compliance.evidence", None),
        ("freesecdev.linux_compliance.evidence", "summary.yml"),
        ("freesecdev.linux_compliance.audit", "gate.yml"),
    ]
    assert plays[2]["hosts"] == "localhost"


def test_the_audit_role_defers_its_gates_only_on_request() -> None:
    audit = REPOSITORY_ROOT / "roles" / "audit"
    defaults = cast("dict[str, object]", load(audit / "defaults" / "main.yml"))
    assert defaults["linux_compliance_audit_defer_gate"] is False
    for entry in ("main.yml", "evaluate.yml"):
        gates = [
            task
            for task in cast("list[dict[str, object]]", load(audit / "tasks" / entry))
            if task.get("ansible.builtin.import_tasks") == "gate.yml"
        ]
        assert [task["when"] for task in gates] == ["not linux_compliance_audit_defer_gate"]
