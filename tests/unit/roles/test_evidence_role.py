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
    "ansible.builtin.include_tasks",
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


def test_only_the_fetch_task_reaches_the_host_and_only_it_may_become() -> None:
    for path in sorted((ROLE / "tasks").glob("*.yml")):
        for task in tasks(path):
            module = module_of(task)
            if module in CONTROLLER_MODULES:
                assert task.get("delegate_to") == "localhost", task["name"]
                assert task.get("become") is False, task["name"]
            elif module in HOST_MODULES:
                assert task.get("become") == "{{ linux_compliance_evidence_become }}"
                assert "delegate_to" not in task
            else:
                assert module in LOCAL_MODULES, task["name"]
                assert "become" not in task, task["name"]


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
