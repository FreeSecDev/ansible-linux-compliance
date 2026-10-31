"""The Molecule audit names the scanner's own reason when a scan fails (FREES-180).

A scan that ends ``failed``, not ``timed_out``, fails the scenario; the instance is then
destroyed, so the failure message is the only place left for ``scan_run.error_message``.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

AUDIT_TASKS = (
    Path(__file__).resolve().parents[3]
    / "extensions"
    / "molecule"
    / "shared"
    / "tasks"
    / "audit.yml"
)


def failure_task() -> dict[str, object]:
    tasks = cast("list[dict[str, object]]", yaml.safe_load(AUDIT_TASKS.read_text(encoding="utf-8")))
    [block] = [task for task in tasks if "rescue" in task]
    rescue = cast("list[dict[str, object]]", block["rescue"])
    [task] = [task for task in rescue if "ansible.builtin.fail" in task]
    return task


def test_the_failure_message_carries_the_scanner_error_of_this_audit_only() -> None:
    task = failure_task()
    message = str(cast("dict[str, object]", task["ansible.builtin.fail"])["msg"])
    assert "ansible_failed_result.msg" in message
    assert ".error_message | default('none reported by the scanner', true)" in message
    assert "audit_published.run_id | default('none') != audit_previous_run_id" in message
    assert task["when"] == "not audit_timed_out | bool"
