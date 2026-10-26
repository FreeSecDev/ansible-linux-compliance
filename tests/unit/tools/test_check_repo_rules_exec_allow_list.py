from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.lint import check_repo_rules as rules
from tools.lint.repo_rules import exec_variables

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

SETTING = re.compile(r"^setting '(?P<name>[^']+)' to '(?P<value>.*)' is not allowed")


def test_every_reviewed_setting_is_used_by_its_file(monkeypatch: pytest.MonkeyPatch) -> None:
    allowed = exec_variables.ALLOWED_SETTINGS
    monkeypatch.setattr(exec_variables, "ALLOWED_SETTINGS", frozenset[object]())
    files = sorted({rules.REPO_ROOT / path for path, _, _ in allowed})
    used: set[tuple[Path, str, str]] = set()
    for violation in rules.check_paths(files):
        match = SETTING.match(violation.message)
        assert match is not None, violation
        used.add(
            (
                violation.path.relative_to(rules.REPO_ROOT),
                match.group("name"),
                match.group("value"),
            )
        )
    assert used == allowed


def test_the_molecule_allow_list_is_narrow() -> None:
    molecule = {
        (path.as_posix(), name, value)
        for path, name, value in exec_variables.ALLOWED_SETTINGS
        if path.parts[0] == "extensions"
    }
    assert molecule == {
        (
            "extensions/molecule/shared/vars/guard_cases.yml",
            "connection",
            "community.docker.docker",
        ),
        (
            "extensions/molecule/shared/vars/guard_cases.yml",
            "ansible_connection",
            "community.docker.docker",
        ),
        (
            "extensions/molecule/shared/vars/guard_cases.yml",
            "ansible_docker_extra_args",
            "-H tcp://192.0.2.1:2375",
        ),
        (
            "extensions/molecule/shared/vars/guard_cases.yml",
            "docker_extra_args",
            "-H tcp://192.0.2.1:2375",
        ),
        ("extensions/molecule/shared/create.yml", "connection", "community.docker.docker"),
        ("extensions/molecule/selftest/bypass.yml", "ansible_connection", "{{ selftest_docker }}"),
        ("extensions/molecule/selftest/bypass.yml", "ansible_connection", "selftest_docker"),
        (
            "extensions/molecule/selftest/bypass.yml",
            "ansible_docker_extra_args",
            "--host tcp://192.0.2.1:2375",
        ),
    }
    others = {
        name for path, name, _ in exec_variables.ALLOWED_SETTINGS if path.parts[0] != "extensions"
    }
    assert others == {"ansible_python_interpreter", "ansible_ssh_common_args"}
    assert all(
        path.parts[:2] == ("tests", "playbooks")
        for path, _, _ in exec_variables.ALLOWED_SETTINGS
        if path.parts[0] != "extensions"
    )
