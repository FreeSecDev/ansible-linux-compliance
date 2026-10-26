from __future__ import annotations

import runpy
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.roles import check_role_specs as specs

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ROLES = ("discover", "audit", "remediate", "verify", "evidence")
FLAG = "linux_compliance_demo_flag"
TASKS = [{"name": "Demo", "ansible.builtin.fail": {"msg": "x"}, "tags": ["always"]}]


def write_role(
    root: Path,
    options: object | None = None,
    defaults: object | None = None,
    argument_specs: object | None = None,
) -> Path:
    role = root / "demo"
    (role / "meta").mkdir(parents=True)
    (role / "defaults").mkdir()
    if options is None:
        options = {FLAG: {"type": "bool", "default": False, "description": ["A flag."]}}
    if defaults is None:
        defaults = {FLAG: False}
    if argument_specs is None:
        argument_specs = {"argument_specs": {"main": {"options": options}}}
    (role / "meta" / "argument_specs.yml").write_text(yaml.safe_dump(argument_specs))
    (role / "defaults" / "main.yml").write_text(yaml.safe_dump(defaults))
    (role / "tasks").mkdir()
    (role / "tasks" / "main.yml").write_text(yaml.safe_dump(TASKS))
    return role


@pytest.mark.parametrize("role", ROLES)
def test_repository_roles_exist_and_match(role: str) -> None:
    assert (REPOSITORY_ROOT / "roles" / role / "tasks" / "main.yml").is_file()
    assert specs.check_role(REPOSITORY_ROOT / "roles" / role) == []


def test_repository_roles_directory_is_clean() -> None:
    assert specs.check_roles(REPOSITORY_ROOT / "roles") == []


def test_remediation_is_disabled_by_default() -> None:
    defaults = specs.load_mapping(REPOSITORY_ROOT / "roles/remediate/defaults/main.yml")
    assert defaults is not None
    assert defaults["linux_compliance_remediate_enabled"] is False
    assert defaults["linux_compliance_remediate_allow_disruptive"] == []


def test_remediation_spec_default_is_disabled() -> None:
    loaded = specs.load_mapping(REPOSITORY_ROOT / "roles/remediate/meta/argument_specs.yml")
    assert loaded is not None
    entry_points = cast("dict[str, dict[str, dict[str, dict[str, object]]]]", loaded)
    options = entry_points["argument_specs"]["main"]["options"]
    option = cast("dict[str, object]", options["linux_compliance_remediate_enabled"])
    assert option["default"] is False
    assert option["type"] == "bool"


def test_valid_role_has_no_findings(tmp_path: Path) -> None:
    assert specs.check_role(write_role(tmp_path)) == []


def test_missing_files(tmp_path: Path) -> None:
    role = tmp_path / "demo"
    role.mkdir()
    assert "argument_specs.yml is missing" in specs.check_role(role)[0]


def test_specs_not_a_mapping(tmp_path: Path) -> None:
    role = write_role(tmp_path, argument_specs=["list"])
    assert "missing or not a mapping" in specs.check_role(role)[0]


@pytest.mark.parametrize(
    "argument_specs",
    [{"other": 1}, {"argument_specs": []}, {"argument_specs": {"x": {}}}],
)
def test_missing_entry_point(tmp_path: Path, argument_specs: object) -> None:
    role = write_role(tmp_path, argument_specs=argument_specs)
    assert "must define the main entry point" in specs.check_role(role)[0]


@pytest.mark.parametrize("entry", [None, [], {"options": 1}, {}])
def test_missing_options(tmp_path: Path, entry: object) -> None:
    role = write_role(tmp_path, argument_specs={"argument_specs": {"main": entry}})
    assert "must define options" in specs.check_role(role)[0]


def test_missing_defaults_file(tmp_path: Path) -> None:
    role = write_role(tmp_path)
    (role / "defaults" / "main.yml").unlink()
    assert "defaults/main.yml is missing" in specs.check_role(role)[0]


def test_extra_and_missing_defaults(tmp_path: Path) -> None:
    role = write_role(tmp_path, defaults={"linux_compliance_demo_other": 1})
    findings = specs.check_role(role)
    assert any("not in the argument spec" in item for item in findings)
    assert any("missing from defaults/main.yml" in item for item in findings)


def test_prefix_is_enforced(tmp_path: Path) -> None:
    option = {"type": "bool", "default": False, "description": "x"}
    role = write_role(tmp_path, options={"flag": option}, defaults={"flag": False})
    assert "must be prefixed linux_compliance_demo_" in specs.check_role(role)[0]


def test_shared_variables_need_no_role_prefix(tmp_path: Path) -> None:
    name = "linux_compliance_exceptions_file"
    option = {"type": "str", "default": None, "description": "x"}
    role = write_role(tmp_path, options={name: option}, defaults={name: None})
    assert specs.check_role(role) == []


def test_unlisted_unprefixed_variables_are_still_refused(tmp_path: Path) -> None:
    name = "linux_compliance_other_file"
    option = {"type": "str", "default": None, "description": "x"}
    role = write_role(tmp_path, options={name: option}, defaults={name: None})
    assert "must be prefixed linux_compliance_demo_" in specs.check_role(role)[0]


@pytest.mark.parametrize("type_name", ["str", "path"])
def test_optional_string_options_may_default_to_null(tmp_path: Path, type_name: str) -> None:
    name = "linux_compliance_demo_file"
    option = {"type": type_name, "default": None, "description": "x"}
    role = write_role(tmp_path, options={name: option}, defaults={name: None})
    assert specs.check_role(role) == []


@pytest.mark.parametrize(
    "option",
    [
        {"type": "str", "default": None, "required": True, "description": "x"},
        {"type": "bool", "default": None, "description": "x"},
        {"type": "list", "elements": "str", "default": None, "description": "x"},
    ],
)
def test_null_defaults_are_refused_elsewhere(tmp_path: Path, option: dict[str, object]) -> None:
    name = "linux_compliance_demo_value"
    role = write_role(tmp_path, options={name: option}, defaults={name: None})
    assert any("default does not have the declared type" in item for item in specs.check_role(role))


def test_null_defaults_must_match(tmp_path: Path) -> None:
    name = "linux_compliance_demo_file"
    option = {"type": "str", "default": None, "description": "x"}
    role = write_role(tmp_path, options={name: option}, defaults={name: ""})
    assert "does not equal the argument spec default" in specs.check_role(role)[0]


def test_option_spec_must_be_mapping(tmp_path: Path) -> None:
    role = write_role(tmp_path, options={FLAG: "bool"}, defaults={FLAG: False})
    assert "option spec must be a mapping" in specs.check_role(role)[0]


@pytest.mark.parametrize("type_name", [None, "set", 3])
def test_type_must_be_known(tmp_path: Path, type_name: object) -> None:
    option = {"type": type_name, "default": False, "description": "x"}
    role = write_role(tmp_path, options={FLAG: option}, defaults={FLAG: False})
    assert "type must be one of" in specs.check_role(role)[0]


def test_description_and_spec_default_are_required(tmp_path: Path) -> None:
    role = write_role(tmp_path, options={FLAG: {"type": "bool"}}, defaults={FLAG: False})
    findings = specs.check_role(role)
    assert any("description is missing" in item for item in findings)
    assert any("default is missing from the argument spec" in item for item in findings)


def test_default_value_mismatch(tmp_path: Path) -> None:
    option = {"type": "bool", "default": False, "description": "x"}
    role = write_role(tmp_path, options={FLAG: option}, defaults={FLAG: True})
    assert "does not equal the argument spec default" in specs.check_role(role)[0]


def test_default_type_mismatch(tmp_path: Path) -> None:
    option = {"type": "bool", "default": 0, "description": "x"}
    role = write_role(tmp_path, options={FLAG: option}, defaults={FLAG: 0})
    assert "declared type bool" in specs.check_role(role)[0]


def test_equal_values_of_different_type_are_a_mismatch(tmp_path: Path) -> None:
    option = {"type": "int", "default": 0, "description": "x"}
    role = write_role(tmp_path, options={FLAG: option}, defaults={FLAG: False})
    findings = specs.check_role(role)
    assert any("does not equal the argument spec default" in item for item in findings)
    assert any("declared type int" in item for item in findings)


@pytest.mark.parametrize(
    ("value", "type_name", "expected"),
    [
        ("a", "str", True),
        ("a", "path", True),
        (True, "bool", True),
        (True, "int", False),
        (1, "int", True),
        (1.5, "float", True),
        ([], "list", True),
        ({}, "dict", True),
        (1, "str", False),
    ],
)
def test_matches_type(value: object, type_name: str, expected: bool) -> None:
    assert specs.matches_type(value, type_name) is expected


@pytest.mark.parametrize(
    ("type_name", "nullable", "expected"),
    [("str", True, True), ("path", True, True), ("str", False, False), ("int", True, False)],
)
def test_matches_type_with_null(type_name: str, nullable: bool, expected: bool) -> None:
    assert specs.matches_type(None, type_name, nullable=nullable) is expected


def test_list_requires_elements(tmp_path: Path) -> None:
    name = "linux_compliance_demo_items"
    option: dict[str, object] = {"type": "list", "default": [], "description": "x"}
    role = write_role(tmp_path, options={name: option}, defaults={name: []})
    assert "must declare elements" in specs.check_role(role)[0]


def test_load_mapping_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "x.yml"
    path.write_text("- a\n")
    assert specs.load_mapping(path) is None


def test_check_roles_ignores_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("x")
    write_role(tmp_path)
    assert specs.check_roles(tmp_path) == []


def test_main_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_role(tmp_path)
    assert specs.main([str(tmp_path)]) == 0
    assert "match defaults" in capsys.readouterr().out


def test_main_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_role(tmp_path, defaults={FLAG: True})
    assert specs.main([str(tmp_path)]) == 1
    assert "1 role specification problem(s)" in capsys.readouterr().err


def test_main_defaults_to_repository_roles(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(REPOSITORY_ROOT)
    assert specs.main([]) == 0
    assert "roles" in capsys.readouterr().out


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(REPOSITORY_ROOT)
    monkeypatch.setattr(sys, "argv", ["check_role_specs"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(specs.__file__, run_name="__main__")
    assert raised.value.code == 0


def test_tasks_file_is_required(tmp_path: Path) -> None:
    role = write_role(tmp_path)
    (role / "tasks" / "main.yml").unlink()
    assert "tasks/main.yml is missing" in specs.check_role(role)[0]


def test_tasks_must_be_a_list(tmp_path: Path) -> None:
    role = write_role(tmp_path)
    (role / "tasks" / "main.yml").write_text("a: 1\n")
    assert "must be a list of tasks" in specs.check_role(role)[0]


@pytest.mark.parametrize(
    "task",
    [
        {"name": "x"},
        {"name": "x", "tags": ["other"]},
        {"name": "x", "tags": "always"},
        {"name": "x", "tags": ["linux_compliance_demo_guard", "other"]},
        {"name": "x", "tags": ["linux_compliance_other_guard"]},
        {"name": "x", "tags": "linux_compliance_demo_guard"},
        "x",
    ],
)
def test_every_task_must_be_tagged_always(tmp_path: Path, task: object) -> None:
    role = write_role(tmp_path)
    (role / "tasks" / "main.yml").write_text(yaml.safe_dump([task]))
    assert "tagged always" in specs.check_role(role)[0]


GUARD = ["linux_compliance_demo_guard"]
GUARD_TASKS = [
    {
        "name": "Arm",
        "ansible.builtin.set_fact": {"__linux_compliance_demo_dispatched": False},
        "tags": GUARD,
    },
    {"name": "Check", "ansible.builtin.assert": {"that": ["x"]}, "tags": GUARD},
    {"name": "Stop", "ansible.builtin.fail": {"msg": "x"}, "tags": GUARD},
]


def test_the_guard_tasks_of_a_role_are_allowed(tmp_path: Path) -> None:
    role = write_role(tmp_path)
    (role / "tasks" / "main.yml").write_text(yaml.safe_dump([*TASKS, *GUARD_TASKS]))
    (role / "tasks" / "other.yml").write_text(yaml.safe_dump(TASKS))
    assert specs.check_role(role) == []
    assert specs.guard_tag("remediate") == "linux_compliance_remediate_guard"
    assert specs.dispatched_variable("remediate") == "__linux_compliance_remediate_dispatched"


@pytest.mark.parametrize(
    "task",
    [
        {
            "name": "x",
            "ansible.builtin.file": {"path": "/etc/crontab", "mode": "0600"},
            "tags": GUARD,
        },
        {
            "name": "x",
            "ansible.builtin.set_fact": {"__linux_compliance_demo_dispatched": False, "other": 1},
            "tags": GUARD,
        },
        {
            "name": "x",
            "ansible.builtin.set_fact": {"__linux_compliance_demo_dispatched": True},
            "tags": GUARD,
        },
        {"name": "x", "ansible.builtin.set_fact": {"other": False}, "tags": GUARD},
        {"name": "x", "ansible.builtin.include_tasks": {"file": "other.yml"}, "tags": GUARD},
        {"name": "x", "ansible.builtin.import_tasks": {"file": "other.yml"}, "tags": GUARD},
        {
            "name": "x",
            "block": [{"name": "y", "ansible.builtin.file": {"path": "/etc/crontab"}}],
            "tags": GUARD,
        },
        {"name": "x", "ansible.builtin.assert": {"that": ["x"]}, "when": "y", "tags": GUARD},
        {"name": "x", "ansible.builtin.assert": {"that": ["x"]}, "loop": [1], "tags": GUARD},
        {
            "name": "x",
            "ansible.builtin.assert": {"that": ["x"]},
            "tags": ["linux_compliance_other_guard"],
        },
    ],
)
def test_a_guard_tag_on_anything_but_a_guard_task_is_refused(tmp_path: Path, task: object) -> None:
    role = write_role(tmp_path)
    (role / "tasks" / "main.yml").write_text(yaml.safe_dump([*TASKS, task]))
    findings = specs.check_role(role)
    assert any("guard" in finding for finding in findings), findings
    assert findings


@pytest.mark.parametrize(
    "tasks",
    [
        [{"name": "x", "block": [GUARD_TASKS[1]], "tags": ["always"]}],
        [{"name": "x", "block": [], "rescue": [GUARD_TASKS[1]], "tags": ["always"]}],
        [{"name": "x", "block": [], "always": [GUARD_TASKS[2]], "tags": ["always"]}],
        [
            {
                "name": "x",
                "ansible.builtin.include_tasks": {"file": "other.yml", "apply": {"tags": GUARD}},
                "tags": ["always"],
            }
        ],
        [{"name": "x", "ansible.builtin.assert": {"that": ["x"]}, "tags": ["always", *GUARD]}],
    ],
)
def test_a_guard_tag_nested_or_combined_in_main_is_refused(
    tmp_path: Path, tasks: list[object]
) -> None:
    role = write_role(tmp_path)
    (role / "tasks" / "main.yml").write_text(yaml.safe_dump([*TASKS, *tasks]))
    findings = specs.check_role(role)
    assert len(findings) == 1
    assert "the guard tag linux_compliance_demo_guard is allowed only" in findings[0]


@pytest.mark.parametrize("guard", GUARD_TASKS)
def test_a_guard_tag_outside_tasks_main_is_refused(tmp_path: Path, guard: object) -> None:
    role = write_role(tmp_path)
    (role / "tasks" / "other.yml").write_text(yaml.safe_dump([guard]))
    findings = specs.check_role(role)
    assert len(findings) == 1
    assert findings[0].startswith("demo: tasks/other.yml: the guard tag")


def test_a_task_file_that_is_not_a_list_has_no_guard_findings(tmp_path: Path) -> None:
    role = write_role(tmp_path)
    (role / "tasks" / "other.yml").write_text("a: 1\n")
    assert specs.check_role(role) == []


def test_the_guard_tag_of_another_role_is_refused_in_main(tmp_path: Path) -> None:
    role = write_role(tmp_path)
    other = {
        "name": "x",
        "ansible.builtin.fail": {"msg": "x"},
        "tags": ["linux_compliance_other_guard"],
    }
    (role / "tasks" / "main.yml").write_text(yaml.safe_dump([*TASKS, other]))
    findings = specs.check_role(role)
    assert any("must be tagged always" in finding for finding in findings)
    assert any("found ['linux_compliance_other_guard']" in finding for finding in findings)
