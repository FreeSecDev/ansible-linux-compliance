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
