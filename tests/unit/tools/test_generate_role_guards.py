from __future__ import annotations

import runpy
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.lint import check_repo_rules as rules
from tools.roles import generate_role_guards as gen
from tools.roles import generate_toggles

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SENTINEL = "__linux_compliance_unset__"


def copy_roles(root: Path) -> Path:
    shutil.copytree(REPOSITORY_ROOT / "roles", root / "roles")
    return root


def load(text: str) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", yaml.safe_load(text))


def make_role(root: Path, tasks: dict[str, str], variables: dict[str, str] | None = None) -> Path:
    role = root / "roles" / "demo"
    (role / "tasks").mkdir(parents=True)
    for name, text in tasks.items():
        (role / "tasks" / name).write_text(text, encoding="utf-8")
    for name, text in (variables or {}).items():
        (role / "vars").mkdir(exist_ok=True)
        (role / "vars" / name).write_text(text, encoding="utf-8")
    return role


def test_the_repository_files_are_up_to_date() -> None:
    generated = gen.outputs(REPOSITORY_ROOT)
    assert set(generated) == {
        gen.DISPATCH,
        Path("roles/audit/tasks/internal_variables.yml"),
        Path("roles/remediate/tasks/internal_variables.yml"),
        Path("roles/verify/tasks/internal_variables.yml"),
    }
    for relative, content in generated.items():
        assert (REPOSITORY_ROOT / relative).read_text(encoding="utf-8") == content


def test_the_dispatch_names_one_literal_file_per_catalogued_family() -> None:
    text = (REPOSITORY_ROOT / gen.DISPATCH).read_text(encoding="utf-8")
    tasks = load(text)
    assert [task["when"] for task in tasks] == [
        "__linux_compliance_remediate_family.name == 'file_permissions'"
    ]
    include = cast("dict[str, object]", tasks[0]["ansible.builtin.include_tasks"])
    assert include["file"] == "{{ role_path }}/tasks/file_permissions.yml"
    assert rules.check_banned_modules(REPOSITORY_ROOT / gen.DISPATCH, text) == []
    assert "{{ __linux_compliance_remediate_family" not in str(include["file"])


def test_the_dispatch_keeps_registry_order(tmp_path: Path) -> None:
    for family in ("alpha", "beta"):
        (tmp_path / f"{family}.yml").write_text("---\n[]\n", encoding="utf-8")
    tasks = load(gen.dispatch(["beta", "alpha"], tmp_path))
    files = [
        cast("dict[str, str]", task["ansible.builtin.include_tasks"])["file"] for task in tasks
    ]
    assert files == ["{{ role_path }}/tasks/beta.yml", "{{ role_path }}/tasks/alpha.yml"]
    assert all(task["tags"] == ["always"] for task in tasks)


def test_a_family_with_only_audit_only_rules_gets_no_include_and_no_error(tmp_path: Path) -> None:
    root = copy_roles(tmp_path)
    catalogue_file = root / generate_toggles.CATALOGUE
    data = cast("dict[str, object]", yaml.safe_load(catalogue_file.read_text(encoding="utf-8")))
    audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])
    audit_only["sysctl"].append("xccdf_org.ssgproject.content_rule_sysctl_synthetic_only")
    catalogue_file.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert not (root / "roles" / "remediate" / "tasks" / "sysctl.yml").exists()
    tasks = load(gen.outputs(root)[gen.DISPATCH])
    assert [task["when"] for task in tasks] == [
        "__linux_compliance_remediate_family.name == 'file_permissions'"
    ]
    catalogue = generate_toggles.load_catalogue(catalogue_file)
    assert "sysctl" in {str(rule["family"]) for rule in catalogue.rules}
    assert generate_toggles.native_families(catalogue) == ["file_permissions"]


def test_a_family_with_a_native_rule_but_no_task_file_is_an_error(tmp_path: Path) -> None:
    root = copy_roles(tmp_path)
    catalogue_file = root / generate_toggles.CATALOGUE
    data = cast("dict[str, object]", yaml.safe_load(catalogue_file.read_text(encoding="utf-8")))
    rule_id = "xccdf_org.ssgproject.content_rule_sysctl_kernel_dmesg_restrict"
    audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])
    audit_only["sysctl"].remove(rule_id)
    cast("list[dict[str, object]]", data[generate_toggles.RULES_KEY]).append(
        {
            "rule_id": rule_id,
            "family": "sysctl",
            "disruptive": False,
            "reversible": True,
            "revert_strategy": "owned_dropin",
            "toggle": "linux_compliance_rule_sysctl_kernel_dmesg_restrict_enabled",
            "runbook": None,
            "parameters": {},
        }
    )
    catalogue_file.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(gen.GenerationError, match="the family sysctl has no task file"):
        gen.outputs(root)


def test_a_family_without_a_task_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(gen.GenerationError, match="has no task file"):
        gen.dispatch(["sysctl"], tmp_path)


@pytest.mark.parametrize("family", sorted(gen.ROLE_TASK_FILES))
def test_a_family_may_not_be_named_like_a_task_file_of_the_role(
    tmp_path: Path, family: str
) -> None:
    (tmp_path / f"{family}.yml").write_text("---\n[]\n", encoding="utf-8")
    with pytest.raises(gen.GenerationError, match="name of a task file"):
        gen.dispatch([family], tmp_path)


def test_every_internal_variable_of_a_role_is_classified(tmp_path: Path) -> None:
    role = make_role(
        tmp_path,
        {
            "main.yml": (
                "---\n"
                "- ansible.builtin.set_fact:\n"
                "    __linux_compliance_demo_fact: 1\n"
                "    cacheable: true\n"
                "    linux_compliance_public: 2\n"
                "- ansible.builtin.debug: {msg: x}\n"
                "  register: __linux_compliance_demo_result\n"
                "- block:\n"
                "    - ansible.builtin.debug: {msg: '{{ __linux_compliance_demo_item }}'}\n"
                "      loop: [1]\n"
                "      loop_control:\n"
                "        loop_var: __linux_compliance_demo_item\n"
                "  rescue:\n"
                "    - ansible.builtin.debug: {msg: '{{ __linux_compliance_demo_local }}'}\n"
                "      vars:\n"
                "        __linux_compliance_demo_local: 1\n"
                "  vars:\n"
                "    __linux_compliance_demo_block: 1\n"
                "- ansible.builtin.include_vars:\n"
                "    file: extra.yml\n"
                "- ansible.builtin.include_vars:\n"
                "    file: '{{ role_path }}/../other/vars/all.yml'\n"
                "    name: __linux_compliance_demo_named\n"
                "- ansible.builtin.debug: {msg: x}\n"
                "  loop_control: {label: x}\n"
                "- just a string\n"
            ),
            gen.GUARD_FILE: (
                "---\n- ansible.builtin.debug: {msg: '{{ __linux_compliance_demo_x }}'}\n"
            ),
        },
        {
            "main.yml": "---\n__linux_compliance_demo_constant: 1\n",
            "extra.yml": "---\n__linux_compliance_demo_loaded: 2\nother_name: 3\n",
        },
    )
    found = gen.role_variables(role, {})
    assert found.facts == {"__linux_compliance_demo_fact", "__linux_compliance_demo_result"}
    assert found.locals == {
        "__linux_compliance_demo_item",
        "__linux_compliance_demo_local",
        "__linux_compliance_demo_block",
    }
    assert set(found.constants) == {
        "__linux_compliance_demo_constant",
        "__linux_compliance_demo_loaded",
        "__linux_compliance_demo_named",
    }
    assert found.constants["__linux_compliance_demo_named"] == (
        "(lookup('ansible.builtin.file', role_path ~ '/../other/vars/all.yml')"
        " | ansible.builtin.from_yaml)"
    )
    assert found.constants["__linux_compliance_demo_loaded"].endswith(
        "['__linux_compliance_demo_loaded']"
    )


def test_generated_task_files_replace_the_files_on_disk(tmp_path: Path) -> None:
    role = make_role(tmp_path, {"main.yml": "---\n[]\n"})
    generated = {
        "main.yml": ("---\n- ansible.builtin.set_fact:\n    __linux_compliance_demo_generated: 1\n")
    }
    assert gen.role_variables(role, generated).facts == {"__linux_compliance_demo_generated"}


@pytest.mark.parametrize(
    ("task", "message"),
    [
        (
            (
                "- ansible.builtin.set_fact:\n    __linux_compliance_demo_x: 1\n"
                "- ansible.builtin.debug: {msg: x}\n  vars:\n    __linux_compliance_demo_x: 1\n"
            ),
            "both a fact and a task variable: __linux_compliance_demo_x",
        ),
        (
            "- ansible.builtin.set_fact:\n    __linux_compliance_demo_constant: 1\n",
            "a constant that is also assigned: __linux_compliance_demo_constant",
        ),
        (
            "- ansible.builtin.debug: {msg: '{{ __linux_compliance_demo_missing }}'}\n",
            "used but never defined: __linux_compliance_demo_missing",
        ),
        ("- ansible.builtin.include_vars: extra.yml\n", "must use the mapping form"),
        (
            "- ansible.builtin.include_vars:\n    file: /etc/vars.yml\n",
            "is neither a vars file nor below role_path",
        ),
        (
            "- ansible.builtin.include_vars:\n    file: absent.yml\n",
            "must exist and hold a mapping",
        ),
    ],
)
def test_unclassifiable_variables_are_errors(tmp_path: Path, task: str, message: str) -> None:
    role = make_role(
        tmp_path,
        {"main.yml": "---\n" + task},
        {"main.yml": "---\n__linux_compliance_demo_constant: 1\n"},
    )
    with pytest.raises(gen.GenerationError, match=message):
        gen.role_variables(role, {})


def test_a_variables_file_must_hold_a_mapping(tmp_path: Path) -> None:
    role = make_role(tmp_path, {"main.yml": "---\n[]\n"}, {"main.yml": "---\n- x\n"})
    with pytest.raises(gen.GenerationError, match="must exist and hold a mapping"):
        gen.role_variables(role, {})


def test_the_guard_resets_facts_and_shadows_task_variables() -> None:
    found = gen.RoleVariables(
        {"__linux_compliance_remediate_b", "__linux_compliance_remediate_a"},
        {"__linux_compliance_remediate_local"},
        {"__linux_compliance_remediate_constant": "(x)['y']"},
    )
    text = gen.guard("remediate", found)
    reset, refuse = load(text)
    assert reset["ansible.builtin.set_fact"] == {
        "__linux_compliance_remediate_a": SENTINEL,
        "__linux_compliance_remediate_b": SENTINEL,
    }
    assertion = cast("dict[str, object]", refuse["ansible.builtin.assert"])
    assert assertion["that"] == [
        f"__linux_compliance_remediate_a == '{SENTINEL}'",
        f"__linux_compliance_remediate_b == '{SENTINEL}'",
        f"__linux_compliance_remediate_local == '{SENTINEL}'",
        (
            "__linux_compliance_remediate_constant is not defined or "
            "__linux_compliance_remediate_constant == (x)['y']"
        ),
    ]
    assert refuse["vars"] == {"__linux_compliance_remediate_local": SENTINEL}
    assert "set from outside the role" in str(assertion["fail_msg"])
    assert all(len(line) <= generate_toggles.MAX_LINE for line in text.splitlines())
    assert reset["tags"] == refuse["tags"] == ["always"]


def test_a_guard_without_facts_or_task_variables_has_only_the_assertion() -> None:
    text = gen.guard(
        "verify", gen.RoleVariables(set(), set(), {"__linux_compliance_verify_c": "1"})
    )
    tasks = load(text)
    assert len(tasks) == 1
    assert "vars" not in tasks[0]


def test_long_assertions_are_folded_within_the_line_limit() -> None:
    value = (
        "(lookup('ansible.builtin.file', role_path ~ '/vars/main.yml') | from_yaml)['"
        + ("x" * 40)
        + "']"
    )
    found = gen.RoleVariables(set(), set(), {"__linux_compliance_audit_" + "y" * 40: value})
    text = gen.guard("audit", found)
    assert all(len(line) <= generate_toggles.MAX_LINE for line in text.splitlines())
    that = cast("dict[str, list[str]]", load(text)[0]["ansible.builtin.assert"])["that"]
    assert that[0].endswith(value)


def test_main_writes_checks_and_reports_drift(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = copy_roles(tmp_path)
    assert gen.main(["--root", str(root), "--check"]) == 0
    guard = root / "roles/verify/tasks/internal_variables.yml"
    guard.write_text("---\n[]\n", encoding="utf-8")
    assert gen.main(["--root", str(root), "--check"]) == 1
    assert "run make role-guards" in capsys.readouterr().err
    assert gen.main(["--root", str(root)]) == 0
    assert gen.main(["--root", str(root), "--check"]) == 0
    assert "role guards match" in capsys.readouterr().out


def test_main_reports_a_generation_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = copy_roles(tmp_path)
    (root / "roles/remediate/tasks/file_permissions.yml").unlink()
    assert gen.main(["--root", str(root), "--check"]) == 2
    assert "has no task file" in capsys.readouterr().err


def test_main_runs_as_a_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = copy_roles(tmp_path)
    monkeypatch.setattr(sys, "argv", ["generate_role_guards", "--root", str(root), "--check"])
    monkeypatch.delitem(sys.modules, "tools.roles.generate_role_guards", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.roles.generate_role_guards", run_name="__main__")
    assert raised.value.code == 0
