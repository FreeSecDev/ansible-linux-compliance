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
from tools.roles import generate_toggles, run_start

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SENTINEL = "__linux_compliance_unset__"
SECOND_SENTINEL = "__linux_compliance_unset_again__"
NATIVE_FAMILIES = (
    "file_permissions",
    "banners",
    "auditd_rules_time",
    "auditd_conf",
    "ssh",
    "pwquality",
    "login_defs",
    "sudo",
)


def copy_roles(root: Path) -> Path:
    shutil.copytree(REPOSITORY_ROOT / "roles", root / "roles")
    shutil.copytree(REPOSITORY_ROOT / "playbooks", root / "playbooks")
    return root


def assert_nonce(record: dict[str, object], check: dict[str, object], name: str) -> None:
    assert record[gen.SET_FACT] == {name: "{{ 1000000000000 | ansible.builtin.random }}"}
    assertion = cast("dict[str, object]", check["ansible.builtin.assert"])
    assert [" ".join(item.split()) for item in cast("list[str]", assertion["that"])] == [
        f"(hostvars[inventory_hostname] | default({{}}))['{name}'] | default(none) == {name}"
    ]
    assert str(check["name"]).endswith("Refuse an inventory_hostname that names another host")
    assert "vars" not in check
    assert "vars" not in record
    assert record["tags"] == check["tags"] == ["always"]


def parameter_check(name: str) -> str:
    return (
        f"query('ansible.builtin.varnames', '^{name}$') == [] "
        f"or '{name}' in (hostvars[inventory_hostname] | list)"
    )


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
        Path("roles/evidence/tasks/internal_variables.yml"),
        Path("roles/remediate/tasks/internal_variables.yml"),
        Path("roles/verify/tasks/internal_variables.yml"),
        run_start.RUN_START,
    }
    for relative, content in generated.items():
        assert (REPOSITORY_ROOT / relative).read_text(encoding="utf-8") == content


def test_the_dispatch_names_one_literal_file_per_catalogued_family() -> None:
    text = (REPOSITORY_ROOT / gen.DISPATCH).read_text(encoding="utf-8")
    tasks = load(text)
    assert [task["when"] for task in tasks] == [
        f"__linux_compliance_remediate_family.name == '{family}'" for family in NATIVE_FAMILIES
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
        f"__linux_compliance_remediate_family.name == '{family}'" for family in NATIVE_FAMILIES
    ]
    catalogue = generate_toggles.load_catalogue(catalogue_file)
    assert "sysctl" in {str(rule["family"]) for rule in catalogue.rules}
    assert generate_toggles.native_families(catalogue) == list(NATIVE_FAMILIES)


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


def test_a_run_output_is_classified_but_never_reset_or_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(gen.RUN_OUTPUTS, "demo", frozenset({"__linux_compliance_demo_marker"}))
    role = make_role(
        tmp_path,
        {
            "main.yml": (
                "---\n- ansible.builtin.set_fact:\n"
                "    __linux_compliance_demo_marker: 1\n"
                "    __linux_compliance_demo_fact: 2\n"
                "- ansible.builtin.debug: {msg: '{{ __linux_compliance_demo_marker }}'}\n"
            )
        },
    )
    found = gen.role_variables(role, {})
    assert found.facts == {"__linux_compliance_demo_fact"}
    assert found.outputs == {"__linux_compliance_demo_marker"}
    assert "__linux_compliance_demo_marker" not in gen.guard("evidence", found)


def test_a_run_output_that_the_role_never_sets_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(gen.RUN_OUTPUTS, "demo", frozenset({"__linux_compliance_demo_marker"}))
    role = make_role(tmp_path, {"main.yml": "---\n[]\n"})
    with pytest.raises(gen.GenerationError, match="a run output that the role never sets"):
        gen.role_variables(role, {})


def test_the_evidence_marker_is_a_run_output_outside_the_guard() -> None:
    marker = "__linux_compliance_evidence_run_bundle"
    assert dict(gen.RUN_OUTPUTS) == {"evidence": frozenset({marker})}
    found = gen.role_variables(REPOSITORY_ROOT / "roles" / "evidence", {})
    assert found.outputs == {marker}
    assert marker not in found.facts
    guard = (REPOSITORY_ROOT / "roles/evidence/tasks" / gen.GUARD_FILE).read_text(encoding="utf-8")
    assert marker not in guard
    for name in (
        "__linux_compliance_evidence_published",
        "__linux_compliance_evidence_marker",
        "__linux_compliance_evidence_marked",
    ):
        assert name in found.locals
        assert f"{name} == '{SENTINEL}'" in guard
        assert f"{name} == '{SECOND_SENTINEL}'" in guard


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
    tasks = load(text)
    parameters, record, nonce_check = tasks[:3]
    reset, refuse, second_reset, second_refuse, final_reset = tasks[3:]
    checks = cast("dict[str, object]", parameters["ansible.builtin.assert"])
    assert checks["that"] == [
        parameter_check("__linux_compliance_remediate_a"),
        parameter_check("__linux_compliance_remediate_b"),
        parameter_check("__linux_compliance_remediate_constant"),
        parameter_check("__linux_compliance_remediate_host_nonce"),
        parameter_check("__linux_compliance_remediate_local"),
    ]
    assert_nonce(record, nonce_check, "__linux_compliance_remediate_host_nonce")
    assert parameters["name"] == f"{refuse['name']} as parameters"
    assert "vars" not in parameters
    assert "whatever its value" in str(checks["fail_msg"])
    assert "set from outside the role" in str(checks["fail_msg"])
    assert reset["ansible.builtin.set_fact"] == {
        "__linux_compliance_remediate_a": SENTINEL,
        "__linux_compliance_remediate_b": SENTINEL,
    }
    assert second_reset["ansible.builtin.set_fact"] == {
        "__linux_compliance_remediate_a": SECOND_SENTINEL,
        "__linux_compliance_remediate_b": SECOND_SENTINEL,
    }
    assert final_reset["ansible.builtin.set_fact"] == reset["ansible.builtin.set_fact"]
    second = cast("dict[str, object]", second_refuse["ansible.builtin.assert"])
    assert second["that"] == [
        f"__linux_compliance_remediate_a == '{SECOND_SENTINEL}'",
        f"__linux_compliance_remediate_b == '{SECOND_SENTINEL}'",
        f"__linux_compliance_remediate_local == '{SECOND_SENTINEL}'",
    ]
    assert second_refuse["vars"] == {"__linux_compliance_remediate_local": SECOND_SENTINEL}
    assert str(second_refuse["name"]).startswith(str(refuse["name"]))
    assert (
        second["fail_msg"]
        == cast("dict[str, object]", refuse["ansible.builtin.assert"])["fail_msg"]
    )
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
    assert all(task["tags"] == ["always"] for task in load(text))


def test_a_value_supplied_from_outside_cannot_equal_both_sentinels() -> None:
    assert SENTINEL != SECOND_SENTINEL
    assert gen.SENTINEL == SENTINEL
    assert gen.SECOND_SENTINEL == SECOND_SENTINEL
    for relative in gen.outputs(REPOSITORY_ROOT):
        if relative.name != gen.GUARD_FILE:
            continue
        role = relative.parts[1]
        found = gen.role_variables(REPOSITORY_ROOT / "roles" / role, {})
        tasks = load((REPOSITORY_ROOT / relative).read_text(encoding="utf-8"))
        checks = [
            cast("list[str]", cast("dict[str, object]", task["ansible.builtin.assert"])["that"])
            for task in tasks
            if "ansible.builtin.assert" in task
        ]
        assert len(checks) == 4, role
        for name in [*found.facts, *found.locals, gen.host_nonce(role)]:
            assert parameter_check(name) in [" ".join(item.split()) for item in checks[0]], name
        assert_nonce(tasks[1], tasks[2], gen.host_nonce(role))
        for name in [*found.facts, *found.locals]:
            assert f"{name} == '{SENTINEL}'" in checks[2], name
            assert f"{name} == '{SECOND_SENTINEL}'" in checks[3], name
        assert gen.host_nonce(role) not in str(tasks[3:]), role
        assert tasks[0]["ansible.builtin.assert"] is not None
        assert gen.SET_FACT not in tasks[0]
        resets = [task["ansible.builtin.set_fact"] for task in tasks if gen.SET_FACT in task]
        assert resets[-1] == dict.fromkeys(sorted(found.facts), SENTINEL), role


def test_a_guard_with_only_task_variables_reads_back_twice_without_a_reset() -> None:
    found = gen.RoleVariables(set(), {"__linux_compliance_verify_local"}, {})
    parameters, _, _, first, second = load(gen.guard("verify", found))
    assert cast("dict[str, list[str]]", parameters["ansible.builtin.assert"])["that"] == [
        parameter_check("__linux_compliance_verify_host_nonce"),
        parameter_check("__linux_compliance_verify_local"),
    ]
    assert first["vars"] == {"__linux_compliance_verify_local": SENTINEL}
    assert second["vars"] == {"__linux_compliance_verify_local": SECOND_SENTINEL}
    assert cast("dict[str, list[str]]", second["ansible.builtin.assert"])["that"] == [
        f"__linux_compliance_verify_local == '{SECOND_SENTINEL}'"
    ]


def test_every_role_with_internal_variables_is_guarded() -> None:
    roles = gen.internal_variable_roles(REPOSITORY_ROOT / "roles")
    assert roles == {"audit", "evidence", "remediate", "verify"}
    assert roles <= set(gen.GUARDED_ROLES)
    for role in gen.GUARDED_ROLES:
        first = load((REPOSITORY_ROOT / "roles" / role / "tasks" / "main.yml").read_text())[0]
        assert "internal_variables.yml" in str(
            first.get("ansible.builtin.import_tasks", first.get("ansible.builtin.include_tasks"))
        ), role
    summary = load((REPOSITORY_ROOT / "roles/evidence/tasks/summary.yml").read_text())[0]
    assert summary["ansible.builtin.import_tasks"] == gen.GUARD_FILE


def test_internal_variables_are_found_in_every_file_of_a_role(tmp_path: Path) -> None:
    roles = tmp_path / "roles"
    for role, relative, text in (
        ("plain", "tasks/main.yml", "---\n- ansible.builtin.debug: {msg: '{{ linux_x }}'}\n"),
        (
            "other",
            "tasks/main.yml",
            "---\n- ansible.builtin.debug: {msg: '{{ __linux_compliance_plain_x }}'}\n",
        ),
        ("defaults_only", "defaults/main.yml", "---\n__linux_compliance_defaults_only_x: 1\n"),
        ("templated", "templates/a.j2", "{{ __linux_compliance_templated_y }}\n"),
    ):
        (roles / role / relative).parent.mkdir(parents=True, exist_ok=True)
        (roles / role / relative).write_text(text, encoding="utf-8")
    (roles / "binary" / "files").mkdir(parents=True)
    (roles / "binary" / "files" / "blob").write_bytes(b"\xff\xfe__linux_compliance_binary_z")
    (roles / "README.md").write_text("__linux_compliance_README_x\n", encoding="utf-8")
    assert gen.internal_variable_roles(roles) == {"binary", "defaults_only", "templated"}


def test_a_role_with_internal_variables_but_no_guard_is_an_error(tmp_path: Path) -> None:
    root = copy_roles(tmp_path)
    make_role(
        root, {"main.yml": "---\n- ansible.builtin.set_fact:\n    __linux_compliance_demo_x: 1\n"}
    )
    with pytest.raises(gen.GenerationError, match="internal variables but no guard: demo;"):
        gen.outputs(root)


def test_a_guard_without_facts_or_task_variables_reads_back_only_the_constants() -> None:
    text = gen.guard(
        "verify",
        gen.RoleVariables(
            set(),
            set(),
            {"__linux_compliance_verify_c": "1"},
            role_vars={"__linux_compliance_verify_c"},
        ),
    )
    tasks = load(text)
    assert len(tasks) == 4
    assert cast("dict[str, list[str]]", tasks[0]["ansible.builtin.assert"])["that"] == [
        parameter_check("__linux_compliance_verify_host_nonce")
    ]
    assert "vars" not in tasks[3]
    assert cast("dict[str, list[str]]", tasks[3]["ansible.builtin.assert"])["that"] == [
        "__linux_compliance_verify_c is not defined or __linux_compliance_verify_c == 1"
    ]


def test_long_assertions_are_folded_within_the_line_limit() -> None:
    value = (
        "(lookup('ansible.builtin.file', role_path ~ '/vars/main.yml') | from_yaml)['"
        + ("x" * 40)
        + "']"
    )
    name = "__linux_compliance_audit_" + "y" * 40
    found = gen.RoleVariables(set(), set(), {name: value}, role_vars={name})
    text = gen.guard("audit", found)
    assert all(len(line) <= generate_toggles.MAX_LINE for line in text.splitlines())
    that = cast("dict[str, list[str]]", load(text)[3]["ansible.builtin.assert"])["that"]
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


def test_the_parameter_check_comes_first_and_skips_only_the_constants_of_the_vars_file(
    tmp_path: Path,
) -> None:
    role = make_role(
        tmp_path,
        {
            "main.yml": (
                "---\n- ansible.builtin.include_vars:\n    file: extra.yml\n"
                "- ansible.builtin.set_fact:\n    __linux_compliance_demo_fact: 1\n"
                "    cacheable: true\n"
                "- ansible.builtin.set_fact: linux_compliance_demo_free=1\n"
                "- ansible.builtin.debug: {msg: '{{ __linux_compliance_demo_main }}'}\n"
            )
        },
        {
            "main.yml": "---\n__linux_compliance_demo_main: 1\n",
            "extra.yml": "---\n__linux_compliance_demo_loaded: 2\n",
        },
    )
    found = gen.role_variables(role, {})
    assert found.role_vars == {"__linux_compliance_demo_main"}
    assert found.cacheable == {"__linux_compliance_demo_fact"}
    assert set(found.constants) == {
        "__linux_compliance_demo_main",
        "__linux_compliance_demo_loaded",
    }
    first = load(gen.guard("verify", found))[0]
    assert cast("dict[str, list[str]]", first["ansible.builtin.assert"])["that"] == [
        parameter_check("__linux_compliance_demo_fact"),
        parameter_check("__linux_compliance_demo_loaded"),
        parameter_check("__linux_compliance_verify_host_nonce"),
    ]


def test_every_guard_refuses_its_internal_names_as_parameters_before_any_reset() -> None:
    for role in gen.GUARDED_ROLES:
        found = gen.role_variables(REPOSITORY_ROOT / "roles" / role, {})
        guard = (REPOSITORY_ROOT / "roles" / role / "tasks" / gen.GUARD_FILE).read_text()
        first = load(guard)[0]
        assert str(first["name"]).endswith("supplied from outside the role as parameters"), role
        that = [
            " ".join(item.split())
            for item in cast("dict[str, list[str]]", first["ansible.builtin.assert"])["that"]
        ]
        names = found.facts | found.locals | (set(found.constants) - found.role_vars)
        names |= {gen.host_nonce(role)}
        assert that == [parameter_check(name) for name in sorted(names)], role
        assert not found.role_vars & (found.facts | found.locals), role


def test_the_role_outputs_are_the_public_facts_of_every_role() -> None:
    assert gen.role_outputs(REPOSITORY_ROOT / "roles") == {
        "linux_compliance_audit_stale_exceptions",
        "linux_compliance_audited",
        "linux_compliance_baseline",
        "linux_compliance_discovered",
        "linux_compliance_evidence_bundle",
        "linux_compliance_evidence_collection",
        "linux_compliance_evidence_play_hosts",
        "linux_compliance_evidence_reached",
        "linux_compliance_remediated",
        "linux_compliance_verified",
    }
    cacheable = {
        name
        for role in gen.GUARDED_ROLES
        for name in gen.role_variables(REPOSITORY_ROOT / "roles" / role, {}).cacheable
    }
    assert cacheable == {"__linux_compliance_verify_baseline_recorded"}


def test_main_creates_the_directory_of_the_run_start_playbook(tmp_path: Path) -> None:
    root = copy_roles(tmp_path)
    shutil.rmtree(root / "playbooks")
    assert gen.main(["--root", str(root)]) == 0
    assert (root / run_start.RUN_START).is_file()


def test_the_name_of_the_host_nonce_is_reserved(tmp_path: Path) -> None:
    role = make_role(
        tmp_path,
        {
            "main.yml": (
                "---\n- ansible.builtin.set_fact:\n    __linux_compliance_demo_host_nonce: 1\n"
            )
        },
    )
    with pytest.raises(gen.GenerationError, match="the name of the host nonce of the guard"):
        gen.role_variables(role, {})
