"""Each remediation family's task files have an internal variable prefix of their own (FREES-208).

Most tests copy the remediate role's real task and variable files and change one thing (a
mutation), so the rule is proven against the convention of the repository, not a model of it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tools.lint import check_repo_rules as rules
from tools.lint.repo_rules import family_prefixes as prefixes

ROLE = rules.REPO_ROOT / "roles" / "remediate"
TASKS = Path("roles/remediate/tasks")
PREFIX = prefixes.ROLE_PREFIX
REFERENCE = prefixes.REFERENCE
ANOTHER_FAMILY = "is also used by the task files of another family"
ONE_FAMILY = "give them the one prefix of the family"
OWNED = "belongs to the role: only main.yml and dispatch.yml may define it"
TEMPLATED = "is a template, so the variable that it defines cannot be checked"
RESERVED = "is the first component of a constant of the role"
FACT = """
- name: Mutation | Set a fact
  ansible.builtin.set_fact:
    {name}: 1
  tags:
    - always
"""
DEFINITIONS = {
    "set_fact": FACT,
    "register": """
- name: Mutation | Register a result
  ansible.builtin.debug:
    msg: x
  register: {name}
  tags:
    - always
""",
    "task vars": """
- name: Mutation | Use a task variable
  vars:
    {name}: 1
  ansible.builtin.debug:
    msg: x
  tags:
    - always
""",
    "loop_var": """
- name: Mutation | Loop
  ansible.builtin.debug:
    msg: x
  loop: [1]
  loop_control:
    loop_var: {name}
  tags:
    - always
""",
    "legacy set_fact": """
- name: Mutation | Set a fact through the legacy name
  ansible.legacy.set_fact:
    {name}: 1
  tags:
    - always
""",
    "short set_fact": """
- name: Mutation | Set a fact through the short name
  set_fact:
    {name}: 1
  tags:
    - always
""",
    "set_fact args": """
- name: Mutation | Set a fact through the task's arguments
  ansible.builtin.set_fact:
  args:
    {name}: 1
  tags:
    - always
""",
    "set_fact args merged": """
- name: Mutation | Set a fact through the task's arguments next to another
  ansible.builtin.set_fact:
    __linux_compliance_remediate_ssh_merged: 1
  args:
    {name}: 1
  tags:
    - always
""",
    "action mapping": """
- name: Mutation | Set a fact through an action mapping
  action:
    module: ansible.builtin.set_fact
    {name}: 1
  tags:
    - always
""",
    "local_action mapping": """
- name: Mutation | Set a fact through a local action mapping
  local_action:
    module: set_fact
    {name}: 1
  tags:
    - always
""",
    "index_var": """
- name: Mutation | Loop with an index
  ansible.builtin.debug:
    msg: x
  loop: [1]
  loop_control:
    index_var: {name}
  tags:
    - always
""",
    "include apply vars": """
- name: Mutation | Include with variables applied to the included tasks
  ansible.builtin.include_tasks:
    file: "{{{{ role_path }}}}/tasks/ssh.yml"
    apply:
      vars:
        {name}: 1
      tags:
        - always
  when: false
  tags:
    - always
""",
    "include_vars name": """
- name: Mutation | Load variables under a name
  ansible.builtin.include_vars:
    file: main.yml
    name: {name}
  tags:
    - always
""",
    "rescue": """
- name: Mutation | Block with a rescue
  tags:
    - always
  block:
    - name: Mutation | Debug
      ansible.builtin.debug:
        msg: x
  rescue:
    - name: Mutation | Set a fact in the rescue
      ansible.builtin.set_fact:
        {name}: 1
""",
    "always": """
- name: Mutation | Block with an always
  tags:
    - always
  block:
    - name: Mutation | Debug
      ansible.builtin.debug:
        msg: x
  always:
    - name: Mutation | Set a fact in the always
      ansible.builtin.set_fact:
        {name}: 1
""",
    "nested block": """
- name: Mutation | Block
  tags:
    - always
  block:
    - name: Mutation | Inner block
      block:
        - name: Mutation | Set a fact
          ansible.builtin.set_fact:
            {name}: 1
      rescue:
        - name: Mutation | Rescue
          ansible.builtin.debug:
            msg: x
      always:
        - name: Mutation | Always
          ansible.builtin.debug:
            msg: x
""",
}


@pytest.fixture
def role(tmp_path: Path) -> Path:
    """Return a root that holds a copy of the remediate role's task and variable files."""
    for directory in ("tasks", "vars"):
        shutil.copytree(ROLE / directory, tmp_path / "roles" / "remediate" / directory)
    return tmp_path


def task_file(root: Path, name: str) -> Path:
    return root / TASKS / name


def append(root: Path, name: str, text: str) -> Path:
    path = task_file(root, name)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)
    return path


def write(root: Path, name: str, text: str) -> Path:
    path = task_file(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---" + text, encoding="utf-8")
    return path


def messages(root: Path, name: str) -> list[str]:
    path = task_file(root, name)
    return [
        violation.message
        for violation in rules.check_file(path, root)
        if REFERENCE in violation.message
    ]


def test_the_repository_task_files_satisfy_the_rule() -> None:
    assert prefixes.analyse(rules.REPO_ROOT) == {}


def test_the_repository_groups_are_the_families_and_their_shared_helpers() -> None:
    files = prefixes.read_task_files(rules.REPO_ROOT / TASKS)
    groups = {tuple(group) for group in prefixes.groups(files)}
    kernel = ("ipv4_parameters.yml", "ipv6_parameters.yml", "sysctl.yml", "sysctl_parameters.yml")
    assert kernel in groups
    assert (
        "faillock.yml",
        "pam_conf_apply.yml",
        "pam_conf_cleanup.yml",
        "pam_conf_prepare.yml",
        "pwhistory.yml",
    ) in groups
    assert ("ssh.yml",) in groups
    assert not {"main.yml", "dispatch.yml", "internal_variables.yml"} & {
        name for group in groups for name in group
    }


def test_the_prefix_of_the_pam_helpers_in_the_kernel_parameter_helper_is_refused(
    role: Path,
) -> None:
    path = task_file(role, "sysctl_parameters.yml")
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(f"{PREFIX}kp_", f"{PREFIX}sc_"), encoding="utf-8")
    found = messages(role, "sysctl_parameters.yml")
    assert any(
        ANOTHER_FAMILY in message and "pam_conf_apply.yml" in message for message in found
    ), found
    assert any(
        ANOTHER_FAMILY in message and "sysctl_parameters.yml" in message
        for message in messages(role, "pam_conf_apply.yml")
    )


@pytest.mark.parametrize("kind", sorted(DEFINITIONS))
def test_a_variable_with_the_prefix_of_another_family_is_refused(role: Path, kind: str) -> None:
    append(role, "ssh.yml", DEFINITIONS[kind].format(name=f"{PREFIX}ld_extra"))
    found = messages(role, "ssh.yml")
    assert any(ONE_FAMILY in message for message in found), found
    assert any(ANOTHER_FAMILY in message and "login_defs.yml" in message for message in found)
    assert any(ANOTHER_FAMILY in message for message in messages(role, "login_defs_decide.yml"))


@pytest.mark.parametrize("kind", sorted(DEFINITIONS))
def test_a_variable_of_the_family_s_own_prefix_is_accepted(role: Path, kind: str) -> None:
    append(role, "ssh.yml", DEFINITIONS[kind].format(name=f"{PREFIX}ssh_extra"))
    assert messages(role, "ssh.yml") == []


def test_a_helper_with_a_prefix_of_its_own_is_refused(role: Path) -> None:
    append(
        role,
        "sudo.yml",
        """
- name: Mutation | Include a helper
  ansible.builtin.include_tasks:
    file: "{{ role_path }}/tasks/sudo_extra.yml"
  tags:
    - always
""",
    )
    write(role, "sudo_extra.yml", FACT.format(name=f"{PREFIX}sx_value"))
    found = messages(role, "sudo_extra.yml")
    assert any(ONE_FAMILY in message and f"{PREFIX}sx_" in message for message in found), found
    assert any(ONE_FAMILY in message for message in messages(role, "sudo_dropin_apply.yml"))


def test_a_new_family_with_a_prefix_of_its_own_is_accepted(role: Path) -> None:
    write(
        role,
        "new_family.yml",
        FACT.format(name=f"{PREFIX}nf_value")
        + DEFINITIONS["loop_var"].format(name=f"{PREFIX}rule")
        + FACT.format(name=f"{PREFIX}results")
        + FACT.format(name=f"{PREFIX}nf"),
    )
    assert messages(role, "new_family.yml") == []


def test_two_new_families_with_one_prefix_are_both_refused(role: Path) -> None:
    write(role, "first_family.yml", FACT.format(name=f"{PREFIX}nf_value"))
    write(role, "second_family.yml", FACT.format(name=f"{PREFIX}nf"))
    for name, other in (("first_family.yml", "second"), ("second_family.yml", "first")):
        found = messages(role, name)
        assert any(ANOTHER_FAMILY in message and other in message for message in found), found


@pytest.mark.parametrize(
    "prefix", ["sysctl", "rules", "plan", "results", "rule", "ledger", "family"]
)
def test_a_prefix_of_a_constant_or_of_a_shared_name_is_refused(role: Path, prefix: str) -> None:
    write(role, "new_family.yml", FACT.format(name=f"{PREFIX}{prefix}_value"))
    found = messages(role, "new_family.yml")
    assert any(RESERVED in message for message in found), found


def test_the_line_skips_a_longer_name_that_starts_with_the_variable(role: Path) -> None:
    write(
        role,
        "new_family.yml",
        FACT.format(name=f"{PREFIX}nf_value_longer") + FACT.format(name=f"{PREFIX}nf_value"),
    )
    write(role, "other_family.yml", FACT.format(name=f"{PREFIX}nf_value"))
    violations = [
        violation
        for violation in rules.check_file(task_file(role, "new_family.yml"), role)
        if ANOTHER_FAMILY in violation.message
    ]
    assert [violation.line for violation in violations] == [10]


def test_the_finding_is_reported_at_the_first_line_that_names_the_variable(role: Path) -> None:
    write(role, "new_family.yml", FACT.format(name=f"{PREFIX}sysctl_value"))
    violations = [
        violation
        for violation in rules.check_file(task_file(role, "new_family.yml"), role)
        if REFERENCE in violation.message
    ]
    assert [violation.line for violation in violations] == [4]


@pytest.mark.parametrize("name", sorted(prefixes.ENTRY_FILES))
def test_the_entry_files_of_the_role_are_not_checked(role: Path, name: str) -> None:
    append(role, name, FACT.format(name=f"{PREFIX}ld_extra"))
    assert messages(role, name) == []


def test_a_loop_without_a_loop_variable_and_an_unknown_include_define_nothing(role: Path) -> None:
    write(
        role,
        "new_family.yml",
        """
- name: Mutation | Loop without a loop variable and include a file that does not exist
  ansible.builtin.include_tasks:
    file: "{{ role_path }}/tasks/missing.yml"
  loop: [1]
  loop_control:
    label: x
  tags:
    - always
""",
    )
    assert prefixes.read_task_files(role / TASKS)["new_family.yml"].defined == frozenset()
    assert messages(role, "new_family.yml") == []


@pytest.mark.parametrize(
    "text", ["\n- a scalar item\n- [a, list]\n", f"\n{PREFIX}kp_value: 1\n", "\n"]
)
def test_what_is_not_a_task_defines_nothing(role: Path, text: str) -> None:
    write(role, "new_family.yml", text)
    assert prefixes.read_task_files(role / TASKS)["new_family.yml"].defined == frozenset()


@pytest.mark.parametrize(
    ("name", "prefix"),
    [
        (f"{PREFIX}kp_value", "kp"),
        (f"{PREFIX}kp", "kp"),
        (f"{PREFIX}_value", ""),
        (f"{PREFIX}Kp_value", "Kp"),
    ],
)
def test_the_prefix_is_the_first_component_after_the_role_s_prefix(name: str, prefix: str) -> None:
    assert prefixes.prefix_of(name) == prefix


@pytest.mark.parametrize(
    "name", [f"{PREFIX}plan", f"{PREFIX}ledger", f"{PREFIX}family", f"{PREFIX}dispatched"]
)
def test_a_family_may_not_set_a_name_of_the_role_s_entry_files(role: Path, name: str) -> None:
    write(role, "new_family.yml", FACT.format(name=name))
    expected = (
        f"{name} belongs to the role: only main.yml and dispatch.yml may define it, and a family "
        f"may not set it {REFERENCE}"
    )
    assert messages(role, "new_family.yml") == [expected]


def test_a_name_that_main_yml_adds_belongs_to_the_role(role: Path) -> None:
    append(role, "main.yml", FACT.format(name=f"{PREFIX}zz_shared"))
    write(role, "new_family.yml", FACT.format(name=f"{PREFIX}zz_shared"))
    found = messages(role, "new_family.yml")
    assert any(OWNED in message for message in found), found


def test_the_shared_names_may_be_set_by_every_family(role: Path) -> None:
    for name in ("new_family.yml", "other_family.yml"):
        write(
            role,
            name,
            FACT.format(name=f"{PREFIX}results")
            + DEFINITIONS["loop_var"].format(name=f"{PREFIX}rule"),
        )
    assert messages(role, "new_family.yml") == []
    assert messages(role, "other_family.yml") == []


def test_a_templated_set_fact_key_is_refused(role: Path) -> None:
    write(role, "new_family.yml", FACT.format(name='"{{ item }}"'))
    found = messages(role, "new_family.yml")
    assert any(TEMPLATED in message for message in found), found


def test_a_name_outside_the_role_s_prefix_is_not_checked(role: Path) -> None:
    write(
        role,
        "new_family.yml",
        FACT.format(name="lifecycle_value") + FACT.format(name="__linux_compliance_audit_kp_x"),
    )
    assert messages(role, "new_family.yml") == []


@pytest.mark.parametrize("suffix", [".yml", ".yaml"])
def test_task_files_with_either_suffix_are_checked(role: Path, suffix: str) -> None:
    write(role, f"new_family{suffix}", FACT.format(name=f"{PREFIX}ld_extra"))
    assert any(ANOTHER_FAMILY in message for message in messages(role, f"new_family{suffix}"))


def test_a_task_file_in_a_subdirectory_is_checked_and_grouped_by_its_include(role: Path) -> None:
    write(role, "nested/helper.yml", FACT.format(name=f"{PREFIX}ld_extra"))
    found = messages(role, "nested/helper.yml")
    assert any(ANOTHER_FAMILY in message for message in found), found
    write(role, "nested/helper.yml", FACT.format(name=f"{PREFIX}nf_value"))
    write(
        role,
        "new_family.yml",
        """
- name: Mutation | Include the helper in the subdirectory
  ansible.builtin.include_tasks: "{{ role_path }}/tasks/nested/helper.yml"
  tags:
    - always
"""
        + FACT.format(name=f"{PREFIX}nf_other"),
    )
    assert messages(role, "nested/helper.yml") == []
    files = prefixes.read_task_files(role / TASKS)
    assert ["nested/helper.yml", "new_family.yml"] in prefixes.groups(files)


def test_an_include_is_read_from_the_tasks_not_from_the_text(role: Path) -> None:
    write(
        role,
        "new_family.yml",
        """
- name: Mutation | A name that mentions {{ role_path }}/tasks/ssh.yml includes nothing
  ansible.builtin.debug:
    msg: "{{ role_path }}/tasks/ssh.yml"
  tags:
    - always
"""
        + FACT.format(name=f"{PREFIX}nf_value"),
    )
    assert messages(role, "new_family.yml") == []
    assert messages(role, "ssh.yml") == []
    files = prefixes.read_task_files(role / TASKS)
    assert ["new_family.yml"] in prefixes.groups(files)


def test_foreign_includes_unnamed_variables_and_options_define_nothing(role: Path) -> None:
    write(
        role,
        "new_family.yml",
        """
- name: Mutation | Include a file that is not below the role's tasks
  ansible.builtin.include_tasks:
    file: other.yml
  tags:
    - always
- name: Mutation | Include without a file
  ansible.builtin.include_tasks:
    apply:
      tags:
        - always
  tags:
    - always
- name: Mutation | Load variables without a name
  ansible.builtin.include_vars:
    file: main.yml
  tags:
    - always
- name: Mutation | Load variables in the short form
  ansible.builtin.include_vars: main.yml
  tags:
    - always
- name: Mutation | A set_fact with only its option
  ansible.builtin.set_fact:
    cacheable: false
  tags:
    - always
""",
    )
    found = prefixes.read_task_files(role / TASKS)["new_family.yml"]
    assert found.defined == frozenset()
    assert found.includes == frozenset()


def test_args_next_to_a_short_form_and_other_actions_define_nothing(role: Path) -> None:
    write(
        role,
        "new_family.yml",
        """
- name: Mutation | Short include_vars form with arguments
  ansible.builtin.include_vars: main.yml
  args:
    other: 1
  tags:
    - always
- name: Mutation | Action of another module
  action:
    module: ansible.builtin.debug
    msg: x
  tags:
    - always
- name: Mutation | Action in the string form
  action: ansible.builtin.debug msg=x
  tags:
    - always
""",
    )
    assert prefixes.read_task_files(role / TASKS)["new_family.yml"].defined == frozenset()


@pytest.mark.parametrize("module", ["ansible.legacy.import_tasks", "include_tasks"])
def test_every_form_of_an_include_joins_the_groups(role: Path, module: str) -> None:
    write(
        role,
        "new_family.yml",
        f"""
- name: Mutation | Include the SSH family file
  {module}:
    file: "{{{{ role_path }}}}/tasks/ssh.yml"
  tags:
    - always
"""
        + FACT.format(name=f"{PREFIX}nf_value"),
    )
    found = messages(role, "new_family.yml")
    assert any(ONE_FAMILY in message for message in found), found


def test_task_files_of_other_roles_and_directories_are_not_checked(tmp_path: Path) -> None:
    for relative in (
        "roles/audit/tasks/a.yml",
        "roles/audit/tasks/b.yml",
        "roles/remediate/x.yml",
        "roles/remediate/handlers/main.yml",
        "roles/remediate/tasks_extra/x.yml",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("---" + FACT.format(name=f"{PREFIX}kp_value"), encoding="utf-8")
        assert prefixes.family_prefix_findings(path, Path(relative), tmp_path) == []


def test_a_file_outside_the_repository_is_not_checked(tmp_path: Path) -> None:
    assert prefixes.family_prefix_findings(tmp_path / "x.yml", None, tmp_path) == []


def test_a_root_without_the_role_has_no_findings(tmp_path: Path) -> None:
    assert prefixes.analyse(tmp_path) == {}


def test_unparsable_files_are_left_to_the_other_rules(role: Path) -> None:
    task_file(role, "broken.yml").write_text("---\n- name: [\n", encoding="utf-8")
    task_file(role, "binary.yml").write_bytes(b"---\n\xff\xfe\n")
    (role / "roles" / "remediate" / "vars" / "broken.yml").write_text("a: [\n", encoding="utf-8")
    (role / "roles" / "remediate" / "vars" / "notes.txt").write_text("x\n", encoding="utf-8")
    (role / TASKS / "subdirectory.yml").mkdir()
    assert prefixes.analyse(role) == {}
    assert messages(role, "broken.yml") == []


def test_a_symbolic_link_is_not_read(role: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.yml"
    outside.write_text("---" + FACT.format(name=f"{PREFIX}kp_value"), encoding="utf-8")
    task_file(role, "linked.yml").symlink_to(outside)
    assert prefixes.analyse(role) == {}


def test_a_role_without_variable_files_reserves_only_the_shared_names(role: Path) -> None:
    shutil.rmtree(role / "roles" / "remediate" / "vars")
    write(role, "new_family.yml", FACT.format(name=f"{PREFIX}sysctl_value"))
    assert messages(role, "new_family.yml") == []
    write(role, "new_family.yml", FACT.format(name=f"{PREFIX}results_value"))
    assert any(RESERVED in message for message in messages(role, "new_family.yml"))


def test_the_guard_analyses_the_role_once_for_all_paths(role: Path) -> None:
    write(role, "first_family.yml", FACT.format(name=f"{PREFIX}nf_value"))
    write(role, "second_family.yml", FACT.format(name=f"{PREFIX}nf_value"))
    paths = [task_file(role, "first_family.yml"), task_file(role, "second_family.yml")]
    together = [
        violation for violation in rules.check_paths(paths, role) if REFERENCE in violation.message
    ]
    alone = sorted(
        violation
        for path in paths
        for violation in rules.check_file(path, role)
        if REFERENCE in violation.message
    )
    assert together == alone
    assert {violation.path.name for violation in together} == {
        "first_family.yml",
        "second_family.yml",
    }


def test_the_rule_is_part_of_the_repository_guard() -> None:
    source = (rules.REPO_ROOT / "tools/lint/repo_rules/repository.py").read_text(encoding="utf-8")
    assert "family_prefix_findings" in source
    assert "family_prefixes" in (rules.REPO_ROOT / "tools/lint/check_repo_rules.py").read_text(
        encoding="utf-8"
    )
