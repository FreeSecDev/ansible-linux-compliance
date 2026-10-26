from __future__ import annotations

from pathlib import Path

import pytest

from tools.lint import check_repo_rules as rules

SKIPPED = frozenset({"build", "dist", "node_modules"})
BANNED_FORMS = (
    "shell",
    "command",
    "raw",
    "script",
    "win_shell",
    "win_command",
    "ansible.builtin.shell",
    "ansible.builtin.command",
    "ansible.builtin.raw",
    "ansible.builtin.script",
    "ansible.legacy.shell",
    "ansible.legacy.command",
    "ansible.legacy.raw",
    "ansible.legacy.script",
    "ansible.windows.win_shell",
    "ansible.windows.win_command",
    "community.windows.win_shell",
    "community.windows.win_command",
)


def findings(text: str) -> list[tuple[int, str]]:
    return sorted(
        (violation.line, violation.message)
        for violation in rules.check_banned_modules(Path("f.yml"), text)
    )


def lines(text: str) -> list[int]:
    return sorted(line for line, _ in findings(text))


def play(keyword: str, task: str) -> str:
    return f"---\n- name: p\n  hosts: all\n  {keyword}:\n    - name: t\n      {task}\n"


@pytest.mark.parametrize("module", BANNED_FORMS)
@pytest.mark.parametrize("keyword", ["tasks", "pre_tasks", "post_tasks", "handlers"])
def test_every_play_task_list_is_checked(keyword: str, module: str) -> None:
    assert findings(play(keyword, f"{module}: id")) == [(6, f"banned module: {module!r}")]


@pytest.mark.parametrize("module", BANNED_FORMS)
def test_a_task_file_is_checked(module: str) -> None:
    text = f"---\n- name: first\n  ansible.builtin.debug:\n    msg: ok\n- name: t\n  {module}: id\n"
    assert findings(text) == [(6, f"banned module: {module!r}")]


@pytest.mark.parametrize("module", BANNED_FORMS)
def test_a_bare_task_without_a_name_is_checked(module: str) -> None:
    assert findings(f"---\n- {module}:\n    cmd: id\n") == [(2, f"banned module: {module!r}")]


@pytest.mark.parametrize("section", ["block", "rescue", "always"])
def test_block_sections_are_checked(section: str) -> None:
    text = (
        "---\n- name: b\n  block:\n    - ansible.builtin.debug:\n        msg: x\n"
        f"  {section}:\n    - name: t\n      ansible.builtin.shell: id\n"
    )
    assert lines(text) == [8]


def test_blocks_are_checked_at_any_depth() -> None:
    text = (
        "---\n"
        "- hosts: all\n"
        "  tasks:\n"
        "    - block:\n"
        "        - rescue:\n"
        "            - always:\n"
        "                - block:\n"
        "                    - name: deep\n"
        "                      ansible.legacy.command: id\n"
    )
    assert findings(text) == [(9, "banned module: 'ansible.legacy.command'")]


def test_blocks_inside_handlers_and_pre_tasks_are_checked() -> None:
    text = (
        "---\n"
        "- hosts: all\n"
        "  pre_tasks:\n"
        "    - block:\n"
        "        - raw: id\n"
        "  handlers:\n"
        "    - name: h\n"
        "      block:\n"
        "        - script: x.sh\n"
    )
    assert lines(text) == [5, 9]


@pytest.mark.parametrize(
    "action",
    [
        "action: ansible.builtin.shell echo hi",
        "local_action: command echo hi",
        "action: shell",
        "action: '  raw   id'",
        "action: |\n        shell echo",
        "action:\n        module: ansible.legacy.raw\n        args: x",
        "local_action:\n        module: shell",
        "action:\n        module: shell echo hi",
        "action:\n        module: ansible.builtin.copy\n        module: ansible.builtin.shell",
        "local_action:\n        module: win_shell\n        delegate_to: localhost",
    ],
)
@pytest.mark.parametrize("keyword", ["tasks", "handlers", "block"])
def test_action_forms_are_checked_in_every_task_list(keyword: str, action: str) -> None:
    messages = [message for _, message in findings(play(keyword, action))]
    assert len(messages) == 1
    assert messages[0].startswith("banned module: ")


@pytest.mark.parametrize(
    "action",
    [
        "action: '{{ module_name }}'",
        "action: '{{ module_name }} echo hi'",
        "local_action: '{{module_name}}'",
        "action: ansible.builtin.{{ name }}",
        "action: 'sh{{ \"ell\" }} id'",
        "action: '{% if x %}shell{% endif %} id'",
        "action: '{# comment #}shell id'",
        "action:\n        module: '{{ module_name }}'",
    ],
)
def test_a_templated_module_name_in_an_action_is_denied(action: str) -> None:
    messages = [message for _, message in findings(play("tasks", action))]
    assert len(messages) == 1
    assert messages[0].startswith("templated module name in an action is not allowed: ")


def test_a_banned_module_through_a_merge_key_is_checked() -> None:
    text = (
        "---\n"
        "- hosts: all\n"
        "  vars:\n"
        "    template: &shell_task\n"
        "      ansible.builtin.shell: id\n"
        "  tasks:\n"
        "    - <<: *shell_task\n"
        "      name: merged\n"
    )
    assert findings(text) == [(5, "banned module: 'ansible.builtin.shell'")]


def test_a_banned_module_through_a_merge_list_is_checked() -> None:
    text = (
        "---\n"
        "- hosts: all\n"
        "  vars:\n"
        "    a: &a {name: a}\n"
        "    b: &b {<<: {command: id}}\n"
        "  tasks:\n"
        "    - <<: [*a, *b]\n"
    )
    assert findings(text) == [(5, "banned module: 'command'")]


def test_an_action_through_a_merge_key_is_checked() -> None:
    text = (
        "---\n"
        "- hosts: all\n"
        "  vars:\n"
        "    base: &base\n"
        "      action:\n"
        "        <<: {module: raw}\n"
        "  tasks:\n"
        "    - <<: *base\n"
    )
    assert findings(text) == [(6, "banned module: 'raw'")]


def test_a_task_list_through_an_alias_is_checked() -> None:
    text = (
        "---\n"
        "- hosts: all\n"
        "  vars:\n"
        "    shared: &shared\n"
        "      - ansible.builtin.script: run.sh\n"
        "  tasks: *shared\n"
    )
    assert findings(text) == [(5, "banned module: 'ansible.builtin.script'")]


def test_a_play_through_a_merge_key_keeps_its_task_lists() -> None:
    text = (
        "---\n"
        "- &base\n"
        "  hosts: none\n"
        "  tasks:\n"
        "    - ansible.builtin.debug: {msg: ok}\n"
        "- <<: *base\n"
        "  post_tasks:\n"
        "    - win_command: id\n"
    )
    assert findings(text) == [(8, "banned module: 'win_command'")]


def test_a_task_list_that_is_a_mapping_fails_safe() -> None:
    text = "---\n- hosts: all\n  tasks:\n    shell: id\n"
    assert findings(text) == [(4, "banned module: 'shell'")]


def test_a_sequence_nested_in_a_task_list_fails_safe() -> None:
    assert findings("---\n- - - raw: id\n") == [(2, "banned module: 'raw'")]


def test_a_banned_key_on_a_play_fails_safe() -> None:
    assert findings("---\n- hosts: all\n  shell: id\n") == [(3, "banned module: 'shell'")]


def test_recursive_task_lists_and_merges_terminate() -> None:
    text = (
        "---\n"
        "- &task\n"
        "  name: loop\n"
        "  block:\n"
        "    - *task\n"
        "    - &merged\n"
        "      <<: *task\n"
        "      rescue: [*merged]\n"
        "    - shell: id\n"
    )
    assert findings(text) == [(9, "banned module: 'shell'")]


def test_a_task_reached_twice_is_reported_once() -> None:
    text = (
        "---\n"
        "- hosts: all\n"
        "  vars:\n"
        "    t: &t\n"
        "      - command: id\n"
        "  tasks: *t\n"
        "  handlers: *t\n"
        "  pre_tasks:\n"
        "    - <<: {command: x}\n"
    )
    assert findings(text) == [(5, "banned module: 'command'"), (9, "banned module: 'command'")]


NESTED_DATA = {
    "docker-container-command": (
        "---\n"
        "- name: Start\n"
        "  community.docker.docker_container:\n"
        "    name: x\n"
        "    command: /sbin/init\n"
        "    entrypoint: [sleep]\n"
    ),
    "docker-container-command-list": (
        "---\n"
        "- hosts: all\n"
        "  tasks:\n"
        "    - community.docker.docker_container:\n"
        "        command:\n"
        "          - sleep\n"
        "          - infinity\n"
        "        shell: /bin/bash\n"
    ),
    "play-vars": (
        "---\n"
        "- hosts: all\n"
        "  vars:\n"
        "    command: id\n"
        "    shell: /bin/bash\n"
        "    raw:\n"
        "      script: x\n"
        "    action: shell id\n"
        "  tasks: []\n"
    ),
    "task-vars": (
        "---\n"
        "- name: t\n"
        "  ansible.builtin.debug:\n"
        "    msg: '{{ command }}'\n"
        "  vars:\n"
        "    command: id\n"
        "    nested:\n"
        "      - shell: x\n"
        "      - action: command id\n"
    ),
    "set-fact": (
        "---\n"
        "- name: t\n"
        "  ansible.builtin.set_fact:\n"
        "    command: id\n"
        "    shell:\n"
        "      raw: x\n"
        "      local_action: shell id\n"
    ),
    "loop-items": (
        "---\n"
        "- name: t\n"
        "  ansible.builtin.debug:\n"
        "    msg: '{{ item.command }}'\n"
        "  loop:\n"
        "    - command: a\n"
        "    - shell: b\n"
    ),
    "module-defaults": (
        "---\n"
        "- hosts: all\n"
        "  module_defaults:\n"
        "    ansible.builtin.shell:\n"
        "      chdir: /\n"
        "  tasks:\n"
        "    - ansible.builtin.debug: {msg: x}\n"
    ),
    "environment": (
        "---\n- name: t\n  ansible.builtin.debug: {msg: x}\n  environment:\n    shell: sh\n"
    ),
    "nested-in-block": (
        "---\n"
        "- block:\n"
        "    - ansible.builtin.uri:\n"
        "        url: https://example.invalid\n"
        "        body:\n"
        "          command: id\n"
        "  rescue:\n"
        "    - ansible.builtin.set_fact:\n"
        "        raw: true\n"
    ),
    "handler-parameters": (
        "---\n"
        "- name: Restart\n"
        "  community.docker.docker_container:\n"
        "    name: x\n"
        "    command: [a]\n"
        "  listen: restart\n"
    ),
    "role-vars": (
        "---\n"
        "- hosts: all\n"
        "  roles:\n"
        "    - role: freesecdev.linux_compliance.audit\n"
        "      vars:\n"
        "        command: x\n"
        "  tasks:\n"
        "    - ansible.builtin.include_role:\n"
        "        name: freesecdev.linux_compliance.audit\n"
        "      vars:\n"
        "        shell: y\n"
    ),
    "argument-data": "---\n- ansible.builtin.assert:\n    that:\n      - command is defined\n",
    "data-merge-into-params": (
        "---\n- name: t\n  community.docker.docker_container:\n    <<: {command: [a], shell: b}\n"
    ),
    "templated-module-argument": (
        "---\n- name: t\n  ansible.builtin.debug:\n    msg: '{{ x }}'\n  action_hint: '{{ y }}'\n"
    ),
    "args-keyword": "---\n- name: t\n  ansible.builtin.copy:\n  args:\n    shell: x\n",
}


@pytest.mark.parametrize("text", NESTED_DATA.values(), ids=NESTED_DATA.keys())
def test_nested_parameters_and_data_are_not_flagged(text: str) -> None:
    assert findings(text) == []


@pytest.mark.parametrize(
    "task",
    [
        "ansible.builtin.include_tasks: tasks/family.yml",
        "ansible.builtin.include_tasks: tasks/family.yaml",
        "ansible.builtin.import_tasks: other.yml",
        "include_tasks: '{{ family }}.yml'",
        "ansible.legacy.include_tasks:\n        file: guard.yml\n        apply: {tags: [x]}",
        "ansible.builtin.import_tasks:\n        file: shared/tasks/check.yaml",
        "ansible.builtin.include_role:\n        name: x",
        "ansible.builtin.include_role:\n        name: x\n        tasks_from: family.yml",
        "ansible.builtin.import_role:\n        name: x\n        handlers_from: handlers.yaml",
        "ansible.builtin.include_role: x",
    ],
)
def test_includes_of_scanned_files_are_allowed(task: str) -> None:
    assert findings(play("tasks", task)) == []


@pytest.mark.parametrize(
    ("task", "message"),
    [
        ("ansible.builtin.include_tasks: tasks.json", "target must end in .yml or .yaml"),
        ("include_tasks: '{{ task_file }}'", "target must end in .yml or .yaml"),
        ("ansible.builtin.import_tasks: tasks", "target must end in .yml or .yaml"),
        ("ansible.builtin.include_tasks:\n        file: x.txt", "target must end in .yml"),
        ("ansible.builtin.include_tasks:\n        file: [a.yml]", "target must end in .yml"),
        ("ansible.builtin.include_tasks:\n        apply: {}", "needs a file name ending"),
        ("ansible.builtin.include_tasks:", "target must end in .yml or .yaml: ''"),
        ("include: legacy.json", "target must end in .yml or .yaml"),
        (
            "ansible.builtin.include_role:\n        name: x\n        tasks_from: family",
            "tasks_from must end in .yml or .yaml",
        ),
        (
            "ansible.builtin.import_role:\n        name: x\n        handlers_from: main.json",
            "handlers_from must end in .yml or .yaml",
        ),
        (
            "ansible.builtin.include_role:\n        name: x\n        tasks_from: [a.yml]",
            "tasks_from must end in .yml or .yaml: 'sequence'",
        ),
    ],
)
def test_includes_of_files_that_are_never_scanned_are_denied(task: str, message: str) -> None:
    messages = [found for _, found in findings(play("tasks", task))]
    assert len(messages) == 1
    assert message in messages[0]


def test_a_playbook_import_must_name_a_scanned_file() -> None:
    assert findings("---\n- ansible.builtin.import_playbook: other.yml\n") == []
    assert findings("---\n- ansible.builtin.import_playbook: other.json\n") == [
        (2, "ansible.builtin.import_playbook target must end in .yml or .yaml: 'other.json'")
    ]


def test_a_mapping_document_stays_checked_at_any_depth() -> None:
    text = "---\nplatforms:\n  - name: x\n    command: /sbin/init\naction: shell id\n"
    assert findings(text) == [(4, "banned module: 'command'"), (5, "banned module: 'shell id'")]


def test_a_templated_action_in_a_mapping_document_is_denied() -> None:
    assert findings("---\nx:\n  action: '{{ m }}'\n") == [
        (3, "templated module name in an action is not allowed: '{{ m }}'")
    ]


def test_scalar_documents_have_nothing_to_check() -> None:
    assert findings("--- shell\n") == []


def test_repository_task_directories_hold_only_yaml_files() -> None:
    offenders: list[str] = []
    for directory, directories, files in rules.REPO_ROOT.walk():
        directories[:] = [
            name for name in directories if not name.startswith(".") and name not in SKIPPED
        ]
        parts = set(directory.relative_to(rules.REPO_ROOT).parts)
        if parts & {"tasks", "handlers"}:
            offenders.extend(
                (directory / name).relative_to(rules.REPO_ROOT).as_posix()
                for name in files
                if not name.endswith(rules.TASK_FILE_SUFFIXES)
            )
    assert offenders == []


def test_merge_cycles_and_scalar_merges_terminate() -> None:
    text = "---\n- &loop\n  <<: *loop\n  name: x\n- <<: plain\n  raw: id\n"
    assert findings(text) == [(6, "banned module: 'raw'")]


def test_a_shared_anchor_merged_into_two_tasks_is_reported_once() -> None:
    text = (
        "---\n"
        "- hosts: all\n"
        "  vars:\n"
        "    t: &t {shell: id}\n"
        "  tasks:\n"
        "    - <<: *t\n"
        "    - <<: *t\n"
        "      name: again\n"
    )
    assert findings(text) == [(4, "banned module: 'shell'")]


@pytest.mark.parametrize(
    ("task", "expected"),
    [
        ("ansible.builtin.include_role: name=x tasks_from=family.yml", []),
        ("ansible.builtin.include_role: name=x tasks_from=family.yaml handlers_from=h.yml", []),
        ("ansible.builtin.include_role: name=x", []),
        ("ansible.builtin.include_role: [x]", []),
        ("ansible.builtin.include_role: name=x tasks_from", []),
        (
            "ansible.builtin.import_role: name=x tasks_from=family",
            ["ansible.builtin.import_role tasks_from must end in .yml or .yaml: 'family'"],
        ),
        (
            "include_role: name=x handlers_from=main.json",
            ["include_role handlers_from must end in .yml or .yaml: 'main.json'"],
        ),
    ],
)
def test_free_form_role_includes_are_checked(task: str, expected: list[str]) -> None:
    assert [message for _, message in findings(play("tasks", task))] == expected


def test_non_scalar_keys_of_a_mapping_document_are_skipped() -> None:
    assert findings("---\n? [shell]\n: v\nok: 1\n") == []


@pytest.mark.parametrize("target", ["ansible.builtin.shell", "ansible.legacy.raw", "command"])
def test_a_plugin_routing_redirect_to_a_banned_module_is_denied(target: str) -> None:
    text = f"---\nplugin_routing:\n  modules:\n    run:\n      redirect: {target}\n"
    assert findings(text) == [(5, f"redirect to a banned module: {target!r}")]


@pytest.mark.parametrize(
    "text",
    [
        "---\nplugin_routing:\n  modules:\n    old:\n      redirect: community.general.x\n",
        "---\nredirect:\n  - ansible.builtin.shell\n",
    ],
)
def test_other_redirects_are_allowed(text: str) -> None:
    assert findings(text) == []
