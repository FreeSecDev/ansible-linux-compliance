"""Names of arguments and variables that Ansible learns only at run time are refused (FREES-203).

A templated ``set_fact`` key, a module argument written as one template, a ``module_defaults``
entry given as a string and a variable named by ``loop_var``, ``index_var``, ``register`` or the
``name`` of ``include_vars`` and ``vars_prompt`` all get past the rules that read literal keys.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.lint import check_repo_rules as rules
from tools.lint.repo_rules import runtime_names
from tools.lint.repo_rules.remediate_modules import TASK_KEYWORDS

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TASK_FILE = Path("roles/audit/tasks/example.yml")
HARNESS_FILE = Path("extensions/molecule/shared/tasks/example.yml")
ADR = "(ADR 0004)"
SET_FACT_KEY = "set_fact key"
MAPPING = "must be a mapping with literal keys"
FREE_FORM = "free-form arguments"
VARIABLE_NAME = "names the variable that the task sets"


def documents(text: str) -> list[yaml.Node]:
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        return list(iter(loader.get_node, None))
    finally:
        loader.dispose()


def check(text: str, relative: Path | None = TASK_FILE) -> list[str]:
    return [
        violation.message
        for violation in runtime_names.runtime_name_findings(
            relative or Path("x.yml"), relative, documents(text)
        )
    ]


ACCEPTED = [
    pytest.param(
        "---\n- name: Fact\n  ansible.builtin.set_fact:\n    value: '{{ x }}'\n"
        "    cacheable: true\n",
        id="set-fact-literal",
    ),
    pytest.param("---\n- name: Fact\n  ansible.builtin.set_fact: value=1\n", id="set-fact-kv"),
    pytest.param(
        "---\n- &base\n  name: Base\n  ansible.builtin.set_fact:\n    value: 1\n"
        "- <<: *base\n  name: Merged\n",
        id="merge-key",
    ),
    pytest.param(
        "---\n- name: Copy\n  ansible.builtin.copy:\n    content: '{{ x }}'\n    dest: /tmp/x\n"
        "  args:\n    mode: '0600'\n",
        id="args-mapping",
    ),
    pytest.param(
        "---\n- name: Include\n  ansible.builtin.include_tasks: '{{ role_path }}/tasks/x.yml'\n"
        "- name: Import\n  ansible.builtin.import_tasks: other.yml\n"
        "- name: Role\n  ansible.builtin.include_role: name={{ x }}\n",
        id="path-arguments",
    ),
    pytest.param(
        "---\n- name: Meta\n  ansible.builtin.meta: noop\n- name: Null\n  ansible.builtin.ping:\n"
        "- name: Number\n  example.collection.module: 3\n",
        id="free-form-without-template",
    ),
    pytest.param(
        "---\n- name: Loop\n  ansible.builtin.debug:\n    msg: '{{ item }}'\n  loop: [1]\n"
        "  loop_control:\n    loop_var: entry\n    index_var: position\n    label: '{{ entry }}'\n"
        "  register: result\n  with_items: []\n",
        id="variable-keywords",
    ),
    pytest.param(
        "---\n- name: Variables\n  ansible.builtin.include_vars:\n    file: x.yml\n"
        "    name: loaded\n- name: Free\n  ansible.builtin.include_vars: file=x.yml name=loaded\n",
        id="include-vars",
    ),
    pytest.param(
        "---\n- hosts: all\n  vars_prompt:\n    - name: answer\n      prompt: Answer\n"
        "    - plain\n  module_defaults:\n    ansible.builtin.copy:\n      mode: '0600'\n"
        "    group/ansible.builtin.files:\n      owner: root\n  tasks: []\n",
        id="play",
    ),
    pytest.param(
        "---\n- name: Defaults\n  module_defaults:\n    - ansible.builtin.copy:\n"
        "        mode: '0600'\n"
        "  ansible.builtin.debug: {}\n",
        id="defaults-list",
    ),
    pytest.param(
        "---\n- name: Action\n  action: ansible.builtin.debug msg=x\n"
        "- name: Local\n  local_action:\n    module: ansible.builtin.debug msg=x\n"
        "    args:\n      verbosity: 0\n    other: 1\n",
        id="action",
    ),
    pytest.param(
        "---\n- name: Loop control without names\n  ansible.builtin.debug: {}\n"
        "  loop_control: '{{ control }}'\n  vars_prompt: '{{ prompts }}'\n  when: x\n",
        id="keywords-of-another-shape",
    ),
    pytest.param("---\nkey: '{{ x }}'\n", id="not-a-task-list"),
    pytest.param(
        "---\n- name: Sequence\n  ansible.builtin.include_vars: [x.yml]\n"
        "- name: Module mapping\n  local_action:\n    module: {name: x}\n",
        id="shapes-for-other-rules",
    ),
]


@pytest.mark.parametrize("text", ACCEPTED)
def test_accepted(text: str) -> None:
    assert check(text) == []


REFUSED = [
    pytest.param(
        "---\n- name: Fact\n  ansible.builtin.set_fact:\n"
        "    \"{{ 'ansible_python' ~ '_interpreter' }}\": /tmp/x\n",
        SET_FACT_KEY,
        id="set-fact-templated-key",
    ),
    pytest.param(
        "---\n- name: Fact\n  set_fact:\n    '{{ item }}': zz.evil.pwn\n"
        "  loop: [ansible_facts_modules]\n",
        SET_FACT_KEY,
        id="set-fact-looped-key",
    ),
    pytest.param(
        "---\n- &base\n  '{{ item }}': 1\n- name: Fact\n  ansible.legacy.set_fact:\n"
        "    <<: *base\n",
        SET_FACT_KEY,
        id="set-fact-merged-key",
    ),
    pytest.param(
        "---\n- name: Fact\n  ansible.builtin.set_fact:\n    ? [a]\n    : 1\n",
        MAPPING,
        id="set-fact-complex-key",
    ),
    pytest.param(
        "---\n- name: Fact\n"
        "  ansible.builtin.set_fact: \"{{ 'ansible_python' ~ '_interpreter' }}=x\"\n",
        FREE_FORM,
        id="set-fact-free-form-key",
    ),
    pytest.param(
        "---\n- name: Fact\n  ansible.builtin.set_fact: '{{ facts }}'\n",
        FREE_FORM,
        id="set-fact-dict",
    ),
    pytest.param(
        "---\n- name: Fact\n  ansible.builtin.set_fact:\n  args: '{{ facts }}'\n",
        "args must be",
        id="args-template",
    ),
    pytest.param(
        "---\n- name: Copy\n  ansible.builtin.copy:\n  args:\n    '{{ name }}': x\n",
        "args must be",
        id="args-templated-key",
    ),
    pytest.param(
        "---\n- name: Copy\n  ansible.builtin.copy:\n  args: [a]\n", "args must be", id="args-list"
    ),
    pytest.param(
        "---\n- name: Copy\n  ansible.builtin.copy: '{{ arguments }}'\n", FREE_FORM, id="free-form"
    ),
    pytest.param(
        "---\n- name: Copy\n  ansible.builtin.copy: 'dest=/tmp/x {{ arguments }}'\n",
        FREE_FORM,
        id="free-form-rest",
    ),
    pytest.param(
        "---\n- name: Action\n  action: ansible.builtin.copy {{ arguments }}\n",
        FREE_FORM,
        id="action-string",
    ),
    pytest.param(
        "---\n- name: Action\n  local_action:\n    module: ansible.builtin.copy {{ arguments }}\n",
        FREE_FORM,
        id="action-module-string",
    ),
    pytest.param(
        "---\n- name: Action\n  action:\n    module: ansible.builtin.copy\n"
        "    args: '{{ arguments }}'\n",
        "action args must be",
        id="action-args-template",
    ),
    pytest.param(
        "---\n- name: Action\n  action:\n    module: ansible.builtin.set_fact\n"
        "    '{{ name }}': 1\n",
        "action must be",
        id="action-templated-key",
    ),
    pytest.param(
        "---\n- name: Action\n  local_action: [ansible.builtin.debug]\n",
        "local_action must be",
        id="action-list",
    ),
    pytest.param(
        "---\n- hosts: all\n  module_defaults:\n    ansible.builtin.copy: '{{ defaults }}'\n"
        "  tasks: []\n",
        "module_defaults of ansible.builtin.copy must be",
        id="defaults-template",
    ),
    pytest.param(
        "---\n- name: Defaults\n  module_defaults: '{{ defaults }}'\n  ansible.builtin.debug: {}\n",
        "module_defaults must be",
        id="defaults-whole-template",
    ),
    pytest.param(
        "---\n- name: Defaults\n  module_defaults:\n    - '{{ defaults }}'\n"
        "  ansible.builtin.debug: {}\n",
        "module_defaults must be",
        id="defaults-list-template",
    ),
    pytest.param(
        "---\n- name: Loop\n  ansible.builtin.ping:\n  loop: [/tmp/x]\n  loop_control:\n"
        "    loop_var: ansible_python_interpreter\n",
        "loop_var 'ansible_python_interpreter'",
        id="loop-var-exec",
    ),
    pytest.param(
        "---\n- name: Loop\n  ansible.builtin.ping:\n  loop: [/tmp/x]\n  loop_control:\n"
        "    loop_var: \"{{ 'ansible_python' ~ '_interpreter' }}\"\n",
        "loop_var",
        id="loop-var-templated",
    ),
    pytest.param(
        "---\n- name: Loop\n  ansible.builtin.ping:\n  loop: [1]\n  loop_control:\n"
        "    index_var: ansible_connection\n",
        "index_var 'ansible_connection'",
        id="index-var-exec",
    ),
    pytest.param(
        "---\n- name: Loop\n  ansible.builtin.ping:\n  loop: [1]\n  loop_control:\n"
        "    index_var: [a]\n",
        "index_var 'a mapping or sequence'",
        id="index-var-list",
    ),
    pytest.param(
        "---\n- name: Register\n  ansible.builtin.ping:\n  register: ansible_become_method\n",
        "register 'ansible_become_method'",
        id="register-exec",
    ),
    pytest.param(
        "---\n- name: Register\n  ansible.builtin.ping:\n  register: '{{ name }}'\n",
        "register",
        id="register-templated",
    ),
    pytest.param(
        "---\n- name: Variables\n  ansible.builtin.include_vars:\n    file: x.yml\n"
        "    name: ansible_facts_modules\n",
        "include_vars name 'ansible_facts_modules'",
        id="include-vars-exec",
    ),
    pytest.param(
        "---\n- name: Variables\n  include_vars: file=x.yml name=ansible_python_interpreter\n",
        "include_vars name 'ansible_python_interpreter'",
        id="include-vars-free-form",
    ),
    pytest.param(
        "---\n- name: Variables\n  ansible.builtin.include_vars:\n    file: x.yml\n"
        "    name: '{{ name }}'\n",
        "include_vars name",
        id="include-vars-templated",
    ),
    pytest.param(
        "---\n- hosts: all\n  vars_prompt:\n    - name: ansible_connection\n      prompt: x\n"
        "  tasks: []\n",
        "vars_prompt name 'ansible_connection'",
        id="vars-prompt-exec",
    ),
]


@pytest.mark.parametrize(("text", "expected"), REFUSED)
def test_refused(text: str, expected: str) -> None:
    messages = check(text)
    assert len(messages) == 1, messages
    assert expected in messages[0]
    assert ADR in messages[0]


def test_the_line_is_the_line_of_the_name() -> None:
    found = runtime_names.runtime_name_findings(
        TASK_FILE,
        TASK_FILE,
        documents("---\n- name: Fact\n  ansible.builtin.set_fact:\n    a: 1\n    '{{ b }}': 2\n"),
    )
    assert [violation.line for violation in found] == [5]


def test_templated_set_fact_keys_are_accepted_in_the_harness_only() -> None:
    text = (
        "---\n- name: Toggles\n  ansible.builtin.set_fact:\n    '{{ item }}': true\n  loop: [a]\n"
    )
    assert check(text, HARNESS_FILE) == []
    assert check(text, Path("Extensions/Molecule/x.yml")) == []
    assert len(check(text, Path("extensions/other/x.yml"))) == 1
    assert len(check(text, None)) == 1
    harness_args = "---\n- name: Args\n  ansible.builtin.set_fact:\n  args: '{{ facts }}'\n"
    assert len(check(harness_args, HARNESS_FILE)) == 1


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        (None, False),
        (Path("extensions/molecule/shared/tasks/x.yml"), True),
        (Path("EXTENSIONS/molecule/x.yml"), True),
        (Path("extensions/x.yml"), False),
        (Path("roles/remediate/tasks/x.yml"), False),
    ],
)
def test_is_harness_file(relative: Path | None, expected: bool) -> None:
    assert runtime_names.is_harness_file(relative) is expected


def test_check_file_refuses_a_templated_set_fact_key(tmp_path: Path) -> None:
    target = tmp_path / "roles/remediate/tasks/x.yml"
    target.parent.mkdir(parents=True)
    target.write_text("---\n- name: Fact\n  ansible.builtin.set_fact:\n    '{{ k }}': 1\n")
    messages = [violation.message for violation in rules.check_file(target, tmp_path)]
    assert any(SET_FACT_KEY in message for message in messages), messages


def test_play_keywords_match_ansible_core() -> None:
    fields: set[str] = set()
    for module, name in (
        ("ansible.playbook.play", "Play"),
        ("ansible.playbook.task", "Task"),
        ("ansible.playbook.block", "Block"),
        ("ansible.playbook.handler", "Handler"),
    ):
        playbook_class = getattr(importlib.import_module(module), name)
        fields |= set(cast("dict[str, object]", playbook_class.fattributes))
    assert fields - TASK_KEYWORDS == runtime_names.PLAY_KEYWORDS


def test_ansible_templates_set_fact_keys() -> None:
    source = Path(importlib.import_module("ansible.plugins.action.set_fact").__file__ or "")
    assert "k = self._templar.template(k)" in source.read_text(encoding="utf-8")


def test_ansible_turns_one_template_into_module_arguments() -> None:
    parser = importlib.import_module("ansible.parsing.mod_args")
    source = Path(parser.__file__ or "").read_text(encoding="utf-8")
    assert "final_args['_variable_params'] = additional_args" in source
    task = Path(importlib.import_module("ansible.playbook.task").__file__ or "")
    assert "is_possibly_all_template(raw_params_to_finalize)" in task.read_text(encoding="utf-8")


SCOPES = ("roles", "playbooks", "tests", "extensions")


def test_the_repository_passes() -> None:
    files = [
        path
        for scope in SCOPES
        for pattern in ("*.yml", "*.yaml")
        for path in (REPOSITORY_ROOT / scope).rglob(pattern)
    ]
    assert files
    for path in files:
        relative = path.relative_to(REPOSITORY_ROOT)
        try:
            parsed = documents(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        assert runtime_names.runtime_name_findings(path, relative, parsed) == [], relative
