from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path

PREFIXES = ("", "ansible.builtin.", "ansible.legacy.")
TASK_ONLY = tuple(f"{prefix}{name}" for name in ("expect", "cron") for prefix in PREFIXES)
PARAMETERS = (
    ("apt", "dpkg_options", "pre-invoke=id"),
    ("assemble", "validate", "/bin/sh -c id %s"),
    ("blockinfile", "validate", "/bin/sh -c id %s"),
    ("copy", "validate", "/bin/sh -c id %s"),
    ("dnf", "conf_file", "/srv/probe/dnf.conf"),
    ("dnf5", "conf_file", "/srv/probe/dnf.conf"),
    ("gather_facts", "fact_path", "/srv/probe/facts"),
    ("git", "executable", "/srv/probe/git"),
    ("git", "ssh_opts", "-o ProxyCommand=id"),
    ("lineinfile", "validate", "/bin/sh -c id %s"),
    ("mount_facts", "mount_binary", "/srv/probe/mount"),
    ("package", "use", "ansible.builtin.command"),
    ("pip", "executable", "/srv/probe/pip"),
    ("pip", "extra_args", "--index-url x"),
    ("pip", "virtualenv_command", "/srv/probe/venv"),
    ("pip", "virtualenv_python", "/srv/probe/python"),
    ("reboot", "boot_time_command", "id"),
    ("reboot", "reboot_command", "id"),
    ("reboot", "search_paths", "/srv/probe"),
    ("reboot", "test_command", "id"),
    ("replace", "validate", "/bin/sh -c id %s"),
    ("service", "use", "ansible.builtin.command"),
    ("setup", "fact_path", "/srv/probe/facts"),
    ("subversion", "executable", "/srv/probe/svn"),
    ("template", "validate", "/bin/sh -c id %s"),
    ("unarchive", "extra_opts", "--to-command=id"),
)
PARAMETER = "is not allowed: the module runs the command, executable or options it names"


def write(root: Path, name: str, text: str) -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def found(root: Path, text: str, name: str = "roles/r/tasks/main.yml") -> list[tuple[int, str]]:
    target = write(root, name, text)
    return [(violation.line, violation.message) for violation in rules.check_paths([target], root)]


def messages(root: Path, text: str, name: str = "roles/r/tasks/main.yml") -> list[str]:
    return [message for _, message in found(root, text, name)]


@pytest.mark.parametrize("module", TASK_ONLY)
def test_expect_and_cron_are_refused_as_tasks(tmp_path: Path, module: str) -> None:
    text = f"---\n- name: Probe\n  {module}:\n    command: id\n"
    assert found(tmp_path, text) == [(3, f"banned module: {module!r}")]


@pytest.mark.parametrize("module", TASK_ONLY)
@pytest.mark.parametrize("keyword", ["action", "local_action"])
def test_expect_and_cron_are_refused_as_actions(tmp_path: Path, module: str, keyword: str) -> None:
    text = f"---\n- name: Probe\n  {keyword}: {module} command=id\n"
    assert found(tmp_path, text) == [(3, f"banned module: '{module} command=id'")]


@pytest.mark.parametrize("module", TASK_ONLY)
def test_expect_and_cron_are_refused_in_the_mapping_form_of_an_action(
    tmp_path: Path, module: str
) -> None:
    text = f"---\n- name: Probe\n  action:\n    module: {module}\n    command: id\n"
    assert found(tmp_path, text) == [(4, f"banned module: {module!r}")]


@pytest.mark.parametrize("module", TASK_ONLY)
def test_expect_and_cron_are_refused_in_plays_and_handlers(tmp_path: Path, module: str) -> None:
    text = f"---\n- hosts: all\n  handlers:\n    - name: h\n      {module}: id\n"
    assert found(tmp_path, text, "playbooks/p.yml") == [(5, f"banned module: {module!r}")]


@pytest.mark.parametrize("module", ["expect", "ansible.builtin.cron"])
def test_a_redirect_to_expect_or_cron_is_refused(tmp_path: Path, module: str) -> None:
    text = f"---\nplugin_routing:\n  modules:\n    probe:\n      redirect: {module}\n"
    assert found(tmp_path, text, "meta/runtime.yml") == [
        (5, f"redirect to a banned module: {module!r}")
    ]


def test_expect_and_cron_are_ordinary_keys_of_data_documents(tmp_path: Path) -> None:
    assert messages(tmp_path, "---\ncases:\n  - expect: an error message\n", "vars/x.yml") == []
    workflow = "---\non:\n  schedule:\n    - cron: '17 5 * * *'\njobs: {}\n"
    assert messages(tmp_path, workflow, ".github/workflows/w.yml") == []


@pytest.mark.parametrize(("module", "parameter", "value"), PARAMETERS)
@pytest.mark.parametrize("prefix", PREFIXES)
def test_a_command_parameter_is_refused_in_the_mapping_form(
    tmp_path: Path, module: str, parameter: str, value: str, prefix: str
) -> None:
    text = f"---\n- name: Probe\n  {prefix}{module}:\n    name: x\n    {parameter}: '{value}'\n"
    assert found(tmp_path, text) == [
        (5, f"parameter {parameter!r} of {prefix + module!r} {PARAMETER} (ADR 0004)")
    ]


@pytest.mark.parametrize(("module", "parameter", "value"), PARAMETERS)
def test_a_command_parameter_is_refused_in_the_free_form(
    tmp_path: Path, module: str, parameter: str, value: str
) -> None:
    word = value.split(maxsplit=1)[0]
    text = f"---\n- name: Probe\n  ansible.builtin.{module}: name=x {parameter}={word}\n"
    assert any(PARAMETER in message for message in messages(tmp_path, text))


@pytest.mark.parametrize(("module", "parameter", "value"), PARAMETERS)
def test_a_command_parameter_is_refused_through_args(
    tmp_path: Path, module: str, parameter: str, value: str
) -> None:
    text = (
        f"---\n- name: Probe\n  ansible.builtin.{module}:\n    name: x\n"
        f"  args:\n    {parameter}: '{value}'\n"
    )
    assert any(PARAMETER in message for message in messages(tmp_path, text))


@pytest.mark.parametrize(("module", "parameter", "value"), PARAMETERS)
@pytest.mark.parametrize("keyword", ["action", "local_action"])
def test_a_command_parameter_is_refused_in_an_action(
    tmp_path: Path, module: str, parameter: str, value: str, keyword: str
) -> None:
    word = value.split(maxsplit=1)[0]
    free = f"---\n- name: Probe\n  {keyword}: ansible.legacy.{module} {parameter}={word}\n"
    mapping = (
        f"---\n- name: Probe\n  {keyword}:\n    module: {module}\n    {parameter}: '{value}'\n"
    )
    inline = f"---\n- name: Probe\n  {keyword}:\n    module: {module} {parameter}={word}\n"
    for text in (free, mapping, inline):
        assert any(PARAMETER in message for message in messages(tmp_path, text)), text


@pytest.mark.parametrize(("module", "parameter", "value"), PARAMETERS)
@pytest.mark.parametrize("entry", ["{module}", "ansible.builtin.{module}", "group/ansible.x"])
def test_a_command_parameter_is_refused_in_module_defaults(
    tmp_path: Path, module: str, parameter: str, value: str, entry: str
) -> None:
    name = entry.format(module=module)
    text = (
        f"---\n- hosts: all\n  module_defaults:\n    {name}:\n      {parameter}: '{value}'\n"
        "  tasks: []\n"
    )
    assert any(PARAMETER in message for message in messages(tmp_path, text, "playbooks/p.yml"))
    listed = (
        f"---\n- hosts: all\n  module_defaults:\n    - {name}:\n        {parameter}: '{value}'\n"
        "    - other\n  tasks: []\n"
    )
    assert any(PARAMETER in message for message in messages(tmp_path, listed, "playbooks/p.yml"))


def test_fact_path_is_refused_as_a_play_keyword(tmp_path: Path) -> None:
    text = "---\n- hosts: all\n  fact_path: /srv/probe/facts\n  tasks: []\n"
    assert found(tmp_path, text, "playbooks/p.yml") == [
        (3, "keyword 'fact_path' is not allowed: Ansible runs executable facts there")
    ]


@pytest.mark.parametrize(
    "text",
    [
        "---\n- ansible.builtin.copy:\n    src: a\n    dest: b\n    mode: '0644'\n",
        "---\n- ansible.builtin.user:\n    name: daemon\n    shell: /usr/sbin/nologin\n",
        "---\n- ansible.builtin.service:\n    name: cron\n    state: started\n",
        "---\n- ansible.builtin.file:\n    path: /etc/crontab\n    mode: '0600'\n",
        "---\n- ansible.builtin.copy: src=a dest=b\n",
        "---\n- action: ansible.builtin.copy src=a dest=b\n",
        "---\n- action:\n    module: ansible.builtin.copy\n    src: a\n",
        "---\n- action:\n    module: 7\n- action: {}\n- action: ''\n- action:\n    module: ''\n",
        (
            "---\n- hosts: all\n  module_defaults:\n    ansible.builtin.copy:\n      mode: '0644'\n"
            "    ansible.builtin.debug: {}\n  tasks: []\n"
        ),
        "---\n- hosts: all\n  module_defaults:\n    - 7\n  tasks: []\n",
        "---\n- ansible.builtin.copy:\n    - a\n- action: []\n",
        "---\n- action:\n    src: a\n    module: ansible.builtin.copy\n",
    ],
)
def test_ordinary_parameters_pass(tmp_path: Path, text: str) -> None:
    assert messages(tmp_path, text) == []


def test_a_validate_key_of_a_data_document_is_not_a_parameter(tmp_path: Path) -> None:
    assert messages(tmp_path, "---\nvalidate: /bin/true\nuse: x\n", "vars/x.yml") == []
