from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path

NAMES = (
    "ansible_python_interpreter",
    "ansible_perl_interpreter",
    "ansible_interpreter_python_fallback",
    "ansible_ssh_args",
    "ansible_ssh_common_args",
    "ansible_ssh_extra_args",
    "ansible_scp_extra_args",
    "ansible_sftp_extra_args",
    "ansible_ssh_executable",
    "ansible_scp_executable",
    "ansible_sftp_executable",
    "ansible_ssh_pkcs11_provider",
    "ansible_winrm_kinit_cmd",
    "ansible_winrm_kinit_args",
    "ansible_become_exe",
    "ansible_sudo_exe",
    "ansible_su_exe",
    "ansible_become_flags",
    "ansible_sudo_flags",
    "ansible_su_flags",
    "ansible_runas_flags",
    "ansible_shell_executable",
    "ansible_docker_extra_args",
    "docker_extra_args",
    "ansible_facts_modules",
    "ansible_package_use",
    "ansible_playbook_python",
    "pkg_mgr",
    "service_mgr",
    "discovered_interpreter_python",
    "ansible_discovered_interpreter_python",
    "_ansible_ansiballz_debugpy_config",
    "_ansible_shell_executable",
    "become_exe",
    "become_flags",
    "ansible_chroot_exe",
    "ansible_lxc_extra_args",
)
EXEC = "it sets an interpreter, executable, arguments or flags that Ansible runs"
PLUGIN = "it selects a plugin that is not part of ansible-core"


def write(root: Path, name: str, text: str) -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def found(root: Path, name: str, text: str) -> list[str]:
    target = write(root, name, text)
    return [violation.message for violation in rules.check_paths([target], root)]


def refused(name: str, value: str) -> str:
    return f"setting {name!r} to {value!r} is not allowed: {EXEC} (ADR 0004)"


CONTEXTS = (
    ("roles/r/defaults/main.yml", "---\n{name}: {value}\n"),
    ("roles/r/vars/main.yml", "---\n{name}: {value}\n"),
    ("playbooks/p.yml", "---\n- hosts: all\n  vars:\n    {name}: {value}\n  tasks: []\n"),
    (
        "roles/r/tasks/main.yml",
        (
            "---\n- block:\n    - ansible.builtin.debug:\n        msg: hi\n"
            "  vars:\n    {name}: {value}\n"
        ),
    ),
    (
        "roles/r/tasks/main.yml",
        "---\n- ansible.builtin.debug:\n    msg: hi\n  vars:\n    {name}: {value}\n",
    ),
    (
        "roles/r/tasks/main.yml",
        "---\n- ansible.builtin.include_tasks: x.yml\n  vars:\n    {name}: {value}\n",
    ),
    (
        "roles/r/tasks/main.yml",
        "---\n- ansible.builtin.include_role:\n    name: r\n  vars:\n    {name}: {value}\n",
    ),
    ("playbooks/p.yml", "---\n- hosts: all\n  roles:\n    - role: r\n      {name}: {value}\n"),
    ("roles/r/tasks/main.yml", "---\n- ansible.builtin.set_fact:\n    {name}: {value}\n"),
    (
        "roles/r/tasks/main.yml",
        "---\n- ansible.builtin.add_host:\n    name: h\n    {name}: {value}\n",
    ),
    ("roles/r/tasks/main.yml", "---\n- ansible.builtin.add_host: name=h {name}={value}\n"),
    ("roles/r/tasks/main.yml", "---\n- ansible.builtin.set_fact: {name}={value}\n"),
    ("inventory/hosts.yml", "---\nall:\n  hosts:\n    h:\n      {name}: {value}\n"),
    ("inventory/hosts.yml", "---\nall:\n  vars:\n    {name}: {value}\n"),
    ("inventory/group_vars/all.yml", "---\n{name}: {value}\n"),
    ("host_vars/h.yml", "---\n{name}: {value}\n"),
    ("inventory/hosts", "[web]\nh {name}={value}\n"),
    ("inventory/hosts.ini", "[web:vars]\n{name}={value}\n"),
    (
        "extensions/molecule/s/molecule.yml",
        "---\nprovisioner:\n  inventory:\n    host_vars:\n      h:\n        {name}: {value}\n",
    ),
    ("extensions/molecule/s/converge.yml", "---\n- hosts: all\n  vars:\n    {name}: {value}\n"),
    ("tests/playbooks/p.yml", "---\n- hosts: all\n  vars:\n    {name}: {value}\n"),
    ("Makefile", "x:\n\tansible-playbook -e {name}={value} p.yml\n"),
    ("tools/run.sh", "ansible-playbook --extra-vars '{name}={value}' p.yml\n"),
)


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize(("file_name", "template"), CONTEXTS)
def test_an_execution_altering_variable_is_refused_wherever_it_is_set(
    tmp_path: Path, name: str, file_name: str, template: str
) -> None:
    messages = found(tmp_path, file_name, template.format(name=name, value="/srv/probe/evil"))
    assert refused(name, "/srv/probe/evil") in messages, messages


@pytest.mark.parametrize("name", ["ansible_python_interpreter", "ansible_ssh_common_args"])
def test_a_variable_in_a_jinja_dictionary_key_is_refused(tmp_path: Path, name: str) -> None:
    text = (
        "---\n- ansible.builtin.set_fact:\n"
        f"    hosts: \"{{{{ {{'h': {{'{name}': '/srv/probe/evil', 'x': 1}}}} }}}}\"\n"
    )
    assert refused(name, "/srv/probe/evil") in found(tmp_path, "roles/r/tasks/main.yml", text)


def test_a_variable_in_a_json_extra_vars_argument_is_refused(tmp_path: Path) -> None:
    text = 'x:\n\tansible-playbook -e \'{"ansible_python_interpreter": "/x"}\' p.yml\n'
    assert refused("ansible_python_interpreter", "/x") in found(tmp_path, "Makefile", text)


def test_a_structured_value_is_refused(tmp_path: Path) -> None:
    text = "---\nansible_ssh_args:\n  - -o\n  - ProxyCommand=id\n"
    assert (
        f"setting 'ansible_ssh_args' to a mapping or sequence is not allowed: {EXEC} (ADR 0004)"
        in found(tmp_path, "group_vars/all.yml", text)
    )


@pytest.mark.parametrize("name", ["ansible_connection", "connection"])
@pytest.mark.parametrize(
    "value",
    [
        "local",
        "ssh",
        "ansible.builtin.local",
        "ansible.legacy.ssh",
        "ansible.builtin.winrm",
        "psrp",
    ],
)
def test_an_ansible_core_connection_plugin_may_be_selected(
    tmp_path: Path, name: str, value: str
) -> None:
    assert (
        found(tmp_path, "inventory/hosts.yml", f"---\nall:\n  vars:\n    {name}: {value}\n") == []
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ansible_connection", "community.docker.docker"),
        ("ansible_connection", "community.general.chroot"),
        ("ansible_connection", "{{ chosen }}"),
        ("connection", "community.docker.docker"),
        ("ansible_become_method", "community.general.machinectl"),
        ("become_method", "{{ how }}"),
        ("ansible_shell_type", "fish"),
    ],
)
def test_a_plugin_outside_ansible_core_may_not_be_selected(
    tmp_path: Path, name: str, value: str
) -> None:
    text = f"---\n- hosts: all\n  vars:\n    {name}: '{value}'\n"
    message = f"setting {name!r} to {value!r} is not allowed: {PLUGIN} (ADR 0004)"
    assert message in found(tmp_path, "playbooks/p.yml", text)


@pytest.mark.parametrize(
    ("name", "value"), [("ansible_become_method", "sudo"), ("ansible_shell_type", "sh")]
)
def test_an_ansible_core_become_or_shell_plugin_may_be_selected(
    tmp_path: Path, name: str, value: str
) -> None:
    assert found(tmp_path, "group_vars/all.yml", f"---\n{name}: {value}\n") == []


@pytest.mark.parametrize(
    "text",
    [
        "---\n- ansible.builtin.debug:\n    msg: hi\n  when: ansible_connection == 'local'\n",
        '---\n- ansible.builtin.debug:\n    msg: "{{ hostvars[h].ansible_python_interpreter }}"\n',
        (
            "---\n- ansible.builtin.set_fact:\n    names:\n      - ansible_connection\n"
            "      - ansible_ssh_args\n"
        ),
        (
            "---\n- ansible.builtin.debug:\n"
            "    msg: Never set ansible_python_interpreter or ansible_ssh_args\n"
        ),
        '---\n- ansible.builtin.debug:\n    msg: "{{ x | default(ansible_python_interpreter) }}"\n',
        "---\n- ansible.builtin.set_fact:\n    linux_compliance_ssh_args: x\n    ansible_host: h\n",
        "---\n- ansible.builtin.set_fact:\n    ? [ansible_ssh_args]\n    : x\n",
    ],
)
def test_reading_or_naming_a_variable_is_not_setting_it(tmp_path: Path, text: str) -> None:
    assert found(tmp_path, "roles/r/tasks/main.yml", text) == []


def test_the_reviewed_settings_are_keyed_by_file_and_exact_value(tmp_path: Path) -> None:
    python = (
        "---\n- hosts: all\n  vars:\n"
        '    ansible_python_interpreter: "{{ ansible_playbook_python }}"\n'
    )
    assert found(tmp_path, "tests/playbooks/remediate-check-mode.yml", python) == []
    assert refused("ansible_python_interpreter", "{{ ansible_playbook_python }}") in found(
        tmp_path, "tests/playbooks/new-play.yml", python
    )
    other = python.replace("ansible_playbook_python", "custom_python")
    assert refused("ansible_python_interpreter", "{{ custom_python }}") in found(
        tmp_path, "tests/playbooks/remediate-check-mode.yml", other
    )
    docker = (
        "---\nguard_cases:\n  - connection_vars:\n"
        "      ansible_connection: community.docker.docker\n"
    )
    assert found(tmp_path, "extensions/molecule/shared/vars/guard_cases.yml", docker) == []
    message = f"setting 'ansible_connection' to 'community.docker.docker' is not allowed: {PLUGIN}"
    assert any(
        message in item for item in found(tmp_path, "extensions/molecule/shared/vars/x.yml", docker)
    )


def test_an_ini_inventory_named_hosts_is_checked(tmp_path: Path) -> None:
    messages = found(tmp_path, "hosts", "h ansible_ssh_executable=/srv/probe/ssh\n")
    assert refused("ansible_ssh_executable", "/srv/probe/ssh") in messages


def test_an_ordinary_inventory_text_file_passes(tmp_path: Path) -> None:
    assert (
        found(tmp_path, "inventory/hosts", "[web]\nh ansible_host=10.0.0.1 ansible_port=22\n") == []
    )


@pytest.mark.parametrize(
    "name", ["PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "BASH_ENV"]
)
@pytest.mark.parametrize(
    ("file_name", "template"),
    [
        (
            "roles/r/tasks/main.yml",
            "---\n- ansible.builtin.debug:\n    msg: hi\n  environment:\n    {name}: /srv/probe\n",
        ),
        ("playbooks/p.yml", "---\n- hosts: all\n  environment:\n    {name}: /srv/probe\n"),
        ("roles/r/defaults/main.yml", "---\nprobe_environment:\n  {name}: /srv/probe\n"),
    ],
)
def test_a_loader_or_path_environment_variable_is_refused_as_a_key(
    tmp_path: Path, name: str, file_name: str, template: str
) -> None:
    message = (
        f"environment variable {name} is not allowed as a key: as the environment of a task it "
        "changes which program or library a module runs (ADR 0004)"
    )
    assert message in found(tmp_path, file_name, template.format(name=name))


def test_a_loader_environment_variable_in_text_is_not_a_key(tmp_path: Path) -> None:
    text = "---\n- ansible.builtin.debug:\n    msg: PATH and LD_PRELOAD are refused as keys\n"
    assert found(tmp_path, "roles/r/tasks/main.yml", text) == []


def test_an_aliased_mapping_is_checked_once(tmp_path: Path) -> None:
    text = "---\na: &x\n  ansible_ssh_args: x\nb: *x\nc: *x\n"
    assert found(tmp_path, "group_vars/all.yml", text) == [refused("ansible_ssh_args", "x")]
