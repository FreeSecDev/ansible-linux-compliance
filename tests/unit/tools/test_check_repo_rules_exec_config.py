from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path

CODE_SETTINGS = (
    ("defaults", "jinja2_extensions", "evil.Extension"),
    ("defaults", "vault_password_file", "./vault.sh"),
    ("defaults", "vault_identity_list", "dev@./vault.sh"),
    ("defaults", "become_password_file", "./pass.sh"),
    ("defaults", "connection_password_file", "./pass.sh"),
    ("defaults", "callbacks_enabled", "local_callback"),
    ("defaults", "executable", "/srv/probe/sh"),
    ("defaults", "inventory", "./inventory.sh"),
    ("defaults", "interpreter_python", "/srv/probe/python"),
    ("defaults", "facts_modules", "ansible.builtin.command"),
    ("defaults", "cowpath", "/srv/probe/cowsay"),
    ("defaults", "module_name", "ansible.builtin.shell"),
    ("defaults", "module_args", "id"),
    ("defaults", "editor", "/srv/probe/editor"),
    ("defaults", "pager", "/srv/probe/pager"),
    ("defaults", "vars_plugins_enabled", "local_vars"),
    ("defaults", "fact_caching_connection", "/srv/probe/facts"),
    ("defaults", "allow_unsafe_lookups", "True"),
    ("inventory", "enable_plugins", "script"),
    ("privilege_escalation", "become_exe", "/srv/probe/sudo"),
    ("privilege_escalation", "become_flags", "-E"),
    ("sudo_become_plugin", "executable", "/srv/probe/sudo"),
    ("sudo_become_plugin", "flags", "-E"),
    ("su_become_plugin", "executable", "/srv/probe/su"),
    ("runas_become_plugin", "flags", "x"),
    ("ssh_connection", "ssh_args", "-o ProxyCommand=id"),
    ("ssh_connection", "ssh_common_args", "-o ProxyCommand=id"),
    ("ssh_connection", "ssh_extra_args", "-o ProxyCommand=id"),
    ("ssh_connection", "scp_extra_args", "-S /srv/probe/ssh"),
    ("ssh_connection", "sftp_extra_args", "-S /srv/probe/ssh"),
    ("ssh_connection", "ssh_executable", "/srv/probe/ssh"),
    ("ssh_connection", "scp_executable", "/srv/probe/scp"),
    ("ssh_connection", "sftp_executable", "/srv/probe/sftp"),
    ("ssh_connection", "pkcs11_provider", "/srv/probe/p11.so"),
    ("connection", "ssh_agent_executable", "/srv/probe/agent"),
    ("netconf_connection", "ssh_config", "/srv/probe/ssh_config"),
    ("galaxy", "role_skeleton", "/srv/probe/skeleton"),
    ("galaxy", "collection_skeleton", "/srv/probe/skeleton"),
)
SELECTORS = (
    ("stdout_callback", "community.general.yaml"),
    ("fact_caching", "community.general.redis"),
    ("strategy", "debug"),
    ("strategy", "ansible.builtin.debug"),
    ("become_method", "community.general.machinectl"),
    ("transport", "community.docker.docker"),
)
ALLOWED = (
    ("stdout_callback", "ansible.builtin.default"),
    ("stdout_callback", "minimal"),
    ("fact_caching", "memory"),
    ("fact_caching", "ansible.builtin.jsonfile"),
    ("strategy", "linear"),
    ("become_method", "sudo"),
    ("transport", "ssh"),
    ("host_key_checking", "false"),
    ("remote_tmp", "/srv/probe/.ansible"),
)
CODE = "it names an executable, arguments, a script or code that Ansible runs or loads"
PLUGIN = "it may only name a plugin of ansible-core"
ENVIRONMENT = (
    "ANSIBLE_SSH_ARGS",
    "ANSIBLE_SSH_COMMON_ARGS",
    "ANSIBLE_SSH_EXECUTABLE",
    "ANSIBLE_SCP_EXTRA_ARGS",
    "ANSIBLE_SFTP_EXTRA_ARGS",
    "ANSIBLE_BECOME_EXE",
    "ANSIBLE_SUDO_EXE",
    "ANSIBLE_BECOME_FLAGS",
    "ANSIBLE_EXECUTABLE",
    "ANSIBLE_JINJA2_EXTENSIONS",
    "ANSIBLE_VAULT_PASSWORD_FILE",
    "ANSIBLE_VAULT_IDENTITY_LIST",
    "ANSIBLE_PYTHON_INTERPRETER",
    "ANSIBLE_INVENTORY",
    "ANSIBLE_CALLBACKS_ENABLED",
    "ANSIBLE_STDOUT_CALLBACK",
    "ANSIBLE_COW_PATH",
    "ANSIBLE_DOCKER_EXTRA_ARGS",
    "_ANSIBLE_TEMPLAR_SANDBOX_MODE",
    "_ANSIBLE_ANSIBALLZ_DEBUGPY_CONFIG",
)
OPTIONS = (
    "--ssh-common-args",
    "--ssh-extra-args",
    "--scp-extra-args",
    "--sftp-extra-args",
    "--vault-id",
    "--vault-password-file",
    "--vault-pass-file",
    "--connection-password-file",
    "--conn-pass-file",
    "--become-password-file",
    "--become-pass-file",
)


def write(root: Path, name: str, text: str) -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def found(root: Path, name: str, text: str) -> list[tuple[int, str]]:
    target = write(root, name, text)
    return [(violation.line, violation.message) for violation in rules.check_paths([target], root)]


def messages(root: Path, name: str, text: str) -> list[str]:
    return [message for _, message in found(root, name, text)]


@pytest.mark.parametrize(("section", "key", "value"), CODE_SETTINGS)
@pytest.mark.parametrize("config_name", ["ansible.cfg", "Ansible.cfg", "playbooks/ansible.cfg"])
def test_a_code_running_setting_of_ansible_cfg_is_refused(
    tmp_path: Path, section: str, key: str, value: str, config_name: str
) -> None:
    text = f"[colors]\nok = green\n[{section}]\n{key.upper()} = {value}\n"
    assert (
        4,
        f"setting {key!r} is not allowed: {CODE} (ADR 0004)",
    ) in found(tmp_path, config_name, text)


@pytest.mark.parametrize(("key", "value"), SELECTORS)
def test_a_plugin_setting_of_ansible_cfg_must_name_an_ansible_core_plugin(
    tmp_path: Path, key: str, value: str
) -> None:
    text = f"[defaults]\n{key}: {value}\n"
    assert (
        2,
        f"setting {key!r} to {value!r} is not allowed: {PLUGIN} (ADR 0004)",
    ) in found(tmp_path, "ansible.cfg", text)


@pytest.mark.parametrize(("key", "value"), ALLOWED)
def test_an_ordinary_setting_of_ansible_cfg_passes(tmp_path: Path, key: str, value: str) -> None:
    assert found(tmp_path, "ansible.cfg", f"[defaults]\n{key} = {value}\n") == []


def test_an_unparsable_ansible_cfg_is_reported_once(tmp_path: Path) -> None:
    assert [message.split(":")[0] for message in messages(tmp_path, "ansible.cfg", "x = 1\n")] == [
        "cannot parse ansible.cfg"
    ]


@pytest.mark.parametrize(("section", "key", "value"), CODE_SETTINGS)
@pytest.mark.parametrize(
    "template",
    [
        "---\nansible:\n  cfg:\n    {section}:\n      {key}: '{value}'\n",
        "---\nprovisioner:\n  config_options:\n    {section}:\n      {key}: '{value}'\n",
    ],
)
def test_a_code_running_setting_of_molecule_is_refused(
    tmp_path: Path, section: str, key: str, value: str, template: str
) -> None:
    text = template.format(section=section, key=key, value=value)
    assert (5, f"setting {key!r} is not allowed: {CODE} (ADR 0004)") in found(
        tmp_path, "extensions/molecule/s/molecule.yml", text
    )


@pytest.mark.parametrize(("key", "value"), SELECTORS)
def test_a_plugin_setting_of_molecule_must_name_an_ansible_core_plugin(
    tmp_path: Path, key: str, value: str
) -> None:
    text = f"---\nansible:\n  cfg:\n    defaults:\n      {key}: {value}\n"
    assert (5, f"setting {key!r} to {value!r} is not allowed: {PLUGIN} (ADR 0004)") in found(
        tmp_path, "extensions/molecule/s/molecule.yml", text
    )


def test_the_ansible_configuration_of_the_molecule_scenarios_passes(tmp_path: Path) -> None:
    text = (
        "---\nansible:\n  cfg:\n    defaults:\n      stdout_callback: ansible.builtin.default\n"
        "      fact_caching: memory\n      remote_tmp: /srv/probe/x\n    ssh_connection:\n"
        "      pipelining: true\n      ? [a]\n      : b\n    odd: [1]\n    7: {}\n"
        "  executor:\n    args:\n"
        "      ansible_playbook:\n        - --extra-vars=ansible_become=false\n"
        "provisioner: []\n"
    )
    assert found(tmp_path, "extensions/molecule/s/molecule.yml", text) == []


def test_molecule_settings_outside_the_configuration_mappings_are_not_ansible_settings(
    tmp_path: Path,
) -> None:
    text = (
        "---\nprovisioner:\n  inventory:\n    links: {}\n"
        "platforms:\n  - name: x\n    executable: y\n"
    )
    assert found(tmp_path, "extensions/molecule/s/molecule.yml", text) == []


@pytest.mark.parametrize("name", ENVIRONMENT)
@pytest.mark.parametrize(
    ("file_name", "template"),
    [
        ("Makefile", "x:\n\t{name}=x ansible-playbook p.yml\n"),
        ("tools/run.sh", "export {name}=x\n"),
        (".envrc", "export {name}=x\n"),
        ("tox.ini", "[testenv]\nsetenv =\n    {name}=x\n"),
        (
            "roles/r/tasks/main.yml",
            "---\n- ansible.builtin.debug:\n    msg: hi\n  environment:\n    {name}: x\n",
        ),
        ("extensions/molecule/s/molecule.yml", "---\nansible:\n  env:\n    {name}: x\n"),
        (
            ".github/workflows/w.yml",
            "---\njobs:\n  a:\n    steps:\n      - run: {name}=x make ci\n",
        ),
    ],
)
def test_a_code_running_environment_variable_is_refused(
    tmp_path: Path, name: str, file_name: str, template: str
) -> None:
    expected = f"environment variable {name} is not allowed: {CODE} (ADR 0004)"
    assert expected in messages(tmp_path, file_name, template.format(name=name))


def test_a_longer_name_that_contains_an_environment_variable_is_not_it(tmp_path: Path) -> None:
    assert messages(tmp_path, "tools/run.sh", "export MY_ANSIBLE_SSH_ARGS=x\n") == []


@pytest.mark.parametrize("option", OPTIONS)
@pytest.mark.parametrize(
    ("file_name", "template"),
    [
        ("Makefile", "x:\n\tansible-playbook {option}=x p.yml\n"),
        ("tools/run.sh", "ansible-playbook {option} x p.yml\n"),
        (
            "extensions/molecule/s/molecule.yml",
            (
                "---\nansible:\n  executor:\n    args:\n"
                "      ansible_playbook:\n        - {option}=x\n"
            ),
        ),
        (
            ".github/workflows/w.yml",
            "---\njobs:\n  a:\n    steps:\n      - run: ansible-playbook {option} x\n",
        ),
    ],
)
def test_a_code_running_command_line_option_is_refused(
    tmp_path: Path, option: str, file_name: str, template: str
) -> None:
    expected = f"option {option} is not allowed: it passes arguments or a script that Ansible runs"
    found_messages = messages(tmp_path, file_name, template.format(option=option))
    assert any(expected in message for message in found_messages), found_messages


def test_ordinary_command_line_options_pass(tmp_path: Path) -> None:
    text = "x:\n\tansible-playbook --inventory i.yml --become-method sudo --check p.yml\n"
    assert messages(tmp_path, "Makefile", text) == []
