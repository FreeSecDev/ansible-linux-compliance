"""Ansible settings that run code or choose what runs (FREES-159).

ansible-core's ``config/base.yml`` and the ``DOCUMENTATION`` of its connection and become
plugins define settings that name an executable, an interpreter, arguments or flags, a
script that Ansible runs (a vault password file, a password file, an inventory) or code that
it loads (Jinja extensions, callback, inventory and vars plugins). None of them may be set in
an ``ansible.cfg``, in the ``ansible.cfg`` or ``config_options`` mapping of ``molecule.yml``,
through the matching environment variable or through the matching command-line option. A
setting that only selects a plugin may name one of ansible-core's own plugins (ADR 0004).
"""

from __future__ import annotations

import configparser
import re
from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path

BASE_CODE_SETTINGS: Final[frozenset[str]] = frozenset(
    {
        "allow_unsafe_lookups",
        "become_exe",
        "become_flags",
        "become_password_file",
        "callbacks_enabled",
        "collection_skeleton",
        "connection_password_file",
        "cowpath",
        "editor",
        "enable_plugins",
        "executable",
        "fact_caching_connection",
        "facts_modules",
        "interpreter_python",
        "inventory",
        "jinja2_extensions",
        "module_args",
        "module_name",
        "pager",
        "role_skeleton",
        "ssh_agent_executable",
        "ssh_config",
        "vars_plugins_enabled",
        "vault_identity_list",
        "vault_password_file",
    }
)
PLUGIN_CODE_SETTINGS: Final[frozenset[str]] = frozenset(
    {
        "ssh_args",
        "ssh_common_args",
        "ssh_extra_args",
        "scp_extra_args",
        "sftp_extra_args",
        "ssh_executable",
        "scp_executable",
        "sftp_executable",
        "pkcs11_provider",
        "flags",
    }
)
CODE_SETTINGS: Final[frozenset[str]] = BASE_CODE_SETTINGS | PLUGIN_CODE_SETTINGS
PLUGIN_SELECTOR_SETTINGS: Final[dict[str, frozenset[str]]] = {
    "stdout_callback": frozenset({"default", "junit", "minimal", "oneline", "tree"}),
    "fact_caching": frozenset({"jsonfile", "memory"}),
    "strategy": frozenset({"free", "host_pinned", "linear"}),
    "become_method": frozenset({"runas", "su", "sudo"}),
    "transport": frozenset({"local", "psrp", "ssh", "winrm"}),
}
PLUGIN_PREFIXES: Final[tuple[str, ...]] = ("", "ansible.builtin.")
CODE_ENVIRONMENT_VARIABLES: Final[frozenset[str]] = frozenset(
    {
        "ANSIBLE_BECOME_EXE",
        "ANSIBLE_BECOME_FLAGS",
        "ANSIBLE_BECOME_METHOD",
        "ANSIBLE_BECOME_PASSWORD_FILE",
        "ANSIBLE_CACHE_PLUGIN",
        "ANSIBLE_CACHE_PLUGIN_CONNECTION",
        "ANSIBLE_CALLBACKS_ENABLED",
        "ANSIBLE_CONNECTION_PASSWORD_FILE",
        "ANSIBLE_COW_PATH",
        "ANSIBLE_DOCKER_EXTRA_ARGS",
        "ANSIBLE_EDITOR",
        "ANSIBLE_EXECUTABLE",
        "ANSIBLE_FACTS_MODULES",
        "ANSIBLE_GALAXY_COLLECTION_SKELETON",
        "ANSIBLE_GALAXY_ROLE_SKELETON",
        "ANSIBLE_INVENTORY",
        "ANSIBLE_INVENTORY_ENABLED",
        "ANSIBLE_JINJA2_EXTENSIONS",
        "ANSIBLE_MODULE_ARGS",
        "ANSIBLE_NETCONF_SSH_CONFIG",
        "ANSIBLE_PAGER",
        "ANSIBLE_PKCS11_PROVIDER",
        "ANSIBLE_PYTHON_INTERPRETER",
        "ANSIBLE_RUNAS_FLAGS",
        "ANSIBLE_SCP_EXECUTABLE",
        "ANSIBLE_SCP_EXTRA_ARGS",
        "ANSIBLE_SFTP_EXECUTABLE",
        "ANSIBLE_SFTP_EXTRA_ARGS",
        "ANSIBLE_SSH_AGENT_EXECUTABLE",
        "ANSIBLE_SSH_ARGS",
        "ANSIBLE_SSH_COMMON_ARGS",
        "ANSIBLE_SSH_EXECUTABLE",
        "ANSIBLE_SSH_EXTRA_ARGS",
        "ANSIBLE_STDOUT_CALLBACK",
        "ANSIBLE_STRATEGY",
        "ANSIBLE_SU_EXE",
        "ANSIBLE_SU_FLAGS",
        "ANSIBLE_SUDO_EXE",
        "ANSIBLE_SUDO_FLAGS",
        "ANSIBLE_TRANSPORT",
        "ANSIBLE_VARS_ENABLED",
        "ANSIBLE_VAULT_IDENTITY_LIST",
        "ANSIBLE_VAULT_PASSWORD_FILE",
        "_ANSIBLE_ANSIBALLZ_COVERAGE_CONFIG",
        "_ANSIBLE_ANSIBALLZ_DEBUGPY_CONFIG",
        "_ANSIBLE_ANSIBALLZ_PYDEVD_CONFIG",
        "_ANSIBLE_CONNECTION_PATH",
        "_ANSIBLE_COVERAGE_REMOTE_OUTPUT",
        "_ANSIBLE_TEMPLAR_SANDBOX_MODE",
    }
)
CODE_OPTIONS: Final[frozenset[str]] = frozenset(
    {
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
    }
)
OPTION: Final[re.Pattern[str]] = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")
MOLECULE_CONFIG_PATHS: Final[tuple[tuple[str, ...], ...]] = (
    ("ansible", "cfg"),
    ("provisioner", "config_options"),
)


def setting_problem(key: str, value: str) -> str | None:
    """Return why the configuration setting ``key = value`` is refused, or ``None``."""
    name = key.strip().lower()
    if name in CODE_SETTINGS:
        return (
            f"setting {name!r} is not allowed: it names an executable, arguments, a script or "
            "code that Ansible runs or loads (ADR 0004)"
        )
    plugins = PLUGIN_SELECTOR_SETTINGS.get(name)
    if plugins is None:
        return None
    allowed = {f"{prefix}{plugin}" for prefix in PLUGIN_PREFIXES for plugin in plugins}
    if value.strip() in allowed:
        return None
    return (
        f"setting {name!r} to {value.strip()!r} is not allowed: it may only name a plugin of "
        "ansible-core (ADR 0004)"
    )


def _setting_line(text: str, key: str) -> int:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*[=:]", re.IGNORECASE)
    return next(
        (number for number, line in enumerate(text.splitlines(), 1) if pattern.match(line)), 1
    )


def config_file_findings(path: Path, text: str) -> list[Violation]:
    """Reject code-running settings of an ``ansible.cfg``; parse errors are reported elsewhere."""
    parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";",))
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    found: list[Violation] = []
    for section in parser.sections():
        for key, value in parser[section].items():
            problem = setting_problem(key, value)
            if problem is not None:
                found.append(Violation(path, _setting_line(text, key), problem))
    return found


def text_findings(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line, message)`` for code-running command-line options in command text."""
    for number, line in enumerate(text.splitlines(), 1):
        for option in OPTION.findall(line):
            if option in CODE_OPTIONS:
                yield (
                    number,
                    (
                        f"option {option} is not allowed: it passes arguments or a script that "
                        "Ansible runs (ADR 0004)"
                    ),
                )


def _mapping(node: yaml.Node | None, key: str) -> yaml.Node | None:
    if not isinstance(node, yaml.MappingNode):
        return None
    return next(
        (
            value
            for name, value in node.value
            if isinstance(name, yaml.ScalarNode) and name.value == key
        ),
        None,
    )


def _sections(document: yaml.Node) -> Iterator[yaml.MappingNode]:
    for keys in MOLECULE_CONFIG_PATHS:
        node: yaml.Node | None = document
        for key in keys:
            node = _mapping(node, key)
        if isinstance(node, yaml.MappingNode):
            yield from (
                section for _, section in node.value if isinstance(section, yaml.MappingNode)
            )


def molecule_config_findings(path: Path, documents: Iterable[yaml.Node]) -> list[Violation]:
    """Reject code-running settings in the Ansible configuration mappings of ``molecule.yml``."""
    found: list[Violation] = []
    for document in documents:
        for section in _sections(document):
            for key, value in section.value:
                if not isinstance(key, yaml.ScalarNode):
                    continue
                shown = str(value.value) if isinstance(value, yaml.ScalarNode) else ""
                problem = setting_problem(str(key.value), shown)
                if problem is not None:
                    found.append(Violation(path, key.start_mark.line + 1, problem))
    return found
