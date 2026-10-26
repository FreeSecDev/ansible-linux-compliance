"""Variables and keywords that change what Ansible executes (FREES-159).

An interpreter, an executable, command-line arguments or flags of a connection or become
plugin, and the plugin that a connection, become method or shell selects all decide which
program runs on the controller or the managed node. They are refused wherever the repository
sets them: as a mapping key in any YAML file (role defaults and vars, play, block, task and
include vars, ``set_fact``, ``add_host``, inventories, ``host_vars``, ``group_vars`` and
Molecule files), as ``name=value`` or a quoted Jinja dictionary key in a YAML value, and in
inventory and configuration text. The loader, interpreter and ``PATH`` environment variables
(``ENVIRONMENT_EXEC_KEYS``) are refused as YAML keys, because a task ``environment`` sets
them for the module. A plugin selector may name a plugin of ansible-core, and
``ALLOWED_SETTINGS`` lists the reviewed exceptions by file, name and exact value (ADR 0004).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

CONNECTION_EXEC_VARIABLES: Final[frozenset[str]] = frozenset(
    {
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
    }
)
BECOME_EXEC_VARIABLES: Final[frozenset[str]] = frozenset(
    {
        "ansible_become_exe",
        "ansible_su_exe",
        "ansible_sudo_exe",
        "ansible_become_flags",
        "ansible_su_flags",
        "ansible_sudo_flags",
        "ansible_runas_flags",
    }
)
MAGIC_EXEC_VARIABLES: Final[frozenset[str]] = frozenset(
    {"ansible_shell_executable", "ansible_docker_extra_args", "ansible_playbook_python"}
)
CONFIG_EXEC_VARIABLES: Final[frozenset[str]] = frozenset(
    {
        "ansible_python_interpreter",
        "ansible_interpreter_python_fallback",
        "ansible_facts_modules",
        "_ansible_ansiballz_coverage_config",
        "_ansible_ansiballz_debugpy_config",
        "_ansible_ansiballz_pydevd_config",
        "_ansible_coverage_remote_output",
    }
)
BACKEND_VARIABLES: Final[frozenset[str]] = frozenset(
    {"ansible_package_use", "pkg_mgr", "ansible_pkg_mgr", "service_mgr", "ansible_service_mgr"}
)
EXEC_KEYWORDS: Final[frozenset[str]] = frozenset({"become_exe", "become_flags"})
COLLECTION_EXEC_VARIABLES: Final[frozenset[str]] = frozenset({"docker_extra_args"})
ENVIRONMENT_EXEC_KEYS: Final[frozenset[str]] = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PATH",
        "PERL5LIB",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "RUBYOPT",
    }
)
EXEC_VARIABLES: Final[frozenset[str]] = (
    CONNECTION_EXEC_VARIABLES
    | BECOME_EXEC_VARIABLES
    | MAGIC_EXEC_VARIABLES
    | CONFIG_EXEC_VARIABLES
    | BACKEND_VARIABLES
    | EXEC_KEYWORDS
    | COLLECTION_EXEC_VARIABLES
)
EXEC_VARIABLE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"ansible_\w+_interpreter"),
    re.compile(r"(?:ansible_)?discovered_interpreter_\w+"),
    re.compile(r"_ansible_\w+"),
    re.compile(r"ansible_\w*(?:_args|_exe|_executable|_flags|_cmd|_command)"),
)
CONNECTION_PLUGINS: Final[frozenset[str]] = frozenset({"local", "ssh", "psrp", "winrm"})
BECOME_PLUGINS: Final[frozenset[str]] = frozenset({"runas", "su", "sudo"})
SHELL_PLUGINS: Final[frozenset[str]] = frozenset({"cmd", "powershell", "sh"})
PLUGIN_PREFIXES: Final[tuple[str, ...]] = ("", "ansible.builtin.", "ansible.legacy.")
SELECTORS: Final[dict[str, frozenset[str]]] = {
    "ansible_connection": CONNECTION_PLUGINS,
    "connection": CONNECTION_PLUGINS,
    "ansible_become_method": BECOME_PLUGINS,
    "become_method": BECOME_PLUGINS,
    "ansible_shell_type": SHELL_PLUGINS,
}
PLAYBOOK_PYTHON: Final[str] = "{{ ansible_playbook_python }}"
PLAYBOOK_PYTHON_FILES: Final[tuple[str, ...]] = (
    "tests/playbooks/audit-exceptions-files.yml",
    "tests/playbooks/audit-exceptions-free-check.yml",
    "tests/playbooks/audit-exceptions-free.yml",
    "tests/playbooks/audit-toggles-oscap.yml",
    "tests/playbooks/internal-variables-extra.yml",
    "tests/playbooks/internal-variables-include.yml",
    "tests/playbooks/internal-variables-role-param.yml",
    "tests/playbooks/inventory/audit-exceptions-split.yml",
    "tests/playbooks/inventory/audit-exceptions.yml",
    "tests/playbooks/inventory/evidence-gate.yml",
    "tests/playbooks/inventory/gate-routes-group/hosts.yml",
    "tests/playbooks/inventory/gate-routes-host/hosts.yml",
    "tests/playbooks/inventory/verify-forged.yml",
    "tests/playbooks/remediate-check-mode.yml",
    "tests/playbooks/remediate-disruptive.yml",
    "tests/playbooks/remediate-skip-always.yml",
)
MOLECULE_DOCKER: Final[str] = "community.docker.docker"
ALLOWED_SETTINGS: Final[frozenset[tuple[Path, str, str]]] = frozenset(
    {
        *(
            (Path(name), "ansible_python_interpreter", PLAYBOOK_PYTHON)
            for name in PLAYBOOK_PYTHON_FILES
        ),
        (
            Path("tests/playbooks/inventory/evidence-gate.yml"),
            "ansible_ssh_common_args",
            "-o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes",
        ),
        (Path("extensions/molecule/shared/vars/guard_cases.yml"), "connection", MOLECULE_DOCKER),
        (
            Path("extensions/molecule/shared/vars/guard_cases.yml"),
            "ansible_connection",
            MOLECULE_DOCKER,
        ),
        (
            Path("extensions/molecule/shared/vars/guard_cases.yml"),
            "ansible_docker_extra_args",
            "-H tcp://192.0.2.1:2375",
        ),
        (
            Path("extensions/molecule/shared/vars/guard_cases.yml"),
            "docker_extra_args",
            "-H tcp://192.0.2.1:2375",
        ),
        (Path("extensions/molecule/shared/create.yml"), "connection", MOLECULE_DOCKER),
        (
            Path("extensions/molecule/selftest/bypass.yml"),
            "ansible_connection",
            "{{ selftest_docker }}",
        ),
        (Path("extensions/molecule/selftest/bypass.yml"), "ansible_connection", "selftest_docker"),
        (
            Path("extensions/molecule/selftest/bypass.yml"),
            "ansible_docker_extra_args",
            "--host tcp://192.0.2.1:2375",
        ),
    }
)
TEXT_SETTING: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w.])(?P<name>_?[A-Za-z][A-Za-z0-9_]*)"
    r"(?=\s*=(?!=)\s*(?P<word>\S*)|['\"]\s*:\s*(?P<entry>[^,}]*))"
)
INVENTORY_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {"inventory", "inventories", "host_vars", "group_vars"}
)
INVENTORY_FILE_NAMES: Final[frozenset[str]] = frozenset({"hosts", "inventory"})


def is_exec_variable(name: str) -> bool:
    """Return whether setting ``name`` can change what Ansible executes."""
    return (
        name in EXEC_VARIABLES
        or name in SELECTORS
        or any(pattern.fullmatch(name) for pattern in EXEC_VARIABLE_PATTERNS)
    )


def is_inventory_text(relative: Path) -> bool:
    """Return whether ``relative`` is inventory text that is not YAML."""
    folded = [part.casefold() for part in relative.parts]
    return bool(set(folded[:-1]) & INVENTORY_DIRECTORIES) or (
        relative.stem.casefold() in INVENTORY_FILE_NAMES
    )


def _plugin_value(name: str, value: str) -> bool:
    plugins = SELECTORS.get(name)
    return plugins is not None and any(
        value.strip() == f"{prefix}{plugin}" for prefix in PLUGIN_PREFIXES for plugin in plugins
    )


def setting_problem(relative: Path | None, name: str, value: str | None) -> str | None:
    """Return why setting ``name`` to ``value`` in ``relative`` is refused, or ``None``.

    ``value`` is ``None`` when it is not a scalar, which no exception covers.
    """
    if not is_exec_variable(name):
        return None
    if value is not None and (
        _plugin_value(name, value) or (relative, name, value) in ALLOWED_SETTINGS
    ):
        return None
    if name in SELECTORS:
        kind = "selects a plugin that is not part of ansible-core"
    else:
        kind = "sets an interpreter, executable, arguments or flags that Ansible runs"
    shown = "a mapping or sequence" if value is None else repr(value)
    return f"setting {name!r} to {shown} is not allowed: it {kind} (ADR 0004)"


def _scalar_value(node: yaml.Node) -> str | None:
    return str(node.value) if isinstance(node, yaml.ScalarNode) else None


def text_findings(relative: Path | None, text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line, message)`` for ``name=value`` and ``'name': value`` settings in ``text``."""
    for match in TEXT_SETTING.finditer(text):
        name = match.group("name")
        raw = match.group("word") if match.group("word") is not None else match.group("entry")
        value = raw.strip().strip("'\"")
        problem = setting_problem(relative, name, value)
        if problem is not None:
            yield text.count("\n", 0, match.start()) + 1, problem


def _pairs(documents: Iterable[yaml.Node]) -> Iterator[tuple[yaml.Node, yaml.Node | None]]:
    stack: list[yaml.Node] = list(documents)
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                yield key, value
                stack.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
        else:
            yield node, None


def yaml_variable_findings(
    path: Path, relative: Path | None, documents: Iterable[yaml.Node]
) -> list[Violation]:
    """Reject execution-altering variables and keywords that a YAML document sets."""
    found: set[Violation] = set()
    for key, value in _pairs(documents):
        if not isinstance(key, yaml.ScalarNode):
            continue
        start = key.start_mark.line + 1
        if value is not None and key.value in ENVIRONMENT_EXEC_KEYS:
            found.add(
                Violation(
                    path,
                    start,
                    f"environment variable {key.value} is not allowed as a key: as the "
                    "environment of a task it changes which program or library a module runs "
                    "(ADR 0004)",
                )
            )
        if value is not None:
            problem = setting_problem(relative, str(key.value), _scalar_value(value))
            if problem is not None:
                found.add(Violation(path, start, problem))
        if value is None:
            for line, message in text_findings(relative, str(key.value)):
                found.add(Violation(path, start + line - 1, message))
    return sorted(found)


def text_setting_findings(path: Path, relative: Path | None, data: bytes) -> list[Violation]:
    """Reject execution-altering variables that inventory or configuration text sets."""
    text = data.decode("utf-8", errors="replace")
    return sorted(
        {Violation(path, line, message) for line, message in text_findings(relative, text)}
    )
