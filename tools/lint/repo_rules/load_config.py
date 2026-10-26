"""Ansible settings that add a location from which Ansible loads code (FREES-156).

Ansible reads module, ``module_utils``, plugin, role and collection search paths from
``ansible.cfg``, from ``ANSIBLE_*`` environment variables and, under Molecule, from the
``ansible.cfg`` mapping of ``molecule.yml``. None of them may add a location: the
collection's code belongs in ``plugins/`` (ADR 0004).
"""

from __future__ import annotations

import configparser
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

CONFIG_FILE_NAME: Final[str] = "ansible.cfg"
PLUGIN_PATH_SETTINGS: Final[frozenset[str]] = frozenset(
    {
        "library",
        "module_utils",
        "action_plugins",
        "become_plugins",
        "cache_plugins",
        "callback_plugins",
        "cliconf_plugins",
        "connection_plugins",
        "doc_fragment_plugins",
        "filter_plugins",
        "httpapi_plugins",
        "inventory_plugins",
        "lookup_plugins",
        "netconf_plugins",
        "strategy_plugins",
        "terminal_plugins",
        "test_plugins",
        "vars_plugins",
    }
)
CONTAINER_PATH_SETTINGS: Final[frozenset[str]] = frozenset(
    {
        "roles_path",
        "collections_path",
        "collections_paths",
        "home",
        "playbook_dir",
        "ansible_connection_path",
    }
)
CONFIG_PATH_SETTINGS: Final[frozenset[str]] = PLUGIN_PATH_SETTINGS | CONTAINER_PATH_SETTINGS
PATH_ENVIRONMENT_VARIABLES: Final[frozenset[str]] = frozenset(
    {
        *(f"ANSIBLE_{name.upper()}" for name in CONFIG_PATH_SETTINGS - {"ansible_connection_path"}),
        "ANSIBLE_CONNECTION_PATH",
        "ANSIBLE_CONFIG",
    }
)
MAKE_ENVIRONMENT_VARIABLES: Final[frozenset[str]] = frozenset(
    {"ANSIBLE_HOME", "ANSIBLE_COLLECTIONS_PATH"}
)
MAKE_FILE_NAMES: Final[frozenset[str]] = frozenset({"Makefile", "makefile", "GNUmakefile"})
SHELL_TEXT_SUFFIXES: Final[frozenset[str]] = frozenset({".mk", ".sh"})
MOLECULE_FILE_NAMES: Final[frozenset[str]] = frozenset({"molecule.yml", "molecule.yaml"})
ENVIRONMENT_NAME: Final[re.Pattern[str]] = re.compile(r"\bANSIBLE_[A-Z0-9_]+\b")
MODULE_PATH_OPTION: Final[re.Pattern[str]] = re.compile(r"(?<![\w-])(?:--module-path\b|-M)")
EXECUTED_YAML_DIRECTORY: Final[str] = ".github"


def is_configuration_text(path: Path) -> bool:
    """Return whether ``path`` is an ``ansible.cfg``, a makefile or a shell script."""
    return (
        path.name == CONFIG_FILE_NAME
        or path.name in MAKE_FILE_NAMES
        or path.suffix.lower() in SHELL_TEXT_SUFFIXES
    )


def _parse(text: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";",))
    parser.read_string(text)
    return parser


def _setting_line(text: str, key: str) -> int:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*[=:]", re.IGNORECASE)
    return next(
        (number for number, line in enumerate(text.splitlines(), 1) if pattern.match(line)), 1
    )


def _config_findings(path: Path, text: str) -> list[Violation]:
    try:
        parser = _parse(text)
    except configparser.Error as error:
        return [Violation(path, 1, f"cannot parse {CONFIG_FILE_NAME}: {error}")]
    return [
        Violation(
            path,
            _setting_line(text, key),
            f"{CONFIG_FILE_NAME} setting {key!r} is not allowed: it adds a location from which "
            "Ansible loads code; the collection's code belongs in plugins/ (ADR 0004)",
        )
        for section in parser.sections()
        for key in parser[section]
        if key in CONFIG_PATH_SETTINGS
    ]


def _text_findings(path: Path, text: str, allowed: frozenset[str] = frozenset()) -> list[Violation]:
    violations: list[Violation] = []
    for number, line in enumerate(text.splitlines(), 1):
        violations.extend(
            Violation(
                path,
                number,
                f"environment variable {name} is not allowed: it adds a location from "
                "which Ansible loads code (ADR 0004)",
            )
            for name in ENVIRONMENT_NAME.findall(line)
            if name in PATH_ENVIRONMENT_VARIABLES - allowed
        )
        violations.extend(
            Violation(
                path,
                number,
                f"option {option} is not allowed: it adds a location from which Ansible loads "
                "modules (ADR 0004)",
            )
            for option in MODULE_PATH_OPTION.findall(line)
        )
    return violations


def configuration_text_findings(path: Path, data: bytes) -> list[Violation]:
    """Reject settings of an ``ansible.cfg``, makefile or shell script that add a load path."""
    text = data.decode("utf-8", errors="replace")
    if path.name == CONFIG_FILE_NAME:
        return _config_findings(path, text)
    if path.name in MAKE_FILE_NAMES or path.suffix.lower() == ".mk":
        return _text_findings(path, text, MAKE_ENVIRONMENT_VARIABLES)
    return _text_findings(path, text)


def _scalars(documents: Iterable[yaml.Node]) -> Iterator[tuple[yaml.ScalarNode, bool]]:
    """Yield every scalar node of ``documents`` and whether it is a mapping key."""
    stack: list[tuple[yaml.Node, bool]] = [(document, False) for document in documents]
    seen: set[tuple[int, bool]] = set()
    while stack:
        node, is_key = stack.pop()
        if (id(node), is_key) in seen:
            continue
        seen.add((id(node), is_key))
        if isinstance(node, yaml.ScalarNode):
            yield node, is_key
        elif isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                stack.extend(((key, True), (value, False)))
        else:
            stack.extend((item, False) for item in node.value)


def _key_finding(path: Path, key: yaml.ScalarNode, *, molecule: bool) -> list[Violation]:
    line = key.start_mark.line + 1
    if key.value in PATH_ENVIRONMENT_VARIABLES:
        return [
            Violation(
                path,
                line,
                f"environment variable {key.value} is not allowed: it adds a location from "
                "which Ansible loads code (ADR 0004)",
            )
        ]
    if molecule and key.value in CONFIG_PATH_SETTINGS:
        return [
            Violation(
                path,
                line,
                f"Molecule setting {key.value!r} is not allowed: it adds a location from "
                "which Ansible loads code (ADR 0004)",
            )
        ]
    return []


def yaml_setting_findings(path: Path, text: str, *, executed: bool) -> list[Violation]:
    """Reject YAML that sets a load path: environment variables and Molecule settings.

    A mapping key named like a load-path environment variable is refused in every YAML
    file, and in ``molecule.yml`` so is a key named like an ``ansible.cfg`` load-path
    setting. In a file whose values are run as commands or arguments (``executed``: a
    workflow, an action or ``molecule.yml``) every value is also checked as command text.
    Unparsable YAML is reported by the other YAML rules, so it yields nothing here.
    """
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        documents = list(iter(loader.get_node, None))
    except yaml.YAMLError:
        return []
    finally:
        loader.dispose()
    molecule = path.name in MOLECULE_FILE_NAMES
    violations: list[Violation] = []
    for node, is_key in _scalars(documents):
        if is_key:
            violations.extend(_key_finding(path, node, molecule=molecule))
        elif executed or molecule:
            violations.extend(
                Violation(path, node.start_mark.line + violation.line, violation.message)
                for violation in _text_findings(path, node.value)
            )
    return sorted(violations)


def _named_directories(config: Path, base: Path) -> Iterator[Path]:
    try:
        parser = _parse(config.read_text(encoding="utf-8", errors="replace"))
    except (OSError, configparser.Error):
        return
    for section in parser.sections():
        for key, value in parser[section].items():
            if key not in PLUGIN_PATH_SETTINGS:
                continue
            for entry in value.split(os.pathsep):
                if not entry.strip():
                    continue
                directory = Path(os.path.normpath(config.parent / entry.strip()))
                if directory == base or base in directory.parents:
                    yield directory.relative_to(base)


def configured_load_directories(paths: Iterable[Path], root: Path) -> frozenset[Path]:
    """Return the directories, relative to ``root``, that an ``ansible.cfg`` names as load paths.

    The candidates are ``root/ansible.cfg``, every ``ansible.cfg`` among ``paths`` and every
    ``ansible.cfg`` in a directory between ``root`` and a path, so a file is checked against
    the configuration that Ansible would read when it runs from one of those directories.
    """
    base = root.resolve()
    candidates = {base / CONFIG_FILE_NAME}
    for path in paths:
        directory = path.parent.resolve()
        while directory == base or base in directory.parents:
            candidates.add(directory / CONFIG_FILE_NAME)
            directory = directory.parent
    return frozenset(
        directory
        for config in sorted(candidates)
        if config.is_file()
        for directory in _named_directories(config, base)
    )
