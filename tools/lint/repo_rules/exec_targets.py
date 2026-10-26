"""Files that a play or task loads as variables or renders as a template (FREES-159).

``vars_files``, ``include_vars`` (``file``, ``dir`` and the free form) and the ``src`` of the
``template`` module name a file that Ansible loads or renders. The guard reads every
repository file outside ``.github/``, but YAML and JSON value by value, so a target must be
a literal relative path that stays inside the repository outside ``.github/``, and a vars
file must be YAML or JSON. The one templated form is ``{{ role_path }}/`` in a role or
``{{ playbook_dir }}/`` in a playbook, followed by a literal path, resolved against the role
or playbook directory. ``extensions`` of ``include_vars`` is refused by ``exec_modules``
(ADR 0004).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.ansible_tasks import module_name, scalar_items, task_mappings
from tools.lint.repo_rules.common import Violation
from tools.lint.repo_rules.jinja_calls import is_possibly_template

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

VARS_FILES_KEY: Final[str] = "vars_files"
INCLUDE_VARS: Final[str] = "include_vars"
TEMPLATE_MODULE: Final[str] = "template"
TARGET_ARGUMENTS: Final[dict[str, dict[str, bool]]] = {
    INCLUDE_VARS: {"file": True, "_raw_params": True, "dir": False},
    TEMPLATE_MODULE: {"src": False},
}
RAW_PARAMS: Final[str] = "_raw_params"
ARGS_KEY: Final[str] = "args"
ACTION_KEYS: Final[frozenset[str]] = frozenset({"action", "local_action"})
MODULE_KEY: Final[str] = "module"
PLAY_KEYS: Final[frozenset[str]] = frozenset({"hosts", "import_playbook"})
VARS_SUFFIXES: Final[tuple[str, ...]] = (".yml", ".yaml", ".json")
EXECUTED_DIRECTORY: Final[str] = ".github"
ROLES_DIRECTORY: Final[str] = "roles"
ROLE_DEPTH: Final[int] = 2
ROLE_PATH: Final[re.Pattern[str]] = re.compile(r"\{\{\s*role_path\s*\}\}/(?P<rest>.+)")
PLAYBOOK_DIR: Final[re.Pattern[str]] = re.compile(r"\{\{\s*playbook_dir\s*\}\}/(?P<rest>.+)")


def _inside(base: Path, rest: str) -> bool:
    """Return whether ``base / rest`` stays inside the repository outside ``.github/``."""
    if rest.startswith(("/", "~")) or is_possibly_template(rest):
        return False
    resolved = Path(os.path.normpath(base / rest))
    return resolved.parts[:1] not in {("..",), (EXECUTED_DIRECTORY,)}


def _role_directory(relative: Path) -> Path | None:
    parts = relative.parts
    if len(parts) > ROLE_DEPTH and parts[0] == ROLES_DIRECTORY:
        return Path(*parts[:ROLE_DEPTH])
    return None


def target_problem(
    text: str, relative: Path | None, *, playbook: bool, walk_up: bool, vars_file: bool
) -> str | None:
    """Return why the load or render target ``text`` is refused, or ``None``.

    ``walk_up`` allows ``..`` in a literal path that stays inside the repository when it is
    resolved against the directory of the file, which is where ``vars_files`` is resolved;
    elsewhere Ansible also searches other directories, so ``..`` is refused.
    """
    target = text.strip()
    if vars_file and not target.endswith(VARS_SUFFIXES):
        return "must be a .yml, .yaml or .json file, which the guard reads value by value"
    role = ROLE_PATH.fullmatch(target)
    play = PLAYBOOK_DIR.fullmatch(target)
    base: Path | None = None
    rest = target
    if role is not None:
        rest = role["rest"]
        base = None if relative is None else _role_directory(relative)
    elif play is not None:
        rest = play["rest"]
        base = relative.parent if relative is not None and playbook else None
    elif relative is not None and (walk_up or ".." not in target.split("/")):
        base = relative.parent
    if base is not None and _inside(base, rest):
        return None
    return (
        "must be a literal relative path inside the repository and outside .github/, alone "
        "or after {{ role_path }}/ in a role or {{ playbook_dir }}/ in a playbook"
    )


def _arguments(value: yaml.Node, *, action: bool) -> Iterator[tuple[str, yaml.Node, str]]:
    """Yield ``(name, node, text)`` for the scalar arguments of a module value.

    The free form yields its first word as ``_raw_params`` (after the module name in an
    ``action`` string) and every ``name=value`` word.
    """
    if isinstance(value, yaml.MappingNode):
        for name, _, inner in scalar_items(value):
            if isinstance(inner, yaml.ScalarNode):
                yield name, inner, str(inner.value)
    elif isinstance(value, yaml.ScalarNode):
        words = str(value.value).split()[1 if action else 0 :]
        for position, word in enumerate(words):
            name, separator, text = word.partition("=")
            if separator:
                yield name, value, text
            elif position == 0:
                yield RAW_PARAMS, value, word


def _action_module(value: yaml.Node) -> str:
    if isinstance(value, yaml.ScalarNode):
        words = str(value.value).split(maxsplit=1)
        return words[0] if words else ""
    if isinstance(value, yaml.MappingNode):
        for name, _, inner in scalar_items(value):
            if name == MODULE_KEY and isinstance(inner, yaml.ScalarNode):
                return str(inner.value)
    return ""


def _sources(task: yaml.MappingNode) -> Iterator[tuple[str, yaml.Node, bool]]:
    """Yield ``(module, value, is_action)`` for each module of the task and its ``args``."""
    items = list(scalar_items(task))
    modules: list[str] = []
    for name, _, value in items:
        module = _action_module(value) if name in ACTION_KEYS else name.strip()
        if module_name(module) in TARGET_ARGUMENTS:
            modules.append(module)
            yield module, value, name in ACTION_KEYS
    for module in modules:
        for name, _, value in items:
            if name == ARGS_KEY:
                yield module, value, False


def _task_findings(
    task: yaml.MappingNode, relative: Path | None, *, playbook: bool
) -> Iterator[tuple[yaml.Node, str]]:
    for module, value, action in _sources(task):
        wanted = TARGET_ARGUMENTS[module_name(module)]
        for name, node, text in _arguments(value, action=action):
            if name not in wanted:
                continue
            problem = target_problem(
                text, relative, playbook=playbook, walk_up=False, vars_file=wanted[name]
            )
            if problem is not None:
                yield node, f"{module} {name} {text!r} {problem}"


def _vars_files_findings(
    value: yaml.Node, relative: Path | None, *, playbook: bool
) -> Iterator[tuple[yaml.Node, str]]:
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)
        elif isinstance(node, yaml.ScalarNode):
            problem = target_problem(
                str(node.value), relative, playbook=playbook, walk_up=True, vars_file=True
            )
            if problem is not None:
                yield node, f"vars_files entry {str(node.value)!r} {problem}"
        else:
            yield node, "vars_files entry must be a literal path, not a mapping"


def _is_playbook(document: yaml.SequenceNode) -> bool:
    return any(
        isinstance(item, yaml.MappingNode)
        and any(name in PLAY_KEYS for name, _, _ in scalar_items(item))
        for item in document.value
    )


def target_findings(
    path: Path, relative: Path | None, documents: Iterable[yaml.Node]
) -> list[Violation]:
    """Reject computed or escaping ``vars_files``, ``include_vars`` and ``template`` targets."""
    found: set[Violation] = set()
    for document in documents:
        if not isinstance(document, yaml.SequenceNode):
            continue
        playbook = _is_playbook(document)
        for task in task_mappings(document):
            findings = list(_task_findings(task, relative, playbook=playbook))
            for name, _, value in scalar_items(task):
                if name == VARS_FILES_KEY:
                    findings.extend(_vars_files_findings(value, relative, playbook=playbook))
            found.update(
                Violation(path, node.start_mark.line + 1, message) for node, message in findings
            )
    return sorted(found)
