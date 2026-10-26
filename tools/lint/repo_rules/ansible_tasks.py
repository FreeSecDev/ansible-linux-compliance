"""Ansible rules: banned command modules, task keys, includes and role names.

A document whose root is a sequence is a playbook or task file, and only the keys
of its plays and tasks name modules; any other document is checked for banned keys
at any depth (FREES-128, FREES-137).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

BANNED_MODULES: Final[frozenset[str]] = frozenset(
    {"shell", "command", "raw", "script", "win_shell", "win_command"}
)
COLLECTION_PREFIXES: Final[tuple[str, ...]] = (
    "ansible.builtin.",
    "ansible.legacy.",
    "ansible.windows.",
    "community.windows.",
)
ACTION_KEYS: Final[frozenset[str]] = frozenset({"action", "local_action"})
MODULE_KEY: Final[str] = "module"
TASK_LIST_KEYS: Final[frozenset[str]] = frozenset(
    {"tasks", "pre_tasks", "post_tasks", "handlers", "block", "rescue", "always"}
)
TASK_INCLUDE_MODULES: Final[frozenset[str]] = frozenset(
    {"include_tasks", "import_tasks", "include", "import_playbook"}
)
ROLE_INCLUDE_MODULES: Final[frozenset[str]] = frozenset({"include_role", "import_role"})
INCLUDE_FILE_KEYS: Final[frozenset[str]] = frozenset({"file", "_raw_params"})
ROLE_ENTRY_POINT_KEYS: Final[frozenset[str]] = frozenset({"tasks_from", "handlers_from"})
TASK_FILE_SUFFIXES: Final[tuple[str, ...]] = (".yml", ".yaml")
TEMPLATE_MARKERS: Final[tuple[str, ...]] = ("{{", "{%", "{#")
ROLE_NAME_KEY: Final[str] = "name"
PLAY_ROLES_KEY: Final[str] = "roles"
PLAY_ROLE_NAME_KEYS: Final[frozenset[str]] = frozenset({"role", "name"})
ROLE_NAME: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_][A-Za-z0-9_-]*)*"
)
PATH_SEGMENT: Final[str] = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
ROLE_PATH_TARGET: Final[re.Pattern[str]] = re.compile(
    rf"\{{\{{\s*role_path\s*\}}\}}/tasks/(?:{PATH_SEGMENT}/)*{PATH_SEGMENT}\.(?:yml|yaml)"
)
MERGE_TAG: Final[str] = "tag:yaml.org,2002:merge"
REDIRECT_KEY: Final[str] = "redirect"


def _module_name(value: str) -> str:
    """Strip a known collection prefix from ``value`` and return the module name."""
    for prefix in COLLECTION_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _is_banned(value: str) -> bool:
    """Return whether ``value`` names a banned module, with or without prefix."""
    return _module_name(value.strip()) in BANNED_MODULES


def _merged_items(mapping: yaml.MappingNode) -> list[tuple[yaml.Node, yaml.Node]]:
    """Return the key-value pairs of ``mapping`` with YAML merge keys (``<<``) expanded.

    Ansible constructs the merged mapping, so a task can take its module key from
    an anchor that is defined anywhere in the document. Every pair is returned,
    including keys that a later key overrides, and merge cycles terminate.
    """
    items: list[tuple[yaml.Node, yaml.Node]] = []
    seen: set[int] = set()
    pending: list[yaml.Node] = [mapping]
    while pending:
        node = pending.pop()
        if id(node) in seen or not isinstance(node, yaml.MappingNode):
            continue
        seen.add(id(node))
        for key, value in node.value:
            if key.tag != MERGE_TAG:
                items.append((key, value))
            elif isinstance(value, yaml.SequenceNode):
                pending.extend(reversed(value.value))
            else:
                pending.append(value)
    return items


def _scalar_items(mapping: yaml.MappingNode) -> Iterable[tuple[str, yaml.ScalarNode, yaml.Node]]:
    """Yield ``(name, key, value)`` for every scalar key of ``mapping``, merges expanded."""
    for key, value in _merged_items(mapping):
        if isinstance(key, yaml.ScalarNode):
            yield str(key.value), key, value


def _is_templated(text: str) -> bool:
    """Return whether ``text`` contains a Jinja expression, statement or comment."""
    return any(marker in text for marker in TEMPLATE_MARKERS)


def _action_modules(value: yaml.Node) -> Iterable[yaml.ScalarNode]:
    """Yield the scalars that name the module of an ``action`` style value.

    Every ``module`` key of the mapping form is yielded, so a duplicated key
    cannot hide a banned module behind an allowed one.
    """
    if isinstance(value, yaml.ScalarNode):
        yield value
    elif isinstance(value, yaml.MappingNode):
        for name, _, inner in _scalar_items(value):
            if name == MODULE_KEY and isinstance(inner, yaml.ScalarNode):
                yield inner


def _action_findings(value: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield a finding for each banned or templated module named by an ``action`` value.

    Ansible takes the module name from the first word of the string form and of
    the ``module`` key of the mapping form, so ``module: shell echo hi`` names
    ``shell``. A templated module name cannot be checked statically and is denied.
    """
    for module in _action_modules(value):
        words = str(module.value).split(maxsplit=1)
        if not words:
            continue
        if _is_banned(words[0]):
            yield module, f"banned module: {module.value!r}"
        elif _is_templated(words[0]):
            yield module, f"templated module name in an action is not allowed: {module.value!r}"


def _node_text(node: yaml.Node) -> str:
    """Return the value of a scalar node, or the kind of any other node."""
    if isinstance(node, yaml.ScalarNode):
        return str(node.value)
    return "sequence" if isinstance(node, yaml.SequenceNode) else "mapping"


def _path_problem(text: str, *, allow_role_path: bool) -> str | None:
    """Return why the task file ``text`` may not be scanned, or ``None`` if it is safe.

    The check scans every YAML file of the repository, so a target must be a
    relative ``.yml`` or ``.yaml`` path without ``..``: a templated, absolute or
    home-relative target, or one that walks up, could load tasks from a file
    outside the repository that is never scanned. The only templated form is
    ``{{ role_path }}/tasks/`` followed by a literal relative path: ``role_path``
    is the directory of the running role, so the target stays inside it. No
    variable may choose the file, because a role parameter, an include parameter
    or an extra variable outranks every fact the role sets (FREES-137).
    """
    target = text.strip()
    if allow_role_path and ROLE_PATH_TARGET.fullmatch(target):
        return None
    if _is_templated(target):
        return "must not be templated, except {{ role_path }}/tasks/<file>"
    if not target.endswith(TASK_FILE_SUFFIXES):
        return "must end in .yml or .yaml"
    if target.startswith(("/", "~")):
        return "must be a relative path"
    if ".." in target.split("/"):
        return "must not contain '..'"
    return None


def _node_path_problem(node: yaml.Node, *, allow_role_path: bool) -> str | None:
    """Return why the task file named by ``node`` may not be scanned, or ``None``."""
    if not isinstance(node, yaml.ScalarNode):
        return "must end in .yml or .yaml"
    return _path_problem(str(node.value), allow_role_path=allow_role_path)


def _role_name_problem(node: yaml.Node | str) -> str | None:
    """Return why a role name cannot be checked statically, or ``None``.

    A templated name selects a role at run time, and a path (``/srv/role`` or
    ``../role``) loads a role from outside the repository, so only plain and fully
    qualified role names are accepted.
    """
    text = node if isinstance(node, str) else _node_text(node)
    if _is_templated(text):
        return "must not be templated"
    if isinstance(node, yaml.Node) and not isinstance(node, yaml.ScalarNode):
        return "must be a plain or fully qualified role name"
    if ROLE_NAME.fullmatch(text.strip()) is None:
        return "must be a plain or fully qualified role name"
    return None


def _include_findings(
    key: yaml.ScalarNode, value: yaml.Node, name: str
) -> Iterable[tuple[yaml.Node, str]]:
    """Yield findings for an included task or playbook file that the check cannot scan.

    The included file is itself a task file or a playbook, so its target must be
    a file the check scans (:func:`_path_problem`).
    """
    if isinstance(value, yaml.MappingNode):
        targets = [inner for field, _, inner in _scalar_items(value) if field in INCLUDE_FILE_KEYS]
    else:
        targets = [value]
    if not targets:
        yield key, f"{name} needs a file name ending in .yml or .yaml"
    for target in targets:
        problem = _node_path_problem(target, allow_role_path=True)
        if problem is not None:
            yield target, f"{name} target {problem}: {_node_text(target)!r}"


def _free_form_role_findings(value: yaml.ScalarNode, name: str) -> Iterable[str]:
    """Yield findings for the free-form ``key=value`` string of a role include."""
    text = str(value.value)
    if _is_templated(text):
        yield f"{name} arguments must not be templated: {text!r}"
        return
    for word in text.split():
        field, separator, entry = word.partition("=")
        if not separator:
            continue
        if field in ROLE_ENTRY_POINT_KEYS:
            problem = _path_problem(entry, allow_role_path=False)
            if problem is not None:
                yield f"{name} {field} {problem}: {entry!r}"
        elif field == ROLE_NAME_KEY:
            problem = _role_name_problem(entry)
            if problem is not None:
                yield f"{name} role name {problem}: {entry!r}"


def _role_include_findings(value: yaml.Node, name: str) -> Iterable[tuple[yaml.Node, str]]:
    """Yield findings for a role or role entry point that the check cannot scan.

    Without a suffix Ansible also tries ``.json`` and the bare name, which the
    check never scans, so ``tasks_from`` and ``handlers_from`` need ``.yml`` or
    ``.yaml``, and they may not be templated, absolute or walk up. The role name
    must be a plain or fully qualified name (:func:`_role_name_problem`). The
    default entry point is ``main``; a repository test keeps every file below a
    ``tasks`` or ``handlers`` directory a YAML file. The free-form ``key=value``
    string is checked word by word.
    """
    if isinstance(value, yaml.ScalarNode):
        yield from ((value, message) for message in _free_form_role_findings(value, name))
    elif isinstance(value, yaml.MappingNode):
        for field, _, inner in _scalar_items(value):
            if field in ROLE_ENTRY_POINT_KEYS:
                problem = _node_path_problem(inner, allow_role_path=False)
                if problem is not None:
                    yield inner, f"{name} {field} {problem}: {_node_text(inner)!r}"
            elif field == ROLE_NAME_KEY:
                problem = _role_name_problem(inner)
                if problem is not None:
                    yield inner, f"{name} role name {problem}: {_node_text(inner)!r}"


def _play_role_findings(value: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield findings for the ``roles`` of a play whose names cannot be checked."""
    if not isinstance(value, yaml.SequenceNode):
        return
    for item in value.value:
        if isinstance(item, yaml.MappingNode):
            names = [
                inner for field, _, inner in _scalar_items(item) if field in PLAY_ROLE_NAME_KEYS
            ]
        else:
            names = [item]
        for node in names:
            problem = _role_name_problem(node)
            if problem is not None:
                yield node, f"role name in roles {problem}: {_node_text(node)!r}"


def _task_findings(task: yaml.MappingNode) -> Iterable[tuple[yaml.Node, str]]:
    """Yield the findings for one mapping that Ansible may load as a play or a task.

    Only the keys of the mapping itself can name the module of a task. Their
    values are module parameters or keyword data (``vars``, ``set_fact``
    arguments, ``loop`` items, ``module_defaults``) and are not inspected, except
    for ``action`` and ``local_action``, the file names of includes and
    the role names of role includes and of the ``roles`` of a play. A templated
    key could name any module at run time and is denied.
    """
    for name, key, value in _scalar_items(task):
        module = _module_name(name.strip())
        if _is_templated(name):
            yield key, f"templated task key is not allowed: {key.value!r}"
        elif module in BANNED_MODULES:
            yield key, f"banned module: {key.value!r}"
        elif name in ACTION_KEYS:
            yield from _action_findings(value)
        elif module in TASK_INCLUDE_MODULES:
            yield from _include_findings(key, value, name)
        elif module in ROLE_INCLUDE_MODULES:
            yield from _role_include_findings(value, name)
        elif name == PLAY_ROLES_KEY:
            yield from _play_role_findings(value)


def _task_mappings(root: yaml.Node) -> Iterable[yaml.MappingNode]:
    """Yield every mapping that Ansible may load as a play or a task below ``root``.

    ``root`` is a task list: the top-level sequence of a playbook or task file.
    Every mapping in a task list is treated as both a play and a task, and the
    task lists of plays (``tasks``, ``pre_tasks``, ``post_tasks``, ``handlers``)
    and of blocks (``block``, ``rescue``, ``always``) are followed to any depth,
    through aliases and merge keys. A task list that is a mapping instead of a
    sequence, and a sequence nested in a task list, are treated as tasks too,
    which fails safe.
    """
    seen: set[int] = set()
    pending: list[yaml.Node] = [root]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            pending.extend(reversed(node.value))
        elif isinstance(node, yaml.MappingNode):
            yield node
            pending.extend(
                value for name, _, value in _scalar_items(node) if name in TASK_LIST_KEYS
            )


def _walk_nodes(root: yaml.Node) -> Iterable[yaml.Node]:
    """Yield every distinct node below ``root`` without following alias cycles."""
    seen: set[int] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                pending.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)


def _anywhere_findings(root: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield findings for banned module keys, action values and redirects at any depth.

    A ``redirect`` to a banned module (``plugin_routing`` in ``meta/runtime.yml``)
    would make an allowed-looking name an alias of that module, so it is denied.
    """
    for node in _walk_nodes(root):
        if not isinstance(node, yaml.MappingNode):
            continue
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode):
                continue
            if _is_banned(str(key.value)):
                yield key, f"banned module: {key.value!r}"
            elif key.value in ACTION_KEYS:
                yield from _action_findings(value)
            elif (
                key.value == REDIRECT_KEY
                and isinstance(value, yaml.ScalarNode)
                and _is_banned(str(value.value))
            ):
                yield value, f"redirect to a banned module: {value.value!r}"


def _banned_findings(root: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield each banned-module finding of one YAML document once.

    A document whose root is a sequence may be a playbook or a task file: every
    role ``tasks/`` and ``handlers/`` file and every included file is one. Only the
    keys of its plays and tasks name modules, so only they are checked. A
    document with any other root can never be loaded as plays or tasks; it stays
    checked deny-by-default for banned keys and action values at any depth.
    """
    findings: Iterable[tuple[yaml.Node, str]]
    if isinstance(root, yaml.SequenceNode):
        findings = (finding for task in _task_mappings(root) for finding in _task_findings(task))
    else:
        findings = _anywhere_findings(root)
    reported: set[tuple[int, str]] = set()
    for node, message in findings:
        if (id(node), message) not in reported:
            reported.add((id(node), message))
            yield node, message


def _invalid_yaml(path: Path, error: yaml.YAMLError) -> Violation:
    """Describe a YAML error as a violation at the line the parser reports."""
    mark = getattr(error, "problem_mark", None)
    line = 1 if mark is None else int(mark.line) + 1
    return Violation(path, line, f"invalid YAML: {error}")


def check_banned_modules(path: Path, text: str) -> list[Violation]:
    """Reject banned command-execution modules and report unparsable YAML."""
    violations: list[Violation] = []
    try:
        loader = yaml.SafeLoader(text)
    except yaml.YAMLError as error:
        return [_invalid_yaml(path, error)]
    try:
        loader.check_node()
        for document in iter(loader.get_node, None):
            violations.extend(
                Violation(path, node.start_mark.line + 1, message)
                for node, message in _banned_findings(document)
            )
    except yaml.YAMLError as error:
        violations.append(_invalid_yaml(path, error))
    finally:
        loader.dispose()
    return violations
