"""Every file that Ansible may load as a task, handler or metadata of ``roles/remediate`` is read.

The module rule of ADR 0032 §1 (:mod:`tools.lint.repo_rules.remediate_modules`) reads the YAML task
lists of ``roles/remediate``, and Ansible loads more files of a role than those. ``_load_role_yaml``
of ansible-core looks for the ``tasks``, ``handlers`` and ``meta`` entry point ``main`` as
``main.yml``, ``main.yaml``, ``main.json`` and ``main`` without a suffix, and a ``tasks_from`` or
``handlers_from`` of the caller loads any file below ``tasks/`` or ``handlers/`` by its exact name,
whatever its suffix. ``DataLoader`` reads each of them as JSON first and decrypts a vaulted file,
so a ``.yml`` file that PyYAML cannot read (JSON indented with tabs) or whose document is a vault
scalar still runs its tasks.

:func:`role_file_findings` therefore fails closed for every file below ``roles/remediate/tasks/``,
``handlers/`` and ``meta/``, at any depth and case-folded: it must have a ``.yml`` or ``.yaml``
suffix and be YAML that PyYAML reads, and each of its documents must be empty or have the root that
Ansible needs there, a sequence of tasks or a metadata mapping. Every task and handler that the
role can run is then in a document that the module rule reads. A file that is also JSON is read by
``AnsibleJSONDecoder``, which replaces any mapping that holds a load marker (``__ansible_unsafe``,
``__ansible_vault``, ``__ansible_type``) with the value it decodes, so PyYAML and Ansible would see
different tasks; a key that starts with ``__ansible_`` is refused at any depth of these files. The
role's ``vars/`` and ``defaults/`` hold variables, not tasks (``vars_from`` and ``defaults_from``
load variables only).
A handler of the role runs when a task notifies its name or a topic that it listens to, and it is
read like any task; a handler that the playbook defines is the playbook's code and out of scope,
like its tasks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.common import YAML_SUFFIXES, Violation
from tools.lint.repo_rules.remediate_modules import REMEDIATE_ROLE

if TYPE_CHECKING:
    from pathlib import Path

TASK_LIST_DIRECTORIES: Final[frozenset[str]] = frozenset({"tasks", "handlers"})
METADATA_DIRECTORY: Final[str] = "meta"
ROLE_LOAD_DIRECTORIES: Final[frozenset[str]] = TASK_LIST_DIRECTORIES | {METADATA_DIRECTORY}
NULL_TAG: Final[str] = "tag:yaml.org,2002:null"
ROLE_FILE_SUFFIX_MESSAGE: Final[str] = (
    "file {name!r} is not allowed in roles/remediate/{directory}/: only .yml and .yaml files may "
    "be there, because Ansible also loads main.json, main without a suffix and, in tasks/ and "
    "handlers/, any file that tasks_from or handlers_from names, and the rule reads only YAML "
    "files (ADR 0032 §1)"
)
ROLE_FILE_UNREADABLE_MESSAGE: Final[str] = (
    "file {name!r} in roles/remediate/{directory}/ cannot be read as YAML ({error}): Ansible reads "
    "it as JSON first, so it may still load it, and the rule cannot check it (ADR 0032 §1)"
)
ROLE_FILE_ROOT_MESSAGE: Final[str] = (
    "a document of roles/remediate/{directory}/ must be empty or {expected}: Ansible loads "
    "{loaded} from it, and a vaulted or other scalar document hides it from the rule (ADR 0032 §1)"
)
LOAD_MARKER_PREFIX: Final[str] = "__ansible_"
LOAD_MARKER_MESSAGE: Final[str] = (
    "key {key!r} is not allowed in roles/remediate/{directory}/: ansible-core's JSON loader "
    "replaces a mapping that holds a key such as __ansible_unsafe, __ansible_vault or "
    "__ansible_type with the value it decodes, so the rule would read another task than the one "
    "Ansible runs (ADR 0032 §1)"
)
TASK_LIST_ROOT: Final[str] = "a sequence of tasks"
METADATA_ROOT: Final[str] = "a mapping"
TASK_LIST_LOADED: Final[str] = "tasks or handlers"
METADATA_LOADED: Final[str] = "the role metadata, whose dependencies run other roles"


def role_load_directory(relative: Path | None) -> str | None:
    """Return ``tasks``, ``handlers`` or ``meta`` for a file below that directory of the role.

    The names are compared case-folded, as in
    :func:`~tools.lint.repo_rules.remediate_modules.is_remediate_file`; any other file gives
    ``None``.
    """
    if relative is None or len(relative.parts) < len(REMEDIATE_ROLE) + 2:
        return None
    parts = tuple(part.casefold() for part in relative.parts)
    directory = parts[len(REMEDIATE_ROLE)]
    if parts[: len(REMEDIATE_ROLE)] != REMEDIATE_ROLE or directory not in ROLE_LOAD_DIRECTORIES:
        return None
    return directory


def _is_empty(document: yaml.Node) -> bool:
    """Return whether ``document`` is the null document, which Ansible loads as nothing."""
    return isinstance(document, yaml.ScalarNode) and document.tag == NULL_TAG


def _marker_keys(document: yaml.Node) -> list[yaml.ScalarNode]:
    """Return every scalar key below ``document`` that starts with ``LOAD_MARKER_PREFIX``.

    Aliases are followed once, so a cycle ends.
    """
    found: list[yaml.ScalarNode] = []
    seen: set[int] = set()
    pending: list[yaml.Node] = [document]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if isinstance(key, yaml.ScalarNode) and str(key.value).startswith(
                    LOAD_MARKER_PREFIX
                ):
                    found.append(key)
                pending.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)
    return found


def _compose(text: str) -> list[yaml.Node]:
    """Return every document of ``text``; raise ``yaml.YAMLError`` when PyYAML cannot read it."""
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        return list(iter(loader.get_node, None))
    finally:
        loader.dispose()


def role_file_findings(path: Path, relative: Path | None, data: bytes) -> list[Violation]:
    """Refuse a file of the role that Ansible may load as tasks, handlers or metadata unread.

    ``relative`` is the repository path of ``path`` and ``data`` its content. A file below
    ``roles/remediate/tasks/``, ``handlers/`` or ``meta/`` must have a ``.yml`` or ``.yaml``
    suffix, must be UTF-8 YAML that PyYAML composes, and each document must be empty or a sequence
    (``tasks``, ``handlers``) or a mapping (``meta``), and no key may start with ``__ansible_``.
    Other files give no finding.
    """
    directory = role_load_directory(relative)
    if directory is None:
        return []
    if path.suffix.lower() not in YAML_SUFFIXES:
        return [
            Violation(path, 1, ROLE_FILE_SUFFIX_MESSAGE.format(name=path.name, directory=directory))
        ]
    try:
        documents = _compose(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        message = ROLE_FILE_UNREADABLE_MESSAGE.format(
            name=path.name, directory=directory, error=type(error).__name__
        )
        return [Violation(path, 1, message)]
    tasks = directory in TASK_LIST_DIRECTORIES
    expected: type[yaml.Node] = yaml.SequenceNode if tasks else yaml.MappingNode
    message = ROLE_FILE_ROOT_MESSAGE.format(
        directory=directory,
        expected=TASK_LIST_ROOT if tasks else METADATA_ROOT,
        loaded=TASK_LIST_LOADED if tasks else METADATA_LOADED,
    )
    violations = [
        Violation(path, document.start_mark.line + 1, message)
        for document in documents
        if not isinstance(document, expected) and not _is_empty(document)
    ]
    violations.extend(
        Violation(
            path,
            key.start_mark.line + 1,
            LOAD_MARKER_MESSAGE.format(key=key.value, directory=directory),
        )
        for document in documents
        for key in _marker_keys(document)
    )
    return violations
