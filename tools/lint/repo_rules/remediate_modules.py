"""Remediation runs only reviewed modules (FREES-203, ADR 0032 §1).

ADR 0032 §1 widens ADR 0003 and ADR 0025 §1: a task of ``roles/remediate`` may use an
``ansible.builtin`` module, a module or action plugin of this collection, or a module of a community
collection that is on ``ALLOWED_COMMUNITY_MODULES``. The allow list starts empty, so a module such
as ``community.general.make`` or ``ansible.posix.at`` is refused because it is not listed, not
because of a deny entry. Adding a module to the list needs the security review that ADR 0032 §1
describes, in the same pull request.

The rule reads every YAML document below ``roles/remediate/`` whose root is a sequence, which is how
a task or handler file looks, and follows its tasks and blocks with
:func:`~tools.lint.repo_rules.ansible_tasks.task_mappings`, through aliases and merge keys. A key of
a task that is not a keyword of ``TASK_KEYWORDS`` and does not start with ``with_`` names the
module, and so do the first word of an ``action`` or ``local_action`` string and the ``module`` key
of their mapping form. Such a name must be the fully qualified name of an ``ansible.builtin``
module, of a ``freesecdev.linux_compliance`` module or of an allow-listed module: a short name, an
``ansible.legacy`` name and a templated name are refused, because Ansible may resolve them to any
module. A document with another root, such as ``vars/rules.yml`` or ``meta/argument_specs.yml``, is
not a task list and is not read.

An allow-listed module is accepted only while its collection is pinned at one exact version
(``<major>.<minor>.<patch>``) in ``galaxy.yml`` ``dependencies``, in
``extensions/molecule/requirements.yml`` and in ``extensions/molecule/collections.pins``. Files
outside ``roles/remediate`` (Molecule scenarios, test playbooks and the other roles) are not in
scope; the banned modules of :mod:`tools.lint.repo_rules.ansible_tasks` apply to them as before.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml

from tools.lint.repo_rules.ansible_tasks import (
    ACTION_KEYS,
    TEMPLATE_MARKERS,
    action_modules,
    scalar_items,
    task_mappings,
)
from tools.lint.repo_rules.common import REPO_ROOT, YAML_SUFFIXES, Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

ALLOWED_COMMUNITY_MODULES: Final[frozenset[str]] = frozenset()
REMEDIATE_ROLE: Final[tuple[str, str]] = ("roles", "remediate")
TASK_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "action",
        "always",
        "any_errors_fatal",
        "args",
        "async",
        "async_val",
        "become",
        "become_exe",
        "become_flags",
        "become_method",
        "become_user",
        "block",
        "changed_when",
        "check_mode",
        "collections",
        "connection",
        "debugger",
        "delay",
        "delegate_facts",
        "delegate_to",
        "diff",
        "environment",
        "failed_when",
        "ignore_errors",
        "ignore_unreachable",
        "listen",
        "loop",
        "loop_control",
        "loop_with",
        "module_defaults",
        "name",
        "no_log",
        "notify",
        "poll",
        "port",
        "register",
        "remote_user",
        "rescue",
        "retries",
        "run_once",
        "tags",
        "throttle",
        "timeout",
        "until",
        "vars",
        "when",
    }
)
LOOP_PREFIX: Final[str] = "with_"
OWN_MODULE: Final[re.Pattern[str]] = re.compile(
    r"(?:ansible\.builtin|freesecdev\.linux_compliance)\.[a-z_][a-z0-9_]*"
)
COMMUNITY_MODULE: Final[re.Pattern[str]] = re.compile(
    r"(?P<collection>[a-z0-9][a-z0-9_]*\.[a-z0-9][a-z0-9_]*)\.[a-z_][a-z0-9_]*"
)
EXACT_VERSION: Final[re.Pattern[str]] = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
PIN_LINE: Final[re.Pattern[str]] = re.compile(
    r"collection (?P<name>\S+) (?P<version>\S+) [0-9a-f]{64} [0-9]+"
)
GALAXY_FILE: Final[Path] = Path("galaxy.yml")
REQUIREMENTS_FILE: Final[Path] = Path("extensions/molecule/requirements.yml")
PINS_FILE: Final[Path] = Path("extensions/molecule/collections.pins")
DEPENDENCIES_KEY: Final[str] = "dependencies"
COLLECTIONS_KEY: Final[str] = "collections"
NAME_KEY: Final[str] = "name"
VERSION_KEY: Final[str] = "version"

MODULE_MESSAGE: Final[str] = (
    "module {name!r} is not allowed in roles/remediate: use an ansible.builtin or "
    "freesecdev.linux_compliance module by its fully qualified name, or a community module on the "
    "allow list (ADR 0032 §1)"
)
TEMPLATED_MESSAGE: Final[str] = (
    "templated module name {name!r} is not allowed in roles/remediate: the module must be known "
    "before the run (ADR 0032 §1)"
)
PIN_MESSAGE: Final[str] = (
    "allow-listed module {name!r} needs its collection {collection} pinned at one exact version "
    "in galaxy.yml dependencies, extensions/molecule/requirements.yml and "
    "extensions/molecule/collections.pins; found {versions} (ADR 0032 §1)"
)


def is_remediate_file(relative: Path | None) -> bool:
    """Return whether ``relative`` is a YAML file below ``roles/remediate/``.

    The directory names are compared case-folded, because macOS and Windows controllers ignore
    case.
    """
    if relative is None or relative.suffix.lower() not in YAML_SUFFIXES:
        return False
    return tuple(part.casefold() for part in relative.parts[:2]) == REMEDIATE_ROLE


def _is_keyword(name: str) -> bool:
    return name in TASK_KEYWORDS or name.startswith(LOOP_PREFIX)


def _module_names(task: yaml.MappingNode) -> Iterable[tuple[yaml.Node, str]]:
    """Yield the node and text of every name that ``task`` may run as a module.

    That is every key that is not a keyword, the first word of an ``action`` or ``local_action``
    string and every ``module`` key of their mapping form.
    """
    for name, key, value in scalar_items(task):
        if name in ACTION_KEYS:
            for module in action_modules(value):
                words = str(module.value).split(maxsplit=1)
                yield module, words[0] if words else ""
        elif not _is_keyword(name):
            yield key, name


def _mapping(value: object) -> dict[object, object]:
    """Return ``value`` when it is a mapping, else an empty mapping."""
    return cast("dict[object, object]", value) if isinstance(value, dict) else {}


def _load_mapping(path: Path) -> dict[object, object]:
    """Return the YAML mapping of ``path``, or an empty one when it cannot be read or parsed."""
    try:
        loaded: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return {}
    return _mapping(loaded)


def _galaxy_versions(root: Path, collection: str) -> list[object]:
    """Return the versions that ``galaxy.yml`` ``dependencies`` gives ``collection``."""
    dependencies = _mapping(_load_mapping(root / GALAXY_FILE).get(DEPENDENCIES_KEY))
    return [dependencies[collection]] if collection in dependencies else []


def _requirements_versions(root: Path, collection: str) -> list[object]:
    """Return the version of every entry for ``collection`` in the Molecule requirements."""
    entries = _load_mapping(root / REQUIREMENTS_FILE).get(COLLECTIONS_KEY)
    if not isinstance(entries, list):
        return []
    mappings = [_mapping(entry) for entry in cast("list[object]", entries)]
    return [entry.get(VERSION_KEY) for entry in mappings if entry.get(NAME_KEY) == collection]


def _pinned_versions(root: Path, collection: str) -> list[object]:
    """Return the version of every line for ``collection`` in the collection pins."""
    try:
        lines = (root / PINS_FILE).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    matches = (PIN_LINE.fullmatch(line) for line in lines)
    return [
        match.group(VERSION_KEY)
        for match in matches
        if match is not None and match.group(NAME_KEY) == collection
    ]


def pin_sources(collection: str, root: Path = REPO_ROOT) -> dict[str, list[object]]:
    """Return, for each of the three pin files, every version it gives ``collection``."""
    return {
        str(GALAXY_FILE): _galaxy_versions(root, collection),
        str(REQUIREMENTS_FILE): _requirements_versions(root, collection),
        str(PINS_FILE): _pinned_versions(root, collection),
    }


def pinned_version(sources: Mapping[str, Sequence[object]]) -> str | None:
    """Return the one exact version that every pin file of ``sources`` gives, or ``None``.

    Each file must name the collection once, with a ``<major>.<minor>.<patch>`` string, and the
    three versions must be equal.
    """
    if any(len(entries) != 1 for entries in sources.values()):
        return None
    versions = [entries[0] for entries in sources.values()]
    first = versions[0]
    if not isinstance(first, str) or EXACT_VERSION.fullmatch(first) is None:
        return None
    return first if all(version == first for version in versions) else None


def _name_problem(name: str, allowed: frozenset[str], root: Path) -> str | None:
    """Return why ``name`` may not run in ``roles/remediate``, or ``None`` when it may."""
    if any(marker in name for marker in TEMPLATE_MARKERS):
        return TEMPLATED_MESSAGE.format(name=name)
    if OWN_MODULE.fullmatch(name) is not None:
        return None
    match = COMMUNITY_MODULE.fullmatch(name)
    if name not in allowed or match is None:
        return MODULE_MESSAGE.format(name=name)
    collection = match.group("collection")
    sources = pin_sources(collection, root)
    if pinned_version(sources) is None:
        return PIN_MESSAGE.format(name=name, collection=collection, versions=sources)
    return None


def check_remediate_modules(
    path: Path,
    relative: Path | None,
    documents: Iterable[yaml.Node],
    *,
    allowed: frozenset[str] = ALLOWED_COMMUNITY_MODULES,
    root: Path = REPO_ROOT,
) -> list[Violation]:
    """Return a violation for every module a task of ``roles/remediate`` may not run.

    ``documents`` are the composed YAML documents of ``path``; ``relative`` is its repository
    path. ``allowed`` is the allow list and ``root`` the repository whose pin files are read.
    """
    if not is_remediate_file(relative):
        return []
    violations: set[Violation] = set()
    for document in documents:
        if not isinstance(document, yaml.SequenceNode):
            continue
        for task in task_mappings(document):
            for node, name in _module_names(task):
                problem = _name_problem(name, allowed, root)
                if problem is not None:
                    violations.add(Violation(path, node.start_mark.line + 1, problem))
    return sorted(violations)
