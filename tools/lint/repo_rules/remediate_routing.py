"""The routing of ``meta/runtime.yml`` that the module rule reads (FREES-203, ADR 0032 §1).

A fully qualified name of this collection is not proof of the code that runs, because
``meta/runtime.yml`` can route the name before Ansible looks for a file. :func:`is_routed` tells
the module rule of :mod:`tools.lint.repo_rules.remediate_modules` whether a module of the
collection may be routed elsewhere, and :func:`check_runtime_routing` refuses every routing entry
for modules, action plugins and ``module_utils`` that is not in a form the rule reads, and every
``import_redirection``. Routing of the other plugin types (filters, tests, lookups and the rest)
is not read: Jinja plugins are outside the module rule and are left to review (ADR 0033).
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

import yaml

from tools.lint.repo_rules.ansible_tasks import scalar_items
from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

RUNTIME_FILE: Final[Path] = Path("meta/runtime.yml")
ROUTING_KEY: Final[str] = "plugin_routing"
ROUTING_SECTIONS: Final[tuple[str, ...]] = ("modules", "action")
ROUTING_NOTES: Final[frozenset[str]] = frozenset({"deprecation"})
ROUTING_CHANGES: Final[frozenset[str]] = frozenset({"redirect", "tombstone"})
CHECKED_ROUTING: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "modules": ROUTING_CHANGES | ROUTING_NOTES,
        "action": ROUTING_CHANGES | ROUTING_NOTES,
        "module_utils": ROUTING_NOTES,
    }
)
IMPORT_REDIRECTION_KEY: Final[str] = "import_redirection"
RUNTIME_PARTS: Final[tuple[str, str]] = ("meta", "runtime.yml")

ROUTING_ENTRY_MESSAGE: Final[str] = (
    "plugin_routing.{section}.{name}.{field} is not allowed in meta/runtime.yml: the module rule "
    "of roles/remediate reads only redirect, tombstone and deprecation for modules and action "
    "plugins and deprecation for module_utils, and any other entry may run other code under "
    "this collection's names (ADR 0032 §1)"
)
ROUTING_SHAPE_MESSAGE: Final[str] = (
    "{place} must be a mapping in meta/runtime.yml: the module rule of roles/remediate cannot "
    "read routing of another shape (ADR 0032 §1)"
)
IMPORT_REDIRECTION_MESSAGE: Final[str] = (
    "import_redirection is not allowed in meta/runtime.yml: it sends Python imports of this "
    "collection to other code, which the module rule of roles/remediate does not check "
    "(ADR 0032 §1)"
)


def as_mapping(value: object) -> dict[object, object]:
    """Return ``value`` when it is a mapping, else an empty mapping."""
    return cast("dict[object, object]", value) if isinstance(value, dict) else {}


def read_yaml(path: Path) -> object:
    """Return the YAML document of ``path``; raise ``ValueError`` when it cannot be read."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError(str(path)) from error


def is_routed(root: Path, module: str) -> bool:
    """Return whether ``meta/runtime.yml`` below ``root`` may send ``module`` elsewhere.

    Any entry for the module or action plugin other than ``deprecation`` counts (``redirect``,
    ``tombstone``, ``action_plugin`` and every key that a later ansible-core may add), and so
    does a file that cannot be read or parsed or whose document is not a mapping, because
    Ansible's routing is then unknown. A missing file routes nothing.
    """
    path = root / RUNTIME_FILE
    if not path.exists():
        return False
    try:
        loaded = read_yaml(path)
    except ValueError:
        return True
    if loaded is None:
        return False
    if not isinstance(loaded, dict):
        return True
    routing = as_mapping(cast("dict[object, object]", loaded).get(ROUTING_KEY))
    return any(
        as_mapping(as_mapping(routing.get(section)).get(module)).keys() - ROUTING_NOTES
        for section in ROUTING_SECTIONS
    )


def is_runtime_file(relative: Path | None) -> bool:
    """Return whether ``relative`` is the collection's ``meta/runtime.yml``, case-folded."""
    return relative is not None and tuple(part.casefold() for part in relative.parts) == (
        RUNTIME_PARTS
    )


def _routing_section_problems(
    section: str, entries: yaml.Node, fields: frozenset[str]
) -> Iterable[tuple[yaml.Node, str]]:
    """Yield every entry of one ``plugin_routing`` section that the module rule does not read."""
    if not isinstance(entries, yaml.MappingNode):
        yield entries, ROUTING_SHAPE_MESSAGE.format(place=f"plugin_routing.{section}")
        return
    for name, key, entry in scalar_items(entries):
        if not isinstance(entry, yaml.MappingNode):
            yield key, ROUTING_SHAPE_MESSAGE.format(place=f"plugin_routing.{section}.{name}")
            continue
        for field, field_key, _ in scalar_items(entry):
            if field not in fields:
                yield (
                    field_key,
                    ROUTING_ENTRY_MESSAGE.format(section=section, name=name, field=field),
                )


def _runtime_problems(document: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield every routing of a ``meta/runtime.yml`` document that the module rule cannot judge."""
    if not isinstance(document, yaml.MappingNode):
        return
    for name, key, value in scalar_items(document):
        if name == IMPORT_REDIRECTION_KEY:
            yield key, IMPORT_REDIRECTION_MESSAGE
        elif name == ROUTING_KEY:
            if not isinstance(value, yaml.MappingNode):
                yield key, ROUTING_SHAPE_MESSAGE.format(place=ROUTING_KEY)
                continue
            for section, _, entries in scalar_items(value):
                fields = CHECKED_ROUTING.get(section)
                if fields is not None:
                    yield from _routing_section_problems(section, entries, fields)


def check_runtime_routing(
    path: Path, relative: Path | None, documents: Iterable[yaml.Node]
) -> list[Violation]:
    """Return a violation for every routing of ``meta/runtime.yml`` that the rule cannot judge.

    ansible-core also honours ``action_plugin`` in a module's routing entry (the action plugin
    named there runs instead of ``normal``), a ``redirect`` of ``module_utils`` (AnsiballZ then
    bundles the other collection's file into every module that imports it) and
    ``import_redirection`` (controller imports). The rule accepts only the entries it reads:
    ``redirect``, ``tombstone`` and ``deprecation`` for ``modules`` and ``action``, which make
    :func:`is_routed` refuse the module where the role uses it, and ``deprecation`` for
    ``module_utils``. Routing of the other plugin types (filters, tests, lookups) is not read.
    """
    if not is_runtime_file(relative):
        return []
    return sorted(
        {
            Violation(path, node.start_mark.line + 1, problem)
            for document in documents
            for node, problem in _runtime_problems(document)
        }
    )
