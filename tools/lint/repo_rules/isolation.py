"""Deny-by-default process isolation of Python files that Ansible loads (ADR 0004)."""

from __future__ import annotations

import ast
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from tools.lint.repo_rules.attributes import node_findings
from tools.lint.repo_rules.common import PLUGINS_DIRECTORY, Violation
from tools.lint.repo_rules.names import (
    EXTRA_IMPORTS,
    FILE_IO_ATTRIBUTES,
    FILE_IO_HELPER,
    LEDGER_MODULE,
    NO_RESTRICTION,
    OS_MODULE,
    OS_PATH,
    PROCESS_HELPER,
    RESERVED_ATTRIBUTES,
    SEAM_OWNERS,
    dotted_parts,
)
from tools.lint.repo_rules.python_scope import (
    Scope,
    bound_names,
    module_names,
    restricted_bases,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


def is_process_scope(path: Path, root: Path) -> bool:
    """Return whether ``path`` is plugin code that may not run processes itself.

    ``check_file`` also applies the rules to every Python file in a load location.
    """
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return relative.parts[:1] == (PLUGINS_DIRECTORY,) and relative != PROCESS_HELPER


def _reserved_for(extra_imports: frozenset[str]) -> Mapping[str, str]:
    """Return the reserved attribute names that a file with ``extra_imports`` may not use."""
    owned = dotted_parts(extra_imports)
    return MappingProxyType(
        {name: owner for name, owner in RESERVED_ATTRIBUTES.items() if name not in owned}
    )


def check_process_isolation(
    path: Path, data: bytes, relative: Path | None = None
) -> list[Violation]:
    """Reject, by default, anything in plugin code that could run a process.

    Only allow-listed imports are accepted, ``exec``, ``eval``, ``compile`` and
    ``__import__`` are banned, ``os`` is usable only as ``os.path``, attribute
    names that run or spawn processes are banned wherever they appear, and
    ``getattr`` style calls need a literal, permitted attribute name.
    ``relative`` is the path of the file in the repository. It selects the
    allowances of that one file: its ``EXTRA_IMPORTS``, the ``FILE_IO_ATTRIBUTES``
    of the file-I/O helper, the ``fileio`` attribute of the ledger and the test
    seams of ``SEAM_OWNERS`` that it may define and forward unchanged.
    """
    location = Path() if relative is None else relative
    restricted = FILE_IO_ATTRIBUTES if location == FILE_IO_HELPER else NO_RESTRICTION
    extra_imports = EXTRA_IMPORTS.get(location, frozenset()) | frozenset(restricted)
    try:
        tree = ast.parse(data, filename=str(path))
    except (SyntaxError, ValueError) as error:
        return [Violation(path, 1, f"cannot parse Python: {error}")]
    nodes = list(ast.walk(tree))
    call_targets = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
    os_path_bases = {
        id(node.value)
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr == OS_PATH
        and isinstance(node.value, ast.Name)
        and node.value.id == OS_MODULE
    }
    scope = Scope(
        call_targets,
        os_path_bases,
        bound_names(nodes),
        module_names(nodes, path),
        {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)},
        restricted,
        restricted_bases(nodes, restricted),
        location == LEDGER_MODULE,
        _reserved_for(extra_imports),
        SEAM_OWNERS.get(location, frozenset()),
    )
    return sorted(
        {
            Violation(path, getattr(node, "lineno", 1), message)
            for node in nodes
            for message in node_findings(node, scope, extra_imports)
        }
    )
