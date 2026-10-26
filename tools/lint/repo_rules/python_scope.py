"""Facts about one parsed plugin file that the per-node Python rules share."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tools.lint.repo_rules.common import REPO_ROOT
from tools.lint.repo_rules.names import (
    ANSIBLE_PACKAGES,
    BANNED_ATTRIBUTE_PREFIXES,
    BANNED_ATTRIBUTES,
    COLLECTION_PREFIX,
    DUNDER,
    EXEC_FAMILY,
    OWN_NAMES,
    SUBMODULE_ATTRIBUTES,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path


def is_banned_attribute(name: str) -> bool:
    """Return whether ``name`` is a banned attribute, banned prefix or ``exec`` family name."""
    return (
        name in BANNED_ATTRIBUTES
        or name.startswith(BANNED_ATTRIBUTE_PREFIXES)
        or EXEC_FAMILY.fullmatch(name) is not None
    )


def is_private(name: str, *, include_dunder: bool = False) -> bool:
    """Return whether ``name`` starts with an underscore; dunders only on request."""
    if not name.startswith("_"):
        return False
    return include_dunder or DUNDER.fullmatch(name) is None


def binding_names(node: ast.AST) -> Iterable[str]:
    """Yield every name that ``node`` binds, rebinds or deletes."""
    if isinstance(node, ast.Name):
        if not isinstance(node.ctx, ast.Load):
            yield node.id
    elif isinstance(node, ast.arg):
        yield node.arg
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        yield from (alias.asname or alias.name.split(".")[0] for alias in node.names)
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        yield from node.names
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        yield node.name
    elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        yield from (node.name,) if node.name else ()
    elif isinstance(node, ast.MatchMapping):
        yield from (node.rest,) if node.rest else ()


def shadows(
    function: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda, argument: ast.arg
) -> bool:
    """Return whether ``function`` rebinds, deletes or shadows its parameter ``argument``."""
    return any(
        argument.arg in binding_names(node)
        for node in ast.walk(function)
        if node is not argument and node is not function
    )


def _rebinds(method: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    """Return whether ``method`` rebinds, deletes or shadows its first parameter ``name``."""
    first = [*method.args.posonlyargs, *method.args.args][0]
    return any(
        name in binding_names(node)
        for node in ast.walk(method)
        if node is not first and node is not method
    )


@dataclass(frozen=True, slots=True)
class Scope:
    """Facts about one parsed module that the per-node checks need."""

    call_targets: set[int]
    os_path_bases: set[int]
    imported: frozenset[str]
    modules: frozenset[str]
    parents: dict[int, ast.AST]
    restricted: Mapping[str, frozenset[str]]
    restricted_bases: set[int]
    fileio_attribute_allowed: bool
    reserved: Mapping[str, str]
    seams: frozenset[str]

    def ancestors(self, node: ast.AST) -> Iterable[ast.AST]:
        """Yield the parents of ``node``, nearest first."""
        current = self.parents.get(id(node))
        while current is not None:
            yield current
            current = self.parents.get(id(current))

    def own_method(self, node: ast.expr) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """Return the method whose never rebound first parameter ``node`` names, if any."""
        if not (isinstance(node, ast.Name) and node.id in OWN_NAMES):
            return None
        for ancestor in self.ancestors(node):
            if not isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [*ancestor.args.posonlyargs, *ancestor.args.args]
            if (
                isinstance(self.parents.get(id(ancestor)), ast.ClassDef)
                and params
                and params[0].arg == node.id
                and not any(
                    isinstance(d, ast.Name) and d.id == "staticmethod"
                    for d in ancestor.decorator_list
                )
                and not _rebinds(ancestor, node.id)
            ):
                return ancestor
        return None

    def is_own(self, node: ast.expr) -> bool:
        """Return whether ``node`` is the intact ``self`` or ``cls`` parameter of a method."""
        return self.own_method(node) is not None

    def at_module_level(self, node: ast.AST) -> bool:
        """Return whether no function or class encloses ``node``."""
        return not any(
            isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            for ancestor in self.ancestors(node)
        )

    def is_module_rooted(self, node: ast.expr) -> bool:
        """Return whether ``node`` is an attribute chain rooted in a module-bound name."""
        current = node
        while isinstance(current, ast.Attribute):
            current = current.value
        return isinstance(current, ast.Name) and current.id in self.modules

    def is_imported(self, node: ast.expr) -> bool:
        """Return whether ``node`` is rooted in a name that an import statement binds."""
        current = node
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            current = current.value
        return isinstance(current, ast.Name) and current.id in self.imported


def bound_names(nodes: Iterable[ast.AST]) -> frozenset[str]:
    """Return every name that an import statement binds."""
    names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            names.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(a.asname or a.name for a in node.names)
    return frozenset(names)


def _module_exists(base: Path) -> bool:
    return base.with_suffix(".py").is_file() or (base / "__init__.py").is_file()


def _imports_module(node: ast.ImportFrom, name: str, path: Path) -> bool:
    """Return whether ``from module import name`` binds a module."""
    module = node.module or ""
    if node.level:
        base = path.resolve().parent
        for _ in range(node.level - 1):
            base = base.parent
        return _module_exists(base.joinpath(*filter(None, module.split(".")), name))
    if name in SUBMODULE_ATTRIBUTES:
        return True
    full = f"{module}.{name}"
    if module == COLLECTION_PREFIX or module.startswith(COLLECTION_PREFIX + "."):
        return _module_exists(
            REPO_ROOT.joinpath(*full.split(".")[len(COLLECTION_PREFIX.split(".")) :])
        )
    return module in ANSIBLE_PACKAGES and name.islower()


def module_names(nodes: Iterable[ast.AST], path: Path) -> frozenset[str]:
    """Return every name that an import statement binds to a module."""
    names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            names.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(
                a.asname or a.name for a in node.names if _imports_module(node, a.name, path)
            )
    return frozenset(names)


def restricted_bases(
    nodes: Iterable[ast.AST], restricted: Mapping[str, frozenset[str]]
) -> set[int]:
    """Return the ids of module names used as the base of a permitted attribute."""
    return {
        id(node.value)
        for node in nodes
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.attr in restricted.get(node.value.id, frozenset())
    }
