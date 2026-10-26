"""Name, attribute, call and definition rules for Python files under ``plugins/``."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from tools.lint.repo_rules.imports import import_findings
from tools.lint.repo_rules.names import (
    BANNED_KEYWORDS,
    BANNED_MODULE_ATTRIBUTES,
    BANNED_NAMES,
    DUNDER,
    DUNDER_READS,
    DYNAMIC_ATTRIBUTE_BUILTINS,
    FILE_IO_MODULE,
    FUNCTIONS,
    OS_MODULE,
    POST_INIT,
    PROTECTED_NAMES,
    RESERVED_SEAM_ATTRIBUTES,
    SETATTR_ARGUMENTS,
    SUBMODULE_ATTRIBUTES,
    SUPER_ARGUMENTS,
    SUPER_DUNDERS,
)
from tools.lint.repo_rules.python_scope import binding_names, is_banned_attribute, is_private
from tools.lint.repo_rules.seams import (
    class_binding_findings,
    is_foreign_seam_attribute,
    is_forwarded,
    is_seam_attribute,
    seam_attribute_findings,
    seam_definition_findings,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from tools.lint.repo_rules.python_scope import Scope


def _dynamic_attribute_findings(node: ast.Call, name: str, scope: Scope) -> Iterable[str]:
    """Yield descriptions for ``getattr`` style calls with an unsafe target or name."""
    attribute = node.args[1] if len(node.args) > 1 else None
    if not (isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
        yield "getattr, setattr and delattr need a literal attribute name"
    elif attribute.value == FILE_IO_MODULE and not scope.fileio_attribute_allowed:
        yield f"attribute {FILE_IO_MODULE!r} is restricted to ledger.py"
    elif attribute.value in scope.reserved:
        yield f"attribute {attribute.value!r} is restricted to {scope.reserved[attribute.value]}"
    elif is_banned_attribute(attribute.value) or (
        attribute.value in BANNED_MODULE_ATTRIBUTES and scope.is_module_rooted(node.args[0])
    ):
        yield f"attribute {attribute.value!r} is not allowed in plugins"
    elif DUNDER.fullmatch(attribute.value):
        if name != "getattr" or attribute.value not in DUNDER_READS:
            yield f"dunder attribute {attribute.value!r} is not allowed in plugins"
    elif is_private(attribute.value) and not scope.is_own(node.args[0]):
        yield f"underscore-prefixed attribute {attribute.value!r} of another object is not allowed"
    if name != "getattr" and node.args and scope.is_imported(node.args[0]):
        yield f"{name} on an imported module is not allowed in plugins"
    literal = str(attribute.value) if isinstance(attribute, ast.Constant) else ""
    if is_foreign_seam_attribute(literal, scope) or (
        name != "getattr" and is_seam_attribute(literal, scope)
    ):
        yield f"the seam attribute {literal!r} may not be used with {name}"


def _call_findings(node: ast.Call, scope: Scope) -> Iterable[str]:
    """Yield descriptions for forbidden keywords and dynamic attribute access."""
    for keyword in node.keywords:
        if keyword.arg is None:
            yield "dict splat (**) in a call is not allowed in plugins"
        if keyword.arg in BANNED_KEYWORDS and not is_forwarded(keyword, node, scope):
            yield f"keyword {keyword.arg!r} is not allowed in plugins"
        if (
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
        ):
            yield "shell=True is forbidden"
    if isinstance(node.func, ast.Name) and node.func.id in DYNAMIC_ATTRIBUTE_BUILTINS:
        yield from _dynamic_attribute_findings(node, node.func.id, scope)


def _name_findings(node: ast.Name, scope: Scope) -> Iterable[str]:
    """Yield descriptions for banned builtins and for uses of ``os`` other than ``os.path``."""
    if node.id in BANNED_NAMES:
        yield f"use of {node.id} is not allowed in plugins"
    if node.id in DYNAMIC_ATTRIBUTE_BUILTINS and id(node) not in scope.call_targets:
        yield f"{node.id} may only be called directly"
    permitted = scope.os_path_bases | scope.restricted_bases
    if node.id == OS_MODULE and id(node) not in permitted:
        yield "os may only be used as os.path in plugins"
    if node.id in scope.restricted and node.id != OS_MODULE and id(node) not in permitted:
        yield f"{node.id} may only be used through its permitted attributes in plugins"
    parent = scope.parents.get(id(node))
    if node.id in scope.modules and not (
        isinstance(parent, ast.Attribute)
        and parent.value is node
        and isinstance(node.ctx, ast.Load)
    ):
        yield f"module name {node.id!r} may only be used as {node.id}.attribute in plugins"


def _is_guarded_store(node: ast.Attribute, scope: Scope) -> bool:
    """Return whether ``node`` is the allowed ``object.__setattr__`` form."""
    call = scope.parents.get(id(node))
    if not (
        isinstance(call, ast.Call)
        and call.func is node
        and node.attr == "__setattr__"
        and isinstance(node.value, ast.Name)
        and node.value.id == "object"
        and len(call.args) == SETATTR_ARGUMENTS
        and not call.keywords
    ):
        return False
    target, field = call.args[0], call.args[1]
    method = scope.own_method(target)
    return (
        method is not None
        and isinstance(target, ast.Name)
        and target.id == "self"
        and method.name == POST_INIT
        and next((a for a in scope.ancestors(call) if isinstance(a, FUNCTIONS)), None) is method
        and isinstance(field, ast.Constant)
        and isinstance(field.value, str)
        and not is_banned_attribute(field.value)
        and DUNDER.fullmatch(field.value) is None
        and field.value not in RESERVED_SEAM_ATTRIBUTES
    )


def _is_restricted_attribute(node: ast.Attribute, scope: Scope) -> bool:
    """Return whether ``node`` is one of the permitted attributes of a restricted module."""
    return isinstance(node.value, ast.Name) and node.attr in scope.restricted.get(
        node.value.id, frozenset()
    )


def _is_attribute_base(node: ast.Attribute, scope: Scope) -> bool:
    """Return whether ``node`` is the value of an enclosing attribute access."""
    parent = scope.parents.get(id(node))
    return isinstance(parent, ast.Attribute) and parent.value is node


def _is_super_call(node: ast.Attribute, scope: Scope) -> bool:
    """Return whether ``node`` calls __init__ or __post_init__ on ``super()``."""
    call = scope.parents.get(id(node))
    receiver = node.value
    if not (
        isinstance(call, ast.Call)
        and call.func is node
        and node.attr in SUPER_DUNDERS
        and isinstance(receiver, ast.Call)
        and isinstance(receiver.func, ast.Name)
        and receiver.func.id == "super"
        and not receiver.keywords
    ):
        return False
    args = receiver.args
    return not args or (
        len(args) == SUPER_ARGUMENTS and isinstance(args[0], ast.Name) and scope.is_own(args[1])
    )


def _attribute_findings(node: ast.Attribute, scope: Scope) -> Iterable[str]:
    """Yield descriptions for banned, dunder, private and imported-module attribute use."""
    if _is_guarded_store(node, scope):
        return
    if is_banned_attribute(node.attr) or (
        node.attr in BANNED_MODULE_ATTRIBUTES and scope.is_module_rooted(node.value)
    ):
        yield f"attribute {node.attr!r} is not allowed in plugins"
    stored = not isinstance(node.ctx, ast.Load)
    if DUNDER.fullmatch(node.attr):
        if not is_banned_attribute(node.attr) and (
            stored or not (node.attr in DUNDER_READS or _is_super_call(node, scope))
        ):
            yield f"dunder attribute {node.attr!r} is not allowed in plugins"
    elif is_private(node.attr) and not scope.is_own(node.value):
        yield f"underscore-prefixed attribute {node.attr!r} of another object is not allowed"
    if stored and scope.is_imported(node.value):
        yield f"assigning attribute {node.attr!r} of an imported module is not allowed in plugins"
    yield from seam_attribute_findings(node, scope)
    if node.attr == FILE_IO_MODULE and not scope.fileio_attribute_allowed:
        yield f"attribute {FILE_IO_MODULE!r} is restricted to ledger.py"
    if node.attr in scope.reserved:
        yield f"attribute {node.attr!r} is restricted to {scope.reserved[node.attr]}"
    if (
        node.attr in SUBMODULE_ATTRIBUTES
        and scope.is_module_rooted(node.value)
        and not _is_attribute_base(node, scope)
        and not _is_restricted_attribute(node, scope)
    ):
        yield f"module {node.attr!r} may only be used as {node.attr}.attribute in plugins"


def _definition_findings(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, scope: Scope
) -> Iterable[str]:
    """Yield a description for a module-level ``__getattr__`` definition."""
    if node.name == "__getattr__" and scope.at_module_level(node):
        yield "module-level __getattr__ is not allowed in plugins"


def _declaration_findings(node: ast.Global | ast.Nonlocal, scope: Scope) -> Iterable[str]:
    """Yield a description for each module name that ``node`` declares global or nonlocal."""
    for name in node.names:
        if name in scope.modules:
            yield f"module name {name!r} may not be declared global or nonlocal in plugins"


def _binding_findings(node: ast.AST) -> Iterable[str]:
    """Yield a description for each protected builtin name that ``node`` binds."""
    for name in PROTECTED_NAMES.intersection(binding_names(node)):
        yield f"the name {name!r} may not be rebound in plugins"


def _pattern_findings(node: ast.MatchClass, scope: Scope) -> Iterable[str]:
    """Yield a description for each reserved name that a class pattern reads as a keyword."""
    for name in node.kwd_attrs:
        if name in scope.reserved:
            yield f"attribute {name!r} is restricted to {scope.reserved[name]}"
        if is_foreign_seam_attribute(name, scope):
            yield f"the seam attribute {name!r} is reserved for the file that defines the seam"


def node_findings(node: ast.AST, scope: Scope, extra: frozenset[str]) -> Iterable[str]:
    """Yield a description for each forbidden construct on ``node`` itself."""
    yield from _binding_findings(node)
    yield from seam_definition_findings(node, scope)
    yield from class_binding_findings(node, scope)
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        yield from import_findings(node, extra, frozenset(scope.restricted), scope.reserved)
    elif isinstance(node, ast.Name):
        yield from _name_findings(node, scope)
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        yield from _declaration_findings(node, scope)
    elif isinstance(node, ast.Attribute):
        yield from _attribute_findings(node, scope)
    elif isinstance(node, ast.Subscript):
        if not isinstance(node.ctx, ast.Load) and scope.is_imported(node.value):
            yield "assigning an item of an imported module attribute is not allowed in plugins"
    elif isinstance(node, ast.Call):
        yield from _call_findings(node, scope)
    elif isinstance(node, ast.MatchClass):
        yield from _pattern_findings(node, scope)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        yield from _definition_findings(node, scope)
