"""Test seam rules for Python files under ``plugins/`` (FREES-137).

A parameter named like a banned keyword (a test seam) must be keyword-only, and
only the files in ``SEAM_OWNERS`` may define one, forward it unchanged and assign
``self._<seam>`` directly in ``__init__``, never from a function nested in it.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from tools.lint.repo_rules.names import (
    BANNED_KEYWORDS,
    CALLABLES,
    DEFINITIONS,
    INIT,
    RESERVED_SEAM_ATTRIBUTES,
    SCOPE_NODES,
)
from tools.lint.repo_rules.python_scope import binding_names, shadows

if TYPE_CHECKING:
    from collections.abc import Iterable

    from tools.lint.repo_rules.python_scope import Scope


def is_seam_attribute(name: str, scope: Scope) -> bool:
    """Return whether ``name`` is the private attribute that holds a seam of this file."""
    return name in RESERVED_SEAM_ATTRIBUTES and name[1:] in scope.seams


def is_foreign_seam_attribute(name: str, scope: Scope) -> bool:
    """Return whether ``name`` holds a seam that another file of ``SEAM_OWNERS`` defines.

    ``_<seam>`` for every banned keyword is reserved: only the owner of the seam
    may name it, so no other plugin can read or set the seam of an owner object
    through a subclass, a class attribute or a method called on another object.
    """
    return name in RESERVED_SEAM_ATTRIBUTES and name[1:] not in scope.seams


def class_binding_findings(node: ast.AST, scope: Scope) -> Iterable[str]:
    """Yield a description for each reserved seam attribute that ``node`` binds in a class body.

    A class attribute named like a seam attribute would be read where the seam is
    expected, so it is denied in every file, the owners included: an owner sets
    the attribute only in ``__init__`` from its keyword-only parameter.
    """
    names = RESERVED_SEAM_ATTRIBUTES.intersection(binding_names(node))
    if not names:
        return
    owner = next((item for item in scope.ancestors(node) if isinstance(item, SCOPE_NODES)), None)
    if isinstance(owner, ast.ClassDef):
        for name in sorted(names):
            yield f"the seam attribute {name!r} may not be bound in a class body"


def seam_definition_findings(node: ast.AST, scope: Scope) -> Iterable[str]:
    """Yield descriptions for test seam parameters that are positional or defined elsewhere.

    A seam that a positional argument can fill would bypass the keyword ban, so
    every seam is keyword-only, and only the files in ``SEAM_OWNERS`` define seams.
    Nodes other than functions and lambdas define no parameters.
    """
    if not isinstance(node, CALLABLES):
        return
    arguments = node.args
    optional = (arguments.vararg, arguments.kwarg)
    for argument in (
        *arguments.posonlyargs,
        *arguments.args,
        *(item for item in optional if item is not None),
    ):
        if argument.arg in BANNED_KEYWORDS:
            yield f"test seam {argument.arg!r} must be a keyword-only parameter"
    for argument in arguments.kwonlyargs:
        if argument.arg in BANNED_KEYWORDS and argument.arg not in scope.seams:
            yield f"test seam {argument.arg!r} may not be defined in this file"


def _forwards_parameter(name: str, call: ast.Call, scope: Scope) -> bool:
    """Return whether the function around ``call`` has an intact keyword-only ``name``."""
    function = next((item for item in scope.ancestors(call) if isinstance(item, CALLABLES)), None)
    if not isinstance(function, CALLABLES):
        return False
    argument = next((item for item in function.args.kwonlyargs if item.arg == name), None)
    return argument is not None and not shadows(function, argument)


def _forwards_attribute(name: str, value: ast.Attribute, scope: Scope) -> bool:
    """Return whether ``value`` is ``self._<name>`` in a class whose ``__init__`` takes ``name``."""
    if not (
        value.attr == f"_{name}" and isinstance(value.value, ast.Name) and value.value.id == "self"
    ):
        return False
    method = scope.own_method(value.value)
    owner = None if method is None else scope.parents.get(id(method))
    return isinstance(owner, ast.ClassDef) and any(
        isinstance(item, DEFINITIONS)
        and item.name == INIT
        and name in {argument.arg for argument in item.args.kwonlyargs}
        for item in owner.body
    )


def is_forwarded(keyword: ast.keyword, call: ast.Call, scope: Scope) -> bool:
    """Return whether ``keyword`` forwards a seam of this file unchanged.

    Only a file in ``SEAM_OWNERS`` may pass its own seams on, and only as
    ``name=name`` from the keyword-only parameter of the enclosing function or as
    ``name=self._name`` in a class whose ``__init__`` takes the keyword-only seam.
    """
    name = str(keyword.arg)
    value = keyword.value
    if name not in scope.seams:
        return False
    if isinstance(value, ast.Name):
        return value.id == name and _forwards_parameter(name, call, scope)
    return isinstance(value, ast.Attribute) and _forwards_attribute(name, value, scope)


def seam_attribute_findings(node: ast.Attribute, scope: Scope) -> Iterable[str]:
    """Yield descriptions for a reserved seam attribute used outside its owner or set late.

    Another file may not name the attribute at all. The owner may read it, and may
    store or delete it only on ``self`` directly in the body of ``__init__``: a
    function or lambda nested in ``__init__`` could run later, so it may not (FREES-153).
    """
    if is_foreign_seam_attribute(node.attr, scope):
        yield f"the seam attribute {node.attr!r} is reserved for the file that defines the seam"
        return
    if isinstance(node.ctx, ast.Load) or not is_seam_attribute(node.attr, scope):
        return
    target = node.value
    method = scope.own_method(target)
    enclosing = next((item for item in scope.ancestors(node) if isinstance(item, CALLABLES)), None)
    if not (
        isinstance(target, ast.Name)
        and target.id == "self"
        and method is not None
        and method.name == INIT
        and enclosing is method
    ):
        yield f"the seam attribute {node.attr!r} may only be assigned to self in __init__"
