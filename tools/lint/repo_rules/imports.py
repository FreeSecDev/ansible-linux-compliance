"""Import rules for Python files under ``plugins/``."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from tools.lint.repo_rules.common import Violation
from tools.lint.repo_rules.names import (
    ALLOWED_IMPORT_PREFIXES,
    ALLOWED_IMPORTS,
    BANNED_NAMES,
    FILE_IO_MODULE,
    OS_MODULE,
    OS_PATH,
    PROCESS_HELPER,
    RESTRICTED_FROM_IMPORTS,
    STDLIB_MODULE_ATTRIBUTES,
)
from tools.lint.repo_rules.python_scope import is_banned_attribute, is_private

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path


def _is_allowed_import(name: str, extra: frozenset[str]) -> bool:
    return (
        name in ALLOWED_IMPORTS
        or name in extra
        or any(
            name == prefix or name.startswith(prefix + ".") for prefix in ALLOWED_IMPORT_PREFIXES
        )
    )


def _not_allowed(name: str) -> str:
    return f"import of {name!r} is not allowed in plugins outside {PROCESS_HELPER}"


def _alias_findings(node: ast.Import | ast.ImportFrom) -> Iterable[str]:
    """Yield a description for each import bound to a banned name with ``as``."""
    for alias in node.names:
        if alias.asname and (is_banned_attribute(alias.asname) or alias.asname in BANNED_NAMES):
            yield f"import under the name {alias.asname!r} is not allowed in plugins"


def _private_import_findings(node: ast.Import | ast.ImportFrom) -> Iterable[str]:
    """Yield a description for each underscore-prefixed module or name that ``node`` imports."""
    if isinstance(node, ast.Import):
        for alias in node.names:
            if any(is_private(part) for part in alias.name.split(".")):
                yield f"import of private module {alias.name!r} is not allowed in plugins"
        return
    module = node.module or ""
    if any(is_private(part) for part in module.split(".")):
        yield f"import from private module {module!r} is not allowed in plugins"
    for alias in node.names:
        if is_private(alias.name, include_dunder=True):
            yield f"import of private name {alias.name!r} is not allowed in plugins"
        elif alias.name in STDLIB_MODULE_ATTRIBUTES:
            yield f"import of module name {alias.name!r} through another module is not allowed"


def _reserved_findings(names: Iterable[str], reserved: Mapping[str, str]) -> Iterable[str]:
    """Yield a description for each name that only another plugin file may import."""
    for name in names:
        if name in reserved:
            yield f"import of {name!r} is restricted to {reserved[name]}"


def _plain_import_findings(
    node: ast.Import,
    extra: frozenset[str],
    restricted: frozenset[str],
    reserved: Mapping[str, str],
) -> Iterable[str]:
    """Yield a description for each ``import x`` name that is not allow-listed."""
    for alias in node.names:
        if alias.name in RESTRICTED_FROM_IMPORTS or not _is_allowed_import(alias.name, extra):
            yield _not_allowed(alias.name)
        elif alias.name in restricted and alias.asname:
            yield f"import of {alias.name!r} under another name is not allowed in plugins"
        else:
            yield from _reserved_findings(alias.name.split("."), reserved)


def import_findings(
    node: ast.Import | ast.ImportFrom,
    extra: frozenset[str],
    restricted: frozenset[str],
    reserved: Mapping[str, str],
) -> Iterable[str]:
    """Yield a description for each import on ``node`` that is not allow-listed."""
    yield from _alias_findings(node)
    yield from _private_import_findings(node)
    if isinstance(node, ast.Import):
        yield from _plain_import_findings(node, extra, restricted, reserved)
        return
    module = node.module or ""
    if module in restricted and not node.level and module != OS_MODULE:
        yield f"from-import of {module!r} is not allowed in plugins"
    if (
        not node.level
        and module != OS_MODULE
        and not _is_allowed_import(module, extra)
        and not all(f"{module}.{alias.name}" in extra for alias in node.names)
    ):
        yield _not_allowed(module)
    else:
        names = [*module.split("."), *(alias.name for alias in node.names)]
        yield from _reserved_findings(names, reserved)
    for alias in node.names:
        if module in RESTRICTED_FROM_IMPORTS and alias.name not in RESTRICTED_FROM_IMPORTS[module]:
            yield _not_allowed(f"{module}.{alias.name}")
        elif alias.name == "*":
            yield f"star import from {module!r} is not allowed in plugins"
        elif module == OS_MODULE and not node.level and alias.name != OS_PATH:
            yield _not_allowed(f"os.{alias.name}")
        elif is_banned_attribute(alias.name) or alias.name in BANNED_NAMES:
            yield f"import of {alias.name!r} is not allowed in plugins"


def file_io_import_findings(path: Path, data: bytes) -> list[Violation]:
    """Reject imports of the file-I/O helper by any file except its sanctioned importers."""
    try:
        tree = ast.parse(data, filename=str(path))
    except (SyntaxError, ValueError):
        return []
    findings: list[Violation] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or "", *(alias.name for alias in node.names)]
        if any(name.split(".")[-1] == FILE_IO_MODULE for name in names):
            findings.append(
                Violation(
                    path,
                    getattr(node, "lineno", 1),
                    f"import of {FILE_IO_MODULE!r} is restricted to ledger.py",
                )
            )
    return findings
