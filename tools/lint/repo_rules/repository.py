"""Apply the rule groups of the repository guard to files by suffix and location."""

from __future__ import annotations

import io
import tokenize
from typing import TYPE_CHECKING

from tools.lint.repo_rules.ansible_tasks import check_banned_modules
from tools.lint.repo_rules.common import PYTHON_SUFFIXES, REPO_ROOT, YAML_SUFFIXES, Violation
from tools.lint.repo_rules.imports import file_io_import_findings
from tools.lint.repo_rules.isolation import check_process_isolation, is_process_scope
from tools.lint.repo_rules.names import FILE_IO_IMPORTERS, SHEBANG_PREFIX
from tools.lint.repo_rules.yaml_text import check_document_start, check_yaml_comments

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path


def check_python_comments(path: Path, data: bytes) -> list[Violation]:
    """Reject every Python comment except a shebang on the first line."""
    violations: list[Violation] = []
    try:
        for token in tokenize.tokenize(io.BytesIO(data).readline):
            if token.type != tokenize.COMMENT:
                continue
            line = token.start[0]
            if line == 1 and token.string.startswith(SHEBANG_PREFIX):
                continue
            violations.append(Violation(path, line, f"comment is not allowed: {token.string!r}"))
    except (tokenize.TokenError, SyntaxError, UnicodeDecodeError) as error:
        violations.append(Violation(path, 1, f"cannot tokenize Python: {error}"))
    return violations


def check_file(path: Path, root: Path = REPO_ROOT) -> list[Violation]:
    """Apply every rule that matches the suffix and location of ``path``."""
    suffix = path.suffix.lower()
    if suffix not in YAML_SUFFIXES | PYTHON_SUFFIXES:
        return []
    try:
        data = path.read_bytes()
    except OSError as error:
        return [Violation(path, 1, f"cannot read file: {error}")]
    if suffix in PYTHON_SUFFIXES:
        violations = check_python_comments(path, data)
        if is_process_scope(path, root):
            relative = path.resolve().relative_to(root.resolve())
            violations.extend(check_process_isolation(path, data, relative))
            if relative not in FILE_IO_IMPORTERS:
                violations.extend(file_io_import_findings(path, data))
        return violations
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [Violation(path, 1, f"file is not valid UTF-8: {error}")]
    return [
        *check_document_start(path, text),
        *check_yaml_comments(path, text),
        *check_banned_modules(path, text),
    ]


def check_paths(paths: Iterable[Path], root: Path = REPO_ROOT) -> list[Violation]:
    """Check every path and return the violations in sorted order."""
    return sorted(violation for path in paths for violation in check_file(path, root))
