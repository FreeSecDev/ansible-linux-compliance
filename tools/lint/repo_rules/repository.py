"""Apply the rule groups of the repository guard to files by suffix and location."""

from __future__ import annotations

import io
import tokenize
from typing import TYPE_CHECKING

from tools.lint.repo_rules.ansible_tasks import check_banned_modules
from tools.lint.repo_rules.common import (
    COMPILED_MODULE_SUFFIXES,
    PYTHON_SUFFIXES,
    REPO_ROOT,
    YAML_SUFFIXES,
    Violation,
)
from tools.lint.repo_rules.imports import file_io_import_findings
from tools.lint.repo_rules.isolation import check_process_isolation, is_process_scope
from tools.lint.repo_rules.load_config import (
    EXECUTED_YAML_DIRECTORY,
    configuration_text_findings,
    configured_load_directories,
    is_configuration_text,
    yaml_setting_findings,
)
from tools.lint.repo_rules.load_locations import (
    load_location,
    location_findings,
    python_findings,
    repository_path,
)
from tools.lint.repo_rules.names import FILE_IO_IMPORTERS, SHEBANG_PREFIX
from tools.lint.repo_rules.yaml_text import check_document_start, check_yaml_comments

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
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


def check_file(
    path: Path,
    root: Path = REPO_ROOT,
    configured: frozenset[Path] | None = None,
    index: Mapping[Path, str] | None = None,
) -> list[Violation]:
    """Apply every rule that matches the suffix and location of ``path``.

    A compiled module (an extension module or bytecode) is refused wherever it is,
    without being read: the import system loads it before, or instead of, a ``.py``
    source of the same name, so it would run code that no rule has seen (FREES-153).
    The location rules then apply to every file, and a symbolic link is never read
    through. ``configured`` holds the load directories that an ``ansible.cfg`` names;
    without it they are looked up for ``path`` alone (FREES-156). ``index`` maps
    repository paths to their Git index mode, so a link or executable bit that only the
    index records is refused too.
    """
    suffix = path.suffix.lower()
    if suffix in COMPILED_MODULE_SUFFIXES:
        return [
            Violation(
                path,
                1,
                f"compiled module file ({suffix}) is not allowed: the import system loads it "
                "before or instead of the Python source",
            )
        ]
    relative = repository_path(path, root)
    if configured is None:
        configured = configured_load_directories((path,), root)
    violations = (
        []
        if relative is None
        else location_findings(path, relative, configured, (index or {}).get(relative))
    )
    readable = suffix in YAML_SUFFIXES | PYTHON_SUFFIXES or is_configuration_text(path)
    if path.is_symlink() or not readable:
        return violations
    try:
        data = path.read_bytes()
    except OSError as error:
        return [*violations, Violation(path, 1, f"cannot read file: {error}")]
    if suffix in PYTHON_SUFFIXES:
        return [*violations, *_python_violations(path, root, data, relative, configured)]
    if suffix not in YAML_SUFFIXES:
        return [*violations, *configuration_text_findings(path, data)]
    return [*violations, *_yaml_violations(path, data, relative)]


def _yaml_violations(path: Path, data: bytes, relative: Path | None) -> list[Violation]:
    """Apply the document-start, comment, banned-module and load-path rules to YAML."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [Violation(path, 1, f"file is not valid UTF-8: {error}")]
    executed = relative is not None and relative.parts[:1] == (EXECUTED_YAML_DIRECTORY,)
    return [
        *check_document_start(path, text),
        *check_yaml_comments(path, text),
        *check_banned_modules(path, text),
        *yaml_setting_findings(path, text, executed=executed),
    ]


def _python_violations(
    path: Path, root: Path, data: bytes, relative: Path | None, configured: frozenset[Path]
) -> list[Violation]:
    """Apply the comment, shebang, module-style and, in scope, deny-by-default rules.

    The deny-by-default rules apply to plugin code and to every Python file in a load
    location, which is refused there as well (FREES-156).
    """
    violations = [*check_python_comments(path, data), *python_findings(path, relative, data)]
    in_load_location = relative is not None and load_location(relative, configured) is not None
    if is_process_scope(path, root) or in_load_location:
        location = path.resolve().relative_to(root.resolve())
        violations.extend(check_process_isolation(path, data, location))
        if location not in FILE_IO_IMPORTERS:
            violations.extend(file_io_import_findings(path, data))
    return violations


def check_paths(
    paths: Iterable[Path], root: Path = REPO_ROOT, index: Mapping[Path, str] | None = None
) -> list[Violation]:
    """Check every path and return the violations in sorted order.

    The load directories that an ``ansible.cfg`` names are looked up once for all paths.
    """
    files = list(paths)
    configured = configured_load_directories(files, root)
    return sorted(
        violation for path in files for violation in check_file(path, root, configured, index)
    )
