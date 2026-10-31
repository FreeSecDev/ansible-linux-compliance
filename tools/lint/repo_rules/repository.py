"""Apply the rule groups of the repository guard to files by suffix and location."""

from __future__ import annotations

import io
import tokenize
from typing import TYPE_CHECKING

import yaml

from tools.lint.repo_rules.ansible_tasks import check_banned_modules
from tools.lint.repo_rules.common import (
    COMPILED_MODULE_SUFFIXES,
    PYTHON_SUFFIXES,
    REPO_ROOT,
    YAML_SUFFIXES,
    Violation,
)
from tools.lint.repo_rules.exec_config import config_file_findings, molecule_config_findings
from tools.lint.repo_rules.exec_modules import module_parameter_findings
from tools.lint.repo_rules.exec_targets import target_findings
from tools.lint.repo_rules.exec_variables import (
    is_inventory_text,
    text_setting_findings,
    yaml_variable_findings,
)
from tools.lint.repo_rules.imports import file_io_import_findings
from tools.lint.repo_rules.isolation import check_process_isolation, is_process_scope
from tools.lint.repo_rules.jinja_calls import is_template_file, yaml_jinja_findings
from tools.lint.repo_rules.load_config import (
    EXECUTED_YAML_DIRECTORY,
    MOLECULE_FILE_NAMES,
    configuration_text_findings,
    configured_load_directories,
    is_config_file,
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
from tools.lint.repo_rules.own_remediation import own_remediation_findings
from tools.lint.repo_rules.rendered_files import NUL, rendered_file_findings
from tools.lint.repo_rules.yaml_text import check_document_start, check_yaml_comments

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path

JSON_SUFFIX: str = ".json"
VARIABLE_DIRECTORIES: frozenset[str] = frozenset({"vars", "defaults"})


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
    if path.is_symlink() or not _is_readable(path, relative):
        return violations
    try:
        data = path.read_bytes()
    except OSError as error:
        return [*violations, Violation(path, 1, f"cannot read file: {error}")]
    if suffix in PYTHON_SUFFIXES:
        found = _python_violations(path, root, data, relative, configured)
    elif suffix in YAML_SUFFIXES:
        found = _yaml_violations(path, data, relative)
    else:
        found = _text_violations(path, data, relative)
    rendered = [
        violation
        for violation in _rendered_violations(path, data, relative)
        if violation not in found
    ]
    own = own_remediation_findings(path, relative, data)
    return [*violations, *found, *rendered, *own]


def _is_executed(relative: Path | None) -> bool:
    """Return whether ``relative`` is below ``.github/``, whose YAML GitHub runs, not Ansible."""
    return relative is not None and relative.parts[:1] == (EXECUTED_YAML_DIRECTORY,)


def _is_readable(path: Path, relative: Path | None) -> bool:
    """Return whether a rule reads ``path``.

    That is YAML, Python and configuration text anywhere, and every file of the repository
    outside ``.github/``, which Ansible could render as a template (FREES-159).
    """
    if path.suffix.lower() in YAML_SUFFIXES | PYTHON_SUFFIXES or is_configuration_text(path):
        return True
    return relative is not None and not _is_executed(relative)


def _rendered_violations(path: Path, data: bytes, relative: Path | None) -> list[Violation]:
    """Read a repository file outside ``.github/`` as the template Ansible could render it as.

    A file that Ansible may also load value by value (a template or vars location, inventory
    text, ``.json``) is checked strictly; YAML is checked value by value by the YAML rules.
    """
    if relative is None or _is_executed(relative):
        return []
    suffix = path.suffix.lower()
    strict = suffix not in YAML_SUFFIXES and (
        is_template_file(relative) or is_inventory_text(relative) or suffix == JSON_SUFFIX
    )
    return rendered_file_findings(path, data, strict=strict)


def _text_violations(path: Path, data: bytes, relative: Path | None) -> list[Violation]:
    """Apply the rules for configuration text, template files and inventory text (FREES-159)."""
    violations: list[Violation] = []
    if is_configuration_text(path):
        violations.extend(configuration_text_findings(path, data))
        if is_config_file(path):
            text = data.decode("utf-8", errors="replace")
            violations.extend(config_file_findings(path, text))
        else:
            violations.extend(text_setting_findings(path, relative, data))
    elif relative is not None and is_inventory_text(relative):
        violations.extend(text_setting_findings(path, relative, data))
    if relative is not None and not _is_executed(relative) and _is_variable_file(relative):
        violations.extend(_variable_file_violations(path, data, relative))
    return sorted(set(violations))


def _is_variable_file(relative: Path) -> bool:
    """Return whether Ansible may load ``relative`` as YAML variables or inventory.

    A ``.json`` file, and a file without a suffix in an inventory, ``host_vars``,
    ``group_vars``, ``vars`` or ``defaults`` directory.
    """
    if relative.suffix.lower() == JSON_SUFFIX:
        return True
    parents = {part.casefold() for part in relative.parts[:-1]}
    return not relative.suffix and (
        is_inventory_text(relative) or bool(parents & VARIABLE_DIRECTORIES)
    )


def _variable_file_violations(path: Path, data: bytes, relative: Path) -> list[Violation]:
    """Read a ``.json`` or extensionless file as the YAML that Ansible loads it as (FREES-159).

    ``include_vars``, the ``host_group_vars`` plugin and the ``yaml`` inventory plugin load
    such files as YAML, and JSON is YAML, so their values and keys get the YAML rules. A file
    that is not YAML is still read as a template by ``rendered_file_findings``.
    """
    if NUL in data:
        return []
    documents = _documents(data.decode("utf-8", errors="replace"))
    return [
        *yaml_jinja_findings(path, documents),
        *yaml_variable_findings(path, relative, documents),
    ]


def _documents(text: str) -> list[yaml.Node]:
    """Compose every document of ``text``; unparsable YAML is reported by the other rules."""
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        return list(iter(loader.get_node, None))
    except yaml.YAMLError:
        return []
    finally:
        loader.dispose()


def _yaml_violations(path: Path, data: bytes, relative: Path | None) -> list[Violation]:
    """Apply the document-start, comment, banned-module and load-path rules to YAML."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [Violation(path, 1, f"file is not valid UTF-8: {error}")]
    executed = _is_executed(relative)
    documents = _documents(text)
    violations = [
        *check_document_start(path, text),
        *check_yaml_comments(path, text),
        *check_banned_modules(path, text),
        *yaml_setting_findings(path, text, executed=executed),
        *module_parameter_findings(path, documents, relative),
        *target_findings(path, relative, documents),
        *yaml_variable_findings(path, relative, documents),
    ]
    if not executed:
        violations.extend(yaml_jinja_findings(path, documents))
    if path.name.casefold() in MOLECULE_FILE_NAMES:
        violations.extend(molecule_config_findings(path, documents))
    return violations


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
