"""Enforce repository-wide source rules on the files passed as arguments.

Rules:

* Every YAML file starts with ``---`` followed by a newline.
* YAML files contain no comments, except a trailing ``# vX.Y.Z`` version
  annotation on a ``uses: owner/repo@<40-hex>`` or ``rev: <40-hex>`` line.
* YAML files contain no banned Ansible command-execution modules.
* Python files contain no comments, except a shebang on the first line.
* Python files under ``plugins/`` are checked deny-by-default: they import only
  allow-listed standard library modules, ``ansible.module_utils`` and this
  collection, never use ``os`` except as ``os.path``, never use ``exec``, ``eval``,
  ``compile`` or ``__import__``, never reference process, fork or ``run_command``
  attributes, never import or name ``subprocess``, ``pty``, ``posix``, ``sys`` or
  ``os`` as an imported name or attribute, never use ``vars``, ``globals``,
  ``locals``, ``__dict__`` or ``get_type_hints``, never pass ``shell=True``,
  ``use_unsafe_shell`` or the test-only ``owner_uid``, ``state_dir``, ``lock_timeout``,
  ``policies``, ``trusted_dirs``, ``runner``, ``clock`` and ``limits`` keywords, never use a ``**``
  dict splat in a call, never use the attribute ``__self__``, and
  only call ``getattr`` with a literal permitted name. ``xml.parsers.expat`` may be imported
  only by ``plugins/module_utils/compliance/openscap.py``. Only
  ``plugins/module_utils/compliance/process.py`` is exempt (ADR 0004).
  ``plugins/module_utils/compliance/fileio.py`` may additionally ``import`` ``os``, ``fcntl``,
  ``errno`` and ``time`` and use only the attributes listed in ``FILE_IO_ATTRIBUTES``, always as
  ``module.attribute``; it keeps every other rule. Only
  ``plugins/module_utils/compliance/ledger.py`` may import ``fileio`` (ADR 0011).

Violations are printed as ``path:line: message`` and the exit status is 1.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import io
import re
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol, cast

import yaml

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

YAML_SUFFIXES: Final[frozenset[str]] = frozenset({".yml", ".yaml"})
PYTHON_SUFFIXES: Final[frozenset[str]] = frozenset({".py"})
DOCUMENT_START: Final[str] = "---\n"
BANNED_MODULES: Final[frozenset[str]] = frozenset(
    {"shell", "command", "raw", "script", "win_shell", "win_command"}
)
COLLECTION_PREFIXES: Final[tuple[str, ...]] = (
    "ansible.builtin.",
    "ansible.legacy.",
    "ansible.windows.",
    "community.windows.",
)
ACTION_KEYS: Final[frozenset[str]] = frozenset({"action", "local_action"})
MODULE_KEY: Final[str] = "module"
VERSION_ANNOTATION: Final[re.Pattern[str]] = re.compile(r"# v\d+\.\d+\.\d+")
PINNED_USES: Final[re.Pattern[str]] = re.compile(
    r"\s*(?:-\s+)?uses:\s+[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}\s*"
)
PINNED_REV: Final[re.Pattern[str]] = re.compile(r"\s*(?:-\s+)?rev:\s+[0-9a-f]{40}\s*")
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
PLUGINS_DIRECTORY: Final[str] = "plugins"
PROCESS_HELPER: Final[Path] = Path("plugins/module_utils/compliance/process.py")
FILE_IO_HELPER: Final[Path] = Path("plugins/module_utils/compliance/fileio.py")
FILE_IO_IMPORTERS: Final[frozenset[Path]] = frozenset(
    {Path("plugins/module_utils/compliance/ledger.py"), FILE_IO_HELPER}
)
FILE_IO_MODULE: Final[str] = "fileio"
FILE_IO_ATTRIBUTES: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "errno": frozenset({"ELOOP", "EMLINK", "ENOTDIR"}),
        "fcntl": frozenset({"flock", "LOCK_EX", "LOCK_NB"}),
        "os": frozenset(
            {
                "O_CLOEXEC",
                "O_CREAT",
                "O_DIRECTORY",
                "O_EXCL",
                "O_NOFOLLOW",
                "O_NONBLOCK",
                "O_RDONLY",
                "O_WRONLY",
                "close",
                "fchmod",
                "fstat",
                "scandir",
                "fsync",
                "mkdir",
                "open",
                "read",
                "rename",
                "stat",
                "supports_dir_fd",
                "unlink",
                "urandom",
                "write",
            }
        ),
        "time": frozenset({"monotonic", "sleep"}),
    }
)
NO_RESTRICTION: Final[Mapping[str, frozenset[str]]] = MappingProxyType({})
ALLOWED_IMPORTS: Final[frozenset[str]] = frozenset(
    {
        "__future__",
        "collections",
        "collections.abc",
        "dataclasses",
        "datetime",
        "enum",
        "functools",
        "hashlib",
        "itertools",
        "json",
        "os.path",
        "pathlib",
        "re",
        "stat",
        "types",
        "typing",
        "unicodedata",
    }
)
EXTRA_IMPORTS: Final[Mapping[Path, frozenset[str]]] = MappingProxyType(
    {Path("plugins/module_utils/compliance/openscap.py"): frozenset({"xml.parsers.expat"})}
)
ALLOWED_IMPORT_PREFIXES: Final[tuple[str, ...]] = (
    "ansible.module_utils",
    "ansible_collections.freesecdev.linux_compliance",
)
MODULE_NAMES: Final[frozenset[str]] = frozenset(
    {"subprocess", "pty", "posix", "_posixsubprocess", "os", "sys"}
)
REFLECTION_NAMES: Final[frozenset[str]] = frozenset({"vars", "globals", "locals", "get_type_hints"})
BANNED_NAMES: Final[frozenset[str]] = (
    frozenset({"exec", "eval", "compile", "__import__", "__builtins__"})
    | REFLECTION_NAMES
    | (MODULE_NAMES - {"os"})
)
DYNAMIC_ATTRIBUTE_BUILTINS: Final[frozenset[str]] = frozenset({"getattr", "setattr", "delattr"})
BANNED_ATTRIBUTES: Final[frozenset[str]] = (
    frozenset(
        {
            "system",
            "popen",
            "run_command",
            "create_subprocess_exec",
            "create_subprocess_shell",
            "Popen",
            "import_module",
            "exec",
            "__import__",
            "__builtins__",
            "__subclasses__",
            "__globals__",
            "__bases__",
            "__base__",
            "__mro__",
            "__code__",
            "__loader__",
            "__dict__",
            "__self__",
        }
    )
    | REFLECTION_NAMES
    | MODULE_NAMES
)
BANNED_ATTRIBUTE_PREFIXES: Final[tuple[str, ...]] = ("spawn", "fork", "posix_spawn", "_create_")
EXEC_FAMILY: Final[re.Pattern[str]] = re.compile(r"f?exec[lv][a-z]*")
BANNED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "use_unsafe_shell",
        "owner_uid",
        "state_dir",
        "lock_timeout",
        "policies",
        "trusted_dirs",
        "runner",
        "clock",
        "limits",
    }
)
OS_MODULE: Final[str] = "os"
OS_PATH: Final[str] = "path"
SHEBANG_PREFIX: Final[str] = "#!"
BLOCK_STYLES: Final[frozenset[str]] = frozenset({"|", ">"})
LINE_BREAK: Final[re.Pattern[str]] = re.compile(r"\r\n|[\n\r\x85\u2028\u2029]")
COMMENT_START: Final[re.Pattern[str]] = re.compile(r"(?:^|(?<=[ \t\r\n\x85\u2028\u2029]))#")


@dataclass(frozen=True, order=True, slots=True)
class Violation:
    """A single rule violation at ``path:line``."""

    path: Path
    line: int
    message: str

    def __str__(self) -> str:
        """Render the violation as ``path:line: message``."""
        return f"{self.path}:{self.line}: {self.message}"


@dataclass(frozen=True, slots=True)
class Comment:
    """A YAML comment with the code that precedes it on the same line."""

    line: int
    code: str
    text: str


class _TokenSource(Protocol):
    """Typed view of the untyped PyYAML scanner interface."""

    def check_token(self) -> bool:
        """Return whether another token is available."""
        ...

    def get_token(self) -> yaml.Token:
        """Consume and return the next token."""
        ...


def _line_breaks(text: str) -> list[tuple[int, int]]:
    """Return the ``(start, end)`` span of every line break in ``text``."""
    return [(match.start(), match.end()) for match in LINE_BREAK.finditer(text)]


def _block_content_start(text: str, indicator: int) -> int:
    """Return the offset of the line that follows the block scalar indicator."""
    match = LINE_BREAK.search(text, indicator)
    return len(text) if match is None else match.end()


def _scalar_spans(text: str) -> list[tuple[int, int]]:
    """Return the character spans that YAML scalars occupy in ``text``.

    The spans come from the PyYAML scanner, so quoted, plain and block scalars
    follow YAML semantics. Block scalar spans start on the line after the
    indicator, which leaves a header comment outside the span. A scanner
    error ends the scan; the spans found so far are returned.
    """
    spans: list[tuple[int, int]] = []
    try:
        loader = yaml.SafeLoader(text)
    except yaml.YAMLError:
        return spans
    source = cast("_TokenSource", loader)
    try:
        while source.check_token():
            token = source.get_token()
            if not isinstance(token, yaml.ScalarToken):
                continue
            start = token.start_mark.index
            if token.style in BLOCK_STYLES:
                start = _block_content_start(text, start)
            spans.append((start, token.end_mark.index))
    except yaml.YAMLError:
        return spans
    finally:
        loader.dispose()
    return spans


def scan_yaml_comments(text: str) -> list[Comment]:
    """Return every YAML comment in ``text``.

    A ``#`` starts a comment when it is at the start of a line or follows
    whitespace and lies outside every scalar span reported by the scanner.
    """
    spans = _scalar_spans(text)
    breaks = _line_breaks(text)
    line_ends = [start for start, _ in breaks]
    line_starts = [0, *(end for _, end in breaks)]
    comments: list[Comment] = []
    for match in COMMENT_START.finditer(text):
        offset = match.start()
        if any(start <= offset < end for start, end in spans):
            continue
        index = bisect.bisect_right(line_starts, offset) - 1
        line_end = line_ends[index] if index < len(line_ends) else len(text)
        comments.append(
            Comment(index + 1, text[line_starts[index] : offset], text[offset:line_end].rstrip())
        )
    return comments


def is_allowed_annotation(comment: Comment) -> bool:
    """Return whether ``comment`` is a permitted version annotation on a pinned line."""
    if VERSION_ANNOTATION.fullmatch(comment.text) is None:
        return False
    return (
        PINNED_USES.fullmatch(comment.code) is not None
        or PINNED_REV.fullmatch(comment.code) is not None
    )


def check_document_start(path: Path, text: str) -> list[Violation]:
    """Require the YAML document-start marker on the first line."""
    if text.startswith(DOCUMENT_START):
        return []
    return [Violation(path, 1, "YAML file must start with '---' followed by a newline")]


def check_yaml_comments(path: Path, text: str) -> list[Violation]:
    """Reject YAML comments other than a version annotation on a pinned line."""
    return [
        Violation(path, comment.line, f"comment is not allowed: {comment.text!r}")
        for comment in scan_yaml_comments(text)
        if not is_allowed_annotation(comment)
    ]


def _module_name(value: str) -> str:
    """Strip a known collection prefix from ``value`` and return the module name."""
    for prefix in COLLECTION_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _is_banned(value: str) -> bool:
    """Return whether ``value`` names a banned module, with or without prefix."""
    return _module_name(value.strip()) in BANNED_MODULES


def _banned_in_action(value: yaml.Node) -> yaml.Node | None:
    """Return the node naming a banned module in an ``action`` style value."""
    if isinstance(value, yaml.ScalarNode):
        words = str(value.value).split(maxsplit=1)
        return value if words and _is_banned(words[0]) else None
    if isinstance(value, yaml.MappingNode):
        for key, inner in value.value:
            if (
                isinstance(key, yaml.ScalarNode)
                and key.value == MODULE_KEY
                and isinstance(inner, yaml.ScalarNode)
                and _is_banned(str(inner.value))
            ):
                return inner
    return None


def _walk_nodes(root: yaml.Node) -> Iterable[yaml.Node]:
    """Yield every distinct node below ``root`` without following alias cycles."""
    seen: set[int] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                pending.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)


def _banned_nodes(root: yaml.Node) -> Iterable[yaml.Node]:
    """Yield nodes that name a banned module as a key or as an action value."""
    for node in _walk_nodes(root):
        if not isinstance(node, yaml.MappingNode):
            continue
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode):
                continue
            key_name = str(key.value)
            if _is_banned(key_name):
                yield key
            elif key_name in ACTION_KEYS:
                offender = _banned_in_action(value)
                if offender is not None:
                    yield offender


def _invalid_yaml(path: Path, error: yaml.YAMLError) -> Violation:
    """Describe a YAML error as a violation at the line the parser reports."""
    mark = getattr(error, "problem_mark", None)
    line = 1 if mark is None else int(mark.line) + 1
    return Violation(path, line, f"invalid YAML: {error}")


def check_banned_modules(path: Path, text: str) -> list[Violation]:
    """Reject banned command-execution modules and report unparsable YAML."""
    violations: list[Violation] = []
    try:
        loader = yaml.SafeLoader(text)
    except yaml.YAMLError as error:
        return [_invalid_yaml(path, error)]
    try:
        loader.check_node()
        for document in iter(loader.get_node, None):
            violations.extend(
                Violation(path, node.start_mark.line + 1, f"banned module: {node.value!r}")
                for node in _banned_nodes(document)
                if isinstance(node, yaml.ScalarNode)
            )
    except yaml.YAMLError as error:
        violations.append(_invalid_yaml(path, error))
    finally:
        loader.dispose()
    return violations


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


def is_process_scope(path: Path, root: Path) -> bool:
    """Return whether ``path`` is plugin code that may not run processes itself."""
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return relative.parts[:1] == (PLUGINS_DIRECTORY,) and relative != PROCESS_HELPER


def _is_banned_attribute(name: str) -> bool:
    return (
        name in BANNED_ATTRIBUTES
        or name.startswith(BANNED_ATTRIBUTE_PREFIXES)
        or EXEC_FAMILY.fullmatch(name) is not None
    )


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
        if alias.asname and (_is_banned_attribute(alias.asname) or alias.asname in BANNED_NAMES):
            yield f"import under the name {alias.asname!r} is not allowed in plugins"


def _plain_import_findings(
    node: ast.Import, extra: frozenset[str], restricted: frozenset[str]
) -> Iterable[str]:
    """Yield a description for each ``import x`` name that is not allow-listed."""
    for alias in node.names:
        if not _is_allowed_import(alias.name, extra):
            yield _not_allowed(alias.name)
        elif alias.name in restricted and alias.asname:
            yield f"import of {alias.name!r} under another name is not allowed in plugins"


def _import_findings(
    node: ast.Import | ast.ImportFrom, extra: frozenset[str], restricted: frozenset[str]
) -> Iterable[str]:
    """Yield a description for each import on ``node`` that is not allow-listed."""
    yield from _alias_findings(node)
    if isinstance(node, ast.Import):
        yield from _plain_import_findings(node, extra, restricted)
        return
    module = node.module or ""
    if module in restricted and not node.level and module != OS_MODULE:
        yield f"from-import of {module!r} is not allowed in plugins"
    if not node.level and module != OS_MODULE and not _is_allowed_import(module, extra):
        yield _not_allowed(module)
    for alias in node.names:
        if alias.name == "*":
            yield f"star import from {module!r} is not allowed in plugins"
        elif module == OS_MODULE and not node.level and alias.name != OS_PATH:
            yield _not_allowed(f"os.{alias.name}")
        elif _is_banned_attribute(alias.name):
            yield f"import of {alias.name!r} is not allowed in plugins"


def _dynamic_attribute_findings(node: ast.Call) -> Iterable[str]:
    """Yield descriptions for ``getattr`` style calls with an unsafe attribute name."""
    attribute = node.args[1] if len(node.args) > 1 else None
    if not (isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
        yield "getattr, setattr and delattr need a literal attribute name"
    elif _is_banned_attribute(attribute.value):
        yield f"attribute {attribute.value!r} is not allowed in plugins"


def _call_findings(node: ast.Call) -> Iterable[str]:
    """Yield descriptions for forbidden keywords and dynamic attribute access."""
    for keyword in node.keywords:
        if keyword.arg is None:
            yield "dict splat (**) in a call is not allowed in plugins"
        if keyword.arg in BANNED_KEYWORDS:
            yield f"keyword {keyword.arg!r} is not allowed in plugins"
        if (
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
        ):
            yield "shell=True is forbidden"
    if isinstance(node.func, ast.Name) and node.func.id in DYNAMIC_ATTRIBUTE_BUILTINS:
        yield from _dynamic_attribute_findings(node)


@dataclass(frozen=True)
class _Scan:
    """Facts about one parsed file that the per-node checks share."""

    call_targets: set[int]
    os_path_bases: set[int]
    extra: frozenset[str]
    restricted: Mapping[str, frozenset[str]]
    restricted_bases: set[int]


def _name_findings(node: ast.Name, scan: _Scan) -> Iterable[str]:
    """Yield descriptions for banned builtins and for uses of ``os`` other than ``os.path``."""
    if node.id in BANNED_NAMES:
        yield f"use of {node.id} is not allowed in plugins"
    if node.id in DYNAMIC_ATTRIBUTE_BUILTINS and id(node) not in scan.call_targets:
        yield f"{node.id} may only be called directly"
    permitted = scan.os_path_bases | scan.restricted_bases
    if node.id == OS_MODULE and id(node) not in permitted:
        yield "os may only be used as os.path in plugins"
    if node.id in scan.restricted and node.id != OS_MODULE and id(node) not in permitted:
        yield f"{node.id} may only be used through its permitted attributes in plugins"


def _process_findings(node: ast.AST, scan: _Scan) -> Iterable[str]:
    """Yield a description for each forbidden construct on ``node`` itself."""
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        yield from _import_findings(node, scan.extra, frozenset(scan.restricted))
    elif isinstance(node, ast.Name):
        yield from _name_findings(node, scan)
    elif isinstance(node, ast.Attribute):
        if _is_banned_attribute(node.attr):
            yield f"attribute {node.attr!r} is not allowed in plugins"
    elif isinstance(node, ast.Call):
        yield from _call_findings(node)


def _restricted_bases(
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


def check_process_isolation(
    path: Path,
    data: bytes,
    extra_imports: frozenset[str] = frozenset(),
    restricted: Mapping[str, frozenset[str]] = NO_RESTRICTION,
) -> list[Violation]:
    """Reject, by default, anything in plugin code that could run a process.

    Only allow-listed imports are accepted, ``exec``, ``eval``, ``compile`` and
    ``__import__`` are banned, ``os`` is usable only as ``os.path``, attribute
    names that run or spawn processes are banned wherever they appear, and
    ``getattr`` style calls need a literal, permitted attribute name.
    """
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
    scan = _Scan(
        call_targets,
        os_path_bases,
        extra_imports,
        restricted,
        _restricted_bases(nodes, restricted),
    )
    return sorted(
        {
            Violation(path, getattr(node, "lineno", 1), message)
            for node in nodes
            for message in _process_findings(node, scan)
        }
    )


def _file_io_import_findings(path: Path, data: bytes) -> list[Violation]:
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
            extra = EXTRA_IMPORTS.get(relative, frozenset())
            restricted = FILE_IO_ATTRIBUTES if relative == FILE_IO_HELPER else NO_RESTRICTION
            if restricted:
                extra = extra | frozenset(restricted)
            violations.extend(check_process_isolation(path, data, extra, restricted))
            if relative not in FILE_IO_IMPORTERS:
                violations.extend(_file_io_import_findings(path, data))
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


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Files to check.")
    arguments = parser.parse_args(argv)
    violations = check_paths(arguments.paths)
    for violation in violations:
        print(violation, file=sys.stderr)
    if violations:
        print(f"{len(violations)} repository rule violation(s)", file=sys.stderr)
        return 1
    print(f"repository rules satisfied in {len(arguments.paths)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
