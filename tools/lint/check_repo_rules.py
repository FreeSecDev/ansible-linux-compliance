"""Enforce repository-wide source rules on the files passed as arguments.

Rules:

* Every YAML file starts with ``---`` followed by a newline.
* YAML files contain no comments, except a trailing ``# vX.Y.Z`` version
  annotation on a ``uses: owner/repo@<40-hex>`` or ``rev: <40-hex>`` line.
* YAML files contain no banned Ansible command-execution modules.
* Python files contain no comments, except a shebang on the first line.

Violations are printed as ``path:line: message`` and the exit status is 1.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

YAML_SUFFIXES: Final[frozenset[str]] = frozenset({".yml", ".yaml"})
PYTHON_SUFFIXES: Final[frozenset[str]] = frozenset({".py"})
DOCUMENT_START: Final[str] = "---\n"
BANNED_MODULES: Final[frozenset[str]] = frozenset(
    {"shell", "command", "raw", "script", "win_shell", "win_command"}
)
COLLECTION_PREFIXES: Final[tuple[str, ...]] = ("ansible.builtin.", "ansible.legacy.")
ACTION_KEYS: Final[frozenset[str]] = frozenset({"action", "local_action"})
MODULE_KEY: Final[str] = "module"
VERSION_ANNOTATION: Final[re.Pattern[str]] = re.compile(r"# v\d+\.\d+\.\d+")
PINNED_USES: Final[re.Pattern[str]] = re.compile(
    r"\s*(?:-\s+)?uses:\s+[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}\s*"
)
PINNED_REV: Final[re.Pattern[str]] = re.compile(r"\s*(?:-\s+)?rev:\s+[0-9a-f]{40}\s*")
SEQUENCE_ENTRY: Final[re.Pattern[str]] = re.compile(r"-\s+")
BLOCK_SCALAR_VALUE: Final[re.Pattern[str]] = re.compile(r"(?:[!&]\S*\s+)*[|>][1-9+-]{0,2}")
BLOCK_SCALAR_LINE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[-:?]\s)(?:[!&]\S*\s+)*[|>][1-9+-]{0,2}$"
)
SHEBANG_PREFIX: Final[str] = "#!"
QUOTES: Final[str] = "\"'"
FLOW_OPENERS: Final[str] = "[{"
FLOW_CLOSERS: Final[str] = "]}"
INDICATORS: Final[str] = "-?:"
PROPERTY_MARKERS: Final[str] = "!&"
WHITESPACE: Final[str] = " \t"


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


@dataclass(slots=True)
class _ScanState:
    """Scanner state that carries over from one line to the next."""

    quote: str | None = None
    flow_depth: int = 0


@dataclass(slots=True)
class _LineScan:
    """Scanner cursor for a single line."""

    raw: str
    state: _ScanState
    index: int = 0
    value_start: bool = True

    def advance_in_quote(self) -> None:
        """Consume one character while inside a quoted scalar."""
        character = self.raw[self.index]
        if self.state.quote == '"' and character == "\\":
            self.index += 2
            return
        if (
            self.state.quote == "'"
            and character == "'"
            and self.raw[self.index + 1 : self.index + 2] == "'"
        ):
            self.index += 2
            return
        if character == self.state.quote:
            self.state.quote = None
        self.index += 1

    def skip_property(self) -> None:
        """Skip a tag or anchor token, keeping the scalar-start position."""
        while self.index < len(self.raw) and self.raw[self.index] not in WHITESPACE:
            self.index += 1

    def advance_outside_quote(self) -> None:
        """Consume one token outside quoted scalars."""
        character = self.raw[self.index]
        if character in WHITESPACE:
            self.index += 1
        elif self.value_start and character in PROPERTY_MARKERS:
            self.skip_property()
        elif self.value_start and character in QUOTES:
            self.state.quote = character
            self.value_start = False
            self.index += 1
        elif self.value_start and character in FLOW_OPENERS:
            self.state.flow_depth += 1
            self.index += 1
        elif self.state.flow_depth and character in FLOW_CLOSERS:
            self.state.flow_depth -= 1
            self.value_start = False
            self.index += 1
        elif self.state.flow_depth and character == ",":
            self.value_start = True
            self.index += 1
        else:
            following = self.raw[self.index + 1 : self.index + 2]
            self.value_start = character in INDICATORS and (
                not following or following in WHITESPACE
            )
            self.index += 1

    def comment_column(self) -> int | None:
        """Return the column where a comment starts on this line, if any."""
        self.value_start = self.state.quote is None
        while self.index < len(self.raw):
            if self.state.quote is not None:
                self.advance_in_quote()
            elif self.raw[self.index] == "#" and (
                self.index == 0 or self.raw[self.index - 1] in WHITESPACE
            ):
                return self.index
            else:
                self.advance_outside_quote()
        return None


def _indent(line: str) -> int:
    """Return the number of leading spaces of ``line``."""
    return len(line) - len(line.lstrip(" "))


def _block_parent_indent(code: str) -> int:
    """Return the indentation of the node that owns a block scalar on ``code``."""
    position = _indent(code)
    last_dash: int | None = None
    while (entry := SEQUENCE_ENTRY.match(code, position)) is not None:
        last_dash = position
        position = entry.end()
    if BLOCK_SCALAR_VALUE.fullmatch(code[position:].strip()) is None:
        return position
    return -1 if last_dash is None else last_dash


def scan_yaml_comments(text: str) -> list[Comment]:
    """Return every comment in ``text``, ignoring ``#`` in quotes and block scalars."""
    comments: list[Comment] = []
    state = _ScanState()
    block_parent: int | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        if block_parent is not None:
            if not raw.strip() or _indent(raw) > block_parent:
                continue
            block_parent = None
        column = _LineScan(raw, state).comment_column()
        code = raw if column is None else raw[:column]
        if column is not None:
            comments.append(Comment(number, code, raw[column:].rstrip()))
        if state.quote is None and BLOCK_SCALAR_LINE.search(code.rstrip()) is not None:
            block_parent = _block_parent_indent(code.rstrip())
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


def check_banned_modules(path: Path, text: str) -> list[Violation]:
    """Reject banned command-execution modules and report unparsable YAML."""
    violations: list[Violation] = []
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        for document in iter(loader.get_node, None):
            violations.extend(
                Violation(path, node.start_mark.line + 1, f"banned module: {node.value!r}")
                for node in _banned_nodes(document)
                if isinstance(node, yaml.ScalarNode)
            )
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        line = 1 if mark is None else int(mark.line) + 1
        violations.append(Violation(path, line, f"invalid YAML: {error}"))
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


def check_file(path: Path) -> list[Violation]:
    """Apply every rule that matches the suffix of ``path``."""
    suffix = path.suffix.lower()
    if suffix not in YAML_SUFFIXES | PYTHON_SUFFIXES:
        return []
    try:
        data = path.read_bytes()
    except OSError as error:
        return [Violation(path, 1, f"cannot read file: {error}")]
    if suffix in PYTHON_SUFFIXES:
        return check_python_comments(path, data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return [Violation(path, 1, f"file is not valid UTF-8: {error}")]
    return [
        *check_document_start(path, text),
        *check_yaml_comments(path, text),
        *check_banned_modules(path, text),
    ]


def check_paths(paths: Iterable[Path]) -> list[Violation]:
    """Check every path and return the violations in sorted order."""
    return sorted(violation for path in paths for violation in check_file(path))


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
