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
import bisect
import io
import re
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

import yaml

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

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
