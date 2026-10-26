"""YAML text rules: the document-start marker and the comment ban.

A YAML file starts with ``---`` followed by a newline and contains no comments,
except a trailing ``# vX.Y.Z`` version annotation on a ``uses: owner/repo@<40-hex>``
or ``rev: <40-hex>`` line.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, cast

import yaml

from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from pathlib import Path

DOCUMENT_START: Final[str] = "---\n"
VERSION_ANNOTATION: Final[re.Pattern[str]] = re.compile(r"# v\d+\.\d+\.\d+")
PINNED_USES: Final[re.Pattern[str]] = re.compile(
    r"\s*(?:-\s+)?uses:\s+[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}\s*"
)
PINNED_REV: Final[re.Pattern[str]] = re.compile(r"\s*(?:-\s+)?rev:\s+[0-9a-f]{40}\s*")
BLOCK_STYLES: Final[frozenset[str]] = frozenset({"|", ">"})
LINE_BREAK: Final[re.Pattern[str]] = re.compile(r"\r\n|[\n\r\x85\u2028\u2029]")
COMMENT_START: Final[re.Pattern[str]] = re.compile(r"(?:^|(?<=[ \t\r\n\x85\u2028\u2029]))#")


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
