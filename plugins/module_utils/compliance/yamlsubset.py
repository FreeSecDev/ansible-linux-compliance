r"""Strict loader for a small, safe subset of YAML.

Target-side code may only use the standard library, which has no YAML parser.
This module reads the subset of YAML that hand-written configuration files such
as the exceptions file need, and rejects everything else instead of guessing.
It runs on Python 3.9 and newer.

Supported:

* One document that starts with a ``---`` line. Blank lines and comment lines
  are ignored; a comment may follow a value after a space.
* Block mappings whose keys are plain identifiers (``[A-Za-z_][A-Za-z0-9_]*``)
  and block sequences, nested at most :data:`MAX_DEPTH` levels. A sequence may
  sit at the same indentation as the key that owns it.
* Plain scalars on one line, single- and double-quoted scalars on one line
  (double quotes support the escapes ``\\``, ``\"``, ``\n``, ``\t`` and
  ``\/``), flow sequences of scalars on one line (``[a, "b"]``) and literal
  (``|``) or folded (``>``) block scalars with optional ``-`` or ``+`` chomping.

Rejected with :class:`YamlSubsetError`, which names the line:

* Duplicate keys, anchors, aliases, tags, directives, flow mappings, explicit
  keys, merge keys, multi-line plain or quoted scalars, several documents, tab
  characters, carriage returns, a byte order mark, control and bidi characters,
  explicit block scalar indentation and more-indented lines in folded scalars.
* Plain scalars that other YAML loaders would not read as strings: booleans
  (``yes``, ``on``, ``true`` and their variants), numbers, ``=`` and keys that
  read as booleans or null. They must be quoted. ``~``, ``null`` and an absent
  value load as ``None``.

Every scalar loads as a string, so an unquoted date stays text. Loaded values
are ``None``, ``str``, ``list`` and ``dict`` only.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final, NoReturn

MAX_DOCUMENT_CHARS: Final[int] = 1024 * 1024
MAX_DEPTH: Final[int] = 8
MAX_SEQUENCE_ITEMS: Final[int] = 10000
DOCUMENT_START: Final[str] = "---"

_KEY_LINE: Final[str] = r"([A-Za-z_][A-Za-z0-9_]*):(?:[ ]+(.*))?"
_BLOCK_HEADER: Final[str] = r"([|>])([+-]?)(?:[ ]+#.*|[ ]*)"
_TRAILER: Final[str] = r"[ ]*(?:[ ]#.*)?"
_NUMBER: Final[str] = (
    r"[-+]?(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][-+]?[0-9]+)?"
    r"|[-+]?0[boxBOX][0-9a-fA-F_]+"
    r"|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?"
    r"|[-+]?\.(?:inf|Inf|INF)"
    r"|\.(?:nan|NaN|NAN)"
)
_NULL_WORDS: Final[frozenset[str]] = frozenset({"~", "null", "Null", "NULL"})
_BOOLEAN_WORDS: Final[frozenset[str]] = frozenset(
    {
        "y",
        "Y",
        "yes",
        "Yes",
        "YES",
        "n",
        "N",
        "no",
        "No",
        "NO",
        "true",
        "True",
        "TRUE",
        "false",
        "False",
        "FALSE",
        "on",
        "On",
        "ON",
        "off",
        "Off",
        "OFF",
    }
)
_RESERVED_PLAIN: Final[frozenset[str]] = _BOOLEAN_WORDS | frozenset({"="})
_INDICATORS: Final[str] = "-?:,[]{}#&*!|>'\"%@`"
_FLOW_PLAIN_FORBIDDEN: Final[str] = ",[]{}#:&*!|>'\"%@`?"
_FLOW_START_FORBIDDEN: Final[str] = _FLOW_PLAIN_FORBIDDEN + "-"
_DOUBLE_ESCAPES: Final[dict[str, str]] = {
    "\\": "\\",
    '"': '"',
    "n": "\n",
    "t": "\t",
    "/": "/",
}
_BIDI_CONTROLS: Final[frozenset[str]] = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\ufeff",
    }
)


class YamlSubsetError(ValueError):
    """Raised when a document is not in the supported YAML subset."""

    def __init__(self, message: str, line: int) -> None:
        """Record the message and the 1-based line number it refers to."""
        super().__init__(f"line {line}: {message}")
        self.line = line


def _raise(message: str, line: int) -> NoReturn:
    raise YamlSubsetError(message, line)


def _require_text(value: object) -> None:
    if not isinstance(value, str):
        _raise("the document must be text", 1)


def _is_sequence_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _resolve(value: str, line: int) -> str | None:
    if value in _NULL_WORDS:
        return None
    if value in _RESERVED_PLAIN or re.fullmatch(_NUMBER, value) is not None:
        _raise(f"the plain value {value[:64]!r} is not read as a string by YAML; quote it", line)
    return value


def _expect_trailer(rest: str, line: int) -> None:
    if re.fullmatch(_TRAILER, rest) is None:
        _raise("unexpected text after a quoted value or flow sequence", line)


def _quoted(text: str, start: int, line: int) -> tuple[str, int]:
    quote = text[start]
    characters: list[str] = []
    index = start + 1
    while index < len(text):
        character = text[index]
        if character == quote and quote == "'":
            if text[index + 1 : index + 2] == "'":
                characters.append("'")
                index += 2
                continue
            return "".join(characters), index + 1
        if character == quote:
            return "".join(characters), index + 1
        if character == "\\" and quote == '"':
            escape = text[index + 1 : index + 2]
            if escape not in _DOUBLE_ESCAPES:
                _raise("unsupported escape sequence in a double-quoted value", line)
            characters.append(_DOUBLE_ESCAPES[escape])
            index += 2
            continue
        characters.append(character)
        index += 1
    _raise("a quoted value must end on the same line", line)


def _plain(text: str, line: int) -> str | None:
    comment = text.find(" #")
    value = (text if comment < 0 else text[:comment]).rstrip(" ")
    if ": " in value or value.endswith(":"):
        _raise("a plain value must not contain ': ' or end with ':'; quote it", line)
    return _resolve(value, line)


def _skip_spaces(text: str, index: int) -> int:
    while index < len(text) and text[index] == " ":
        index += 1
    return index


def _flow_item(text: str, index: int, line: int) -> tuple[str | None, int]:
    if text[index] in "'\"":
        return _quoted(text, index, line)
    if text[index] in _FLOW_START_FORBIDDEN:
        _raise("unsupported item in a flow sequence", line)
    end = index
    while end < len(text) and text[end] not in ",]":
        if text[end] in _FLOW_PLAIN_FORBIDDEN:
            _raise("unsupported character in a flow sequence item; quote it", line)
        end += 1
    return _resolve(text[index:end].rstrip(" "), line), end


def _flow_sequence(text: str, line: int) -> list[object]:
    items: list[object] = []
    index = _skip_spaces(text, 1)
    if text[index : index + 1] == "]":
        _expect_trailer(text[index + 1 :], line)
        return items
    while True:
        if index >= len(text):
            _raise("a flow sequence must end on the same line", line)
        value, index = _flow_item(text, index, line)
        items.append(value)
        index = _skip_spaces(text, index)
        if index >= len(text):
            _raise("a flow sequence must end on the same line", line)
        if text[index] == "]":
            _expect_trailer(text[index + 1 :], line)
            return items
        if text[index] != ",":
            _raise("expected ',' or ']' in a flow sequence", line)
        index = _skip_spaces(text, index + 1)
        if text[index : index + 1] == "]":
            _raise("a flow sequence must not end with a comma", line)


def _fold(lines: list[str]) -> str:
    parts: list[str] = []
    breaks = 0
    for text in lines:
        if not text:
            breaks += 1
            continue
        if parts and not breaks:
            parts.append(" ")
        parts.append("\n" * breaks)
        parts.append(text)
        breaks = 0
    return "".join(parts)


def _chomp(body: str, chomping: str, *, has_content: bool, trailing: int) -> str:
    if chomping == "-":
        return body
    if chomping == "+":
        return body + "\n" * (trailing + int(has_content))
    return body + "\n" * int(has_content)


def _check_characters(text: str) -> None:
    for number, line in enumerate(text.split("\n"), start=1):
        for character in line:
            if character == "\t":
                _raise("tab characters are not allowed", number)
            if character == "\r":
                _raise("carriage returns are not allowed; use LF line endings", number)
            category = unicodedata.category(character)
            if category in {"Cc", "Cs", "Zl", "Zp"} or character in _BIDI_CONTROLS:
                _raise("control, surrogate, separator or bidi characters are not allowed", number)


class _Parser:
    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._index = 1

    def _fail(self, message: str) -> NoReturn:
        _raise(message, self._index + 1)

    def _peek(self) -> int | None:
        while self._index < len(self._lines):
            line = self._lines[self._index]
            content = line.lstrip(" ")
            if content and not content.startswith("#"):
                return len(line) - len(content)
            self._index += 1
        return None

    def _content(self, indent: int) -> str:
        return self._lines[self._index][indent:]

    def document(self) -> object:
        """Parse the whole document and return its top-level node."""
        indent = self._peek()
        if indent is None:
            self._fail("the document has no content")
        if indent:
            self._fail("the top-level node must not be indented")
        value = self._block(0, 1)
        if self._peek() is not None:
            self._fail("unexpected content after the top-level node")
        return value

    def _block(self, indent: int, depth: int) -> object:
        if depth > MAX_DEPTH:
            self._fail(f"the document is nested deeper than {MAX_DEPTH} levels")
        if _is_sequence_item(self._content(indent)):
            return self._sequence(indent, depth)
        return self._mapping(indent, depth)

    def _mapping(self, indent: int, depth: int) -> dict[str, object]:
        result: dict[str, object] = {}
        while True:
            current = self._peek()
            if current is None or current < indent:
                return result
            if current > indent:
                self._fail("unexpected indentation")
            match = re.fullmatch(_KEY_LINE, self._content(indent))
            if match is None:
                self._fail("expected 'key: value' with a plain identifier as the key")
            key = match.group(1)
            if key in _BOOLEAN_WORDS or key in _NULL_WORDS:
                self._fail(f"the key {key!r} is not read as a string by YAML")
            if key in result:
                self._fail(f"duplicate key {key!r}")
            result[key] = self._value(match.group(2) or "", indent, depth, nested_sequence=True)

    def _sequence(self, indent: int, depth: int) -> list[object]:
        result: list[object] = []
        while True:
            current = self._peek()
            if current is None or current < indent:
                return result
            if current > indent:
                self._fail("unexpected indentation")
            content = self._content(indent)
            if not _is_sequence_item(content):
                return result
            if len(result) >= MAX_SEQUENCE_ITEMS:
                self._fail(f"a sequence has more than {MAX_SEQUENCE_ITEMS} items")
            body = content[1:].lstrip(" ")
            if _is_sequence_item(body) or re.fullmatch(_KEY_LINE, body) is not None:
                column = len(self._lines[self._index]) - len(body)
                self._lines[self._index] = " " * column + body
                result.append(self._block(column, depth + 1))
            else:
                result.append(self._value(body, indent, depth, nested_sequence=False))

    def _value(self, text: str, indent: int, depth: int, *, nested_sequence: bool) -> object:
        line = self._index + 1
        self._index += 1
        if not text or text.startswith("#"):
            return self._nested(indent, depth, nested_sequence=nested_sequence)
        first = text[0]
        if first in "|>":
            return self._block_scalar(text, indent, line)
        if first in "'\"":
            value, end = _quoted(text, 0, line)
            _expect_trailer(text[end:], line)
            return value
        if first == "[":
            return _flow_sequence(text, line)
        if first in _INDICATORS:
            _raise(f"unsupported YAML construct starting with {first!r}", line)
        return _plain(text, line)

    def _nested(self, indent: int, depth: int, *, nested_sequence: bool) -> object:
        current = self._peek()
        if current is None or current < indent:
            return None
        if current > indent:
            return self._block(current, depth + 1)
        if nested_sequence and _is_sequence_item(self._content(indent)):
            return self._block(indent, depth + 1)
        return None

    def _block_scalar(self, header: str, indent: int, line: int) -> str:
        match = re.fullmatch(_BLOCK_HEADER, header)
        if match is None:
            _raise("unsupported block scalar header", line)
        lines: list[str] = []
        content_indent = 0
        leading_spaces = 0
        while self._index < len(self._lines):
            raw = self._lines[self._index]
            content = raw.lstrip(" ")
            spaces = len(raw) - len(content)
            if not content:
                if content_indent and spaces > content_indent:
                    self._fail("a whitespace-only line in a block scalar has extra spaces")
                leading_spaces = max(leading_spaces, spaces * int(not content_indent))
                lines.append("")
                self._index += 1
                continue
            if not content_indent and spaces <= indent:
                break
            if content_indent and spaces < content_indent:
                break
            if not content_indent:
                content_indent = spaces
                if leading_spaces > content_indent:
                    self._fail("a leading blank line in a block scalar has extra spaces")
            if match.group(1) == ">" and spaces > content_indent:
                self._fail("a folded block scalar must not have more-indented lines; use '|'")
            lines.append(raw[content_indent:])
            self._index += 1
        last = max((number for number, text in enumerate(lines) if text), default=-1)
        body_lines = lines[: last + 1]
        body = "\n".join(body_lines) if match.group(1) == "|" else _fold(body_lines)
        return _chomp(body, match.group(2), has_content=last >= 0, trailing=len(lines) - last - 1)


def load(text: str) -> object:
    """Load a document written in the supported YAML subset.

    Args:
        text: The document text.

    Returns:
        The loaded value: a ``dict`` or ``list`` whose leaves are ``str`` or
        ``None``.

    Raises:
        YamlSubsetError: If the text is not a string, is too large or is not in
            the supported subset.
    """
    _require_text(text)
    if len(text) > MAX_DOCUMENT_CHARS:
        _raise(f"the document exceeds {MAX_DOCUMENT_CHARS} characters", 1)
    _check_characters(text)
    lines = text.split("\n")
    if len(lines) > 1 and not lines[-1]:
        lines.pop()
    if lines[0] != DOCUMENT_START:
        _raise("the document must start with a line that is exactly '---'", 1)
    for number, line in enumerate(lines[1:], start=2):
        if line in {DOCUMENT_START, "..."} or line.startswith(("--- ", "... ", "%")):
            _raise("only one document is allowed and directives are not supported", number)
    return _Parser(lines).document()
