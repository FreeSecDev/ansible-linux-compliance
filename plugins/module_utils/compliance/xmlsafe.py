"""Hardened streaming XML parsing for untrusted documents on managed hosts.

The standard library expat parser is used because target-side code may only use
the Python standard library. It is made safe by layering:

1. A file must be a regular file, not a symlink, and is read in chunks that are
   bounded before and while reading, so memory does not grow with its size.
2. A DOCTYPE or ENTITY declaration is rejected in the raw bytes before the chunk
   that holds it is parsed, across chunk boundaries, so the entity expansion and
   external entity paths of the parser are unreachable for accepted input. The
   expat handlers reject the same declarations again if that check were bypassed.
3. The expat parser is created directly with the encoding forced to UTF-8,
   parameter entity parsing turned off
   (``SetParamEntityParsing(XML_PARAM_ENTITY_PARSING_NEVER)``) and no external
   entity handler, so an external subset or entity is never loaded.
4. Element count and nesting depth are bounded while parsing.
5. UTF-16, UTF-32 and NUL bytes are rejected.
6. Elements are never stored: callers receive start, end and text events and keep
   only the values they need.

Element names reach the caller in Clark notation (``{namespace}local``), so a
caller that wants one namespace compares full names and rejects the rest.

Python and expat versions differ in their entity-expansion defences: the
billion-laughs limits arrived with expat 2.4.0 (2.4.1 for the final fixes) and
Python bundles or links different expat versions across 3.9 to 3.14. This module
does not depend on them, because a document with any entity declaration is
rejected before parsing.
"""

from __future__ import annotations

import stat
import xml.parsers.expat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, NoReturn, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

_expat = xml.parsers.expat
DEFAULT_MAX_ELEMENTS: Final[int] = 5_000_000
DEFAULT_MAX_DEPTH: Final[int] = 64
READ_CHUNK_BYTES: Final[int] = 1024 * 1024

_MORE: Final[bool] = False
_FINAL: Final[bool] = True
_DECLARATION_MARKERS: Final[tuple[bytes, ...]] = (b"<!DOCTYPE", b"<!ENTITY")
_MARKER_OVERLAP: Final[int] = max(len(marker) for marker in _DECLARATION_MARKERS) - 1
_NUL: Final[bytes] = b"\x00"
_NON_UTF8_MARKS: Final[tuple[bytes, ...]] = (b"\xff\xfe", b"\xfe\xff")


class XmlSafetyError(ValueError):
    """Raised when a document is unsafe, malformed, too large or unreadable."""


def _fail(message: str) -> NoReturn:
    raise XmlSafetyError(message)


@dataclass(frozen=True)
class XmlBounds:
    """Bounds applied while a document is parsed.

    Attributes:
        max_elements: Largest number of elements in the document.
        max_depth: Deepest element nesting, where the root has depth 1.
    """

    max_elements: int = DEFAULT_MAX_ELEMENTS
    max_depth: int = DEFAULT_MAX_DEPTH


class XmlEvents(Protocol):
    """Receiver of parse events; element names use Clark notation."""

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        """Handle an element start."""

    def end(self, name: str, /) -> None:
        """Handle an element end."""

    def text(self, data: str, /) -> None:
        """Handle character data."""


class _Guard:
    """Expat handlers that bound the document and forward events."""

    def __init__(self, events: XmlEvents, bounds: XmlBounds) -> None:
        self.events = events
        self.bounds = bounds
        self.count = 0
        self.depth = 0

    @staticmethod
    def reject_declaration(*_arguments: object) -> NoReturn:
        _fail("DOCTYPE, ENTITY and external entity declarations are not allowed")

    def start(self, name: str, attributes: dict[str, str]) -> None:
        self.count += 1
        if self.count > self.bounds.max_elements:
            _fail(f"document has more than {self.bounds.max_elements} elements")
        if self.depth >= self.bounds.max_depth:
            _fail(f"document is nested deeper than {self.bounds.max_depth} levels")
        self.depth += 1
        self.events.start(_clark(name), attributes)

    def end(self, name: str) -> None:
        self.depth -= 1
        self.events.end(_clark(name))


def _clark(name: str) -> str:
    namespace, separator, local = name.partition("}")
    return f"{{{namespace}}}{local}" if separator else name


def _scan_for_declarations(previous: bytes, chunk: bytes) -> bytes:
    window = previous + chunk
    if any(marker in window for marker in _DECLARATION_MARKERS):
        _fail("DOCTYPE and ENTITY declarations are not allowed")
    return window[-_MARKER_OVERLAP:]


def parse_chunks(
    chunks: Iterable[bytes], events: XmlEvents, bounds: XmlBounds | None = None
) -> None:
    """Parse a UTF-8 document delivered in chunks, forwarding events.

    Args:
        chunks: The document bytes in order. Chunk boundaries may fall anywhere.
        events: Receiver of start, end and text events. It may raise to abort.
        bounds: Element and depth bounds; the defaults apply when omitted.

    Raises:
        XmlSafetyError: If the document is empty, not well-formed, not UTF-8,
            contains a NUL byte, declares a DOCTYPE or entity, or exceeds the
            bounds. Errors raised by ``events`` propagate unchanged.
    """
    guard = _Guard(events, XmlBounds() if bounds is None else bounds)
    parser = _expat.ParserCreate(encoding="utf-8", namespace_separator="}")
    parser.SetParamEntityParsing(_expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.buffer_text = True
    parser.StartElementHandler = guard.start
    parser.EndElementHandler = guard.end
    parser.CharacterDataHandler = events.text
    parser.StartDoctypeDeclHandler = guard.reject_declaration
    parser.EntityDeclHandler = guard.reject_declaration
    parser.ExternalEntityRefHandler = guard.reject_declaration
    previous = b""
    received = 0
    try:
        for chunk in chunks:
            if received == 0 and chunk.startswith(_NON_UTF8_MARKS):
                _fail("the document is UTF-16 or UTF-32, only UTF-8 is accepted")
            if _NUL in chunk:
                _fail("the document contains a NUL byte, only UTF-8 text is accepted")
            received += len(chunk)
            previous = _scan_for_declarations(previous, chunk)
            parser.Parse(chunk, _MORE)
        if received == 0:
            _fail("the document is empty")
        parser.Parse(b"", _FINAL)
    except _expat.ExpatError as error:
        _fail(f"not well-formed XML: {_expat.ErrorString(error.code)} at line {error.lineno}")


def open_regular(path: str, max_bytes: int) -> BinaryIO:
    """Open a regular, non-symlink file of at most ``max_bytes`` for binary reading.

    The caller uses the returned handle for every pass over the file, so the path
    is opened once. The repository guard allows ``os`` only as ``os.path``, so
    ``O_NOFOLLOW`` is not available; a path swapped between the check and the open
    is covered by the callers, which compare the digest of the bytes they actually
    read with the pinned digest.

    Raises:
        XmlSafetyError: If the path is not a regular file, is a symlink, is
            larger than ``max_bytes`` or cannot be opened.
    """
    target = Path(path)
    try:
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            _fail("the path is not a regular file")
        if info.st_size > max_bytes:
            _fail(f"the file is larger than {max_bytes} bytes")
        return target.open("rb")
    except OSError as error:
        _fail(f"the file cannot be read: {error.strerror or type(error).__name__}")


def iter_handle_chunks(handle: BinaryIO, max_bytes: int) -> Iterator[bytes]:
    """Yield the bytes of an open file from its start, bounded by ``max_bytes``.

    The handle is rewound first, so it can be read again for a second pass. The
    size is checked while reading, so memory does not grow with the file size.

    Raises:
        XmlSafetyError: If the file is larger than ``max_bytes`` or cannot be read.
    """
    try:
        handle.seek(0)
        total = 0
        while chunk := handle.read(READ_CHUNK_BYTES):
            total += len(chunk)
            if total > max_bytes:
                _fail(f"the file is larger than {max_bytes} bytes")
            yield chunk
    except OSError as error:
        _fail(f"the file cannot be read: {error.strerror or type(error).__name__}")


def iter_file_chunks(path: str, max_bytes: int) -> Iterator[bytes]:
    """Yield the bytes of a regular, non-symlink file with a size bound.

    Nothing is checked until the iterator is first advanced. See
    :func:`open_regular` and :func:`iter_handle_chunks` for the checks and errors.
    """
    with open_regular(path, max_bytes) as handle:
        yield from iter_handle_chunks(handle, max_bytes)
