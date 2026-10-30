"""Remove the Script Check Engine checks and scripts from a pinned datastream (FREES-191).

ComplianceAsCode datastreams embed shell scripts for the OpenSCAP Script Check Engine (SCE):
each script is a data stream ``extended-component`` holding one ``sce:script``, referenced by
a ``component-ref`` and a catalog ``uri`` of the checklist, and a rule's XCCDF ``check`` with
the system ``http://open-scap.org/page/SCE`` points at it. ``oscap xccdf eval`` runs such a
script as root while it audits (threat model T-AUDIT-2). ADR 0026 decides that no script
written by ComplianceAsCode ever runs on a managed host, so the controller removes all of
them before the content leaves it:

* every SCE ``check`` of a rule; a rule that has no other automated check then evaluates as
  ``notchecked``, and a rule that also has an OVAL check keeps it, which ``oscap`` evaluates
  in preference to SCE already;
* every ``extended-component``, which must hold exactly one SCE script;
* every ``component-ref`` that points at a removed component, and every catalog ``uri`` that
  points at a removed ``component-ref``.

The document is parsed once with the bounded parser of :mod:`xmlsafe` (no DOCTYPE, no
entities, bounded size and depth), which reports the byte offset of every tag, and the
elements are cut out of the original bytes together with the indentation in front of them.
Nothing else changes: the result is not serialised again, so every other byte, prefix and
attribute order stays as published and the result is reproducible. Anything this module does
not recognise fails closed: a check of another script system, an SCE check outside a rule, an
extended component with other content, an SCE element outside a component, a reference that
does not resolve, and an element whose children would all be removed. The result is parsed
again and must not contain any script check (:func:`catalog.refuse_script_check`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
    xmlsafe,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

XCCDF: Final[str] = f"{{{catalog.XCCDF_NAMESPACE}}}"
DATASTREAM: Final[str] = f"{{{catalog.DATASTREAM_NAMESPACE}}}"
CHECK: Final[str] = f"{XCCDF}check"
RULE: Final[str] = f"{XCCDF}Rule"
CONTENT_REF: Final[str] = f"{XCCDF}check-content-ref"
EXTENDED_COMPONENT: Final[str] = f"{DATASTREAM}extended-component"
COMPONENT_REF: Final[str] = f"{DATASTREAM}component-ref"
CATALOG_URI: Final[str] = "{urn:oasis:names:tc:entity:xmlns:xml:catalog}uri"
SCE_SCRIPT: Final[str] = f"{{{catalog.SCE_NAMESPACE}}}script"
SCE_PREFIX: Final[str] = f"{{{catalog.SCE_NAMESPACE}}}"
XLINK_HREF: Final[str] = "http://www.w3.org/1999/xlink}href"
CHUNK_BYTES: Final[int] = xmlsafe.READ_CHUNK_BYTES
QUOTES: Final[frozenset[int]] = frozenset(b"'\"")
INDENTATION: Final[bytes] = b" \t"
NEWLINE: Final[int] = ord("\n")
CLOSE: Final[int] = ord(">")
SLASH: Final[int] = ord("/")


class ScriptCheckError(ValueError):
    """The datastream holds a script construct that this module does not remove safely."""


@dataclass(frozen=True)
class Stripped:
    """A datastream without its SCE checks and scripts, and what was removed."""

    data: bytes
    checks: int
    scripts: int
    component_refs: int
    catalog_uris: int


def _attributes() -> dict[str, str]:
    return {}


def _frames() -> list[Frame]:
    return []


def _texts() -> list[str]:
    return []


@dataclass
class Frame:
    """An open element; only candidates for removal keep their attributes."""

    name: str
    start: int
    attributes: dict[str, str] = field(default_factory=_attributes)
    children: int = 0
    candidates: list[Frame] = field(default_factory=_frames)
    content_refs: list[str] = field(default_factory=_texts)
    child_names: list[str] = field(default_factory=_texts)
    end: int = -1


@dataclass
class Collector:
    """Parse events that record the script constructs of a datastream and where they are."""

    data: bytes
    offset: int = 0
    stack: list[Frame] = field(default_factory=_frames)
    parents: list[Frame] = field(default_factory=_frames)
    checks: list[Frame] = field(default_factory=_frames)
    components: list[Frame] = field(default_factory=_frames)
    references: list[Frame] = field(default_factory=_frames)
    uris: list[Frame] = field(default_factory=_frames)

    def locate(self, offset: int) -> None:
        """Remember the byte offset of the tag of the next event."""
        self.offset = offset

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        """Open an element and record it when it is a candidate for removal."""
        parent = self.stack[-1] if self.stack else None
        frame = Frame(name, self.offset)
        kind = self._kind(name, attributes, parent)
        if kind is not None:
            frame.attributes = dict(attributes)
            kind.append(frame)
            if parent is not None:
                parent.candidates.append(frame)
        if parent is not None:
            parent.children += 1
            if parent.name in {CHECK, EXTENDED_COMPONENT}:
                parent.child_names.append(name)
            if parent.name == CHECK and name == CONTENT_REF:
                parent.content_refs.append(attributes.get("href", ""))
        self.stack.append(frame)

    def _kind(
        self, name: str, attributes: dict[str, str], parent: Frame | None
    ) -> list[Frame] | None:
        if name == CHECK and attributes.get("system", "") not in catalog.ACCEPTED_CHECK_SYSTEMS:
            system = attributes.get("system", "")
            if system != catalog.SCE_CHECK_SYSTEM:
                message = f"a check uses the system {system!r}, which is not removed safely"
                raise ScriptCheckError(message)
            if parent is None or parent.name != RULE:
                message = "an SCE check is not a direct child of a rule"
                raise ScriptCheckError(message)
            return self.checks
        if name == EXTENDED_COMPONENT:
            return self.components
        if name == COMPONENT_REF:
            return self.references
        if name == CATALOG_URI:
            return self.uris
        if name.startswith(SCE_PREFIX) and (parent is None or parent.name != EXTENDED_COMPONENT):
            message = f"the SCE element {name} is not the content of an extended component"
            raise ScriptCheckError(message)
        return None

    def end(self, name: str, /) -> None:
        """Close an element and record where it ends when that is needed."""
        frame = self.stack.pop()
        if frame.candidates:
            self.parents.append(frame)
        if frame.attributes or frame.candidates:
            frame.end = self.element_end(frame)
        if name == EXTENDED_COMPONENT and frame.child_names != [SCE_SCRIPT]:
            identifier = frame.attributes.get("id", "")
            message = f"the extended component {identifier!r} is not exactly one SCE script"
            raise ScriptCheckError(message)

    def text(self, data: str, /) -> None:
        """Ignore character data."""

    def element_end(self, frame: Frame) -> int:
        """Return the offset just after ``frame``, which ends at the current position."""
        closed = tag_end(self.data, frame.start)
        if self.data[closed - 2] == SLASH:
            return closed
        if not self.data.startswith(b"</", self.offset):
            message = f"the end tag of {frame.name} is not where the parser reported it"
            raise ScriptCheckError(message)
        return self.data.index(b">", self.offset) + 1


def tag_end(data: bytes, start: int) -> int:
    """Return the offset just after the start tag at ``start``, honouring quoted values."""
    quote: int | None = None
    for index in range(start + 1, len(data)):
        byte = data[index]
        if quote is not None:
            quote = None if byte == quote else quote
        elif byte in QUOTES:
            quote = byte
        elif byte == CLOSE:
            return index + 1
    message = "a start tag is not closed"
    raise ScriptCheckError(message)


def _chunks(data: bytes) -> Iterator[bytes]:
    for index in range(0, len(data), CHUNK_BYTES):
        yield data[index : index + CHUNK_BYTES]


def _reference(frame: Frame, key: str) -> str:
    value = frame.attributes.get(key, "")
    return value[1:] if value.startswith("#") else ""


def _line_start(data: bytes, start: int) -> int:
    """Return where the line of the element at ``start`` begins.

    That is the newline before it, when only indentation separates the two; otherwise ``start``.
    """
    index = start
    while index > 0 and data[index - 1] in INDENTATION:
        index -= 1
    return index - 1 if index > 0 and data[index - 1] == NEWLINE else start


def removed_elements(collector: Collector) -> tuple[list[Frame], int, int, int]:
    """Return the elements to remove, and the numbers of scripts, references and catalog uris."""
    components = {frame.attributes.get("id", ""): frame for frame in collector.components}
    references = [
        frame for frame in collector.references if _reference(frame, XLINK_HREF) in components
    ]
    if sorted(_reference(frame, XLINK_HREF) for frame in references) != sorted(components):
        message = "an extended component is not referenced by exactly one component-ref"
        raise ScriptCheckError(message)
    reference_ids = {frame.attributes.get("id", "") for frame in references}
    uris = [frame for frame in collector.uris if _reference(frame, "uri") in reference_ids]
    hrefs = {href for frame in collector.checks for href in frame.content_refs}
    if (
        hrefs != {frame.attributes.get("name", "") for frame in uris}
        or {_reference(frame, "uri") for frame in uris} != reference_ids
    ):
        message = "the SCE checks, catalog entries and component references do not match"
        raise ScriptCheckError(message)
    removed = [*collector.checks, *components.values(), *references, *uris]
    chosen = {id(frame) for frame in removed}
    for parent in collector.parents:
        if parent.children == sum(id(child) in chosen for child in parent.candidates):
            message = f"removing the scripts would leave {parent.name} without children"
            raise ScriptCheckError(message)
    return removed, len(components), len(references), len(uris)


def strip_script_checks(data: bytes) -> Stripped:
    """Return ``data`` without its SCE checks, scripts and their references.

    Raises:
        ScriptCheckError: When the document is not safe XML, holds a script construct that is
            not removed safely, or still holds a script check afterwards.
    """
    collector = Collector(data)
    try:
        xmlsafe.parse_chunks(_chunks(data), collector, on_position=collector.locate)
    except xmlsafe.XmlSafetyError as error:
        raise ScriptCheckError(str(error)) from error
    removed, scripts, references, uris = removed_elements(collector)
    pieces: list[bytes] = []
    cursor = 0
    for frame in sorted(removed, key=lambda item: item.start):
        start = _line_start(data, frame.start)
        if start < cursor:
            message = "two removed elements overlap"
            raise ScriptCheckError(message)
        pieces.append(data[cursor:start])
        cursor = frame.end
    pieces.append(data[cursor:])
    result = b"".join(pieces)
    try:
        xmlsafe.parse_chunks(_chunks(result), catalog.ScriptCheckScanner())
    except (xmlsafe.XmlSafetyError, catalog.ScriptCheckError) as error:
        message = f"the datastream without its scripts is not acceptable: {error}"
        raise ScriptCheckError(message) from error
    return Stripped(result, len(collector.checks), scripts, references, uris)
