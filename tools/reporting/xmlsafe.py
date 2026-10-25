"""Hardened XML reading: no DTD, no entities, no external references, bounded shape."""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Final

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, iterparse

from tools.reporting.common import InvalidInputError

MAX_ELEMENTS: Final[int] = 1_000_000
MAX_DEPTH: Final[int] = 100


def _no_children() -> list[XmlNode]:
    return []


@dataclass
class XmlNode:
    """Minimal XML element: tag, attributes, leading text and children."""

    tag: str
    attributes: dict[str, str]
    text: str = ""
    children: list[XmlNode] = field(default_factory=_no_children)

    @property
    def local(self) -> str:
        """Return the tag without its namespace."""
        return self.tag.rsplit("}", 1)[-1]

    def descendants(self) -> list[XmlNode]:
        """Return this node and every node below it in document order, iteratively."""
        found: list[XmlNode] = []
        pending: list[XmlNode] = [self]
        while pending:
            node = pending.pop()
            found.append(node)
            pending.extend(reversed(node.children))
        return found


def _check_limits(depth: int, count: int) -> None:
    if depth > MAX_DEPTH or count > MAX_ELEMENTS:
        message = "XML document exceeds the nesting or element limit"
        raise InvalidInputError(message)


def parse_xml(data: bytes) -> XmlNode:
    """Parse XML bytes into a bounded tree.

    DOCTYPE declarations, entity declarations and external references are rejected
    by defusedxml. Element count and nesting depth are checked while parsing, so a
    hostile document stops early instead of exhausting memory.

    Raises:
        InvalidInputError: For malformed, truncated, unsafe or too large documents.
    """
    stack: list[XmlNode] = []
    roots: list[XmlNode] = []
    count = 0
    try:
        for event, element in iterparse(io.BytesIO(data), events=("start", "end"), forbid_dtd=True):
            if event == "start":
                count += 1
                node = XmlNode(element.tag, {key: str(val) for key, val in element.attrib.items()})
                if stack:
                    stack[-1].children.append(node)
                else:
                    roots.append(node)
                stack.append(node)
                _check_limits(len(stack), count)
            else:
                stack.pop().text = element.text or ""
                element.clear()
    except InvalidInputError:
        raise
    except (DefusedXmlException, ParseError, ValueError) as error:
        message = f"XML document is malformed or unsafe ({type(error).__name__})"
        raise InvalidInputError(message) from None
    return roots[0]
