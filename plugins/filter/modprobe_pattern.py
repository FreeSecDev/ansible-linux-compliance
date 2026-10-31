"""Filter that turns the module name of a modprobe ``install`` line into the regex kmod matches."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: modprobe_pattern
short_description: Translate the module name of a modprobe install line as kmod matches it
version_added: "0.1.0"
description:
  - kmod first normalises the module name of an C(install) line (C(underscores()) of
    libkmod) and then matches it against a module with C(fnmatch(3)) without flags. This
    filter returns a Python regular expression that matches, as a whole, exactly the
    normalised module names that kmod would match, or C(None) when kmod rejects the line
    and so ignores it.
  - "Normalisation: C(-) becomes C(_) outside brackets. A bracket ends at the first C(])
    after its C([), so an unterminated C([), a stray C(]) and every C([[:class:]]) or
    C([[=x=]]) form are rejected, and so is a bracket closed straight after C([), C([!) or
    C([^), which kmod rejects or which can match no module."
  - "Matching: C(*) is any run of characters, C(?) one character, C(\\x) the literal C(x),
    and a bracket the characters it lists, with ranges in byte order and C(!) or C(^) first
    for negation. A reversed range matches nothing. A trailing C(\\) matches nothing."
  - Two forms cannot be modelled exactly, because C(fnmatch) would read them differently
    from where kmod ends the bracket. A bracket whose content ends with C(\\), and one that
    holds C([) followed by C(:), C(.) or C(=), are taken to match every module, so they can
    only make a caller refuse.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input
options:
  _input:
    description: The module name of the install line, as written, for example C(cram*).
    type: str
    required: true
"""

EXAMPLES = r"""
- name: Decide whether an install line applies to cramfs
  vars:
    pattern: "{{ 'cram*' | freesecdev.linux_compliance.modprobe_pattern }}"
  ansible.builtin.set_fact:
    applies: "{{ 'cramfs' is match('^(?:' ~ pattern ~ ')$') }}"
"""

RETURN = r"""
_value:
  description: The regular expression, to be matched as a whole against the module name
    with C(-) as C(_), or C(None) when kmod ignores the line.
  type: str
  sample: "cram.*"
"""

MATCH_ALL: Final[str] = ".*"
MATCH_NONE: Final[str] = "(?!)"
BACKSLASH: Final[str] = "\\"
NEGATION: Final[frozenset[str]] = frozenset({"!", "^"})
CLASS_OPENERS: Final[frozenset[str]] = frozenset({":", ".", "="})
SPECIAL: Final[frozenset[str]] = frozenset("\\.^$*+?{}[]|()-/#&~ ")


def _literal(character: str) -> str:
    """Return ``character`` escaped for a regular expression, inside or outside a class."""
    return BACKSLASH + character if character in SPECIAL else character


def _units(content: str) -> list[tuple[str, bool]] | None:
    """Return the characters of a bracket and whether each was escaped, or ``None``."""
    units: list[tuple[str, bool]] = []
    escaped = False
    for index, character in enumerate(content):
        if escaped:
            units.append((character, True))
            escaped = False
        elif character == BACKSLASH:
            escaped = True
        elif character == "[" and content[index + 1 : index + 2] in CLASS_OPENERS:
            return None
        else:
            units.append((character, False))
    return None if escaped else units


def _bracket(content: str) -> str | None:
    """Return the regex of one bracket expression, or ``None`` when it cannot be modelled."""
    negated = content[0] in NEGATION
    units = _units(content[1:] if negated else content)
    if units is None:
        return None
    items: list[str] = []
    index = 0
    while index < len(units):
        first = units[index][0]
        if index + 2 < len(units) and units[index + 1] == ("-", False):
            last = units[index + 2][0]
            if first <= last:
                items.append(_literal(first) + "-" + _literal(last))
            index += 3
        else:
            items.append(_literal(first))
            index += 1
    if not items:
        return "." if negated else MATCH_NONE
    return "[" + ("^" if negated else "") + "".join(items) + "]"


def _split(name: str) -> list[tuple[str, str]] | None:
    """Split a name as kmod's ``underscores()`` does, or return ``None`` when kmod rejects it.

    Each part is ``("text", value)`` outside brackets, with ``-`` already turned into ``_``, or
    ``("bracket", content)``.
    """
    parts: list[tuple[str, str]] = []
    text = ""
    index = 0
    while index < len(name):
        character = name[index]
        if character == "]":
            return None
        if character == "[":
            end = name.find("]", index)
            content = name[index + 1 : end]
            if end < 0 or content in {"", "!", "^"}:
                return None
            parts.append(("text", text))
            parts.append(("bracket", content))
            text = ""
            index = end + 1
            continue
        text += "_" if character == "-" else character
        index += 1
    parts.append(("text", text))
    return parts


def _text(text: str) -> str:
    """Return the regex of the text between brackets, with fnmatch's wildcards and escapes."""
    out = ""
    escaped = False
    for character in text:
        if escaped:
            out += _literal(character)
            escaped = False
        elif character == BACKSLASH:
            escaped = True
        elif character == "*":
            out += ".*"
        elif character == "?":
            out += "."
        else:
            out += _literal(character)
    return out + MATCH_NONE if escaped else out


def modprobe_pattern(name: object) -> str | None:
    """Return the regex that kmod matches for the module name of an install line, or ``None``."""
    if not isinstance(name, str) or not name:
        message = (
            f"the module name of an install line must be a non-empty string, got {repr(name)[:32]}"
        )
        raise ValueError(message)
    parts = _split(name)
    if parts is None:
        return None
    out = ""
    for kind, value in parts:
        if kind == "text":
            out += _text(value)
            continue
        bracket = _bracket(value)
        if bracket is None:
            return MATCH_ALL
        out += bracket
    return out


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object], str | None]]:
        """Return the filters of this plugin."""
        return {"modprobe_pattern": modprobe_pattern}
