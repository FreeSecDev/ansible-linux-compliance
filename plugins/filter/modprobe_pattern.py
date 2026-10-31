"""Filter that turns the module name of a modprobe ``install`` line into the regex kmod matches."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: modprobe_pattern
short_description: Translate the module name of a modprobe install directive as kmod matches it
version_added: "0.1.0"
description:
  - Takes the module name of an C(install) directive as kmod has already read it, that is as
    C(modprobe -c) prints it, with the backslashes of the file resolved and continued lines joined
    by kmod's own line reader. kmod checks and normalises the name with C(underscores()) and then
    matches it against a module with the C library's C(fnmatch(3)) without flags. This filter
    returns a Python regular expression that matches, as a whole, the normalised module names that
    kmod would match, or C(None) when kmod rejects the name.
  - "Normalisation, as C(underscores()) of libkmod: C(-) becomes C(_) outside brackets, where a
    bracket ends at the first C(]) after its C([). An unterminated C([) or a stray C(]) is
    rejected."
  - "Matching, as C(fnmatch) of glibc: C(*) is any run of characters, C(?) one character, C(\\x) the
    literal C(x) and a trailing C(\\) matches nothing. A bracket reads a C(]) right after C([),
    C([!) or C([^) as a member and ends at the next C(]), which can be further than where kmod
    ended it (C(cr[]a[a]mfs) is one bracket of C(], a, [, a)). Ranges are in byte order, a reversed
    range matches nothing, and an unterminated bracket matches no module name."
  - A character class, an equivalence class or a collating symbol inside a bracket (C([:alpha:]),
    C([=a=]), C([.a.])) is not modelled; such a name is taken to match every module, so it can only
    make a caller refuse.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input
options:
  _input:
    description: The module name of the install directive, as kmod read it, for example C(cram*).
    type: str
    required: true
"""

EXAMPLES = r"""
- name: Decide whether an install directive applies to cramfs
  vars:
    pattern: "{{ 'cram*' | freesecdev.linux_compliance.modprobe_pattern }}"
  ansible.builtin.set_fact:
    applies: "{{ 'cramfs' is match('^(?:' ~ pattern ~ ')$') }}"
"""

RETURN = r"""
_value:
  description: The regular expression, to be matched as a whole against the module name
    with C(-) as C(_), or C(None) when kmod rejects the name.
  type: str
  sample: "cram.*"
"""

MATCH_ALL: Final[str] = ".*"
MATCH_NONE: Final[str] = "(?!)"
BACKSLASH: Final[str] = "\\"
NEGATION: Final[frozenset[str]] = frozenset({"!", "^"})
CLASS_OPENERS: Final[frozenset[str]] = frozenset({":", ".", "="})
SPECIAL: Final[frozenset[str]] = frozenset("\\.^$*+?{}[]|()-/#&~ ")


class UnmodelledError(Exception):
    """A bracket that holds a class, an equivalence class or a collating symbol."""


class NoMatchError(Exception):
    """A pattern that ``fnmatch`` matches against no module name."""


def _literal(character: str) -> str:
    """Return ``character`` escaped for a regular expression, inside or outside a class."""
    return BACKSLASH + character if character in SPECIAL else character


def normalised(name: str) -> str | None:
    """Return ``name`` as kmod's ``underscores()`` leaves it, or ``None`` when kmod rejects it."""
    out = ""
    index = 0
    while index < len(name):
        character = name[index]
        if character == "]":
            return None
        if character == "[":
            end = name.find("]", index)
            if end < 0:
                return None
            out += name[index : end + 1]
            index = end + 1
            continue
        out += "_" if character == "-" else character
        index += 1
    return out


def _member(pattern: str, index: int) -> tuple[str, int]:
    """Return one member character of a bracket starting at ``index``, and the next index."""
    character = pattern[index]
    if character == BACKSLASH:
        if index + 1 >= len(pattern):
            raise NoMatchError
        return pattern[index + 1], index + 2
    if character == "[" and pattern[index + 1 : index + 2] in CLASS_OPENERS:
        raise UnmodelledError
    return character, index + 1


def _bracket(pattern: str, index: int) -> tuple[str, int]:
    """Translate the bracket that starts after the ``[`` at ``index - 1``, as glibc reads it."""
    negated = pattern[index : index + 1] in NEGATION
    index += 1 if negated else 0
    items: list[str] = []
    first = True
    while True:
        if index >= len(pattern):
            raise NoMatchError
        if pattern[index] == "]" and not first:
            index += 1
            break
        first = False
        start, index = _member(pattern, index)
        if pattern[index : index + 1] == "-" and pattern[index + 1 : index + 2] not in {"", "]"}:
            end, index = _member(pattern, index + 1)
            if start <= end:
                items.append(_literal(start) + "-" + _literal(end))
            continue
        items.append(_literal(start))
    if not items:
        return ("." if negated else MATCH_NONE), index
    return "[" + ("^" if negated else "") + "".join(items) + "]", index


def translated(pattern: str) -> str:
    """Translate an ``fnmatch`` pattern without flags into a regular expression."""
    out = ""
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            out += ".*"
            index += 1
        elif character == "?":
            out += "."
            index += 1
        elif character == BACKSLASH:
            if index + 1 >= len(pattern):
                raise NoMatchError
            out += _literal(pattern[index + 1])
            index += 2
        elif character == "[":
            part, index = _bracket(pattern, index + 1)
            out += part
        else:
            out += _literal(character)
            index += 1
    return out


def modprobe_pattern(name: object) -> str | None:
    """Return the regex that kmod matches for the module name of an install line, or ``None``."""
    if not isinstance(name, str) or not name:
        message = (
            f"the module name of an install line must be a non-empty string, got {repr(name)[:32]}"
        )
        raise ValueError(message)
    pattern = normalised(name)
    if pattern is None:
        return None
    try:
        return translated(pattern)
    except UnmodelledError:
        return MATCH_ALL
    except NoMatchError:
        return MATCH_NONE


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object], str | None]]:
        """Return the filters of this plugin."""
        return {"modprobe_pattern": modprobe_pattern}
