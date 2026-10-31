"""Read the lines of an sshd configuration file as sshd reads them (FREES-200).

OpenSSH 9.6p1 (Ubuntu 24.04) and 9.9p1 (Rocky Linux 9) read a configuration file in
``load_server_config`` and ``process_server_config_line_depth`` of ``servconf.c``:

1. ``getline`` reads each line. The blanks, tabs and CRs at its start are dropped, and the line
   ends at its first NUL byte. A NUL also drops the line break, so the rest of the next line is
   joined to it.
2. The blanks, tabs, CRs, LFs and FFs at the end of the line are dropped.
3. ``strdelim`` of ``misc.c`` takes the keyword. A token ends at white space, a ``"`` or an
   ``=``. A ``"`` anywhere in it is removed and the token runs to the next ``"``; without one the
   line is ignored. After the token, white space and at most one ``=`` are skipped. If the line
   starts with ``=``, the first token is empty and ``strdelim`` runs a second time.
4. An empty keyword, or one that starts with ``#``, is a comment. A keyword without an argument
   is an error. Keywords are compared without case, and ``DSAAuthentication`` is another name of
   ``PubkeyAuthentication``.

:func:`read_lines` reproduces this for each line of a text, so the ``ssh`` family of the remediate
role finds every setting, ``Match`` line and ``Include`` line as sshd does. The family refuses a
text that it cannot rewrite exactly: one with a NUL byte, which joins lines, or with bytes that are
not UTF-8. ``tests/fixtures/sshd_readers/verdicts.json`` holds what sshd read for every case, in
both Molecule images, and ``tests/unit/tools/test_sshd_verdicts.py`` checks this reader against it.
"""

from __future__ import annotations

import re
from typing import Final

LEADING: Final[str] = " \t\r"
WHITESPACE: Final[str] = " \t\r\n"
TRAILING: Final[str] = " \t\r\n\f"
DELIMITERS: Final[str] = ' \t\r\n"='
QUOTE: Final[str] = '"'
EQUALS: Final[str] = "="
COMMENT: Final[str] = "#"
NEWLINE: Final[str] = "\n"
ALIASES: Final[dict[str, str]] = {"dsaauthentication": "pubkeyauthentication"}
PLAIN_ARGUMENTS: Final[str] = r"([^\s\"'\\#]+(?:[ \t]+[^\s\"'\\#]+)*)(?:[ \t]+#.*)?"
SURROGATE: Final[str] = r"[\ud800-\udfff]"


def _span(text: str, start: int, characters: str) -> int:
    """Return the index of the first character from ``start`` that is not in ``characters``."""
    index = start
    while index < len(text) and text[index] in characters:
        index += 1
    return index


def strdelim(text: str, start: int | None) -> tuple[str | None, int | None]:
    """Return the token that ``strdelim`` of OpenSSH returns at ``start``, and where it goes on.

    ``None`` as the token means that ``strdelim`` returned ``NULL``: no matching quote, or no text
    left. ``None`` as the position means that nothing is left after the token.
    """
    if start is None:
        return None, None
    found = [index for index in range(start, len(text)) if text[index] in DELIMITERS]
    if not found:
        return text[start:], None
    index = found[0]
    if text[index] == QUOTE:
        closing = text.find(QUOTE, index + 1)
        if closing < 0:
            return None, None
        return text[start:index] + text[index + 1 : closing], _span(text, closing + 1, WHITESPACE)
    equals = text[index] == EQUALS
    position = _span(text, index + 1, WHITESPACE)
    if not equals and position < len(text) and text[position] == EQUALS:
        position = _span(text, position + 1, WHITESPACE)
    return text[start:index], position


def read_line(line: str) -> dict[str, object]:
    """Return how sshd reads one line: its ``keyword``, its ``arguments`` and its ``value``.

    ``keyword`` is the keyword in lower case with aliases resolved, ``None`` for a comment or an
    ignored line. ``error`` is true when sshd refuses the line. ``arguments`` are the plain words
    after the keyword, or ``None`` when they hold quotes, backslashes or anything else that the
    collection does not read; ``value`` is the one argument, or ``None``.
    """
    text = line[_span(line, 0, LEADING) :].rstrip(TRAILING)
    keyword, position = strdelim(text, 0)
    if keyword == "":
        keyword, position = strdelim(text, position)
    result: dict[str, object] = {"keyword": None, "error": False, "arguments": None, "value": None}
    if not keyword or keyword.startswith(COMMENT):
        return result
    rest = "" if position is None else text[position:]
    if not rest:
        return result | {"error": True}
    name = keyword.lower()
    found = re.fullmatch(PLAIN_ARGUMENTS, rest)
    arguments = found.group(1).split() if found is not None else None
    return result | {
        "keyword": ALIASES.get(name, name),
        "arguments": arguments,
        "value": arguments[0] if arguments is not None and len(arguments) == 1 else None,
    }


def read_lines(text: str) -> dict[str, object]:
    """Return how sshd reads every line of ``text``, one entry per line split at LF.

    ``exact`` is false when the text holds a NUL byte or a byte that is not UTF-8, so that the
    collection neither maps the lines that sshd reads to the lines of the file nor rewrites it.
    """
    exact = "\x00" not in text and re.search(SURROGATE, text) is None
    return {"exact": exact, "lines": [read_line(line) for line in text.split(NEWLINE)]}
