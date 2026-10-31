"""Model of how systemd-sysctl and procps decide a persistent kernel parameter (FREES-107).

The kernel parameter topics must never report ``compliant`` or ``applied`` while a real reader of
the configuration would set a looser value ("the reader is the oracle"). This module decides, from
the configuration entries of an instance, what each reader writes for a key:

* ``systemd``: ``systemd-sysctl`` at boot. It reads the ``*.conf`` files of ``/etc/sysctl.d``,
  ``/run/sysctl.d``, ``/usr/local/lib/sysctl.d``, ``/usr/lib/sysctl.d`` and ``/lib/sysctl.d``, the
  first directory winning for a file name, skips hidden files, sorts all names bytewise and merges
  every file into one ordered table before it writes anything. A line ends at a line feed, a
  carriage return (a CR LF counts once) or a NUL. A key is normalised: when its first separator is
  a dot, dots and slashes are interchanged; then repeated slashes and ``.`` components are dropped,
  and a leading and a trailing slash; a key with a ``..`` component is never written. An
  assignment of a key that the table holds with another value moves it to the end, one with the
  same value keeps its place; a ``-key`` line without ``=`` assigns no value, so the key is not
  written at all, and no glob sets it. A key that the table holds is never set by a glob; of the
  globs that match a key, the last in table order wins. ``/etc/sysctl.conf`` counts only through a
  link such as ``/etc/sysctl.d/99-sysctl.conf``.
* ``procps``: ``sysctl --system`` (procps-ng 4.0.4 and 3.3.17 write the same values for every case
  of the fixture). It reads the same directories, hidden files included, then ``/etc/sysctl.conf``,
  and makes every setting in order, so the last one wins. A line ends at a line feed only, and its
  text at a NUL. The key, with dots and slashes interchanged when its first separator is a dot, is
  opened below ``/proc/sys`` as written, so repeated slashes, ``.`` and ``..`` components and a
  leading slash resolve as the kernel resolves them, and a trailing slash opens nothing. A
  ``-key`` line without ``=`` only excludes the key from globs. A key that any file assigns is never
  set by a glob. procps expands a configuration file name with glob(3), braces and ``~``
  included, so a name with one of ``*?[]{}~`` may read other files a second time; the model does
  not follow that and reports it in ``unsupported``.

Both skip empty lines and ``#`` and ``;`` comments and drop a leading ``-`` of an assignment.
systemd strips spaces, tabs and line ends from the key and the value, also after the ``-``; procps
strips every white-space character from the line, the value and the end of the key, but not from
the key after a ``-``. An entry that is a directory or a link claims its file name as well: a link
to ``/dev/null`` masks a file of the same name in a later directory, and so does a directory.

Files named in ``after`` (ufw's ``/etc/ufw/sysctl.conf``, which ufw applies with ``sysctl -p`` when
it starts) are read last with the rules of procps, after either reader.

``tests/fixtures/sysctl_reader/verdicts.json`` holds what the readers of the Molecule images wrote
into a private ``/proc/sys`` for the cases of ``cases.json`` (``make sysctl-reader-verdicts``); the
unit tests check this model against every value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence

DIRECTORIES: Final[tuple[str, ...]] = (
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
)
SYSCTL_CONF: Final[str] = "/etc/sysctl.conf"
SYSTEMD: Final[str] = "systemd"
PROCPS: Final[str] = "procps"
READERS: Final[tuple[str, ...]] = (SYSTEMD, PROCPS)
SYSTEMD_SPACE: Final[str] = " \t\n\r"
SYSTEMD_LINE_END: Final[str] = r"\r\n|[\r\n\0]"
GLOB_CHARACTERS: Final[frozenset[str]] = frozenset("*?[")
PROCPS_NAME_EXPANSION: Final[frozenset[str]] = frozenset("*?[]{}~")
KINDS: Final[frozenset[str]] = frozenset({"file", "link", "directory", "other"})
READABLE_KINDS: Final[frozenset[str]] = frozenset({"file", "link"})


class ConfigError(ValueError):
    """The entries handed to the model are malformed."""


@dataclass(frozen=True)
class Entry:
    """One entry of a configuration directory, ``/etc/sysctl.conf`` or a file read after boot."""

    path: str
    kind: str
    text: str | None


@dataclass(frozen=True)
class Assignment:
    """A value for a key below ``/proc/sys``; for a ``-key`` line without ``=``, ``value`` is None.

    ``path`` is the path that the reader opens below ``/proc/sys``, or None when it opens none.
    """

    path: str | None
    value: str | None
    source: str


def load_entries(raw: Iterable[Mapping[str, object]]) -> list[Entry]:
    """Return the entries of ``raw``, each a mapping with ``path``, ``kind`` and ``text``."""
    entries: list[Entry] = []
    for item in raw:
        path = item.get("path")
        kind = item.get("kind")
        text = item.get("text")
        if not isinstance(path, str) or not path.startswith("/") or kind not in KINDS:
            message = f"an entry needs an absolute path and a kind of {sorted(KINDS)}: {dict(item)}"
            raise ConfigError(message)
        if text is not None and not isinstance(text, str):
            message = f"the text of {path} must be a string or null"
            raise ConfigError(message)
        entries.append(Entry(path=path, kind=str(kind), text=text))
    return entries


def _bytes(text: str) -> bytes:
    return text.encode("utf-8", "surrogateescape")


def ordered_files(entries: Sequence[Entry], reader: str) -> list[Entry]:
    """Return the files that ``reader`` reads, in the order it reads them."""
    by_path = {entry.path: entry for entry in entries}
    chosen: dict[str, Entry] = {}
    for directory in DIRECTORIES:
        for entry in entries:
            parent, name = entry.path.rsplit("/", 1)
            if parent != directory or not name.endswith(".conf"):
                continue
            if reader == SYSTEMD and name.startswith("."):
                continue
            chosen.setdefault(name, entry)
    files = [chosen[name] for name in sorted(chosen, key=_bytes)]
    if reader == PROCPS and SYSCTL_CONF in by_path:
        files.append(by_path[SYSCTL_CONF])
    return [entry for entry in files if entry.kind in READABLE_KINDS]


def unsupported(entries: Sequence[Entry]) -> list[str]:
    """Return why the model cannot decide what procps reads, or an empty list.

    procps expands every configuration file name with glob(3), so a name with a glob, brace or
    tilde character may read other files a second time, at its own place in the order.
    """
    reasons = []
    for entry in ordered_files(entries, PROCPS):
        name = entry.path.rsplit("/", 1)[1]
        if PROCPS_NAME_EXPANSION & set(name):
            reasons.append(
                f"{entry.path}: sysctl --system expands the name of this file as a pattern, which"
                " may read other files a second time"
            )
    return reasons


def _swap(key: str) -> str:
    for character in key:
        if character == "/":
            return key
        if character == ".":
            break
    return key.translate(str.maketrans("./", "/."))


def normalise(key: str, reader: str = SYSTEMD) -> str | None:
    """Return the path below ``/proc/sys`` that ``reader`` opens for a key, or None for none."""
    swapped = _swap(key)
    parts: list[str] = []
    if reader == SYSTEMD:
        components = [part for part in swapped.split("/") if part not in {"", "."}]
        return None if ".." in components else "/".join(components)
    if swapped.endswith("/"):
        return None
    for part in swapped.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in {"", "."}:
            parts.append(part)
    return "/".join(parts)


def _lines(text: str, reader: str) -> list[str]:
    if reader == SYSTEMD:
        return re.split(SYSTEMD_LINE_END, text)
    return [raw.split("\0", 1)[0] for raw in text.split("\n")]


def assignments(entry: Entry, reader: str) -> Iterator[Assignment]:
    """Yield the assignments of one file, in order, including ``-key`` lines without ``=``."""
    for raw in _lines(entry.text or "", reader):
        line = raw.strip(SYSTEMD_SPACE) if reader == SYSTEMD else raw.strip()
        if not line or line[0] in "#;":
            continue
        name, separator, value = line.partition("=")
        dash = name.startswith("-")
        name = name.removeprefix("-")
        name = name.strip(SYSTEMD_SPACE) if reader == SYSTEMD else name.rstrip()
        if not dash and reader == PROCPS:
            name = name.strip()
        if not name or (not separator and not dash):
            continue
        written = (
            (value.strip(SYSTEMD_SPACE) if reader == SYSTEMD else value.strip())
            if separator
            else None
        )
        yield Assignment(path=normalise(name, reader), value=written, source=entry.path)


def _is_glob(path: str) -> bool:
    return any(character in GLOB_CHARACTERS for character in path)


def glob_pattern(path: str) -> str:
    """Return the regular expression, for ``re.fullmatch``, of a glob(7) pattern over a path.

    Both readers expand a glob with glob(3) below ``/proc/sys``: ``*`` and ``?`` never match a
    ``/``, a bracket expression matches one character other than ``/``, and an unclosed ``[`` is
    literal.
    """
    parts: list[str] = []
    index = 0
    while index < len(path):
        character = path[index]
        if character == "*":
            parts.append("[^/]*")
        elif character == "?":
            parts.append("[^/]")
        elif character == "[":
            end = path.find("]", index + 2)
            if end == -1:
                parts.append(re.escape(character))
            else:
                body = path[index + 1 : end]
                negate = body[:1] in {"!", "^"}
                members = re.escape(body[1:] if negate else body).replace("\\-", "-")
                parts.append(f"(?!/)[{'^' if negate else ''}{members}]")
                index = end
        else:
            parts.append(re.escape(character))
        index += 1
    return "".join(parts)


def _matches(pattern: str, path: str) -> bool:
    return re.fullmatch(glob_pattern(pattern), path) is not None


def _systemd(lines: Sequence[Assignment], path: str) -> tuple[str, str] | None:
    table: dict[str, Assignment] = {}
    for item in lines:
        if item.path is None:
            continue
        held = table.get(item.path)
        if held is not None and held.value == item.value:
            continue
        table.pop(item.path, None)
        table[item.path] = item
    if path in table:
        held = table[path]
        return None if held.value is None else (held.value, held.source)
    found = None
    for pattern, item in table.items():
        if item.value is not None and _is_glob(pattern) and _matches(pattern, path):
            found = (item.value, item.source)
    return found


def _procps(lines: Sequence[Assignment], path: str) -> tuple[str, str] | None:
    named = {item.path for item in lines if item.path is not None and not _is_glob(item.path)}
    found = None
    for item in lines:
        if item.path is None or item.value is None:
            continue
        if item.path == path or (
            _is_glob(item.path) and path not in named and _matches(item.path, path)
        ):
            found = (item.value, item.source)
    return found


def effective(
    raw_entries: Iterable[Mapping[str, object]], key: str, after: Sequence[str] = ()
) -> dict[str, object]:
    """Return what each reader writes last for ``key``, its file, and what the model cannot follow.

    The result maps ``systemd`` and ``procps`` to ``{"value", "source"}`` (nulls when the reader
    writes nothing), and ``unsupported`` to a list of reasons; the caller must refuse to decide
    when that list is not empty.
    """
    entries = load_entries(raw_entries)
    by_path = {entry.path: entry for entry in entries}
    path = normalise(key) or key
    late = [
        item for name in after if name in by_path for item in assignments(by_path[name], PROCPS)
    ]
    later = _procps(late, path)
    result: dict[str, object] = {}
    for reader in READERS:
        lines = [
            item for entry in ordered_files(entries, reader) for item in assignments(entry, reader)
        ]
        found = later or (_systemd(lines, path) if reader == SYSTEMD else _procps(lines, path))
        result[reader] = (
            {"value": found[0], "source": found[1]} if found else {"value": None, "source": None}
        )
    result["unsupported"] = unsupported(entries)
    return result
