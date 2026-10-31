"""Model of how systemd-sysctl and procps decide a persistent kernel parameter (FREES-107).

The kernel parameter topics must never report ``compliant`` or ``applied`` while a real reader of
the configuration would set a looser value ("the reader is the oracle"). This module decides, from
the configuration entries of an instance, what each reader sets for a key:

* ``systemd``: ``systemd-sysctl`` at boot. It reads the ``*.conf`` files of ``/etc/sysctl.d``,
  ``/run/sysctl.d``, ``/usr/local/lib/sysctl.d``, ``/usr/lib/sysctl.d`` and ``/lib/sysctl.d``, the
  first directory winning for a file name, skips hidden files, sorts all names bytewise, merges
  every file and then sets each key once. ``/etc/sysctl.conf`` counts only through a link such as
  ``/etc/sysctl.d/99-sysctl.conf``.
* ``procps``: ``sysctl --system``. It reads the same directories, hidden files included, and
  ``/etc/sysctl.conf`` last, and then makes every setting in order, so the last one wins.

Both skip empty lines, ``#`` and ``;`` comments and lines without ``=`` (a ``-key`` line alone
excludes the key from globs), and drop a leading ``-``. The first separator of a key decides its
form: a key whose first separator is ``/`` is a path as written, otherwise dots and slashes are
interchanged. A key that any file assigns explicitly is never set by a glob. systemd strips spaces,
tabs and line ends from the key and the value, also after the ``-``; procps strips every white-space
character from the line, the value and the end of the key, but not from the key after a ``-``. A
line ends at a NUL byte. An entry that is a directory or a link claims its file name as well: a link
to ``/dev/null`` masks a file of the same name in a later directory, and so does a directory.

``tests/fixtures/sysctl_reader/verdicts.json`` holds what the readers of the Molecule images set for
the cases of ``cases.json`` (``make sysctl-reader-verdicts``); the unit tests check this model
against it. Files named in ``after`` (ufw's ``/etc/ufw/sysctl.conf``, which ufw applies when it
starts) are read last by both readers.
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
GLOB_CHARACTERS: Final[frozenset[str]] = frozenset("*?[")
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
    """A value for a path below ``/proc/sys``, or a glob exclusion when ``value`` is None."""

    path: str
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


def ordered_files(entries: Sequence[Entry], reader: str, after: Sequence[str] = ()) -> list[Entry]:
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
    files.extend(by_path[path] for path in after if path in by_path)
    return [entry for entry in files if entry.kind in READABLE_KINDS]


def normalise(key: str) -> str:
    """Return the path below ``/proc/sys`` that a key names."""
    for character in key:
        if character == "/":
            return key
        if character == ".":
            break
    return key.translate(str.maketrans("./", "/."))


def assignments(entry: Entry, reader: str) -> Iterator[Assignment]:
    """Yield the assignments and glob exclusions of one file, in order."""
    for raw in (entry.text or "").split("\n"):
        line = raw.split("\0", 1)[0]
        line = line.strip(SYSTEMD_SPACE) if reader == SYSTEMD else line.strip()
        if not line or line[0] in "#;":
            continue
        name, separator, value = line.partition("=")
        dash = name.startswith("-")
        name = name.removeprefix("-")
        name = name.strip(SYSTEMD_SPACE) if reader == SYSTEMD else name.rstrip()
        if not dash and reader == PROCPS:
            name = name.strip()
        if not separator:
            if dash:
                yield Assignment(path=normalise(name), value=None, source=entry.path)
            continue
        value = value.strip(SYSTEMD_SPACE) if reader == SYSTEMD else value.strip()
        yield Assignment(path=normalise(name), value=value, source=entry.path)


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


def sequence(
    raw_entries: Iterable[Mapping[str, object]],
    keys: Sequence[str],
    reader: str,
    after: Sequence[str] = (),
) -> list[tuple[str, str, str]]:
    """Return the settings of ``keys`` that ``reader`` makes, in order, as ``(key, value, source)``.

    systemd merges first and sets each key once, from its last explicit assignment, or from the last
    glob that matches it when no file assigns it explicitly and no ``-key`` line excludes it. procps
    makes every setting in order, a glob's at its own line; the last one wins. The keys a glob sets
    are in the order of their paths.
    """
    entries = load_entries(raw_entries)
    paths = {normalise(key): key for key in keys}
    lines = [
        item
        for entry in ordered_files(entries, reader, after)
        for item in assignments(entry, reader)
    ]
    explicit = {item.path for item in lines if not _is_glob(item.path)}
    settings: list[tuple[str, str, str]] = []
    for item in lines:
        if item.value is None:
            continue
        if not _is_glob(item.path):
            if item.path in paths:
                settings.append((paths[item.path], item.value, item.source))
            continue
        pattern = glob_pattern(item.path)
        settings.extend(
            (paths[path], item.value, item.source)
            for path in sorted(paths, key=_bytes)
            if path not in explicit and re.fullmatch(pattern, path)
        )
    if reader == PROCPS:
        return settings
    last: dict[str, tuple[str, str, str]] = {}
    for setting in settings:
        last[setting[0]] = setting
    return [last[key] for key in keys if key in last]


def effective(
    raw_entries: Iterable[Mapping[str, object]], key: str, after: Sequence[str] = ()
) -> dict[str, dict[str, str | None]]:
    """Return, per reader, the value it sets last for ``key`` and its file, or nulls."""
    entries = [dict(item) for item in raw_entries]
    result: dict[str, dict[str, str | None]] = {}
    for reader in READERS:
        settings = sequence(entries, [key], reader, after)
        value, source = (settings[-1][1], settings[-1][2]) if settings else (None, None)
        result[reader] = {"value": value, "source": source}
    return result
