r"""Model of how systemd-sysctl and procps decide a persistent kernel parameter (FREES-107).

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
  ``-key`` line without ``=`` only excludes the key from globs. A glob never sets a path that any
  line names exactly as written, so ``net/ipv4//conf/all/rp_filter`` excludes nothing. procps
  expands a configuration file name with glob(3), braces and ``~`` included, so a name with one of
  ``*?[]{}~\`` may read other files a second time; the model does not follow that and reports it in
  ``unsupported``, for every ``*.conf`` entry whatever its kind.

Both skip empty lines and ``#`` and ``;`` comments and drop a leading ``-`` of an assignment.
systemd strips spaces, tabs and line ends from the key and the value, also after the ``-``; procps
strips the characters of C ``isspace`` (space, tab, line feed, vertical tab, form feed, carriage
return) from the line, the value and the end of the key, but not from the key after a ``-``. An
entry that is a directory or a link claims its file name as well: a link to ``/dev/null`` masks a
file of the same name in a later directory, and so does a directory.

What the model cannot prove to match both readers is reported in ``unsupported`` instead of being
guessed: a procps key that still starts with ``-`` after the first one is dropped (procps drops a
second one from the path it opens), a procps glob that is not in canonical form (a repeated slash,
a ``.`` component, a leading or trailing slash: glob(3) keeps them in the paths it returns, and
procps compares those with the keys as written), a glob with a component that starts with ``.``
(it can match ``.`` and ``..``), and a glob that :func:`glob_pattern` cannot translate exactly.

Files named in ``after`` (ufw's ``/etc/ufw/sysctl.conf``, which ufw applies with ``sysctl -p`` when
it starts) are read last with the rules of procps, after either reader.

``tests/fixtures/sysctl_reader/verdicts.json`` holds what the readers of the Molecule images wrote
into a private ``/proc/sys`` for the cases of ``cases.json`` (``make sysctl-reader-verdicts``); the
unit tests check this model against every value.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

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
PROCPS_SPACE: Final[str] = " \t\n\v\f\r"
SYSTEMD_LINE_END: Final[str] = r"\r\n|[\r\n\0]"
GLOB_CHARACTERS: Final[frozenset[str]] = frozenset("*?[")
GLOB_REFUSED: Final[frozenset[str]] = frozenset("\\{}")
GLOB_RANGES: Final[tuple[tuple[str, str], ...]] = (("0", "9"), ("a", "z"), ("A", "Z"))
PROCPS_NAME_EXPANSION: Final[frozenset[str]] = frozenset("*?[]{}~\\")
SYSTEMD_LINE_LIMIT: Final[int] = 1_000_000
UFW_CONF: Final[str] = "/etc/ufw/ufw.conf"
UFW_DEFAULT: Final[str] = "/etc/default/ufw"
UFW_SYSCTL: Final[str] = "/etc/ufw/sysctl.conf"
UFW_ENABLED: Final[frozenset[str]] = frozenset({"yes", "YES"})
SHELL_PLAIN: Final[str] = (
    r"([A-Za-z_][A-Za-z0-9_]*)="
    r"(?:([A-Za-z0-9_./,:+@%-]*)|'([^']*)'|\"([^\"$`\\]*)\")"
)
SHELL_BLANK: Final[str] = " \t"
UFW_VALUE: Final[str] = r"[A-Za-z0-9_./-]*"
UFW_VARIABLES: Final[tuple[str, ...]] = ("ENABLED", "IPT_SYSCTL")
UFW_NAMES: Final[frozenset[str]] = frozenset(
    {
        "ENABLED",
        "LOGLEVEL",
        "IPV6",
        "DEFAULT_INPUT_POLICY",
        "DEFAULT_OUTPUT_POLICY",
        "DEFAULT_FORWARD_POLICY",
        "DEFAULT_APPLICATION_POLICY",
        "MANAGE_BUILTINS",
        "IPT_SYSCTL",
        "IPT_MODULES",
    }
)
KINDS: Final[frozenset[str]] = frozenset({"file", "link", "directory", "other"})
READABLE_KINDS: Final[frozenset[str]] = frozenset({"file", "link"})
LINK_TARGETS: Final[frozenset[str]] = frozenset({"file", "null"})
KERNEL_INTEGER: Final[str] = r"0|-?[1-9][0-9]{0,18}"
KERNEL_VECTOR_SEPARATOR: Final[str] = r"[ \t]+"


class ConfigError(ValueError):
    """The entries handed to the model are malformed."""


@dataclass(frozen=True)
class Entry:
    """One entry of a configuration directory, ``/etc/sysctl.conf`` or a file read after boot.

    ``target`` says what a link points to: ``file`` (a regular file, whose content is ``text``),
    ``null`` (``/dev/null``) or anything else (a FIFO, a device, a directory or nothing).
    """

    path: str
    kind: str
    text: str | None
    target: str | None = None


@dataclass(frozen=True)
class Assignment:
    """A value for a key below ``/proc/sys``; for a ``-key`` line without ``=``, ``value`` is None.

    ``path`` is the path that the reader opens below ``/proc/sys``, or None when it opens none;
    ``raw`` is the key as the reader keeps it, with dots and slashes interchanged, which procps
    compares with the paths that a glob returns; ``problems`` says why the model cannot follow the
    line.
    """

    path: str | None
    value: str | None
    source: str
    escapes: bool = False
    raw: str = ""
    problems: tuple[str, ...] = ()


def load_entries(raw: Iterable[Mapping[str, object]]) -> list[Entry]:
    """Return the entries of ``raw``.

    Each is a mapping with ``path``, ``kind``, ``text`` and, for a link, ``target``.
    """
    entries: list[Entry] = []
    for item in raw:
        path = item.get("path")
        kind = item.get("kind")
        text = item.get("text")
        target = item.get("target")
        if not isinstance(path, str) or not path.startswith("/") or kind not in KINDS:
            message = f"an entry needs an absolute path and a kind of {sorted(KINDS)}: {dict(item)}"
            raise ConfigError(message)
        if text is not None and not isinstance(text, str):
            message = f"the text of {path} must be a string or null"
            raise ConfigError(message)
        if target is not None and not isinstance(target, str):
            message = f"the target of {path} must be a string or null"
            raise ConfigError(message)
        entries.append(Entry(path=path, kind=str(kind), text=text, target=target))
    return entries


def kernel_integer(value: object) -> int | None:
    """Return the integer that the kernel takes from ``value`` for an integer parameter, or None.

    The kernel reads an integer with ``proc_get_long``, in base 0: a leading ``0`` is octal and
    ``0x`` hexadecimal, a leading ``+`` and a value of 21 characters or more are refused, and the
    unsigned handlers (``proc_douintvec``, ``proc_dou8vec_minmax``) refuse any ``-``. Only the
    plain decimal form (``^(0|-?[1-9][0-9]{0,18})$``, so not ``-0``) reads the same in base 10
    and base 0 for every handler, so any other form gives None, which the caller treats as a value
    that is not accepted.
    """
    if not isinstance(value, str) or re.fullmatch(KERNEL_INTEGER, value) is None:
        return None
    return int(value)


def kernel_vector(value: object, count: int) -> list[int] | None:
    """Return the ``count`` integers that the kernel takes from ``value`` for a vector, or None.

    The kernel reads a vector such as ``net.ipv4.ip_local_port_range`` with ``proc_dointvec``:
    each field with ``proc_get_long`` in base 0, followed only by a space, a tab or a line feed
    (``proc_wspace_sep``), so a vertical tab between the fields and ``32768 65535x`` are refused.
    The model accepts only fields separated by spaces and tabs, exactly ``count`` of them, each in
    the form of :func:`kernel_integer`; any other value gives None, which the caller treats as a
    value that is not accepted. The handler's own bounds (1 to 65535 for the port range, the low
    end not above the high end) hold for every value that equals an accepted vector.
    """
    if not isinstance(value, str):
        return None
    fields = [kernel_integer(field) for field in re.split(KERNEL_VECTOR_SEPARATOR, value)]
    if len(fields) != count:
        return None
    found = [field for field in fields if field is not None]
    return found if len(found) == count else None


def _bytes(text: str) -> bytes:
    return text.encode("utf-8", "surrogateescape")


def _listed(entries: Sequence[Entry]) -> list[Entry]:
    """Return every ``*.conf`` entry of the configuration directories, whatever its kind."""
    return [
        entry
        for entry in entries
        if entry.path.rsplit("/", 1)[0] in DIRECTORIES
        and entry.path.rsplit("/", 1)[1].endswith(".conf")
    ]


def ordered_files(entries: Sequence[Entry], reader: str) -> list[Entry]:
    """Return the files that ``reader`` reads, in the order it reads them."""
    by_path = {entry.path: entry for entry in entries}
    listed = _listed(entries)
    chosen: dict[str, Entry] = {}
    for directory in DIRECTORIES:
        for entry in listed:
            parent, name = entry.path.rsplit("/", 1)
            if parent != directory or (reader == SYSTEMD and name.startswith(".")):
                continue
            chosen.setdefault(name, entry)
    files = [chosen[name] for name in sorted(chosen, key=_bytes)]
    if reader == PROCPS and SYSCTL_CONF in by_path:
        files.append(by_path[SYSCTL_CONF])
    return [entry for entry in files if entry.kind in READABLE_KINDS]


def problems(lines: Iterable[Assignment]) -> list[str]:
    """Return, once each and in order, why the model cannot follow some of ``lines``."""
    return list(
        dict.fromkeys(f"{item.source}: {problem}" for item in lines for problem in item.problems)
    )


def unsupported(entries: Sequence[Entry]) -> list[str]:
    """Return why the model cannot decide what a reader writes, or an empty list.

    procps lists every ``*.conf`` name of its directories, whatever the kind of the entry, and
    expands it with glob(3), so a name with a glob, brace, tilde or backslash character may read
    other files a second time, at its own place in the order; a reader blocks on a FIFO and reads
    a device such as ``/dev/zero`` without end, so such an entry, and a link to anything but a
    regular file or ``/dev/null``, is refused; procps opens a key with a ``..``
    component as the kernel resolves it, which may leave ``/proc/sys`` and come back; systemd stops
    reading a file at a line of 1 MiB or more; and some keys are refused line by line (see
    :func:`assignments`).
    """
    reasons = [
        f"{entry.path}: sysctl --system expands the name of this entry as a pattern, which may"
        " read other files a second time"
        for entry in _listed(entries)
        if PROCPS_NAME_EXPANSION & set(entry.path.rsplit("/", 1)[1])
    ]
    reasons.extend(
        f"{entry.path}: a FIFO, socket or device, or a link to something other than a regular"
        " file or /dev/null, on which a reader may block or which it may read without end"
        for entry in _listed(entries)
        if entry.kind == "other" or (entry.kind == "link" and entry.target not in LINK_TARGETS)
    )
    for entry in ordered_files(entries, PROCPS):
        lines = list(assignments(entry, PROCPS))
        if any(item.escapes for item in lines):
            reasons.append(
                f"{entry.path}: a key with a .. component, which sysctl --system resolves"
            )
        reasons.extend(problems(lines))
    for entry in ordered_files(entries, SYSTEMD):
        if any(
            len(_bytes(line)) >= SYSTEMD_LINE_LIMIT for line in _lines(entry.text or "", SYSTEMD)
        ):
            reasons.append(
                f"{entry.path}: a line of 1 MiB or more, at which systemd-sysctl stops reading"
            )
        reasons.extend(problems(assignments(entry, SYSTEMD)))
    return list(dict.fromkeys(reasons))


def _shell_assignments(text: str) -> dict[str, str] | None:
    """Return the variables that a sourced shell file assigns, or None when it does more.

    Only comments, blank lines and plain ``NAME=value`` assignments of a variable that ufw
    defines (``UFW_NAMES``), whose value is a word without expansions or a quoted string without
    ``$``, backticks or backslashes, are read; any other line (``;``, ``&&``, a command, ``.`` or
    ``source``, ``export``, an expansion, a line continuation, a variable such as ``IFS``,
    ``PATH``, ``ENV``, ``BASH_ENV`` or ``LD_PRELOAD`` that changes how the script runs) makes the
    file one that the model does not follow.
    """
    values: dict[str, str] = {}
    for raw in text.split("\n"):
        line = raw.strip(SHELL_BLANK)
        if not line or line.startswith("#"):
            continue
        found = re.fullmatch(SHELL_PLAIN, line)
        if found is None or found.group(1) not in UFW_NAMES:
            return None
        name, word, single, double = found.groups()
        values[name] = word if word is not None else single if single is not None else double
    return values


def _ufw_sourced(entry: Entry | None) -> bool:
    """Return whether ufw's start script sources ``entry``, a non-empty regular file or link."""
    if entry is None or not entry.text:
        return False
    return entry.kind == "file" or (entry.kind == "link" and entry.target == "file")


def _ufw_values(by_path: Mapping[str, Entry]) -> tuple[dict[str, str] | None, list[str]]:
    """Return the variables of ufw's sourced files, in ufw's order, and what is unclear.

    The caller has made sure that both files exist when ``ufw.conf`` does.
    """
    if UFW_CONF not in by_path:
        return {}, []
    values: dict[str, str] = {}
    for path in (UFW_DEFAULT, UFW_CONF):
        found = _shell_assignments(by_path[path].text or "")
        if found is None:
            return None, [
                (
                    f"{path}: a line other than a comment or a plain NAME=value assignment of a"
                    " variable that ufw defines, which ufw's start script runs and the collection"
                    " cannot follow"
                )
            ]
        values.update(found)
    if any(re.fullmatch(UFW_VALUE, values.get(name, "")) is None for name in UFW_VARIABLES):
        return None, [
            (
                f"{UFW_CONF}: ENABLED or IPT_SYSCTL holds a character other than a letter, a"
                " digit or one of _./-, which the collection cannot follow"
            )
        ]
    return values, []


def ufw_files(entries: Sequence[Entry]) -> tuple[list[str], list[str]]:
    """Return the file that ufw applies with ``sysctl -p`` when it starts, and what is unclear.

    ufw sources ``/etc/default/ufw`` and then ``/etc/ufw/ufw.conf``, so a variable of either counts
    and the later assignment wins. Its start script stops before it applies anything unless both
    are non-empty regular files (``[ -s ... ] || exit 1``), so then the file counts for no reader.
    Both files must hold only comments, blank lines and plain assignments of ufw's own variables,
    and ``ENABLED`` and ``IPT_SYSCTL`` only letters, digits and ``_./-``; anything else is refused
    as unclear. ufw applies ``IPT_SYSCTL`` only when ``ENABLED`` is ``yes`` or ``YES``; another
    spelling of yes is refused as unclear. Without ``ufw.conf`` ufw is not installed.
    """
    by_path = {entry.path: entry for entry in entries}
    if UFW_CONF in by_path and not all(
        _ufw_sourced(by_path.get(path)) for path in (UFW_DEFAULT, UFW_CONF)
    ):
        return [], []
    values, unclear = _ufw_values(by_path)
    if values is None:
        return [], unclear
    enabled = values.get("ENABLED", "")
    target = values.get("IPT_SYSCTL", "")
    if enabled not in UFW_ENABLED or not target:
        spelling = enabled not in UFW_ENABLED and enabled.lower() == "yes"
        return [], (
            [f"{UFW_CONF}: ENABLED is a spelling of yes that ufw may not read as yes"]
            if spelling
            else []
        )
    if target != UFW_SYSCTL:
        return [], [f"{UFW_DEFAULT}: ufw applies IPT_SYSCTL, which the collection cannot follow"]
    return [UFW_SYSCTL], []


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


def _canonical(path: str) -> bool:
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def _line_problems(name: str, path: str | None, reader: str) -> tuple[str, ...]:
    """Return why the model cannot follow a key that ``reader`` keeps as ``name``.

    procps builds the path from the key without a second leading ``-``; a procps glob is
    expanded as written, so it must be canonical; a glob component that starts with ``.`` can
    match ``.`` and ``..``; and a glob must translate exactly.
    """
    found: list[str] = []
    raw = _swap(name)
    if reader == PROCPS and name.startswith("-"):
        found.append("a key that starts with a second -, which procps drops from the path it opens")
    pattern = raw if reader == PROCPS else path
    if pattern is None or not _is_glob(pattern):
        return tuple(found)
    if reader == PROCPS and not _canonical(pattern):
        found.append(
            "a glob with a repeated slash, a . component or a leading or trailing slash, whose"
            " matches procps compares with the keys as written"
        )
    if any(part.startswith(".") for part in pattern.split("/")):
        found.append("a glob with a component that starts with ., which can match . and ..")
    if glob_pattern(pattern) is None:
        found.append("a glob that the collection cannot translate exactly")
    return tuple(found)


def assignments(entry: Entry, reader: str) -> Iterator[Assignment]:
    """Yield the assignments of one file, in order, including ``-key`` lines without ``=``."""
    space = SYSTEMD_SPACE if reader == SYSTEMD else PROCPS_SPACE
    for raw in _lines(entry.text or "", reader):
        line = raw.strip(space)
        if not line or line[0] in "#;":
            continue
        name, separator, value = line.partition("=")
        dash = name.startswith("-")
        name = name.removeprefix("-")
        name = name.strip(space) if reader == SYSTEMD or not dash else name.rstrip(space)
        if not name or (not separator and not dash):
            continue
        path = normalise(name, reader)
        yield Assignment(
            path=path,
            value=value.strip(space) if separator else None,
            source=entry.path,
            escapes=".." in _swap(name).split("/"),
            raw=_swap(name),
            problems=_line_problems(name, path, reader),
        )


def _is_glob(path: str) -> bool:
    return any(character in GLOB_CHARACTERS for character in path)


def _members(body: str) -> str | None:
    """Return the regular expression members of a bracket expression, or None.

    Only single characters and ranges within the digits, the lower-case or the upper-case ASCII
    letters translate exactly; a ``-`` is literal only first or last.
    """
    members: list[str] = []
    index = 0
    while index < len(body):
        low = body[index]
        if index + 2 < len(body) and body[index + 1] == "-":
            high = body[index + 2]
            if not any(first <= low <= high <= last for first, last in GLOB_RANGES):
                return None
            members.append(f"{re.escape(low)}-{re.escape(high)}")
            index += 3
            continue
        if low == "-" and 0 < index < len(body) - 1:
            return None
        members.append(re.escape(low))
        index += 1
    return "".join(members)


def _bracket(path: str, start: int) -> tuple[str, int] | None:
    """Return the expression of the bracket at ``start`` and the index of its ``]``, or None.

    glob(3) splits a pattern at ``/`` first, and a ``]`` right after ``[``, ``[!`` or ``[^`` is a
    member. None means that the bracket is not closed within its component (glob(3) and fnmatch
    disagree with each other about such a ``[`` followed by ``-`` or ``[.``) or holds a class, an
    equivalence class, a collating symbol or a range that does not translate.
    """
    component_end = path.find("/", start)
    if component_end == -1:
        component_end = len(path)
    first = start + 1
    negate = path[first : first + 1] in {"!", "^"}
    if negate:
        first += 1
    end = path.find("]", first + 1, component_end) if first < component_end else -1
    body = path[first:end]
    members = None if end == -1 or "[" in body else _members(body)
    if members is None:
        return None
    return f"[{'^/' if negate else ''}{members}]", end


def glob_pattern(path: str) -> str | None:
    """Return the regular expression, for ``re.fullmatch``, of a glob(7) pattern over a path.

    Both readers expand a glob with glob(3) below ``/proc/sys``: ``*`` and ``?`` never match a
    ``/``, a bracket expression matches one character other than ``/``, and none of them matches a
    ``.`` at the start of a component. A pattern that does not translate exactly (a ``[`` that is
    not closed within its component, a backslash escape, a brace, a character class, a range other
    than of digits or ASCII letters, a character outside ASCII) gives None, which the model
    refuses.
    """
    if not path.isascii() or GLOB_REFUSED & set(path):
        return None
    parts: list[str] = []
    index = 0
    while index < len(path):
        character = path[index]
        guard = "(?!\\.)" if index == 0 or path[index - 1] == "/" else ""
        if character == "*":
            parts.append(f"{guard}[^/]*")
        elif character == "?":
            parts.append(f"{guard}[^/]")
        elif character == "[":
            found = _bracket(path, index)
            if found is None:
                return None
            expression, end = found
            parts.append(f"{guard}{expression}")
            index = end
        else:
            parts.append(re.escape(character))
        index += 1
    return "".join(parts)


def _matches(pattern: str, path: str) -> bool:
    expression = glob_pattern(pattern)
    return expression is not None and re.fullmatch(expression, path) is not None


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


def _procps_writes(lines: Sequence[Assignment], path: str) -> list[int]:
    """Return the indexes of the lines with which procps writes ``path``, in its order."""
    named = {item.raw for item in lines if not _is_glob(item.raw)}
    return [
        index
        for index, item in enumerate(lines)
        if item.path is not None
        and item.value is not None
        and (
            item.path == path
            or (_is_glob(item.path) and path not in named and _matches(item.path, path))
        )
    ]


def _procps(lines: Sequence[Assignment], path: str) -> tuple[str, str] | None:
    writes = _procps_writes(lines, path)
    if not writes:
        return None
    item = lines[writes[-1]]
    return str(item.value), item.source


def effective(raw_entries: Iterable[Mapping[str, object]], key: str) -> dict[str, object]:
    """Return what each reader writes last for ``key``, its file, and what the model cannot follow.

    The result maps ``systemd`` and ``procps`` to ``{"value", "source"}`` (nulls when the reader
    writes nothing), and ``unsupported`` to a list of reasons; the caller must refuse to decide
    when that list is not empty.
    """
    entries = load_entries(raw_entries)
    by_path = {entry.path: entry for entry in entries}
    path = normalise(key) or key
    after, unclear = ufw_files(entries)
    late = [
        item for name in after if name in by_path for item in assignments(by_path[name], PROCPS)
    ]
    later = _procps(late, path)
    unclear.extend(
        f"{item.source}: a key with a .. component, which sysctl -p resolves"
        for item in late
        if item.escapes
    )
    unclear.extend(problems(late))
    result: dict[str, object] = {}
    for reader in READERS:
        lines = [
            item for entry in ordered_files(entries, reader) for item in assignments(entry, reader)
        ]
        found = later or (_systemd(lines, path) if reader == SYSTEMD else _procps(lines, path))
        result[reader] = (
            {"value": found[0], "source": found[1]} if found else {"value": None, "source": None}
        )
    result["unsupported"] = unsupported(entries) + unclear
    return result


def _refusing(value: str, refused: Sequence[int]) -> bool:
    found = kernel_integer(value)
    return found is None or found in refused


def _procps_refusal(
    parts: Sequence[Sequence[Assignment]],
    key_path: str,
    companion_path: str,
    refused: Sequence[int],
) -> dict[str, str] | None:
    """Return the first refusing assignment of the companion before procps's last write of the key.

    ``parts`` are the runs of procps in order (``sysctl --system``, then ufw's ``sysctl -p``),
    each with its own exclusions from globs.
    """
    sequence: list[Assignment] = []
    key_writes: list[int] = []
    companion_writes: list[int] = []
    for part in parts:
        offset = len(sequence)
        key_writes.extend(offset + index for index in _procps_writes(part, key_path))
        companion_writes.extend(offset + index for index in _procps_writes(part, companion_path))
        sequence.extend(part)
    return next(
        (
            {"value": str(sequence[index].value), "source": sequence[index].source}
            for index in companion_writes
            if key_writes
            and index < key_writes[-1]
            and _refusing(str(sequence[index].value), refused)
        ),
        None,
    )


def companion_refusals(
    raw_entries: Iterable[Mapping[str, object]],
    key: str,
    companion: str,
    refused: Sequence[int],
) -> dict[str, dict[str, str] | None]:
    """Return, per reader, the setting of ``companion`` at which the kernel refuses ``key``.

    The kernel refuses some parameters while another has certain values:
    ``kernel.perf_event_max_sample_rate`` while ``kernel.perf_cpu_time_max_percent`` is 0 or 100.
    A value of the companion that :func:`kernel_integer` does not read counts as one of
    ``refused`` (it may be one in another notation). For ``systemd`` the setting is the
    companion's last value, as :func:`effective` decides it (ufw's file included). ``procps``
    makes every assignment in turn, so for it the setting is the first assignment of the companion
    with such a value that comes before the last assignment of ``key``, in the files of
    ``sysctl --system`` and then in those that ufw applies with ``sysctl -p``; a later assignment
    that sets the companion back comes too late for that write. The result maps ``systemd`` and
    ``procps`` to ``{"value", "source"}`` of that setting, or None when the reader's write of
    ``key`` is not refused.
    """
    entries = load_entries(raw_entries)
    by_path = {entry.path: entry for entry in entries}
    key_path = normalise(key) or key
    companion_path = normalise(companion) or companion
    after, _ = ufw_files(entries)
    late = [
        item for name in after if name in by_path for item in assignments(by_path[name], PROCPS)
    ]
    boot = [item for entry in ordered_files(entries, PROCPS) for item in assignments(entry, PROCPS)]
    procps = _procps_refusal((boot, late), key_path, companion_path, refused)
    systemd_lines = [
        item for entry in ordered_files(entries, SYSTEMD) for item in assignments(entry, SYSTEMD)
    ]
    found = _procps(late, companion_path) or _systemd(systemd_lines, companion_path)
    systemd = (
        {"value": found[0], "source": found[1]} if found and _refusing(found[0], refused) else None
    )
    return {SYSTEMD: systemd, PROCPS: procps}


def _with_companion(
    entries: Sequence[Mapping[str, object]], plan: Mapping[str, object], path: str, content: str
) -> list[Mapping[str, object]]:
    """Return ``entries`` as they will be after the companion rule's ``plan``.

    The vendor lines that the plan edits are swapped for the lines it writes, and when it writes
    its drop-in, the drop-in at ``path`` holds ``content``.
    """
    edits = cast("list[Mapping[str, object]]", plan.get("edits") or [])
    write = bool(plan.get("write"))
    result: list[Mapping[str, object]] = []
    for item in entries:
        if write and item.get("path") == path:
            continue
        mine = {
            str(edit.get("original")): str(edit.get("written"))
            for edit in edits
            if edit.get("path") == item.get("path")
        }
        if mine and isinstance(item.get("text"), str):
            lines = str(item["text"]).split("\n")
            result.append({**item, "text": "\n".join(mine.get(line, line) for line in lines)})
        else:
            result.append(item)
    if write:
        result.append({"path": path, "kind": "file", "text": content})
    return result


def companion_check(
    planned_entries: Sequence[Mapping[str, object]],
    current_entries: Sequence[Mapping[str, object]],
    key: str,
    blocker: Mapping[str, object],
    rule: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Decide whether the companion makes the kernel refuse ``key``, before and after the run.

    ``planned_entries`` are the entries with the drop-in and the vendor edits of the rule of
    ``key``; ``current_entries`` those as they are. ``rule`` describes the companion's own rule
    when it is selected in the same run: ``plan`` (its plan entry, with ``status``, ``write`` and
    ``edits``, or None when it is not decided yet), ``path`` (its drop-in) and ``content``. Only
    when its status is ``applied`` or ``compliant`` will its drop-in and edits take effect, so only
    then are they added to the planned entries; with any other status, or without the rule, the
    companion is judged as the files leave it. A selected rule without a plan entry is
    ``undecided``, which the caller must refuse. ``blocker`` names the companion (``key``) and
    the integers at which the kernel refuses ``key`` (``refused``). The result holds
    ``undecided`` and, for ``planned`` and ``current``, :func:`companion_refusals`.

    Raises:
        ConfigError: If ``blocker`` does not name a companion and a list of integers.
    """
    companion = blocker.get("key")
    refused = blocker.get("refused")
    if not isinstance(companion, str) or not isinstance(refused, list):
        message = f"a companion needs a key and a list of refused integers: {dict(blocker)}"
        raise ConfigError(message)
    values = [value for value in cast("list[object]", refused) if isinstance(value, int)]
    if len(values) != len(cast("list[object]", refused)):
        message = f"the refused values of {companion} must be integers: {refused}"
        raise ConfigError(message)
    plan = rule.get("plan") if rule is not None else None
    entries: Sequence[Mapping[str, object]] = planned_entries
    if rule is not None and isinstance(plan, Mapping):
        decided = cast("Mapping[str, object]", plan)
        if decided.get("status") in {"applied", "compliant"}:
            entries = _with_companion(
                planned_entries, decided, str(rule.get("path")), str(rule.get("content"))
            )
    return {
        "undecided": rule is not None and not isinstance(plan, Mapping),
        "planned": companion_refusals(entries, key, companion, values),
        "current": companion_refusals(current_entries, key, companion, values),
    }
