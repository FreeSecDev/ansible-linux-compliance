"""Filter that turns the walks of a Molecule instance into the records of the lifecycle harness."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, NoReturn, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

DOCUMENTATION = r"""
---
name: lifecycle_record
short_description: Normalise the walks of a Molecule instance into the harness records
version_added: "0.1.0"
description:
  - Used by the Molecule harness of this collection and by nothing else
    (C(extensions/molecule/shared/tasks/snapshot.yml) and C(lifecycle_broad_lines.yml),
    FREES-180). It takes the C(ansible.builtin.find) results of an instance and returns the
    lines that the harness built with Jinja before, byte for byte, because templating the
    100,000 entries of a virtual machine took up to half a minute per record.
  - The no-change snapshot has one line per entry,
    C(path|mode|uid|gid|size|mtime|ctime|checksum), each ended by a space and the two
    characters C(\n) that the Jinja literal C('\n') of the harness renders, in the
    case-insensitive order of the paths. A volatile directory counts with its path, mode and
    owner only, as does an entry whose content a running system rewrites
    (C(volatile_contents)); the times of an entry that matches C(volatile_times) do not count.
  - The whole-instance record has one line per file entry, kernel parameter, package, user,
    group and service, sorted case-insensitively. Only the differences that the harness lists
    in C(docs/molecule.md) are left out.
  - Entries come from three sources, in this order. The walk, without its entries that match
    C(walk_excluded); the entries that further walks listed (C(extra)); and the entries of the
    paths that are listed without their content (C(metadata)). The checksum of an entry is
    its own C(checksum), else its C(checksums) entry, else empty.
  - An entry that ansible-core stores as a plain mapping of text, numbers, booleans and nulls,
    as every C(find) entry is, is read as stored; every other item is rendered (ADR 0031).
  - Raises an error for input of the wrong shape; it never guesses a value.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, options
options:
  _input:
    description:
      - The sources of the record. C(walk) and C(extra) are lists of C(ansible.builtin.find)
        entries, C(walk_excluded) is a regular expression and C(checksums) maps a path to its
        checksum. C(metadata) is the C(listing) of M(freesecdev.linux_compliance.tree_info), or a
        list of C(find) entries.
      - For a whole-instance record also C(sysctl), the C(find) entries below C(/proc/sys);
        C(packages), the C(packages) fact; C(users) and C(groups), the C(getent) databases;
        and C(services), the C(services) fact, or null where no service manager runs.
    type: dict
    required: true
  options:
    description:
      - C(snapshot) holds C(paths), the watched paths of the snapshot or null for every entry;
        C(volatile_directories), a list of paths; and C(volatile_contents) and
        C(volatile_times), regular expressions.
      - C(instance) is null for a snapshot alone. Otherwise it holds C(declared),
        C(rewritten), C(ignored_paths), C(ignored_trees), C(volatile_sysctl) and
        C(volatile_sysctl_trees), lists of paths, and C(volatile_contents) and
        C(volatile_times), regular expressions.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Record the watched paths of the instance
  ansible.builtin.set_fact:
    snapshot_record: >-
      {{ {'walk': find_whole.files, 'walk_excluded': '^$', 'extra': [], 'metadata': [],
          'checksums': {}}
         | freesecdev.linux_compliance.lifecycle_record(
             {'snapshot': snapshot_options, 'instance': none}) }}
"""

RETURN = r"""
_value:
  description:
    - C(snapshot) with C(lines), the text of the no-change snapshot, C(digest), its SHA-256,
      and C(count), its number of entries.
    - C(instance), only for a whole-instance record, with C(lines), the sorted lines joined
      by the same two characters, C(digest), their SHA-256, and C(count), their number.
  type: dict
"""

SNAPSHOT_KEYS: Final[frozenset[str]] = frozenset(
    {"paths", "volatile_directories", "volatile_contents", "volatile_times"}
)
INSTANCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "declared",
        "rewritten",
        "ignored_paths",
        "ignored_trees",
        "volatile_sysctl",
        "volatile_sysctl_trees",
        "volatile_contents",
        "volatile_times",
    }
)
SOURCE_KEYS: Final[frozenset[str]] = frozenset(
    {"walk", "walk_excluded", "extra", "metadata", "checksums"}
)
INSTANCE_SOURCE_KEYS: Final[frozenset[str]] = frozenset(
    {"sysctl", "packages", "users", "groups", "services"}
)
NO_SERVICE_MANAGER: Final[str] = "services|no service manager"
MASKED: Final[str] = "-"
LINE_END: Final[str] = "\\n"
STORED_WRAPPER: Final[str] = "_LazyValue"
PLAIN_TYPES: Final[frozenset[type]] = frozenset({str, int, float, bool, type(None)})
TEXT_TYPES: Final[frozenset[type]] = frozenset({str})
LISTING_SEPARATOR: Final[str] = "\x00"
LISTING_FIELDS: Final[tuple[str, ...]] = (
    "path",
    "kind",
    "mode",
    "uid",
    "gid",
    "size",
    "inode",
    "mtime",
    "ctime",
)
KINDS: Final[frozenset[str]] = frozenset({"link", "file", "directory", "other"})
MAPPING_TYPES: Final[frozenset[type]] = frozenset({dict})


class _Wrapped(Protocol):
    """A stored item that a lazy container of Ansible has not rendered yet."""

    value: object


class RecordError(ValueError):
    """Raised when the sources or options of a record have the wrong shape."""


@dataclass(frozen=True, slots=True)
class Entry:
    """The attributes of one entry of a walk that a record uses, as the text that Jinja printed."""

    path: str
    kind: str
    mode: str
    uid: str
    gid: str
    size: str
    inode: str
    mtime: str
    ctime: str
    checksum: str


@dataclass(frozen=True, slots=True)
class SnapshotOptions:
    """What the no-change snapshot leaves out."""

    paths: tuple[str, ...] | None
    volatile_directories: frozenset[str]
    volatile_contents: str
    volatile_times: str


@dataclass(frozen=True, slots=True)
class InstanceOptions:
    """What the whole-instance record leaves out."""

    declared: frozenset[str]
    parents: frozenset[str]
    rewritten: frozenset[str]
    ignored_paths: frozenset[str]
    ignored_trees: str
    volatile_sysctl: frozenset[str]
    volatile_sysctl_trees: str
    volatile_contents: str
    volatile_times: str


def _fail(message: str) -> NoReturn:
    raise RecordError(message)


def _text(value: object) -> str:
    """Return ``value`` as Jinja prints it: a string as it is, a number as Python prints it."""
    if isinstance(value, str):
        return str(value)
    if isinstance(value, (bool, int, float)):
        return str(value)
    _fail(f"expected a string or a number, got {type(value).__name__}")


def _plain(value: object) -> object:
    """Return ``value`` as plain JSON data, so that every container serialises as it is."""
    if isinstance(value, Mapping):
        return {
            _text(key): _plain(item) for key, item in cast("Mapping[object, object]", value).items()
        }
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in cast("Sequence[object]", value)]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _text(value)


def _mapping(value: object, what: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _fail(f"{what} must be a mapping")
    return cast("Mapping[str, object]", value)


def _list(value: object, what: str) -> Sequence[object]:
    if not isinstance(value, (list, tuple)):
        _fail(f"{what} must be a list")
    return cast("Sequence[object]", value)


def _strings(value: object, what: str) -> tuple[str, ...]:
    items = _list(value, what)
    if not all(isinstance(item, str) for item in items):
        _fail(f"{what} must be a list of strings")
    return tuple(str(item) for item in items)


def _pattern(value: object, what: str) -> str:
    if not isinstance(value, str):
        _fail(f"{what} must be a regular expression")
    return str(value)


def _keys(value: Mapping[str, object], expected: frozenset[str], what: str) -> None:
    if frozenset(value) != expected:
        _fail(f"{what} must have exactly the keys {sorted(expected)}, got {sorted(value)}")


def _tree(paths: Iterable[str]) -> str:
    """Return the expression that the harness built with ``regex_escape`` for these trees."""
    return "^(" + "|".join(re.escape(path) for path in paths) + ")(/|$)"


def dirname(path: str) -> str:
    """Return the directory of ``path`` exactly as ``posixpath.dirname`` returns it."""
    head = path[: path.rfind("/") + 1]
    if head and head != "/" * len(head):
        head = head.rstrip("/")
    return head


def _snapshot_options(value: object) -> SnapshotOptions:
    options = _mapping(value, "the snapshot options")
    _keys(options, SNAPSHOT_KEYS, "the snapshot options")
    paths = options["paths"]
    return SnapshotOptions(
        paths=None if paths is None else _strings(paths, "the snapshot paths"),
        volatile_directories=frozenset(
            _strings(options["volatile_directories"], "the volatile directories")
        ),
        volatile_contents=_pattern(options["volatile_contents"], "volatile_contents"),
        volatile_times=_pattern(options["volatile_times"], "volatile_times"),
    )


def _instance_options(value: object) -> InstanceOptions:
    options = _mapping(value, "the instance options")
    _keys(options, INSTANCE_KEYS, "the instance options")
    declared = _strings(options["declared"], "the declared paths")
    return InstanceOptions(
        declared=frozenset(declared),
        parents=frozenset(dirname(path) for path in declared),
        rewritten=frozenset(_strings(options["rewritten"], "the rewritten paths")),
        ignored_paths=frozenset(_strings(options["ignored_paths"], "the ignored paths")),
        ignored_trees=_tree(_strings(options["ignored_trees"], "the ignored trees")),
        volatile_sysctl=frozenset(_strings(options["volatile_sysctl"], "the volatile parameters")),
        volatile_sysctl_trees=_tree(
            _strings(options["volatile_sysctl_trees"], "the volatile parameter trees")
        ),
        volatile_contents=_pattern(options["volatile_contents"], "volatile_contents"),
        volatile_times=_pattern(options["volatile_times"], "volatile_times"),
    )


def _is_plain_entry(value: object) -> bool:
    """Return whether ``value`` is a mapping of text to text, numbers, booleans and nulls only.

    Ansible renders only text that is trusted as a template, and such text is a tagged subclass
    of ``str``; a value of exactly these types is therefore what rendering it returns.
    """
    if type(value) not in MAPPING_TYPES:
        return False
    fields = cast("dict[object, object]", value)
    return all(
        type(key) in TEXT_TYPES and type(item) in PLAIN_TYPES for key, item in fields.items()
    )


def stored_items(value: object, what: str) -> list[object]:
    """Return the items of the list ``value``, read as stored when that is the same as rendered.

    This is the one adapter of ADR 0031 to the lazy containers of ansible-core. A filter gets a
    list from the variables as a lazy container that renders each item when it is read, which
    costs about 30 microseconds for a ``find`` entry, three seconds for the 100,000 entries of a
    walk. The container stores each item that it has not rendered yet in a wrapper named
    ``_LazyValue``. An item stored as a plain entry (see ``_is_plain_entry``), which every
    entry of a ``find`` result is, is used as stored; every other item, including one stored
    without that wrapper, is read through the container and so rendered. If ansible-core
    stores items differently, every item is read through the container: slower, the same lines.
    """
    items = _list(value, what)
    if not isinstance(items, list):
        return list(items)
    found: list[object] = []
    for index, stored in enumerate(list[object].copy(items)):
        if type(stored).__name__ == STORED_WRAPPER:
            candidate = cast("_Wrapped", stored).value
        else:
            candidate = stored
        found.append(candidate if _is_plain_entry(candidate) else items[index])
    return found


def _kind(entry: Mapping[str, object]) -> str:
    if entry["islnk"]:
        return "link"
    if entry["isreg"]:
        return "file"
    if entry["isdir"]:
        return "directory"
    return "other"


def _entry(raw: object, checksums: Mapping[str, object]) -> Entry:
    entry = _mapping(raw, "an entry")
    try:
        path = _text(entry["path"])
        checksum = entry["checksum"] if "checksum" in entry else checksums.get(path, "")
        return Entry(
            path=path,
            kind=_kind(entry),
            mode=_text(entry["mode"]),
            uid=_text(entry["uid"]),
            gid=_text(entry["gid"]),
            size=_text(entry["size"]),
            inode=_text(entry["inode"]),
            mtime=_text(entry["mtime"]),
            ctime=_text(entry["ctime"]),
            checksum=_text(checksum),
        )
    except KeyError as error:
        message = f"an entry lacks the key {error}"
        raise RecordError(message) from error


def entries(sources: Mapping[str, object]) -> list[Entry]:
    """Return the entries of the walk, the further walks and the metadata walk, in that order."""
    excluded = _pattern(sources["walk_excluded"], "walk_excluded")
    checksums = _mapping(sources["checksums"], "the checksums")
    walked = [_entry(raw, checksums) for raw in stored_items(sources["walk"], "the walk")]
    found = [entry for entry in walked if not re.match(excluded, entry.path)]
    found.extend(
        _entry(raw, checksums) for raw in stored_items(sources["extra"], "the extra entries")
    )
    found.extend(_metadata_entries(sources["metadata"], checksums))
    return found


def _metadata_entries(raw: object, checksums: Mapping[str, object]) -> list[Entry]:
    """Return the entries of a ``tree_info`` listing, or of a list of ``find`` entries."""
    if not isinstance(raw, str):
        return [_entry(item, checksums) for item in stored_items(raw, "the metadata walk")]
    values = raw.split(LISTING_SEPARATOR)
    width = len(LISTING_FIELDS)
    if values[-1] or (len(values) - 1) % width:
        _fail(f"the metadata listing must hold whole entries of {width} fields")
    return [
        _listed_entry(values[start : start + width], checksums)
        for start in range(0, len(values) - 1, width)
    ]


def _listed_entry(fields: list[str], checksums: Mapping[str, object]) -> Entry:
    path, kind, mode, uid, gid, size, inode, mtime, ctime = fields
    if kind not in KINDS:
        _fail(f"the metadata listing names the unknown type {kind!r} for {path}")
    checksum = _text(checksums.get(path, ""))
    return Entry(path, kind, mode, uid, gid, size, inode, mtime, ctime, checksum)


def _ordered(found: Iterable[Entry]) -> list[Entry]:
    return sorted(found, key=lambda entry: entry.path.lower())


def _below(path: str, paths: tuple[str, ...]) -> bool:
    return any(path.startswith(root + "/") for root in paths)


def snapshot_text(found: Iterable[Entry], options: SnapshotOptions) -> tuple[str, int]:
    """Return the no-change snapshot of ``found`` and its number of entries."""
    selected = [
        entry for entry in found if options.paths is None or _below(entry.path, options.paths)
    ]
    lines: list[str] = []
    for entry in _ordered(selected):
        if entry.path in options.volatile_directories:
            tail = "volatile-directory"
        elif re.match(options.volatile_contents, entry.path):
            tail = "volatile-contents"
        elif re.match(options.volatile_times, entry.path):
            tail = f"{entry.size}|volatile-times|{entry.checksum}"
        else:
            tail = f"{entry.size}|{entry.mtime}|{entry.ctime}|{entry.checksum}"
        lines.append(f"{entry.path}|{entry.mode}|{entry.uid}|{entry.gid}|{tail} {LINE_END}")
    return "".join(lines), len(selected)


def _file_line(entry: Entry, options: InstanceOptions) -> str:
    volatile = re.match(options.volatile_contents, entry.path) is not None
    masked_times = (
        volatile
        or entry.path in options.declared
        or entry.path in options.parents
        or re.match(options.volatile_times, entry.path) is not None
    )
    times = f"{MASKED}|{MASKED}" if masked_times else f"{entry.mtime}|{entry.ctime}"
    size = MASKED if volatile else entry.size
    inode = MASKED if volatile or entry.path in options.rewritten else entry.inode
    checksum = MASKED if volatile else entry.checksum
    return (
        f"file|{entry.path}|{entry.kind}|{entry.mode}|{entry.uid}|{entry.gid}|{size}|{inode}|"
        f"{times}|{checksum}{LINE_END}"
    )


def _sysctl_lines(
    raw: object, checksums: Mapping[str, object], options: InstanceOptions
) -> Iterable[str]:
    parameters = [_mapping(item, "a kernel parameter") for item in stored_items(raw, "sysctl")]
    for parameter in sorted(parameters, key=lambda item: _text(item["path"]).lower()):
        path = _text(parameter["path"])
        if path in options.volatile_sysctl or re.match(options.volatile_sysctl_trees, path):
            continue
        value = parameter["checksum"] if "checksum" in parameter else checksums.get(path, "")
        yield f"sysctl|{path}|{_text(value)}{LINE_END}"


def _by_name(raw: object, what: str) -> list[tuple[str, object]]:
    items = [(_text(name), value) for name, value in _mapping(raw, what).items()]
    return sorted(items, key=lambda item: item[0].lower())


def _json(value: object) -> str:
    return json.dumps(_plain(value))


def _package_line(name: str, versions: object) -> str:
    described = [
        _json(
            sorted(_mapping(version, "a package version").items(), key=lambda item: item[0].lower())
        )
        for version in _list(versions, "the versions of a package")
    ]
    return f"package|{name}|{','.join(sorted(described, key=str.lower))}{LINE_END}"


def _service_line(name: str, raw: object) -> str:
    service = _mapping(raw, "a service")
    state = _text(service["state"]) if "state" in service else ""
    status = _text(service["status"]) if "status" in service else ""
    return f"service|{name}|{state}|{status}{LINE_END}"


def instance_lines(
    found: Iterable[Entry], sources: Mapping[str, object], options: InstanceOptions
) -> list[str]:
    """Return the sorted lines of the whole-instance record."""
    checksums = _mapping(sources["checksums"], "the checksums")
    parts = [
        _file_line(entry, options)
        for entry in _ordered(found)
        if entry.path not in options.ignored_paths
        and not re.match(options.ignored_trees, entry.path)
    ]
    parts.extend(_sysctl_lines(sources["sysctl"], checksums, options))
    parts.extend(
        _package_line(name, versions)
        for name, versions in _by_name(sources["packages"], "packages")
    )
    parts.extend(
        f"user|{name}|{_json(entry)}{LINE_END}"
        for name, entry in _by_name(sources["users"], "users")
    )
    parts.extend(
        f"group|{name}|{_json(entry)}{LINE_END}"
        for name, entry in _by_name(sources["groups"], "groups")
    )
    if sources["services"] is None:
        parts.append(f"{NO_SERVICE_MANAGER}{LINE_END}")
    else:
        parts.extend(
            _service_line(name, raw) for name, raw in _by_name(sources["services"], "services")
        )
    lines = [line for line in "".join(parts).split(LINE_END) if line]
    return sorted(lines, key=str.lower)


def digest(text: str) -> str:
    """Return the SHA-256 of ``text`` as the ``hash('sha256')`` filter computes it."""
    return hashlib.sha256(text.encode("utf-8", errors="surrogateescape")).hexdigest()


def lifecycle_record(sources: object, options: object) -> dict[str, object]:
    """Return the no-change snapshot and, when asked for, the whole-instance record."""
    given = _mapping(sources, "the sources")
    chosen = _mapping(options, "the options")
    _keys(chosen, frozenset({"snapshot", "instance"}), "the options")
    instance = None if chosen["instance"] is None else _instance_options(chosen["instance"])
    _keys(
        given, SOURCE_KEYS | (INSTANCE_SOURCE_KEYS if instance else frozenset[str]()), "the sources"
    )
    found = entries(given)
    text, count = snapshot_text(found, _snapshot_options(chosen["snapshot"]))
    record: dict[str, object] = {
        "snapshot": {"lines": text, "digest": digest(text), "count": count}
    }
    if instance is not None:
        lines = instance_lines(found, given, instance)
        joined = LINE_END.join(lines)
        record["instance"] = {"lines": joined, "digest": digest(joined), "count": len(lines)}
    return record


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object, object], dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"lifecycle_record": lifecycle_record}
