"""Sort the entries of the PAM directories into the files to read and those that refuse (FREES-213).

libpam opens a service name, and every ``include`` and ``substack`` target, with
``fopen(path, "r")`` in ``_pam_open_config_file`` of ``libpam/pam_handlers.c`` (linux-pam 1.5.1
on Rocky Linux 9, 1.5.3 on Ubuntu 24.04). ``fopen`` follows symbolic links, so on a host where
authselect makes ``/etc/pam.d/system-auth`` a link into ``/etc/authselect``, libpam reads the
file that the link names. ``ansible.builtin.find`` with ``file_type: file`` keeps only regular
files, whatever ``follow`` says, so the families list every entry with ``file_type: any``, stat
every link through it, and sort the entries here:

- a regular file, or a link that resolves to one, is read; it keeps the name in the PAM
  directory, which is the name that libpam opens;
- a directory, or a link to one, is left out: ``fopen`` opens it, ``getline`` then fails with
  ``EISDIR``, and ``_pam_assemble_line`` takes that for the end of the file, so libpam reads no
  line from it;
- a link that resolves to nothing, a link to anything else (a FIFO, a device, a socket), an entry
  that is none of a regular file, a directory and a link, and an entry that ``find`` could not
  inspect are returned as unreadable. The families refuse their rules on any of them, because
  the collection cannot read what libpam would read there; nothing is read through them, so a
  link to ``/dev/zero`` or to a FIFO is never opened.

Only the Python standard library is used, and nothing here touches a host.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

BROKEN_LINK: Final[str] = "broken_link"
LINK: Final[str] = "link"
SPECIAL: Final[str] = "special"
UNLISTED: Final[str] = "unlisted"
KINDS: Final[Mapping[str, str]] = {
    BROKEN_LINK: "is a symbolic link that resolves to nothing",
    LINK: "is a symbolic link to something that is neither a regular file nor a directory",
    SPECIAL: "is neither a regular file, a directory nor a symbolic link",
    UNLISTED: "could not be inspected when the PAM directories were listed",
}


class PamEntryError(ValueError):
    """The entries, the link targets or the unreadable entries have the wrong shape."""


def _mapping(value: object, what: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        message = f"{what} must be a mapping"
        raise PamEntryError(message)
    found = cast("dict[object, object]", value)
    if not all(isinstance(key, str) for key in found):
        message = f"{what} must be a mapping"
        raise PamEntryError(message)
    return cast("Mapping[str, object]", found)


def _path(entry: Mapping[str, object], what: str) -> str:
    path = entry.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        message = f"{what} needs an absolute path, got {path!r}"
        raise PamEntryError(message)
    return path


def _flag(entry: Mapping[str, object], name: str, what: str) -> bool:
    value = entry.get(name)
    if not isinstance(value, bool):
        message = f"{what} needs a boolean {name}"
        raise PamEntryError(message)
    return value


def _kind_of_target(path: str, target: Mapping[str, object]) -> str:
    """Return ``file``, ``directory`` or the unreadable kind of a link from its followed stat."""
    what = f"the stat of the link {path}"
    if not _flag(target, "exists", what):
        return BROKEN_LINK
    if _flag(target, "isreg", what):
        return "file"
    if _flag(target, "isdir", what):
        return "directory"
    return LINK


def sort_entries(
    entries: Sequence[object], targets: Mapping[str, object], skipped: Sequence[object]
) -> dict[str, list[object]]:
    """Return the paths to read and the unreadable entries of the PAM directories.

    ``entries`` are the files of ``ansible.builtin.find`` with ``file_type: any`` and
    ``follow: false``, each with ``path``, ``isreg``, ``isdir`` and ``islnk`` from ``lstat``.
    ``targets`` maps the path of every entry that is a link to its ``ansible.builtin.stat``
    result with ``follow: true``. ``skipped`` holds the paths of the ``skipped_paths`` of the
    find. The result holds ``read``, the sorted paths to read, and ``unreadable``, every entry to
    refuse on, with ``path`` and ``kind`` (one of :data:`KINDS`).
    """
    read: set[str] = set()
    unreadable: dict[str, str] = {}
    for item in entries:
        entry = _mapping(item, "every PAM directory entry")
        path = _path(entry, "every PAM directory entry")
        what = f"the PAM directory entry {path}"
        if _flag(entry, "isreg", what):
            read.add(path)
        elif _flag(entry, "isdir", what):
            continue
        elif _flag(entry, "islnk", what):
            if path not in targets:
                message = f"the link {path} has no stat through the link"
                raise PamEntryError(message)
            kind = _kind_of_target(path, _mapping(targets[path], f"the stat of the link {path}"))
            if kind == "file":
                read.add(path)
            elif kind != "directory":
                unreadable[path] = kind
        else:
            unreadable[path] = SPECIAL
    for name in skipped:
        if not isinstance(name, str) or not name.startswith("/"):
            message = f"a skipped PAM path must be absolute, got {name!r}"
            raise PamEntryError(message)
        read.discard(name)
        unreadable[name] = UNLISTED
    return {
        "read": cast("list[object]", sorted(read)),
        "unreadable": [{"path": path, "kind": unreadable[path]} for path in sorted(unreadable)],
    }


def describe(unreadable: object) -> list[str]:
    """Return ``<path> <what it is>`` for every unreadable entry of :func:`sort_entries`."""
    if not isinstance(unreadable, (list, tuple)):
        message = "the unreadable PAM entries must be a list"
        raise PamEntryError(message)
    found: list[str] = []
    for item in cast("Sequence[object]", unreadable):
        entry = _mapping(item, "every unreadable PAM entry")
        path = _path(entry, "every unreadable PAM entry")
        kind = entry.get("kind")
        if not isinstance(kind, str) or kind not in KINDS:
            message = f"the unreadable PAM entry {path} needs a kind of {sorted(KINDS)}"
            raise PamEntryError(message)
        found.append(f"{path} {KINDS[kind]}")
    return sorted(found)
