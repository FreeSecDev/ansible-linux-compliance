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
- a directory, or a link to one, is left out: ``fopen`` opens it, and libpam reads no line from
  it. Every read of a directory fails with ``EISDIR``, whichever reader the version has (the
  ``getline`` one of 1.5.1 on Rocky Linux 9, the fixed-buffer one of 1.5.3 on Ubuntu 24.04), and
  libpam treats the directory as an empty file. It still takes that entry for the name and does
  not look for the name in a lower PAM directory, so a service of that name falls back to
  ``other`` and an include of it adds nothing. The families still read a regular file of the
  same name in a lower PAM directory, which libpam does not open; that can only add a refusal,
  never hide one;
- a link that resolves to nothing, a link to anything else (a FIFO, a device, a socket), a link
  that ``stat`` could not follow (a loop, a path through something that is not a directory, or
  any other error of ``stat``, which the families record instead of failing the run), an entry
  that is none of a regular file, a directory and a link, and an entry that ``find`` could not
  inspect are returned as unreadable, and so is a PAM directory that ``stat`` could not
  inspect through a link (a loop, for example), because the collection cannot list what libpam
  might find there. The families refuse their rules on any of them, because
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
UNFOLLOWED_LINK: Final[str] = "unfollowed_link"
UNINSPECTED_DIRECTORY: Final[str] = "uninspected_directory"
UNLISTED: Final[str] = "unlisted"
KINDS: Final[Mapping[str, str]] = {
    BROKEN_LINK: "is a symbolic link that resolves to nothing",
    LINK: "is a symbolic link to something that is neither a regular file nor a directory",
    UNFOLLOWED_LINK: (
        "is a symbolic link that stat could not follow (a loop, a path through something that "
        "is not a directory, or another error)"
    ),
    SPECIAL: "is neither a regular file, a directory nor a symbolic link",
    UNINSPECTED_DIRECTORY: (
        "is a PAM directory that stat could not inspect (a loop, a path through something that "
        "is not a directory, or another error)"
    ),
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
    """Return ``file``, ``directory`` or the unreadable kind of a link from its followed stat.

    A stat without ``exists`` is one that failed: ``ansible.builtin.stat`` returns no ``stat``
    when ``os.stat`` raises anything but ``FileNotFoundError``, for example ``ELOOP`` or
    ``ENOTDIR``, so the link is :data:`UNFOLLOWED_LINK`.
    """
    what = f"the stat of the link {path}"
    if "exists" not in target:
        return UNFOLLOWED_LINK
    if not _flag(target, "exists", what):
        return BROKEN_LINK
    if _flag(target, "isreg", what):
        return "file"
    if _flag(target, "isdir", what):
        return "directory"
    return LINK


def _uninspected(directories: Mapping[str, object]) -> list[str]:
    """Return every PAM directory whose stat failed, so that it has no ``exists``."""
    found: list[str] = []
    for name, stat in directories.items():
        what = f"the stat of the PAM directory {name}"
        directory = _mapping(stat, what)
        path = _path({"path": name}, "every PAM directory")
        if "exists" not in directory:
            found.append(path)
        else:
            _flag(directory, "exists", what)
    return found


def sort_entries(
    entries: Sequence[object],
    targets: Mapping[str, object],
    skipped: Sequence[object],
    directories: Mapping[str, object],
) -> dict[str, list[object]]:
    """Return the paths to read and the unreadable entries of the PAM directories.

    ``entries`` are the files of ``ansible.builtin.find`` with ``file_type: any`` and
    ``follow: false``, each with ``path``, ``isreg``, ``isdir`` and ``islnk`` from ``lstat``.
    ``targets`` maps the path of every entry that is a link to its ``ansible.builtin.stat``
    result with ``follow: true``; a link that has no stat there, or whose stat has no ``exists``
    because ``stat`` failed on it, is :data:`UNFOLLOWED_LINK`, never read. ``skipped`` holds the
    paths of the ``skipped_paths`` of the find. ``directories`` maps every PAM directory to its
    ``ansible.builtin.stat`` result with ``follow: true``; one whose stat has no ``exists``,
    because ``stat`` failed on it, is :data:`UNINSPECTED_DIRECTORY`. A directory that does not
    exist, or is not a directory, is left out, as libpam leaves it out. The result holds
    ``read``, the sorted paths to read, and ``unreadable``, every entry to refuse on, with
    ``path`` and ``kind`` (one of :data:`KINDS`).
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
            kind = (
                _kind_of_target(path, _mapping(targets[path], f"the stat of the link {path}"))
                if path in targets
                else UNFOLLOWED_LINK
            )
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
    unreadable.update(dict.fromkeys(_uninspected(directories), UNINSPECTED_DIRECTORY))
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
