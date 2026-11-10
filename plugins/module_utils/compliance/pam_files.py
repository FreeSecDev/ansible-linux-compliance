"""Sort the entries of the PAM directories into the files to read and those that refuse (FREES-213).

libpam opens a service name, and every ``include`` and ``substack`` target, with
``fopen(path, "r")`` in ``_pam_open_config_file`` of ``libpam/pam_handlers.c`` (linux-pam 1.5.1
on Rocky Linux 9, 1.5.3 on Ubuntu 24.04). ``fopen`` follows symbolic links, so on a host where
authselect makes ``/etc/pam.d/system-auth`` a link into ``/etc/authselect``, libpam reads the
file that the link names. ``ansible.builtin.find`` with ``file_type: file`` keeps only regular
files, whatever ``follow`` says, so the families list every entry with ``file_type: any``, stat
every link through it and without following it, and sort the entries here:

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
  link to ``/dev/zero`` or to a FIFO is never opened. The error message of a failed ``stat`` is
  kept in the entry's ``detail`` and in the reason (FREES-212);
- a link, or a PAM directory, that resolves to a path below ``/proc``, ``/sys`` or ``/dev`` is
  unreadable too (FREES-212): such a file can read differently in the process that calls libpam
  than in the module that reads it for the collection; ``/proc/self/environ``, for example, is
  the environment of whichever process opens it;
- when neither ``/etc/pam.d`` nor ``/usr/lib/pam.d`` is a directory, libpam reads
  ``/etc/pam.conf`` instead of any service file (FREES-212). Ubuntu's libpam 1.5.3 has no vendor
  directory; libpam 1.5.1 on Rocky Linux 9 also needs ``/usr/share/pam.d`` to be missing, so the
  condition here holds whenever either reads ``/etc/pam.conf``. The collection does not read that
  file, whose lines carry the service name first, so ``/etc/pam.conf`` is returned as
  unreadable and the families refuse.

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
VIRTUAL: Final[str] = "virtual_file"
PAM_CONF_FALLBACK: Final[str] = "pam_conf_fallback"
PAM_CONF: Final[str] = "/etc/pam.conf"
CONFIGURATION_DIRECTORIES: Final[tuple[str, ...]] = ("/etc/pam.d", "/usr/lib/pam.d")
VIRTUAL_ROOTS: Final[tuple[str, ...]] = ("/proc", "/sys", "/dev")
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
    VIRTUAL: (
        "resolves to a path below /proc, /sys or /dev, which can read differently in the process "
        "that calls libpam than in the collection's"
    ),
    PAM_CONF_FALLBACK: (
        "is what libpam reads instead of the service files, because neither /etc/pam.d nor "
        "/usr/lib/pam.d is a directory, and the collection does not read it"
    ),
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


def _message(stat: Mapping[str, object]) -> str | None:
    """Return the error message of a failed ``stat`` (its ``msg``), or None when it has none."""
    message = stat.get("msg")
    return message if isinstance(message, str) and message else None


def is_virtual(path: str) -> bool:
    """Return whether a resolved path lies below ``/proc``, ``/sys`` or ``/dev``."""
    return any(path == root or path.startswith(root + "/") for root in VIRTUAL_ROOTS)


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


def _resolution(path: str, resolved: Mapping[str, object]) -> tuple[str | None, str | None]:
    """Return the path that ``path`` resolves to and, when it is unknown, why.

    ``resolved`` holds the ``ansible.builtin.stat`` with ``follow: false`` of the path; for a
    symbolic link it carries ``lnk_source``, the path that ``os.path.realpath`` resolves it to.
    """
    if path not in resolved:
        return None, "it was not resolved"
    stat = _mapping(resolved[path], f"the resolution of {path}")
    if "exists" not in stat:
        return None, _message(stat) or "it could not be resolved"
    what = f"the resolution of {path}"
    if not _flag(stat, "exists", what) or not _flag(stat, "islnk", what):
        return path, None
    source = stat.get("lnk_source")
    if not isinstance(source, str) or not source.startswith("/"):
        message = f"{what} needs the absolute lnk_source of a symbolic link, got {source!r}"
        raise PamEntryError(message)
    return source, None


def _directories(
    directories: Mapping[str, object], resolved: Mapping[str, object]
) -> tuple[dict[str, tuple[str, str | None]], bool]:
    """Return the unreadable PAM directories and whether libpam reads the PAM directories.

    The second value says whether ``/etc/pam.d`` or ``/usr/lib/pam.d`` is a directory, as libpam
    tests with ``stat``; when neither is, libpam reads ``/etc/pam.conf`` instead. Nothing below an
    unreadable directory is read.
    """
    unreadable: dict[str, tuple[str, str | None]] = {}
    configured = False
    for name, stat in directories.items():
        what = f"the stat of the PAM directory {name}"
        directory = _mapping(stat, what)
        path = _path({"path": name}, "every PAM directory")
        if "exists" not in directory:
            unreadable[path] = (UNINSPECTED_DIRECTORY, _message(directory))
            continue
        if not _flag(directory, "exists", what) or not _flag(directory, "isdir", what):
            continue
        configured = configured or path in CONFIGURATION_DIRECTORIES
        real, problem = _resolution(path, resolved)
        if real is None:
            unreadable[path] = (UNINSPECTED_DIRECTORY, problem)
        elif is_virtual(real):
            unreadable[path] = (VIRTUAL, real)
    return unreadable, configured


def _link(
    path: str, targets: Mapping[str, object], resolved: Mapping[str, object]
) -> tuple[str, str | None]:
    """Return ``file``, ``directory`` or the unreadable kind of a link, with its detail."""
    if path not in targets:
        return UNFOLLOWED_LINK, None
    target = _mapping(targets[path], f"the stat of the link {path}")
    kind = _kind_of_target(path, target)
    if kind == UNFOLLOWED_LINK:
        return kind, _message(target)
    if kind != "file":
        return kind, None
    real, problem = _resolution(path, resolved)
    if real is None:
        return UNFOLLOWED_LINK, problem
    if is_virtual(real):
        return VIRTUAL, real
    return kind, None


def _entries(
    entries: Sequence[object],
    targets: Mapping[str, object],
    resolved: Mapping[str, object],
    unreadable: dict[str, tuple[str, str | None]],
) -> set[str]:
    """Return the entries to read, and add every entry that cannot be read to ``unreadable``."""
    read: set[str] = set()
    for item in entries:
        entry = _mapping(item, "every PAM directory entry")
        path = _path(entry, "every PAM directory entry")
        what = f"the PAM directory entry {path}"
        if _flag(entry, "isreg", what):
            read.add(path)
        elif _flag(entry, "isdir", what):
            continue
        elif _flag(entry, "islnk", what):
            kind, detail = _link(path, targets, resolved)
            if kind == "file":
                read.add(path)
            elif kind != "directory":
                unreadable[path] = (kind, detail)
        else:
            unreadable[path] = (SPECIAL, None)
    return read


def sort_entries(
    entries: Sequence[object],
    targets: Mapping[str, object],
    skipped: Sequence[object],
    directories: Mapping[str, object],
    resolved: Mapping[str, object],
) -> dict[str, list[object]]:
    """Return the paths to read and the unreadable entries of the PAM directories.

    ``entries`` are the files of ``ansible.builtin.find`` with ``file_type: any`` and
    ``follow: false``, each with ``path``, ``isreg``, ``isdir`` and ``islnk`` from ``lstat``.
    ``targets`` maps the path of every entry that is a link to its ``ansible.builtin.stat``
    result with ``follow: true``, or to a mapping with the ``msg`` of a stat that failed; a link
    that has no stat there, or whose stat has no ``exists`` because ``stat`` failed on it, is
    :data:`UNFOLLOWED_LINK`, never read. ``skipped`` holds the paths of the ``skipped_paths`` of
    the find. ``directories`` maps every PAM directory to its ``ansible.builtin.stat`` result
    with ``follow: true``, or to the ``msg`` of a stat that failed; one whose stat has no
    ``exists`` is :data:`UNINSPECTED_DIRECTORY`. A directory that does not exist, or is not a
    directory, is left out, as libpam leaves it out; when neither ``/etc/pam.d`` nor
    ``/usr/lib/pam.d`` is a directory, ``/etc/pam.conf`` is :data:`PAM_CONF_FALLBACK`.
    ``resolved`` maps every PAM directory that is a directory and every link that resolves to a
    regular file to its ``ansible.builtin.stat`` with ``follow: false``, whose ``lnk_source`` is
    the path a link resolves to; one that resolves below ``/proc``, ``/sys`` or ``/dev`` is
    :data:`VIRTUAL`, and one missing there, or whose stat failed, is unreadable as well. The
    result holds ``read``, the sorted paths to read, and ``unreadable``, every entry to refuse
    on, with ``path``, ``kind`` (one of :data:`KINDS`) and, when there is one, ``detail``: the
    error message of the failed stat or the path below ``/proc``, ``/sys`` or ``/dev``.
    """
    unreadable, configured = _directories(directories, resolved)
    refused = set(unreadable)
    read = _entries(entries, targets, resolved, unreadable)
    for name in skipped:
        if not isinstance(name, str) or not name.startswith("/"):
            message = f"a skipped PAM path must be absolute, got {name!r}"
            raise PamEntryError(message)
        read.discard(name)
        unreadable[name] = (UNLISTED, None)
    read = {path for path in read if path.rpartition("/")[0] not in refused}
    if not configured:
        unreadable[PAM_CONF] = (PAM_CONF_FALLBACK, None)
    return {
        "read": cast("list[object]", sorted(read)),
        "unreadable": [_unreadable(path, *unreadable[path]) for path in sorted(unreadable)],
    }


def _unreadable(path: str, kind: str, detail: str | None) -> dict[str, str]:
    return {"path": path, "kind": kind} | ({} if detail is None else {"detail": detail})


def describe(unreadable: object) -> list[str]:
    """Return ``<path> <what it is>[: <detail>]`` for every unreadable entry of the sort."""
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
        detail = entry.get("detail")
        if detail is not None and not isinstance(detail, str):
            message = f"the unreadable PAM entry {path} needs a text detail, got {detail!r}"
            raise PamEntryError(message)
        found.append(f"{path} {KINDS[kind]}" + (f": {detail}" if detail else ""))
    return sorted(found)
