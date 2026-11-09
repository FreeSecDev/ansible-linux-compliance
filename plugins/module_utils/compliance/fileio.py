"""Audited file input and output for root-owned state directories.

This is the only module of the collection that may use ``os`` beyond ``os.path``
and the only one that may import ``fcntl``, ``errno`` and ``time`` (ADR 0011).
It uses only the Python standard library and syntax that runs on Python 3.9, the
oldest managed-node interpreter supported by ansible-core 2.20.

The helper offers one safe way to keep a small file in a private directory:

* :func:`open_directory` walks the path from ``/`` one component at a time with
  ``O_NOFOLLOW`` and ``O_DIRECTORY`` relative to the parent descriptor, so no
  component can be a symlink. The final directory must be owned by the expected
  user and have no group or world permission bits. It can be created with mode
  ``0700``.
* :class:`SafeDirectory` performs every later operation relative to the
  directory descriptor, never through the path again, so replacing the path
  after it was opened has no effect.
* Reads open the file with ``O_NOFOLLOW`` and ``O_NONBLOCK`` and then check the
  opened descriptor: a regular file, the expected owner, no group or world
  permission bits, a single hard link and a size within the bound.
* Writes go to a new temporary file in the same directory (``O_EXCL``, mode
  ``0600``), are fsynced, renamed over the target and followed by an fsync of the
  directory. A failure removes the temporary file and leaves the old file intact.
* :meth:`SafeDirectory.lock` takes an exclusive ``flock`` on the directory
  descriptor, with a timeout, so concurrent runs are serialised.

Refusals raise :class:`SafeFileError` with a stable ``reason``. Nothing is
silently repaired: an unsafe file or directory is an error, not something to fix.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import time
from typing import Final, NoReturn

ROOT_UID: Final[int] = 0
DIRECTORY_MODE: Final[int] = 0o700
FILE_MODE: Final[int] = 0o600
FORBIDDEN_MODE_BITS: Final[int] = 0o077
MAX_PATH_LENGTH: Final[int] = 4096
MAX_NAME_LENGTH: Final[int] = 200
READ_CHUNK_BYTES: Final[int] = 65536
DEFAULT_LOCK_TIMEOUT_SECONDS: Final[float] = 30.0
LOCK_POLL_SECONDS: Final[float] = 0.02
MEGABYTE: Final[int] = 1024 * 1024
TEMPORARY_SUFFIX: Final[str] = ".tmp"
TEMPORARY_HEX_PATTERN: Final[str] = "[0-9a-f]{16}"
SYMLINK_ERRORS: Final[frozenset[int]] = frozenset({errno.ELOOP, errno.EMLINK})

REASONS: Final[frozenset[str]] = frozenset(
    {
        "unsupported_platform",
        "unsafe_path",
        "symlink",
        "not_regular",
        "not_directory",
        "wrong_owner",
        "unsafe_mode",
        "hardlinked",
        "too_large",
        "lock_timeout",
        "io_error",
    }
)


class SafeFileError(Exception):
    """A refusal or failure of a safe file operation, with a stable ``reason``."""

    def __init__(self, reason: str, message: str) -> None:
        """Store the reason and message."""
        super().__init__(message)
        self.reason = reason


def filesystem_megabytes(path: str) -> int | None:
    """Return the size of the file system that holds ``path`` in MiB, or ``None`` if unreadable.

    The auditd settings ``space_left`` and ``admin_space_left`` may be percentages of the file
    system of the audit log; auditd compares them in megabytes, so the remediate role needs this
    size to check them before it writes either (FREES-110). Nothing is opened or written.
    """
    try:
        info = os.statvfs(path)
    except OSError:
        return None
    return info.f_frsize * info.f_blocks // MEGABYTE


def _fail(reason: str, message: str) -> NoReturn:
    raise SafeFileError(reason, message)


def _io_failure(error: OSError, action: str) -> NoReturn:
    if error.errno in SYMLINK_ERRORS:
        _fail("symlink", f"{action}: a symbolic link was refused")
    if error.errno == errno.ENOTDIR:
        _fail("not_directory", f"{action}: not a directory")
    _fail("io_error", f"{action}: {error.strerror or 'operating system error'}")


try:
    import fcntl
except ImportError:

    def _flock_supported() -> bool:
        return False

    def _try_lock(descriptor: int) -> bool:
        _fail("unsupported_platform", f"this platform lacks flock (descriptor {descriptor})")

else:

    def _flock_supported() -> bool:
        return True

    def _try_lock(descriptor: int) -> bool:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        except OSError as error:
            _io_failure(error, "cannot lock the state directory")
        return True


def _directory_open_failure(error: OSError, parent: int, name: str) -> NoReturn:
    if error.errno == errno.ENOTDIR:
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError:
            _io_failure(error, f"cannot open directory {name!r}")
        if stat.S_ISLNK(info.st_mode):
            _fail("symlink", f"cannot open directory {name!r}: a symbolic link was refused")
    _io_failure(error, f"cannot open directory {name!r}")


def _require_dir_fd_support() -> None:
    try:
        _probe = (
            os.O_RDONLY,
            os.O_WRONLY,
            os.O_CREAT,
            os.O_EXCL,
            os.O_DIRECTORY,
            os.O_NOFOLLOW,
            os.O_NONBLOCK,
            os.O_CLOEXEC,
        )
    except AttributeError:
        _fail("unsupported_platform", "this platform lacks the required open flags")
    if not _flock_supported():
        _fail("unsupported_platform", "this platform lacks flock")
    required = {os.open, os.mkdir, os.rename, os.stat, os.unlink}
    if not required <= os.supports_dir_fd:
        _fail("unsupported_platform", "this platform lacks directory-relative file operations")


def _components(path: object) -> tuple[str, ...]:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > MAX_PATH_LENGTH:
        _fail("unsafe_path", "the state directory must be an absolute path")
    if "\x00" in path:
        _fail("unsafe_path", "the state directory contains a NUL byte")
    parts = tuple(part for part in path.split("/") if part)
    if not parts or any(part in {".", ".."} for part in parts):
        _fail("unsafe_path", "the state directory has no name or contains '.' or '..'")
    return parts


def _check_name(name: object) -> str:
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_LENGTH:
        _fail("unsafe_path", "the file name is not a plain name")
    if "/" in name or "\x00" in name or name in {".", ".."}:
        _fail("unsafe_path", "the file name is not a plain name")
    return name


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_child(parent: int, name: str, *, create: bool) -> int | None:
    try:
        return os.open(name, _directory_flags(), dir_fd=parent)
    except FileNotFoundError:
        if not create:
            return None
    except OSError as error:
        _directory_open_failure(error, parent, name)
    try:
        os.mkdir(name, DIRECTORY_MODE, dir_fd=parent)
        created = True
    except FileExistsError:
        created = False
    except OSError as error:
        _io_failure(error, f"cannot create directory {name!r}")
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent)
    except OSError as error:
        _directory_open_failure(error, parent, name)
    if created:
        try:
            os.fchmod(descriptor, DIRECTORY_MODE)
        except OSError as error:
            os.close(descriptor)
            _io_failure(error, f"cannot set the mode of directory {name!r}")
    return descriptor


def _check_directory(descriptor: int, *, owner_uid: int) -> None:
    info = os.fstat(descriptor)
    if info.st_uid != owner_uid:
        _fail("wrong_owner", f"the state directory is not owned by uid {owner_uid}")
    if stat.S_IMODE(info.st_mode) & FORBIDDEN_MODE_BITS:
        _fail("unsafe_mode", "the state directory has group or world permission bits")


def _walk(parts: tuple[str, ...], *, create: bool) -> int | None:
    current = os.open("/", _directory_flags())
    for name in parts:
        try:
            child = _open_child(current, name, create=create)
        finally:
            os.close(current)
        if child is None:
            return None
        current = child
    return current


def open_directory(
    path: str, *, owner_uid: int = ROOT_UID, create: bool = False
) -> SafeDirectory | None:
    """Open a private state directory without following any symlink.

    Args:
        path: Absolute path of the directory.
        owner_uid: Required owner. Keyword-only; only tests change the default, root.
        create: Create missing components with mode ``0700``.

    Returns:
        The opened directory, or ``None`` if it does not exist and ``create`` is false.

    Raises:
        SafeFileError: If the path is unsafe, a component is a symlink or not a
            directory, or the final directory has the wrong owner or mode.
    """
    parts = _components(path)
    _require_dir_fd_support()
    try:
        descriptor = _walk(parts, create=create)
    except OSError as error:
        _io_failure(error, "cannot open the state directory")
    if descriptor is None:
        return None
    try:
        _check_directory(descriptor, owner_uid=owner_uid)
    except BaseException:
        os.close(descriptor)
        raise
    return SafeDirectory(descriptor, owner_uid=owner_uid)


class SafeDirectory:
    """A directory descriptor with confined, atomic file operations."""

    def __init__(self, descriptor: int, *, owner_uid: int) -> None:
        """Take ownership of an already vetted directory descriptor."""
        self._descriptor: int | None = descriptor
        self._owner_uid = owner_uid

    def close(self) -> None:
        """Close the descriptor. Closing twice is harmless; closing releases the lock."""
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is not None:
            os.close(descriptor)

    def _open_descriptor(self) -> int:
        if self._descriptor is None:
            _fail("io_error", "the directory is closed")
        return self._descriptor

    def lock(self, timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS) -> None:
        """Take an exclusive lock on the directory, waiting at most ``timeout_seconds``.

        Raises:
            SafeFileError: With reason ``lock_timeout`` if the lock stays busy.
        """
        descriptor = self._open_descriptor()
        deadline = time.monotonic() + timeout_seconds
        while not _try_lock(descriptor):
            if time.monotonic() >= deadline:
                _fail("lock_timeout", "another run holds the state lock")
            time.sleep(LOCK_POLL_SECONDS)

    def read(self, name: str, max_bytes: int) -> bytes | None:
        """Read a vetted regular file of at most ``max_bytes`` bytes.

        Returns:
            The content, or ``None`` if the file does not exist.

        Raises:
            SafeFileError: If the file is a symlink, not regular, has the wrong
                owner, group or world permission bits, several hard links, or is
                larger than ``max_bytes``.
        """
        plain = _check_name(name)
        directory = self._open_descriptor()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            descriptor = os.open(plain, flags, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError as error:
            _io_failure(error, f"cannot open {plain!r}")
        try:
            return self._read_vetted(descriptor, plain, max_bytes)
        except OSError as error:
            _io_failure(error, f"cannot read {plain!r}")
        finally:
            os.close(descriptor)

    def _read_vetted(self, descriptor: int, name: str, max_bytes: int) -> bytes:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            _fail("not_regular", f"{name!r} is not a regular file")
        if info.st_uid != self._owner_uid:
            _fail("wrong_owner", f"{name!r} is not owned by uid {self._owner_uid}")
        if stat.S_IMODE(info.st_mode) & FORBIDDEN_MODE_BITS:
            _fail("unsafe_mode", f"{name!r} has group or world permission bits")
        if info.st_nlink != 1:
            _fail("hardlinked", f"{name!r} has more than one hard link")
        if info.st_size > max_bytes:
            _fail("too_large", f"{name!r} exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > max_bytes:
                _fail("too_large", f"{name!r} exceeds {max_bytes} bytes")
            chunks.append(chunk)

    def write(self, name: str, data: bytes) -> None:
        """Atomically replace ``name`` with ``data``, mode ``0600``.

        The data is written to a new temporary file, fsynced, renamed over the
        target and the directory is fsynced. If anything fails, the temporary file
        is removed and the previous content stays in place.

        Raises:
            SafeFileError: If the write, fsync, rename or directory fsync fails.
        """
        plain = _check_name(name)
        directory = self._open_descriptor()
        temporary = f".{plain}.{os.urandom(8).hex()}{TEMPORARY_SUFFIX}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            descriptor = os.open(temporary, flags, FILE_MODE, dir_fd=directory)
        except OSError as error:
            _io_failure(error, f"cannot create a temporary file for {plain!r}")
        try:
            self._commit(directory, descriptor, temporary, plain, data)
        except BaseException as error:
            self._discard(directory, temporary)
            if isinstance(error, OSError):
                _io_failure(error, f"cannot write {plain!r}")
            raise

    def _commit(
        self, directory: int, descriptor: int, temporary: str, name: str, data: bytes
    ) -> None:
        try:
            os.fchmod(descriptor, FILE_MODE)
            if os.fstat(descriptor).st_uid != self._owner_uid:
                _fail("wrong_owner", f"new files would not be owned by uid {self._owner_uid}")
            view = memoryview(data)
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)

    @staticmethod
    def _discard(directory: int, temporary: str) -> bool:
        try:
            os.unlink(temporary, dir_fd=directory)
        except OSError:
            return False
        return True

    def sweep_temporaries(self, name: str) -> int:
        """Remove stale temporary files that an interrupted :meth:`write` of ``name`` left.

        Only entries named exactly ``.<name>.<16 hex digits>.tmp`` that are regular
        files owned by the expected user are removed; symlinks, directories and
        everything else are left alone. Call it while holding the lock.

        Returns:
            The number of files removed.

        Raises:
            SafeFileError: If the directory cannot be listed.
        """
        plain = _check_name(name)
        directory = self._open_descriptor()
        pattern = re.escape(f".{plain}.") + TEMPORARY_HEX_PATTERN + re.escape(TEMPORARY_SUFFIX)
        try:
            with os.scandir(directory) as entries:
                candidates = [entry.name for entry in entries]
        except OSError as error:
            _io_failure(error, "cannot list the state directory")
        return sum(
            self._sweep_one(directory, candidate)
            for candidate in candidates
            if re.fullmatch(pattern, candidate) is not None
        )

    def _sweep_one(self, directory: int, candidate: str) -> bool:
        try:
            info = os.stat(candidate, dir_fd=directory, follow_symlinks=False)
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self._owner_uid:
            return False
        return self._discard(directory, candidate)
