"""Read and set running kernel parameters below ``/proc/sys`` (FREES-107, ADR 0029).

The remediate role writes the persistent value of a kernel parameter as a drop-in below
``/etc/sysctl.d`` with ``ansible.builtin.copy`` and sets the running value through the
``sysctl_runtime`` module, which uses this helper. No external program runs: the value is read
from and written to the parameter's own file below ``/proc/sys``, as ``sysctl -w`` does.

The helper accepts only parameter names of two to eight dot-separated components; ``.``
separates the components (``net.ipv4.ip_forward`` is ``/proc/sys/net/ipv4/ip_forward``) and, as
for ``sysctl(8)``, a ``/`` inside a component stands for a ``.`` of the file name
(``net.ipv4.conf.eth0/100.forwarding`` is the interface ``eth0.100``). The first component is
lower-case letters, digits and ``_``; the others may also hold upper-case letters, ``-``, ``+``
and ``@``, as interface names do, and a component that would become ``.`` or ``..`` is refused,
so a name cannot reach outside ``/proc/sys``. One component of a name to *read* may be ``*``,
which :func:`expand` turns into the names that exist, such as every interface below
``net.ipv4.conf``. Before it opens a file, the helper resolves the path
and requires that it is the path itself (no component is a symbolic link), that it is a regular
file and that it is on the same file system as ``/proc/sys``, so a file mounted over a parameter
is refused. A procfs file cannot be replaced atomically; the value is written with one
``write`` to the open file, which is how the kernel takes a parameter, and is read back.

Values are printable ASCII and tabs without line breaks, at most 255 characters: the values of the
native rules of the catalogue (``1``, ``32768 65535``, ``|/bin/false``, the empty string) and the
values read before them, which the kernel may print with tabs between fields. A read strips the
one line break that the kernel appends; :func:`normalise` collapses the
whitespace that the kernel prints between the fields of a value (``32768<TAB>65535``), so that a
value read back compares equal to the value that was written.

Failures raise :class:`SysctlError` with a stable ``reason``: ``invalid_name``,
``invalid_value``, ``absent``, ``not_regular``, ``unsafe_path``, ``too_large`` and
``io_error``.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Final, NoReturn

PROC_SYS: Final[Path] = Path("/proc/sys")
NAME_PATTERN: Final[str] = r"[a-z0-9_]+(?:\.(?:[A-Za-z0-9_@+/-]{1,64}|\*)){1,7}"
VALUE_PATTERN: Final[str] = r"[\t\x20-\x7e]{0,255}"
WILDCARD: Final[str] = "*"
MAX_READ_BYTES: Final[int] = 4096
MAX_EXPANDED: Final[int] = 512
REASONS: Final[frozenset[str]] = frozenset(
    {
        "invalid_name",
        "invalid_value",
        "absent",
        "not_regular",
        "unsafe_path",
        "too_large",
        "io_error",
    }
)


class SysctlError(Exception):
    """A refused or failed access to a kernel parameter, with a stable ``reason``."""

    def __init__(self, reason: str, message: str) -> None:
        """Store the reason and the message."""
        super().__init__(message)
        self.reason = reason


def _fail(reason: str, message: str) -> NoReturn:
    raise SysctlError(reason, message)


def components(name: object, *, wildcard: bool = False) -> tuple[str, ...]:
    """Return the path components of the parameter ``name``.

    Raises:
        SysctlError: With reason ``invalid_name`` when the name has another form, or names a
            ``*`` component without ``wildcard`` or more than one.
    """
    if not isinstance(name, str) or re.fullmatch(NAME_PATTERN, name) is None:
        _fail("invalid_name", f"{name!r} is not a kernel parameter name")
    parts = tuple(part.replace("/", ".") for part in name.split("."))
    if any(part.strip(".") == "" for part in parts):
        _fail("invalid_name", f"{name!r} has a component that is only dots")
    count = parts.count(WILDCARD)
    if count > (1 if wildcard else 0):
        _fail("invalid_name", f"{name!r} names more wildcard components than allowed")
    return parts


def _name(parts: tuple[str, ...]) -> str:
    return ".".join(part.replace(".", "/") for part in parts)


def check_value(value: object) -> str:
    """Return ``value`` when it is a value that the helper writes.

    Raises:
        SysctlError: With reason ``invalid_value`` otherwise.
    """
    if not isinstance(value, str) or re.fullmatch(VALUE_PATTERN, value) is None:
        _fail("invalid_value", "a value must be at most 255 printable characters or tabs")
    return value


def normalise(value: str) -> str:
    """Return ``value`` with each run of whitespace as one space and no outer whitespace."""
    return " ".join(value.split())


def _parameter(name: str, *, proc_root: Path) -> Path | None:
    parts = components(name)
    path = proc_root.joinpath(*parts)
    try:
        info = path.lstat()
        root_info = proc_root.stat()
        resolved = path.resolve()
        expected = proc_root.resolve().joinpath(*parts)
    except FileNotFoundError:
        return None
    except OSError as error:
        _fail("io_error", f"cannot inspect {name}: {error.strerror or 'operating system error'}")
    if resolved != expected:
        _fail("unsafe_path", f"{name} is reached through a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        _fail("not_regular", f"{name} is not a kernel parameter file")
    if info.st_dev != root_info.st_dev:
        _fail("unsafe_path", f"{name} is not on the file system of {proc_root}")
    return path


def expand(name: str, *, proc_root: Path = PROC_SYS) -> list[str]:
    """Return the existing parameters that ``name`` names, its ``*`` component expanded.

    A name without ``*`` gives itself when it exists. The result is sorted and bounded.

    Raises:
        SysctlError: When the name is invalid or a directory cannot be listed.
    """
    parts = components(name, wildcard=True)
    if WILDCARD not in parts:
        return [name] if _parameter(name, proc_root=proc_root) is not None else []
    index = parts.index(WILDCARD)
    parent = proc_root.joinpath(*parts[:index])
    try:
        if parent.resolve() != proc_root.resolve().joinpath(*parts[:index]) or not parent.is_dir():
            return []
        children = sorted(entry.name for entry in parent.iterdir())
    except OSError as error:
        _fail("io_error", f"cannot list {name}: {error.strerror or 'operating system error'}")
    found: list[str] = []
    for child in children:
        candidate = _name((*parts[:index], child, *parts[index + 1 :]))
        if re.fullmatch(NAME_PATTERN, candidate) is None or child.strip(".") == "":
            continue
        if _parameter(candidate, proc_root=proc_root) is not None:
            found.append(candidate)
        if len(found) > MAX_EXPANDED:
            _fail("too_large", f"{name} names more than {MAX_EXPANDED} parameters")
    return found


def read(name: str, *, proc_root: Path = PROC_SYS) -> str | None:
    """Return the running value of ``name`` without its final line break, ``None`` if absent.

    Raises:
        SysctlError: When the name is invalid, the file is unsafe, too large or unreadable.
    """
    path = _parameter(name, proc_root=proc_root)
    if path is None:
        return None
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_READ_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as error:
        _fail("io_error", f"cannot read {name}: {error.strerror or 'operating system error'}")
    if len(data) > MAX_READ_BYTES:
        _fail("too_large", f"{name} holds more than {MAX_READ_BYTES} bytes")
    text = data.decode("utf-8", "replace")
    return text.removesuffix("\n")


def writable(name: str, *, proc_root: Path = PROC_SYS) -> bool:
    """Return whether ``name`` exists and can be opened for writing, without writing to it.

    A read-only ``/proc/sys``, as in an unprivileged container, refuses the open.

    Raises:
        SysctlError: When the name is invalid or the file is unsafe.
    """
    path = _parameter(name, proc_root=proc_root)
    if path is None:
        return False
    try:
        with path.open("r+b", buffering=0):
            return True
    except OSError:
        return False


def write(name: str, value: str, *, proc_root: Path = PROC_SYS) -> None:
    """Write ``value`` as the running value of ``name``.

    Raises:
        SysctlError: With reason ``absent`` when the parameter does not exist, and when the
            name, the value or the file is refused or the kernel refuses the value.
    """
    text = check_value(value)
    path = _parameter(name, proc_root=proc_root)
    if path is None:
        _fail("absent", f"{name} does not exist on this kernel")
    try:
        with path.open("r+b", buffering=0) as handle:
            handle.write((text + "\n").encode("ascii"))
    except OSError as error:
        _fail(
            "io_error",
            f"cannot write {name}: {error.strerror or 'operating system error'}",
        )
