r"""Record, in order, what a sysctl reader writes to some files below ``/proc/sys`` (FREES-208).

The kernel refuses ``kernel.perf_event_max_sample_rate`` while ``kernel.perf_cpu_time_max_percent``
is 0 or 100, and checks that only when the sample rate is written, so what counts for the role is
the companion's value at each write of the sample rate. The private ``/proc/sys`` of the verdict
generator only keeps the last value of every file, so for every case of
``tests/fixtures/sysctl_reader/cases.json`` that names keys to ``trace``,
``sysctl-reader-inside.sh`` starts the reader in a process that stops itself before it executes
the reader, and runs this program on it::

    python3 sysctl_trace.py PID WATCHED OUT

It attaches to ``PID`` with ptrace(2), which the oracle may do as root of its own user namespace,
and stops it at the entry and the exit of every system call until it ends. At the entry of every
``write`` or ``pwrite64`` to a file descriptor that is open on one of the paths listed in
``WATCHED`` (one absolute path per line), the bytes about to be written are appended to ``OUT`` as
a line ``<path>\t<base64>``, so ``OUT`` lists every write to those files in the order in which the
reader made them, and the values come from what the reader wrote, not from its output. Anything
that could write to a watched file without being recorded stops the program instead (status 2):
another system call that writes to one (``writev``, ``pwritev``, ``pwritev2``, ``sendfile``,
``splice``, ``copy_file_range``), an ``io_uring`` instance, or a new process or thread, which would
not be traced. The reader is killed when this program ends before it (``PTRACE_O_EXITKILL``), so a
``timeout`` around this program stops both. A ``SIGSTOP`` (the reader's own, or the one that
attaching sends) is not passed on; every other signal is.

It runs inside the Molecule images, with Python 3.9 (Rocky Linux 9) and 3.12 (Ubuntu 24.04), and
on x86_64 only, whose system call numbers and registers it uses. It starts no process itself. The
exit status is 0 when the reader ran to its end, whatever the reader's own status, and 2 when the
tracing failed.
"""

from __future__ import annotations

import base64
import ctypes
import os
import platform
import signal
import sys
from pathlib import Path
from typing import Final

PTRACE_GETREGS: Final[int] = 12
PTRACE_ATTACH: Final[int] = 16
PTRACE_SYSCALL: Final[int] = 24
PTRACE_SETOPTIONS: Final[int] = 0x4200
PTRACE_O_TRACESYSGOOD: Final[int] = 0x1
PTRACE_O_TRACEEXEC: Final[int] = 0x10
PTRACE_O_EXITKILL: Final[int] = 0x100000
OPTIONS: Final[int] = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL
SYSCALL_STOP: Final[int] = 0x80 | signal.SIGTRAP
ENTRY: Final[int] = 2**64 - 38
WRITE: Final[int] = 1
PWRITE64: Final[int] = 18
UNFOLLOWED: Final[dict[int, tuple[str, str]]] = {
    20: ("writev", "rdi"),
    296: ("pwritev", "rdi"),
    328: ("pwritev2", "rdi"),
    40: ("sendfile", "rdi"),
    275: ("splice", "r10"),
    326: ("copy_file_range", "rdx"),
}
REFUSED: Final[dict[int, str]] = {
    56: "clone",
    57: "fork",
    58: "vfork",
    435: "clone3",
    425: "io_uring_setup",
}
MACHINE: Final[str] = "x86_64"
FAILED: Final[int] = 2
ARGUMENTS: Final[int] = 3
REGISTERS: Final[tuple[str, ...]] = (
    "r15",
    "r14",
    "r13",
    "r12",
    "rbp",
    "rbx",
    "r11",
    "r10",
    "r9",
    "r8",
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "orig_rax",
    "rip",
    "cs",
    "eflags",
    "rsp",
    "ss",
    "fs_base",
    "gs_base",
    "ds",
    "es",
    "fs",
    "gs",
)


class TraceError(RuntimeError):
    """The reader could not be traced completely."""


class Registers(ctypes.Structure):
    """``struct user_regs_struct`` of x86_64."""

    _fields_ = tuple((name, ctypes.c_ulonglong) for name in REGISTERS)


def libc() -> ctypes.CDLL:
    """Return the C library, with ``ptrace`` declared."""
    library = ctypes.CDLL(None, use_errno=True)
    library.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    library.ptrace.restype = ctypes.c_long
    return library


def ptrace(request: int, pid: int, data: int | Registers = 0) -> None:
    """Make the ptrace ``request`` for ``pid``.

    Raises:
        TraceError: If the request fails.
    """
    argument = ctypes.byref(data) if isinstance(data, Registers) else ctypes.c_void_p(data)
    if libc().ptrace(request, pid, None, argument) == -1:
        error = ctypes.get_errno()
        message = f"ptrace request {request} for {pid} failed: {os.strerror(error)}"
        raise TraceError(message)


def registers(pid: int) -> Registers:
    """Return the registers of the stopped ``pid``."""
    found = Registers()
    ptrace(PTRACE_GETREGS, pid, found)
    return found


def open_path(pid: int, descriptor: int) -> str | None:
    """Return the path on which ``descriptor`` of ``pid`` is open, or None when it is not open."""
    try:
        return str(Path(f"/proc/{pid}/fd/{descriptor}").readlink())
    except FileNotFoundError:
        return None


def memory(pid: int, address: int, size: int) -> bytes:
    """Return ``size`` bytes of the memory of ``pid`` at ``address``."""
    with Path(f"/proc/{pid}/mem").open("rb", buffering=0) as handle:
        handle.seek(address)
        return handle.read(size)


def on_entry(pid: int, found: Registers, watched: frozenset[str], out: Path) -> None:
    """Record a write to a watched file, or refuse a call that the record would miss.

    Raises:
        TraceError: For a call that could write to a watched file unrecorded, or start a process.
    """
    number = found.orig_rax
    if number in REFUSED:
        message = f"the reader called {REFUSED[number]}, which this program does not follow"
        raise TraceError(message)
    if number in UNFOLLOWED:
        name, register = UNFOLLOWED[number]
        path = open_path(pid, int(getattr(found, register)))
        if path in watched:
            message = f"the reader wrote to {path} with {name}, which this program does not follow"
            raise TraceError(message)
        return
    if number not in {WRITE, PWRITE64}:
        return
    path = open_path(pid, int(found.rdi))
    if path in watched:
        data = memory(pid, int(found.rsi), int(found.rdx))
        with out.open("a", encoding="utf-8") as handle:
            handle.write(f"{path}\t{base64.b64encode(data).decode('ascii')}\n")


def attach(pid: int) -> None:
    """Attach to ``pid`` and wait until it is stopped.

    Raises:
        TraceError: If it cannot be attached to, or ends instead of stopping.
    """
    ptrace(PTRACE_ATTACH, pid)
    _, status = os.waitpid(pid, 0)
    if not os.WIFSTOPPED(status):
        message = f"the reader {pid} ended before it could be traced: status {status}"
        raise TraceError(message)
    ptrace(PTRACE_SETOPTIONS, pid, OPTIONS)


def trace(pid: int, watched: frozenset[str], out: Path) -> int:
    """Trace ``pid`` to its end and record its writes to ``watched`` in ``out``; return its status.

    A system call stop is an entry when ``rax`` holds ``-ENOSYS``, as x86_64 sets it there.

    Raises:
        TraceError: If the reader cannot be traced completely.
    """
    out.write_text("", encoding="utf-8")
    attach(pid)
    delivered = 0
    while True:
        ptrace(PTRACE_SYSCALL, pid, delivered)
        _, status = os.waitpid(pid, 0)
        if not os.WIFSTOPPED(status):
            return os.waitstatus_to_exitcode(status)
        stop = os.WSTOPSIG(status)
        delivered = 0
        if stop == SYSCALL_STOP:
            found = registers(pid)
            if found.rax == ENTRY:
                on_entry(pid, found, watched, out)
        elif status >> 16 == 0 and stop != signal.SIGSTOP:
            delivered = stop


def main(argv: list[str]) -> int:
    """Trace the reader ``PID`` and record its writes to the files of ``WATCHED`` in ``OUT``."""
    if len(argv) != ARGUMENTS or not argv[0].isdigit():
        sys.stderr.write("usage: sysctl_trace.py PID WATCHED OUT\n")
        return FAILED
    if platform.machine() != MACHINE:
        sys.stderr.write(f"error: tracing needs {MACHINE}, not {platform.machine()}\n")
        return FAILED
    watched = frozenset(
        line for line in Path(argv[1]).read_text(encoding="utf-8").splitlines() if line
    )
    try:
        trace(int(argv[0]), watched, Path(argv[2]))
    except TraceError as error:
        sys.stderr.write(f"error: {error}\n")
        return FAILED
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
