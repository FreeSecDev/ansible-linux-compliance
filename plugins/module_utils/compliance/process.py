"""Audited external process execution.

This is the only module of the collection that may import ``subprocess``
(ADR 0004). It uses only the Python standard library and syntax that runs on
Python 3.9, the oldest managed-node interpreter supported by ansible-core 2.20.

A command is described by an immutable :class:`CommandSpec` and executed by
:func:`run`. The helper always uses an argument list with ``shell=False``,
closed standard input, a new session, an explicit minimal environment, a
mandatory timeout and bounded capture of standard output and standard error.
The executable is chosen from an allow-list and resolved to an absolute path
only from a fixed list of trusted directories; the caller's ``PATH`` is never
consulted. Every argument that starts with ``-`` must be an option that the
allow-list of that executable names, and remote resource fetching is always
refused.

Policy violations raise :class:`ProcessPolicyError` before anything runs.
Failures to start or supervise a process raise :class:`ProcessExecutionError`.
A timeout is not an exception: the process group is killed and the result has
``timed_out`` set. Messages render untrusted values with ``repr`` and truncate
them. The environment of the child is never returned, logged or echoed.
"""

from __future__ import annotations

import math
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, NoReturn, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import IO

TRUSTED_DIRECTORIES: Final[tuple[str, ...]] = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
SAFE_PATH: Final[str] = "/usr/sbin:/usr/bin:/sbin:/bin"
FIXED_ENVIRONMENT: Final[Mapping[str, str]] = MappingProxyType(
    {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
)
COPYABLE_ENVIRONMENT: Final[frozenset[str]] = frozenset({"TZ", "TMPDIR"})

MAX_TIMEOUT_SECONDS: Final[float] = 3600.0
DEFAULT_MAX_OUTPUT_BYTES: Final[int] = 1024 * 1024
MAX_OUTPUT_BYTES: Final[int] = 16 * 1024 * 1024
MAX_ARGUMENTS: Final[int] = 64
MAX_ARGUMENT_LENGTH: Final[int] = 4096
MAX_ECHO_LENGTH: Final[int] = 64
READ_CHUNK_BYTES: Final[int] = 65536
WAIT_POLL_SECONDS: Final[float] = 0.01
ROOT_UID: Final[int] = 0

FORBIDDEN_OPTIONS: Final[frozenset[str]] = frozenset({"--fetch-remote-resources"})
FORBIDDEN_WORDS: Final[frozenset[str]] = frozenset({"remediate", "--remediate"})
FORBIDDEN_SEQUENCES: Final[frozenset[tuple[str, ...]]] = frozenset({("generate", "fix")})

_EXECUTABLE_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_ENVIRONMENT_NAME: Final[re.Pattern[str]] = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_FIRST_PRINTABLE: Final[int] = 32
_DELETE: Final[int] = 127
_EXECUTE_BITS: Final[int] = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
_GROUP_OR_OTHER_WRITE: Final[int] = stat.S_IWGRP | stat.S_IWOTH


class ProcessError(Exception):
    """Base class of every error raised by this module."""


class ProcessPolicyError(ProcessError, ValueError):
    """Raised when a command violates the execution policy and was not run."""


class ProcessExecutionError(ProcessError, RuntimeError):
    """Raised when a permitted command cannot be found, started or supervised."""


def _safe(value: object) -> str:
    return repr(str(value)[:MAX_ECHO_LENGTH])


def _is_text(value: object) -> bool:
    return isinstance(value, str)


def _is_sequence(value: object) -> bool:
    return isinstance(value, (tuple, list))


def _deny(message: str) -> NoReturn:
    raise ProcessPolicyError(message)


def _fail(message: str) -> NoReturn:
    raise ProcessExecutionError(message)


@dataclass(frozen=True)
class ExecutablePolicy:
    """What the helper allows for one executable.

    Attributes:
        name: The bare executable name.
        allowed_options: The exact option names that may appear after the
            command prefix. An option may carry a value as ``--name=value``.
        command_prefixes: The leading argument sequences that select a
            permitted sub-command. The arguments must start with one of them.
            An empty prefix permits any leading arguments and is meant for
            tests; the default permits nothing.
        standalone_commands: Argument sequences that are permitted only when
            they are the complete argument list.
    """

    name: str
    allowed_options: frozenset[str] = frozenset()
    command_prefixes: tuple[tuple[str, ...], ...] = ()
    standalone_commands: tuple[tuple[str, ...], ...] = ()


ALLOWED_EXECUTABLES: Final[Mapping[str, ExecutablePolicy]] = MappingProxyType(
    {
        "oscap": ExecutablePolicy(
            "oscap",
            frozenset({"--profile", "--results-arf", "--results", "--report", "--tailoring-file"}),
            command_prefixes=(("xccdf", "eval"), ("info",)),
            standalone_commands=(("--version",),),
        )
    }
)


def _check_encodable(value: str) -> None:
    try:
        os.fsencode(value)
    except UnicodeEncodeError:
        _deny(f"value cannot be encoded for the operating system: {_safe(value)}")


def _check_argument(argument: object) -> str:
    if not isinstance(argument, str):
        _deny(f"argument must be a string, got {type(argument).__name__}")
    if not argument:
        _deny("argument must not be empty")
    if len(argument) > MAX_ARGUMENT_LENGTH:
        _deny(f"argument exceeds {MAX_ARGUMENT_LENGTH} characters: {_safe(argument)}")
    if any(
        ord(character) < _FIRST_PRINTABLE or ord(character) == _DELETE for character in argument
    ):
        _deny(f"argument contains a control character or NUL: {_safe(argument)}")
    _check_encodable(argument)
    return argument


def _check_environment_names(names: object) -> tuple[str, ...]:
    if not isinstance(names, (tuple, list)):
        _deny("env_allow must be a tuple of names")
    checked: list[str] = []
    for name in cast("Sequence[object]", names):
        if not isinstance(name, str) or _ENVIRONMENT_NAME.fullmatch(name) is None:
            _deny(f"invalid environment variable name: {_safe(name)}")
        if name not in COPYABLE_ENVIRONMENT:
            _deny(f"environment variable may not be copied: {_safe(name)}")
        checked.append(name)
    return tuple(checked)


def _check_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _deny(f"timeout_seconds must be a number: {_safe(value)}")
    if not math.isfinite(value) or not 0 < value <= MAX_TIMEOUT_SECONDS:
        _deny(f"timeout_seconds must be above 0 and at most {MAX_TIMEOUT_SECONDS}: {_safe(value)}")
    return float(value)


def _check_output_cap(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _deny(f"max_output_bytes must be an integer: {_safe(value)}")
    if not 0 < value <= MAX_OUTPUT_BYTES:
        _deny(f"max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}: {_safe(value)}")
    return value


def _check_cwd(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or "\x00" in value:
        _deny(f"cwd must be a string without NUL: {_safe(value)}")
    _check_encodable(value)
    if not value.startswith("/") or not Path(value).is_dir():
        _deny(f"cwd must be an absolute existing directory: {_safe(value)}")
    return value


@dataclass(frozen=True)
class CommandSpec:
    """An external command to run.

    Attributes:
        executable: Bare executable name; it must be allow-listed when run.
        args: Arguments after the executable. Options must be allow-listed.
        timeout_seconds: Wall-clock limit above zero and at most
            :data:`MAX_TIMEOUT_SECONDS`.
        max_output_bytes: Capture cap applied to each of stdout and stderr.
        env_allow: Names from :data:`COPYABLE_ENVIRONMENT` copied from the
            parent environment. ``PATH``, ``LC_ALL`` and ``LANG`` are always
            fixed and cannot be copied.
        cwd: Optional absolute existing directory to run in.

    Raises:
        ProcessPolicyError: If a field violates the policy.
    """

    executable: str
    args: tuple[str, ...]
    timeout_seconds: float
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    env_allow: tuple[str, ...] = ()
    cwd: str | None = None

    def __post_init__(self) -> None:
        """Validate every field and normalise the collections to tuples."""
        if not _is_text(self.executable) or not _EXECUTABLE_NAME.fullmatch(self.executable):
            _deny(f"invalid executable name: {_safe(self.executable)}")
        if not _is_sequence(self.args):
            _deny("args must be a tuple of strings")
        if len(self.args) > MAX_ARGUMENTS:
            _deny(f"too many arguments, at most {MAX_ARGUMENTS} are allowed")
        object.__setattr__(self, "args", tuple(_check_argument(arg) for arg in self.args))
        object.__setattr__(self, "timeout_seconds", _check_timeout(self.timeout_seconds))
        object.__setattr__(self, "max_output_bytes", _check_output_cap(self.max_output_bytes))
        object.__setattr__(self, "env_allow", _check_environment_names(self.env_allow))
        object.__setattr__(self, "cwd", _check_cwd(self.cwd))


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a command that was started.

    Attributes:
        argv: The resolved absolute executable followed by the arguments.
        returncode: Exit status, or the negative signal number after a kill.
        stdout: Captured standard output, truncated to the cap.
        stderr: Captured standard error, truncated to the cap.
        stdout_truncated: Whether output beyond the cap was discarded.
        stderr_truncated: Whether error output beyond the cap was discarded.
        duration_seconds: Monotonic wall-clock duration.
        timed_out: Whether the timeout expired and the process group was killed.
    """

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    timed_out: bool


def _option_name(argument: str) -> str:
    return argument.split("=", 1)[0]


def _reject_forbidden_words(
    args: tuple[str, ...],
    words: frozenset[str],
    sequences: frozenset[tuple[str, ...]],
) -> None:
    for index, argument in enumerate(args):
        if _option_name(argument) in words:
            _deny(f"argument is forbidden: {_safe(argument)}")
        for sequence in sequences:
            if args[index : index + len(sequence)] == sequence:
                _deny(f"argument sequence is forbidden: {_safe(' '.join(sequence))}")


def _matching_prefix(args: tuple[str, ...], policy: ExecutablePolicy) -> tuple[str, ...]:
    for prefix in policy.command_prefixes:
        if args[: len(prefix)] == prefix:
            return prefix
    return _deny(f"command is not allow-listed for {policy.name}: {_safe(' '.join(args))}")


def _trusted_directories(search_dirs: Sequence[str], owner_uid: int) -> list[tuple[Path, Path]]:
    directories: list[tuple[Path, Path]] = []
    for directory in search_dirs:
        if not _is_text(directory) or not directory.startswith("/") or "\x00" in directory:
            _deny(f"trusted directory must be an absolute path: {_safe(directory)}")
        real = Path(directory).resolve()
        try:
            mode = real.stat().st_mode
        except OSError:
            continue
        if not stat.S_ISDIR(mode):
            continue
        if mode & _GROUP_OR_OTHER_WRITE:
            _deny(f"trusted directory is writable by group or others: {_safe(directory)}")
        if real.stat().st_uid != owner_uid:
            _deny(f"trusted directory has the wrong owner: {_safe(directory)}")
        directories.append((Path(directory), real))
    return directories


def resolve_executable(
    name: str, search_dirs: Sequence[str] = TRUSTED_DIRECTORIES, owner_uid: int = ROOT_UID
) -> str:
    """Resolve ``name`` to an absolute path inside a trusted directory.

    The caller's ``PATH`` is never used. A symlink is accepted only if it
    resolves to a file directly inside one of the trusted directories. The
    file must be a regular, executable file owned by ``owner_uid`` that is not
    writable by group or others, and so must every trusted directory. The
    returned path is the vetted path inside the trusted directory, not the
    symlink target, so multi-call binaries keep their name.

    Args:
        name: Bare executable name; separators and traversal are rejected.
        search_dirs: Absolute trusted directories, searched in order.
        owner_uid: Required owner of directories and file. Only tests change it.

    Returns:
        The absolute path of the executable.

    Raises:
        ProcessPolicyError: If the name is invalid or the file is unsafe.
        ProcessExecutionError: If no trusted directory contains the file.
    """
    if not _is_text(name) or not _EXECUTABLE_NAME.fullmatch(name):
        _deny(f"invalid executable name: {_safe(name)}")
    directories = _trusted_directories(search_dirs, owner_uid)
    real_directories = {pair[1] for pair in directories}
    for pair in directories:
        candidate = pair[0] / name
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            _deny(f"executable cannot be resolved: {_safe(candidate)}")
        if resolved.parent not in real_directories:
            _deny(f"executable resolves outside the trusted directories: {_safe(candidate)}")
        try:
            info = resolved.stat()
        except OSError:
            continue
        mode = info.st_mode
        if not stat.S_ISREG(mode):
            _deny(f"executable is not a regular file: {_safe(candidate)}")
        if mode & _GROUP_OR_OTHER_WRITE:
            _deny(f"executable is writable by group or others: {_safe(candidate)}")
        if info.st_uid != owner_uid:
            _deny(f"executable has the wrong owner: {_safe(candidate)}")
        if not mode & _EXECUTE_BITS or not os.access(resolved, os.X_OK):
            _deny(f"file is not executable: {_safe(candidate)}")
        return str(candidate)
    _fail(f"executable not found in the trusted directories: {_safe(name)}")


def confined_path(base: str, candidate: str) -> str:
    """Return ``candidate`` as an absolute path confined to ``base``.

    A relative ``candidate`` is taken relative to ``base``. The result is
    normalised lexically, must stay inside ``base`` and may not pass through a
    symlink below ``base``. ``base`` itself is resolved.

    Args:
        base: Absolute existing directory that confines the result.
        candidate: Absolute or relative path to confine.

    Returns:
        The normalised absolute path. It need not exist.

    Raises:
        ProcessPolicyError: If an input is malformed, the path escapes
            ``base`` or a component below ``base`` is a symlink.
    """
    for value in (base, candidate):
        if not _is_text(value) or not value or "\x00" in value:
            _deny(f"path must be a non-empty string without NUL: {_safe(value)}")
    if not base.startswith("/") or not Path(base).is_dir():
        _deny(f"base must be an absolute existing directory: {_safe(base)}")
    root = Path(base).resolve()
    target = Path(os.path.normpath(root / candidate))
    if target != root and root not in target.parents:
        _deny(f"path escapes the base directory: {_safe(candidate)}")
    current = root
    for part in target.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            _deny(f"path contains a symlink: {_safe(candidate)}")
    return str(target)


def build_environment(spec: CommandSpec) -> dict[str, str]:
    """Build the child environment from the fixed values and ``env_allow``.

    Args:
        spec: The command whose ``env_allow`` names are copied.

    Returns:
        A new mapping. Nothing else is inherited from the parent.
    """
    environment = dict(FIXED_ENVIRONMENT)
    for name in spec.env_allow:
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


class _Capture:
    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.data = bytearray()
        self.truncated = False

    def feed(self, chunk: bytes) -> None:
        room = self.cap - len(self.data)
        self.data += chunk[:room]
        if len(chunk) > room:
            self.truncated = True


def _read_chunk(descriptor: int) -> bytes:
    return os.read(descriptor, READ_CHUNK_BYTES)


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _pump(process: subprocess.Popen[bytes], deadline: float, out: _Capture, err: _Capture) -> bool:
    timed_out = False
    with selectors.DefaultSelector() as selector:
        selector.register(cast("IO[bytes]", process.stdout), selectors.EVENT_READ, out)
        selector.register(cast("IO[bytes]", process.stderr), selectors.EVENT_READ, err)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for event in selector.select(timeout=remaining):
                key = event[0]
                chunk = _read_chunk(key.fd)
                if chunk:
                    key.data.feed(chunk)
                else:
                    selector.unregister(key.fileobj)
    return timed_out or _wait_for_exit(process, deadline)


def _wait_for_exit(process: subprocess.Popen[bytes], deadline: float) -> bool:
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    while os.waitid(os.P_PID, process.pid, flags) is None:
        if time.monotonic() >= deadline:
            return True
        time.sleep(WAIT_POLL_SECONDS)
    return False


def _supervise(spec: CommandSpec, argv: tuple[str, ...]) -> CommandResult:
    out = _Capture(spec.max_output_bytes)
    err = _Capture(spec.max_output_bytes)
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            env=build_environment(spec),
            cwd=spec.cwd,
            bufsize=0,
        )
    except OSError as error:
        _fail(f"cannot start {_safe(spec.executable)}: {error.strerror or type(error).__name__}")
    with process:
        try:
            timed_out = _pump(process, started + spec.timeout_seconds, out, err)
            _kill_group(process)
            returncode = process.wait()
        except OSError as error:
            _fail(f"cannot read output of {_safe(spec.executable)}: {error.strerror}")
        finally:
            if process.returncode is None:
                _kill_group(process)
    return CommandResult(
        argv=argv,
        returncode=returncode,
        stdout=bytes(out.data),
        stderr=bytes(err.data),
        stdout_truncated=out.truncated,
        stderr_truncated=err.truncated,
        duration_seconds=time.monotonic() - started,
        timed_out=timed_out,
    )


class _PolicyChecker(Protocol):
    def __call__(
        self, spec: CommandSpec, policies: Mapping[str, ExecutablePolicy]
    ) -> ExecutablePolicy: ...


class _Runner(Protocol):
    def __call__(
        self,
        spec: CommandSpec,
        *,
        policies: Mapping[str, ExecutablePolicy] | None = None,
        trusted_dirs: Sequence[str] | None = None,
        owner_uid: int = ROOT_UID,
    ) -> CommandResult: ...


def bind_policy(
    allowed: Mapping[str, ExecutablePolicy],
    trusted: Sequence[str],
    forbidden_options: frozenset[str],
    forbidden_words: frozenset[str],
    forbidden_sequences: frozenset[tuple[str, ...]],
) -> tuple[_PolicyChecker, _Runner]:
    """Bind the execution policy at import time and return the checker and the runner.

    The returned functions read private immutable copies that live only in their
    closures, so rebinding ``ALLOWED_EXECUTABLES``, ``TRUSTED_DIRECTORIES`` or the
    ``FORBIDDEN_*`` names of this module after import has no effect on them.
    """
    bound_policies = MappingProxyType(
        {
            key: ExecutablePolicy(
                policy.name,
                frozenset(policy.allowed_options),
                tuple(tuple(prefix) for prefix in policy.command_prefixes),
                tuple(tuple(command) for command in policy.standalone_commands),
            )
            for key, policy in allowed.items()
        }
    )
    bound_trusted = tuple(trusted)
    options = frozenset(forbidden_options)
    words = frozenset(forbidden_words)
    sequences = frozenset(forbidden_sequences)

    def check_policy(
        spec: CommandSpec, policies: Mapping[str, ExecutablePolicy]
    ) -> ExecutablePolicy:
        """Check the executable and the options of ``spec`` against ``policies``.

        Args:
            spec: The command to check.
            policies: Allow-list keyed by executable name.

        Returns:
            The policy of the executable.

        Raises:
            ProcessPolicyError: If the executable is not allow-listed, or an
                command is not an allowed sub-command of the executable, an
                argument is forbidden, or an option is not allow-listed.
        """
        _reject_forbidden_words(spec.args, words, sequences)
        policy = policies.get(spec.executable)
        if policy is None:
            _deny(f"executable is not allow-listed: {_safe(spec.executable)}")
        if spec.args in policy.standalone_commands:
            return policy
        prefix = _matching_prefix(spec.args, policy)
        for argument in spec.args[len(prefix) :]:
            if not argument.startswith("-"):
                continue
            name = _option_name(argument)
            if name in options:
                _deny(f"option is forbidden: {_safe(name)}")
            if name not in policy.allowed_options:
                _deny(f"option is not allow-listed for {spec.executable}: {_safe(argument)}")
        return policy

    def run(
        spec: CommandSpec,
        *,
        policies: Mapping[str, ExecutablePolicy] | None = None,
        trusted_dirs: Sequence[str] | None = None,
        owner_uid: int = ROOT_UID,
    ) -> CommandResult:
        """Run ``spec`` under the execution policy and return the bounded result.

        The process runs in its own session with closed standard input. Output is
        read in chunks from both pipes and only the first ``max_output_bytes`` of
        each stream are kept; the rest is drained and discarded. The whole process
        group is killed after the leader exits, so detached members do not outlive
        the run, and when the timeout expires. A timeout sets ``timed_out``. A
        descendant in another session that keeps the pipes open also ends in
        ``timed_out``, even if the leader exited with status 0.

        The specification is validated again here, so a specification that was
        altered after construction cannot bypass the argument checks.

        ``policies``, ``trusted_dirs`` and ``owner_uid`` exist only so that unit tests can run
        harmless system utilities. Production callers never pass them.

        Args:
            spec: The command to run.
            policies: Test-only replacement for :data:`ALLOWED_EXECUTABLES` bound at import.
            trusted_dirs: Test-only replacement for :data:`TRUSTED_DIRECTORIES` bound at import.
            owner_uid: Test-only replacement for the required owner, root.

        Returns:
            The captured result.

        Raises:
            ProcessPolicyError: If the policy rejects the command; nothing ran.
            ProcessExecutionError: If the executable is missing, cannot be
                started or the output cannot be read.
        """
        spec = CommandSpec(
            spec.executable,
            spec.args,
            spec.timeout_seconds,
            spec.max_output_bytes,
            spec.env_allow,
            spec.cwd,
        )
        check_policy(spec, bound_policies if policies is None else policies)
        executable = resolve_executable(
            spec.executable,
            bound_trusted if trusted_dirs is None else trusted_dirs,
            owner_uid,
        )
        argv = (executable, *spec.args)
        return _supervise(spec, argv)

    return check_policy, run


check_policy, run = bind_policy(
    ALLOWED_EXECUTABLES,
    TRUSTED_DIRECTORIES,
    FORBIDDEN_OPTIONS,
    FORBIDDEN_WORDS,
    FORBIDDEN_SEQUENCES,
)
