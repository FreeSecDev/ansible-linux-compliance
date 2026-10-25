"""Backend-neutral scanner interface and backend registry.

Orchestration code asks for a backend by name and calls :meth:`ScanBackend.audit`;
it never imports a concrete backend. A concrete backend registers a factory under
its name in a :class:`BackendRegistry`, and the ``backends`` module is the
composition root that wires the shipped backends. The module uses only the Python
standard library and syntax that runs on Python 3.9 (ADR 0013).

A backend turns a :class:`ScanRequest` into a :class:`model.ScanRun`. A request
that is malformed or unsafe raises :class:`ScanRequestError` before anything runs.
A scanner that cannot finish (missing binary, timeout, unexpected exit status,
unreadable results) is not an exception: the returned run has a ``failed`` or
``timed_out`` status and, per ADR 0013, only ``error`` findings.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, NoReturn, Protocol, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    process,
)

DEFAULT_TIMEOUT_SECONDS: Final[float] = 1800.0
DEFAULT_MAX_RESULT_BYTES: Final[int] = 128 * 1024 * 1024
MAX_RESULT_BYTES_LIMIT: Final[int] = 1024 * 1024 * 1024
MAX_PATH_LENGTH: Final[int] = 4096
MAX_EXPECTED_RULES: Final[int] = model.MAX_ITEMS
MAX_ECHO_LENGTH: Final[int] = 64
_FIRST_PRINTABLE: Final[int] = 32
_DELETE: Final[int] = 127

_BACKEND_NAME: Final[str] = r"[a-z][a-z0-9_-]{0,63}"
_RUN_ID: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}"
_XCCDF_ID: Final[dict[str, str]] = {
    kind: rf"xccdf_[A-Za-z0-9_.-]+?_{kind}_[A-Za-z0-9_.+-]+"
    for kind in ("rule", "profile", "benchmark")
}


class ScanRequestError(ValueError):
    """Raised when a scan request or a backend setting is invalid or unsafe."""


class UnknownBackendError(LookupError):
    """Raised when no backend is registered under a requested name."""


def _safe(value: object) -> str:
    return repr(str(value)[:MAX_ECHO_LENGTH])


def _reject(message: str) -> NoReturn:
    raise ScanRequestError(message)


def check_xccdf_id(value: object, kind: str, name: str) -> str:
    """Validate a full XCCDF identifier of the given kind.

    Args:
        value: The candidate identifier.
        kind: ``rule``, ``profile`` or ``benchmark``.
        name: Field name used in the error message.

    Returns:
        The identifier.

    Raises:
        ScanRequestError: If the value is not a string of at most 256
            characters that matches the full XCCDF identifier format.
    """
    if (
        not isinstance(value, str)
        or len(value) > model.MAX_ID_LENGTH
        or re.fullmatch(_XCCDF_ID[kind], value) is None
    ):
        _reject(f"{name} is not a valid XCCDF {kind} identifier: {_safe(value)}")
    return value


def _check_path(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_PATH_LENGTH
        or any(
            ord(character) < _FIRST_PRINTABLE or ord(character) == _DELETE for character in value
        )
        or value.startswith("-")
    ):
        _reject(f"{name} must be a non-empty path without control characters or a leading '-'")
    return value


def _check_root(value: object, name: str) -> str:
    path = _check_path(value, name)
    if not path.startswith("/"):
        _reject(f"{name} must be an absolute path: {_safe(value)}")
    return path


def _check_timeout(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _reject(f"timeout_seconds must be a number: {_safe(value)}")
    if not 0 < value <= process.MAX_TIMEOUT_SECONDS:
        _reject(f"timeout_seconds must be above 0 and at most {process.MAX_TIMEOUT_SECONDS}")


def _check_size(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        _reject(f"max_result_bytes must be an integer: {_safe(value)}")
    if not 0 < value <= MAX_RESULT_BYTES_LIMIT:
        _reject(f"max_result_bytes must be between 1 and {MAX_RESULT_BYTES_LIMIT}")


def _check_backend_name(value: object) -> None:
    if not isinstance(value, str) or re.fullmatch(_BACKEND_NAME, value) is None:
        _reject(f"backend name is invalid: {_safe(value)}")


def _check_host(value: object) -> None:
    if not isinstance(value, model.HostIdentity):
        _reject("host must be a HostIdentity")


def _check_run_id(value: object) -> None:
    if not isinstance(value, str) or re.fullmatch(_RUN_ID, value) is None:
        _reject(f"run_id is invalid: {_safe(value)}")


def _check_rule_ids(value: object) -> None:
    if not isinstance(value, tuple):
        _reject("expected_rule_ids must be a tuple")
    rule_ids = cast("tuple[object, ...]", value)
    if not rule_ids:
        _reject("expected_rule_ids must not be empty")
    if len(rule_ids) > MAX_EXPECTED_RULES:
        _reject(f"expected_rule_ids exceeds {MAX_EXPECTED_RULES} items")
    for rule_id in rule_ids:
        check_xccdf_id(rule_id, "rule", "expected_rule_ids item")
    if len(set(rule_ids)) != len(rule_ids):
        _reject("expected_rule_ids contains duplicates")


@dataclass(frozen=True)
class ScanSettings:
    """Backend-independent settings, fixed when a backend is created.

    Attributes:
        content_root: Absolute directory that confines content and tailoring paths.
        output_root: Absolute directory that confines output directories.
        timeout_seconds: Wall-clock limit of one scan, above 0 and at most
            :data:`process.MAX_TIMEOUT_SECONDS`.
        max_result_bytes: Largest results document that is parsed.
    """

    content_root: str
    output_root: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES

    def __post_init__(self) -> None:
        """Validate every setting."""
        _check_root(self.content_root, "content_root")
        _check_root(self.output_root, "output_root")
        _check_timeout(self.timeout_seconds)
        _check_size(self.max_result_bytes)


@dataclass(frozen=True)
class ScanRequest:
    """One audit to run.

    Attributes:
        run_id: Identifier recorded in the resulting scan run.
        host: Identity of the host that is scanned.
        benchmark_id: Full XCCDF benchmark identifier the content provides.
        profile_id: Full XCCDF profile identifier to evaluate.
        content_path: Datastream path, absolute or relative to the content root.
        output_dir: Directory the backend creates for its output files,
            absolute or relative to the output root. It must not exist.
        expected_rule_ids: Non-empty tuple of the rules that the profile
            selects, supplied by the caller. A rule without a result, and every
            rule when the scanner fails, is reported as an ``error`` finding;
            a result for any other rule makes the run fail.
        tailoring_path: Optional tailoring file, confined like the content.
    """

    run_id: str
    host: model.HostIdentity
    benchmark_id: str
    profile_id: str
    content_path: str
    output_dir: str
    expected_rule_ids: tuple[str, ...]
    tailoring_path: str | None = None

    def __post_init__(self) -> None:
        """Validate every field."""
        _check_run_id(self.run_id)
        _check_host(self.host)
        check_xccdf_id(self.benchmark_id, "benchmark", "benchmark_id")
        check_xccdf_id(self.profile_id, "profile", "profile_id")
        _check_path(self.content_path, "content_path")
        _check_path(self.output_dir, "output_dir")
        if self.tailoring_path is not None:
            _check_path(self.tailoring_path, "tailoring_path")
        _check_rule_ids(self.expected_rule_ids)


class ScanBackend(Protocol):
    """A scanner backend that turns a request into a normalized scan run."""

    def audit(self, request: ScanRequest) -> model.ScanRun:
        """Run an audit and return its normalized result.

        Raises:
            ScanRequestError: If the request is invalid or unsafe; nothing ran.
        """
        raise NotImplementedError


BackendFactory = Callable[[ScanSettings], ScanBackend]


class BackendRegistry:
    """Maps backend names to factories that create configured backends."""

    def __init__(self) -> None:
        """Create an empty registry."""
        self._factories: dict[str, BackendFactory] = {}

    def register(self, name: str, factory: BackendFactory) -> None:
        """Register ``factory`` under ``name``.

        Raises:
            ScanRequestError: If the name is invalid or already registered.
        """
        _check_backend_name(name)
        if name in self._factories:
            _reject(f"backend is already registered: {_safe(name)}")
        self._factories[name] = factory

    def names(self) -> tuple[str, ...]:
        """Return the registered backend names in sorted order."""
        return tuple(sorted(self._factories))

    def create(self, name: str, settings: ScanSettings) -> ScanBackend:
        """Create the backend registered under ``name``.

        Raises:
            UnknownBackendError: If no backend has that name.
        """
        factory = self._factories.get(name)
        if factory is None:
            message = f"unknown scanner backend: {_safe(name)}"
            raise UnknownBackendError(message)
        return factory(settings)
