"""OpenSCAP scanner backend and hardened XCCDF 1.2 results parser.

The backend runs ``oscap xccdf eval`` through :mod:`process` only, so every
argument is checked against the allow-list of that helper (ADR 0004). It never
remediates and never fetches remote resources. Paths are confined to configured
roots and may not be symlinks, and the output files are written to a directory
that the backend creates with mode 0700 and never reuses.

Exit status of ``oscap xccdf eval``:

* ``0``: every evaluated rule passed.
* ``2``: at least one rule failed or errored. This is a normal scan result.
* Anything else (including a negative signal status), a timeout or a missing
  binary is a scanner failure. A failure is never ``pass`` or ``fail``: the run
  has status ``failed`` or ``timed_out`` and every finding is ``error`` (ADR 0013).

An exit status that contradicts the results file (``0`` with a failed or errored
rule, ``2`` with neither) is also a failure, as are results that name another
profile or benchmark than the request and content that changed during the scan.

XML hardening
-------------

Results come from a process on a managed host, so they are untrusted. The
standard library parser is used because this code must run on managed hosts
with nothing but the Python standard library. It is made safe by layering:

1. The file must be a regular file, not a symlink, and is bounded before and
   while it is read.
2. The text must be valid UTF-8 and may not contain a DOCTYPE or ENTITY
   declaration, so the entity expansion and external entity paths of the parser
   are unreachable for accepted input. The expat handlers reject the same
   declarations again if the textual check were bypassed.
3. The expat parser is created directly with parameter entity parsing turned
   off (``SetParamEntityParsing(XML_PARAM_ENTITY_PARSING_NEVER)``) and no
   external entity handler, so an external subset or entity is never loaded.
4. Element count and nesting depth are bounded while parsing, before a tree of
   that size can exist, and only the elements that the extraction needs are kept.
5. Only the XCCDF 1.2 namespace is accepted.

Python and expat versions differ in their entity-expansion defences: the
billion-laughs limits arrived with expat 2.4.0 (2.4.1 for the final fixes) and
Python bundles or links different expat versions across 3.9 to 3.14. This module
does not depend on them, because a document with any entity declaration is
rejected before parsing.
"""

from __future__ import annotations

import hashlib
import re
import stat
import xml.etree.ElementTree as ET
import xml.parsers.expat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    process,
    scanner,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_expat = xml.parsers.expat
BACKEND_NAME: Final[str] = "openscap"
XCCDF_NAMESPACE: Final[str] = "http://checklists.nist.gov/xccdf/1.2"
RESULTS_FILE_NAME: Final[str] = "results.xml"
ARF_FILE_NAME: Final[str] = "results-arf.xml"
UNKNOWN_VERSION: Final[str] = "unknown"
DEFAULT_MAX_ELEMENTS: Final[int] = 2_000_000
DEFAULT_MAX_DEPTH: Final[int] = 64
EXIT_ALL_PASSED: Final[int] = 0
EXIT_RULES_FAILED: Final[int] = 2
VERSION_TIMEOUT_SECONDS: Final[float] = 30.0
VERSION_MAX_OUTPUT_BYTES: Final[int] = 64 * 1024
OUTPUT_DIRECTORY_MODE: Final[int] = 0o700
MAX_MESSAGE_LENGTH: Final[int] = 1024
EXCERPT_BYTES: Final[int] = 512
HASH_CHUNK_BYTES: Final[int] = 1024 * 1024

_VERSION_LINE: Final[re.Pattern[str]] = re.compile(r"\(oscap\)\s+([0-9][A-Za-z0-9._+-]{0,63})")
_SEVERITIES: Final[dict[str, model.Severity]] = {item.value: item for item in model.Severity}
_ERROR_OUTCOMES: Final[frozenset[model.Outcome]] = frozenset(
    {model.Outcome.FAIL, model.Outcome.ERROR}
)


def _qualified(local: str) -> str:
    return f"{{{XCCDF_NAMESPACE}}}{local}"


_BENCHMARK: Final[str] = _qualified("Benchmark")
_TEST_RESULT: Final[str] = _qualified("TestResult")
_VERSION: Final[str] = _qualified("version")
_BENCHMARK_REF: Final[str] = _qualified("benchmark")
_PROFILE: Final[str] = _qualified("profile")
_RULE_RESULT: Final[str] = _qualified("rule-result")
_RESULT: Final[str] = _qualified("result")
_ROOT_CHILDREN: Final[frozenset[str]] = frozenset({_TEST_RESULT, _VERSION})


class XccdfParseError(ValueError):
    """Raised when a results document is unsafe, malformed or incomplete."""


def _fail(message: str) -> NoReturn:
    raise XccdfParseError(message)


@dataclass(frozen=True)
class XmlLimits:
    """Bounds applied while a results document is parsed.

    Attributes:
        max_elements: Largest number of elements in the document.
        max_depth: Deepest element nesting, where the root has depth 1.
    """

    max_elements: int = DEFAULT_MAX_ELEMENTS
    max_depth: int = DEFAULT_MAX_DEPTH


@dataclass(frozen=True)
class ParsedResults:
    """What the backend extracts from an XCCDF results document.

    Attributes:
        benchmark_id: Full XCCDF benchmark identifier.
        benchmark_version: Version of the benchmark content.
        profile_id: Full XCCDF profile identifier that was evaluated.
        started_at: Scan start, UTC, ``YYYY-MM-DDTHH:MM:SSZ``.
        finished_at: Scan end, UTC, ``YYYY-MM-DDTHH:MM:SSZ``.
        findings: One finding per rule result, in document order.
    """

    benchmark_id: str
    benchmark_version: str
    profile_id: str
    started_at: str
    finished_at: str
    findings: tuple[model.Finding, ...]


class _Frame:
    def __init__(self, element: ET.Element | None, *, inside_result: bool) -> None:
        self.element = element
        self.inside_result = inside_result
        self.text: list[str] = []


class _Builder:
    """Expat handlers that bound the document and keep only what is needed."""

    def __init__(self, limits: XmlLimits) -> None:
        self.limits = limits
        self.root = ET.Element("")
        self.count = 0
        self.frames: list[_Frame] = []

    def reject_declaration(self, *_arguments: object) -> NoReturn:
        _fail("DOCTYPE, ENTITY and external entity declarations are not allowed")

    def start(self, name: str, attributes: dict[str, str]) -> None:
        self.count += 1
        if self.count > self.limits.max_elements:
            _fail(f"document has more than {self.limits.max_elements} elements")
        if len(self.frames) >= self.limits.max_depth:
            _fail(f"document is nested deeper than {self.limits.max_depth} levels")
        namespace, separator, local = name.partition("}")
        tag = f"{{{namespace}}}{local}" if separator else name
        if not self.frames:
            self.root = ET.Element(tag, attributes)
            self.frames.append(_Frame(self.root, inside_result=tag == _TEST_RESULT))
            return
        parent = self.frames[-1]
        parent_element = parent.element
        if parent_element is not None and (
            parent.inside_result or (len(self.frames) == 1 and tag in _ROOT_CHILDREN)
        ):
            element = ET.SubElement(parent_element, tag, attributes)
            self.frames.append(
                _Frame(element, inside_result=parent.inside_result or tag == _TEST_RESULT)
            )
        else:
            self.frames.append(_Frame(None, inside_result=False))

    def end(self, _name: str) -> None:
        frame = self.frames.pop()
        if frame.element is not None:
            frame.element.text = "".join(frame.text).strip() or None

    def text(self, data: str) -> None:
        frame = self.frames[-1]
        if frame.element is not None:
            frame.text.append(data)


def _reject_markup(document: str) -> None:
    if "<!DOCTYPE" in document or "<!ENTITY" in document:
        _fail("DOCTYPE and ENTITY declarations are not allowed")


def _parse_tree(document: str, limits: XmlLimits) -> ET.Element:
    _reject_markup(document)
    builder = _Builder(limits)
    parser = _expat.ParserCreate(namespace_separator="}")
    parser.SetParamEntityParsing(_expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.buffer_text = True
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.text
    parser.StartDoctypeDeclHandler = builder.reject_declaration
    parser.EntityDeclHandler = builder.reject_declaration
    parser.ExternalEntityRefHandler = builder.reject_declaration
    try:
        parser.Parse(document, True)
    except _expat.ExpatError as error:
        _fail(f"not well-formed XML: {_expat.ErrorString(error.code)} at line {error.lineno}")
    return builder.root


def _utc_timestamp(value: str | None, name: str) -> str:
    if value is None or not value.strip():
        _fail(f"{name} is missing")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
        formatted = moment.astimezone(timezone.utc).strftime(model.TIMESTAMP_FORMAT)
    except (ValueError, OverflowError):
        _fail(f"{name} is not an ISO 8601 timestamp")
    if moment.tzinfo is None:
        _fail(f"{name} has no time zone")
    return formatted


def _clip(value: object) -> str:
    return repr(str(value)[: model.MAX_ECHO_LENGTH])


def _finding(rule_result: ET.Element) -> model.Finding:
    rule_id = rule_result.get("idref")
    if rule_id is None:
        _fail("a rule-result has no idref")
    results = rule_result.findall(_RESULT)
    raw = results[0].text if len(results) == 1 else None
    mapping = model.map_xccdf_result(raw)
    message = None
    if mapping.outcome is model.Outcome.ERROR and raw != "error":
        message = f"scanner result {_clip(raw)} was mapped to error"
    severity = _SEVERITIES.get(rule_result.get("severity", ""), model.Severity.UNKNOWN)
    flags = () if mapping.flag is None else (mapping.flag,)
    try:
        return model.Finding(
            rule_id=rule_id,
            outcome=mapping.outcome,
            evaluated_outcome=mapping.outcome,
            severity=severity,
            message=message,
            evidence=(),
            exception=model.ExceptionStatus.none(),
            remediation=None,
            disabled_by=None,
            flags=flags,
        )
    except model.ModelError as error:
        _fail(f"invalid rule-result: {error}")


def _single_result(root: ET.Element) -> ET.Element:
    results = [root] if root.tag == _TEST_RESULT else root.findall(_TEST_RESULT)
    if len(results) != 1:
        _fail(f"expected exactly one TestResult, found {len(results)}")
    return results[0]


def _benchmark_id(root: ET.Element, result: ET.Element) -> str:
    reference = result.find(_BENCHMARK_REF)
    value = None if reference is None else reference.get("id")
    if value is None and root.tag == _BENCHMARK:
        value = root.get("id")
    if value is None:
        _fail("the results do not identify the benchmark")
    return value


def _benchmark_version(root: ET.Element, result: ET.Element) -> str:
    version = root.find(_VERSION)
    value = None if version is None else version.text
    if value is None:
        value = result.get("version")
    if value is None:
        _fail("the results do not state the benchmark version")
    return value


def _profile_id(result: ET.Element) -> str:
    profile = result.find(_PROFILE)
    value = None if profile is None else profile.get("idref")
    if value is None:
        _fail("the results do not identify the profile")
    return value


def parse_results(document: str, limits: XmlLimits | None = None) -> ParsedResults:
    """Parse and map an XCCDF 1.2 results document.

    Args:
        document: Decoded document text.
        limits: Element and depth bounds; the defaults apply when omitted.

    Returns:
        The extracted benchmark, profile, times and findings. Result values go
        through :func:`model.map_xccdf_result`, so unknown values become
        ``error``.

    Raises:
        XccdfParseError: If the document is unsafe, malformed, not XCCDF 1.2
            or lacks required data. A document is never treated as a pass.
    """
    root = _parse_tree(document, XmlLimits() if limits is None else limits)
    if root.tag not in {_BENCHMARK, _TEST_RESULT}:
        _fail("the root element is not an XCCDF 1.2 Benchmark or TestResult")
    result = _single_result(root)
    findings = tuple(_finding(item) for item in result.findall(_RULE_RESULT))
    rule_ids = [finding.rule_id for finding in findings]
    if len(set(rule_ids)) != len(rule_ids):
        _fail("the results contain a rule more than once")
    return ParsedResults(
        benchmark_id=_benchmark_id(root, result),
        benchmark_version=_benchmark_version(root, result),
        profile_id=_profile_id(result),
        started_at=_utc_timestamp(result.get("start-time"), "start-time"),
        finished_at=_utc_timestamp(result.get("end-time"), "end-time"),
        findings=findings,
    )


def read_results(path: str, max_bytes: int, limits: XmlLimits | None = None) -> ParsedResults:
    """Read a results file with bounds and parse it.

    The file must be a regular file that is not a symlink, at most ``max_bytes``
    long (checked before reading and again while reading), non-empty, valid
    UTF-8 and free of DOCTYPE and ENTITY declarations.

    Raises:
        XccdfParseError: For every rejection, including unreadable files.
    """
    target = Path(path)
    try:
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            _fail("the results path is not a regular file")
        if info.st_size > max_bytes:
            _fail(f"the results file is larger than {max_bytes} bytes")
        with target.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as error:
        _fail(f"the results file cannot be read: {error.strerror or type(error).__name__}")
    if len(data) > max_bytes:
        _fail(f"the results file is larger than {max_bytes} bytes")
    if not data:
        _fail("the results file is empty")
    try:
        document = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        _fail("the results file is not valid UTF-8")
    return parse_results(document, limits)


@dataclass(frozen=True)
class _Failure:
    status: model.ScanStatus
    message: str


@dataclass(frozen=True)
class _Provenance:
    scanner_version: str
    content_name: str
    content_sha256: str
    started: datetime
    finished: datetime


def _clean(text: str, limit: int = MAX_MESSAGE_LENGTH) -> str:
    printable = "".join(c if c.isascii() and c.isprintable() else "?" for c in text)
    return printable.strip()[:limit]


def _excerpt(data: bytes) -> str:
    return _clean(data[:EXCERPT_BYTES].decode("utf-8", "replace"))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(model.TIMESTAMP_FORMAT)


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(HASH_CHUNK_BYTES), b""):
                digest.update(chunk)
    except OSError as error:
        message = f"content cannot be read: {error.strerror or type(error).__name__}"
        raise scanner.ScanRequestError(message) from error
    return digest.hexdigest()


def _confine(base: str, candidate: str) -> str:
    try:
        return process.confined_path(base, candidate)
    except process.ProcessPolicyError as error:
        raise scanner.ScanRequestError(str(error)) from error


def _existing_file(base: str, candidate: str, name: str) -> str:
    path = _confine(base, candidate)
    if not Path(path).is_file():
        message = f"{name} is not an existing regular file: {_clip(candidate)}"
        raise scanner.ScanRequestError(message)
    return path


class OpenScapBackend:
    """Backend that evaluates a profile with ``oscap xccdf eval``.

    ``runner`` and ``clock`` are seams for unit tests. Production code uses the
    defaults, and neither is reachable from module arguments: the registry
    factory takes only :class:`scanner.ScanSettings`.
    """

    def __init__(
        self,
        settings: scanner.ScanSettings,
        *,
        runner: Callable[[process.CommandSpec], process.CommandResult] | None = None,
        clock: Callable[[], datetime] | None = None,
        limits: XmlLimits | None = None,
    ) -> None:
        """Create a backend with fixed settings."""
        self._settings = settings
        self._runner = process.run if runner is None else runner
        self._clock = _utc_now if clock is None else clock
        self._limits = XmlLimits() if limits is None else limits

    def audit(self, request: scanner.ScanRequest) -> model.ScanRun:
        """Evaluate ``request.profile_id`` and return the normalized scan run.

        Raises:
            ScanRequestError: If a path is unsafe or missing or the output
                directory cannot be created fresh; nothing ran.
        """
        content = _existing_file(self._settings.content_root, request.content_path, "content")
        tailoring = (
            None
            if request.tailoring_path is None
            else _existing_file(self._settings.content_root, request.tailoring_path, "tailoring")
        )
        digest = _sha256(content)
        output = self._make_output_directory(request.output_dir)
        started = self._clock()
        probe = self._probe_version()
        version = UNKNOWN_VERSION if isinstance(probe, _Failure) else probe
        outcome = (
            probe
            if isinstance(probe, _Failure)
            else self._evaluate(request, content, tailoring, output)
        )
        if isinstance(outcome, ParsedResults) and _sha256(content) != digest:
            outcome = _Failure(model.ScanStatus.FAILED, "content changed during the scan")
        finished = max(started, self._clock())
        provenance = _Provenance(version, Path(content).name, digest, started, finished)
        return self._build_run(request, outcome, provenance)

    def _make_output_directory(self, candidate: str) -> str:
        path = _confine(self._settings.output_root, candidate)
        try:
            Path(path).mkdir(mode=OUTPUT_DIRECTORY_MODE)
        except FileExistsError as error:
            message = f"output directory already exists: {_clip(candidate)}"
            raise scanner.ScanRequestError(message) from error
        except OSError as error:
            message = f"output directory cannot be created: {error.strerror or 'error'}"
            raise scanner.ScanRequestError(message) from error
        Path(path).chmod(OUTPUT_DIRECTORY_MODE)
        return path

    def _probe_version(self) -> str | _Failure:
        spec = process.CommandSpec(
            "oscap",
            ("--version",),
            VERSION_TIMEOUT_SECONDS,
            max_output_bytes=VERSION_MAX_OUTPUT_BYTES,
        )
        try:
            result = self._runner(spec)
        except process.ProcessExecutionError as error:
            return _Failure(model.ScanStatus.FAILED, _clean(f"oscap is not available: {error}"))
        if result.timed_out:
            return _Failure(model.ScanStatus.TIMED_OUT, "oscap --version timed out")
        if result.returncode != 0:
            status = f"oscap --version exited with status {result.returncode}"
            return _Failure(model.ScanStatus.FAILED, status)
        match = _VERSION_LINE.search(result.stdout.decode("utf-8", "replace"))
        return UNKNOWN_VERSION if match is None else match.group(1)

    def _arguments(
        self, request: scanner.ScanRequest, content: str, tailoring: str | None, output: str
    ) -> tuple[str, ...]:
        arguments = ["xccdf", "eval", "--profile", request.profile_id]
        if tailoring is not None:
            arguments += ["--tailoring-file", tailoring]
        arguments += [
            "--results-arf",
            _confine(output, ARF_FILE_NAME),
            "--results",
            _confine(output, RESULTS_FILE_NAME),
            content,
        ]
        return tuple(arguments)

    def _evaluate(
        self, request: scanner.ScanRequest, content: str, tailoring: str | None, output: str
    ) -> ParsedResults | _Failure:
        spec = process.CommandSpec(
            "oscap",
            self._arguments(request, content, tailoring, output),
            self._settings.timeout_seconds,
        )
        try:
            result = self._runner(spec)
        except process.ProcessExecutionError as error:
            return _Failure(model.ScanStatus.FAILED, _clean(f"oscap could not run: {error}"))
        if result.timed_out:
            message = f"oscap exceeded the timeout of {self._settings.timeout_seconds} seconds"
            return _Failure(model.ScanStatus.TIMED_OUT, message)
        if result.returncode not in {EXIT_ALL_PASSED, EXIT_RULES_FAILED}:
            detail = _excerpt(result.stderr)
            message = f"oscap exited with status {result.returncode}"
            return _Failure(model.ScanStatus.FAILED, f"{message}: {detail}" if detail else message)
        try:
            parsed = read_results(
                str(Path(output) / RESULTS_FILE_NAME), self._settings.max_result_bytes, self._limits
            )
        except XccdfParseError as error:
            return _Failure(model.ScanStatus.FAILED, _clean(f"results rejected: {error}"))
        return self._verify(request, result.returncode, parsed)

    @staticmethod
    def _verify(
        request: scanner.ScanRequest, returncode: int, parsed: ParsedResults
    ) -> ParsedResults | _Failure:
        problem = None
        unsatisfied = any(finding.outcome in _ERROR_OUTCOMES for finding in parsed.findings)
        if parsed.profile_id != request.profile_id:
            problem = "the results are for a different profile than requested"
        elif parsed.benchmark_id != request.benchmark_id:
            problem = "the results are for a different benchmark than requested"
        elif returncode == EXIT_ALL_PASSED and unsatisfied:
            problem = "oscap reported success but the results contain failed or errored rules"
        elif returncode == EXIT_RULES_FAILED and not unsatisfied:
            problem = "oscap reported failed rules but the results contain none"
        if problem is None:
            return parsed
        return _Failure(model.ScanStatus.FAILED, problem)

    def _build_run(
        self,
        request: scanner.ScanRequest,
        outcome: ParsedResults | _Failure,
        facts: _Provenance,
    ) -> model.ScanRun:
        info = model.ScannerInfo(BACKEND_NAME, facts.scanner_version)
        source = facts.content_name
        digest = facts.content_sha256
        if isinstance(outcome, ParsedResults):
            try:
                return model.ScanRun(
                    run_id=request.run_id,
                    started_at=outcome.started_at,
                    finished_at=outcome.finished_at,
                    host=request.host,
                    scanner=info,
                    content=model.Provenance(source, outcome.benchmark_version, digest),
                    benchmark_id=request.benchmark_id,
                    profile_id=request.profile_id,
                    status=model.ScanStatus.COMPLETED,
                    error_message=None,
                    findings=outcome.findings,
                )
            except model.ModelError as error:
                outcome = _Failure(
                    model.ScanStatus.FAILED, _clean(f"results rejected by the model: {error}")
                )
        findings = tuple(
            _error_finding(rule_id, outcome.message) for rule_id in request.expected_rule_ids
        )
        return model.ScanRun(
            run_id=request.run_id,
            started_at=_format(facts.started),
            finished_at=_format(facts.finished),
            host=request.host,
            scanner=info,
            content=model.Provenance(source, UNKNOWN_VERSION, digest),
            benchmark_id=request.benchmark_id,
            profile_id=request.profile_id,
            status=outcome.status,
            error_message=outcome.message,
            findings=findings,
        )


def _error_finding(rule_id: str, message: str) -> model.Finding:
    return model.Finding(
        rule_id=rule_id,
        outcome=model.Outcome.ERROR,
        evaluated_outcome=model.Outcome.ERROR,
        severity=model.Severity.UNKNOWN,
        message=message,
        evidence=(),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=None,
        flags=(),
    )


def create_backend(settings: scanner.ScanSettings) -> OpenScapBackend:
    """Create the production OpenSCAP backend for ``settings``."""
    return OpenScapBackend(settings)


def register(registry: scanner.BackendRegistry) -> None:
    """Register the OpenSCAP backend in ``registry`` under ``openscap``."""
    registry.register(BACKEND_NAME, create_backend)
