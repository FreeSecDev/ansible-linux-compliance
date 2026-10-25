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

Result integrity: the request names the rules the profile selects. A rule without
a rule-result becomes an ``error`` finding, a rule-result for a rule that was not
selected, a duplicate rule-result or a rule-result or result element in another
namespace fails the run, and a failed run reports every selected rule as ``error``.

XML hardening
-------------

Results come from a process on a managed host, so they are untrusted. This module
contains no XML parsing code: every byte goes through :mod:`xmlsafe`, which bounds
the file size before and while reading, refuses symlinks and other non-regular
files, rejects DOCTYPE and ENTITY declarations before parsing, forces UTF-8,
rejects UTF-16, UTF-32 and NUL bytes, turns parameter entities off and bounds the
element count and nesting depth (:class:`XmlLimits`, whose defaults are those of
:mod:`xmlsafe`). This module keeps only the XCCDF semantics:

1. Only the XCCDF 1.2 namespace is accepted for the root, the test result, the
   rule results and their result elements.
2. Elements are never stored. Each rule-result is reduced to its identifier,
   severity and result text when it ends. Text is read only before the first child
   element, and a result or ident element with children is malformed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    process,
    scanner,
    xmlsafe,
)

if TYPE_CHECKING:
    from collections.abc import Callable

BACKEND_NAME: Final[str] = "openscap"
XCCDF_NAMESPACE: Final[str] = "http://checklists.nist.gov/xccdf/1.2"
RESULTS_FILE_NAME: Final[str] = "results.xml"
ARF_FILE_NAME: Final[str] = "results-arf.xml"
UNKNOWN_VERSION: Final[str] = "unknown"
DEFAULT_MAX_ELEMENTS: Final[int] = xmlsafe.DEFAULT_MAX_ELEMENTS
DEFAULT_MAX_DEPTH: Final[int] = xmlsafe.DEFAULT_MAX_DEPTH
EXIT_ALL_PASSED: Final[int] = 0
EXIT_RULES_FAILED: Final[int] = 2
VERSION_TIMEOUT_SECONDS: Final[float] = 30.0
VERSION_MAX_OUTPUT_BYTES: Final[int] = 64 * 1024
OUTPUT_DIRECTORY_MODE: Final[int] = 0o700
MAX_MESSAGE_LENGTH: Final[int] = 1024
EXCERPT_BYTES: Final[int] = 512
HASH_CHUNK_BYTES: Final[int] = 1024 * 1024
SOURCE_NAME_LENGTH: Final[int] = 64
RESULTS_SUBJECT: Final[str] = "results"

_LABEL_NAME: Final[str] = r"[A-Za-z0-9._+-]{1,64}"
_VERSION_LINE: Final[str] = r"\(oscap\)\s+([0-9][A-Za-z0-9._+-]{0,63})"
_SEVERITIES: Final[dict[str, model.Severity]] = {item.value: item for item in model.Severity}
_ERROR_OUTCOMES: Final[frozenset[model.Outcome]] = frozenset(
    {model.Outcome.FAIL, model.Outcome.ERROR}
)

_TEST_ATTRIBUTES: Final[frozenset[str]] = frozenset({"start-time", "end-time", "version"})


def _qualified(local: str) -> str:
    return f"{{{XCCDF_NAMESPACE}}}{local}"


_BENCHMARK: Final[str] = _qualified("Benchmark")
_TEST_RESULT: Final[str] = _qualified("TestResult")
_VERSION: Final[str] = _qualified("version")
_BENCHMARK_REF: Final[str] = _qualified("benchmark")
_PROFILE: Final[str] = _qualified("profile")
_RULE_RESULT: Final[str] = _qualified("rule-result")
_RESULT: Final[str] = _qualified("result")
_IDENT: Final[str] = _qualified("ident")

_ROOT: Final[str] = "root"
_TEST: Final[str] = "test-result"
_RULE: Final[str] = "rule-result"
_RESULT_VALUE: Final[str] = "result"
_IDENT_VALUE: Final[str] = "ident"
_VERSION_VALUE: Final[str] = "version"
_OTHER: Final[str] = "other"
_LEAVES: Final[frozenset[str]] = frozenset({_RESULT_VALUE, _IDENT_VALUE})
_COLLECTING: Final[frozenset[str]] = frozenset({_RESULT_VALUE, _VERSION_VALUE})


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


class _RawRule:
    __slots__ = ("idref", "results", "severity")

    def __init__(self, idref: str | None, severity: str | None) -> None:
        self.idref = idref
        self.severity = severity
        self.results: list[str | None] = []


class _Frame:
    __slots__ = ("had_child", "kind", "text")

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.had_child = False
        self.text: list[str] = []


def _reject_foreign(tag: str, local: str) -> None:
    if tag.rsplit("}", 1)[-1] == local:
        _fail(f"a {local} element outside the XCCDF 1.2 namespace is not allowed")


class _Builder:
    """Receiver of :mod:`xmlsafe` events that streams compact rule data.

    Nothing but the few values the extraction needs is kept: rule results are
    reduced to ``(idref, severity, result text)`` as each one ends and the
    elements themselves are never stored, so memory does not grow with the size
    of the document. Text is collected only before the first child element of
    an element, so text that follows a child is never merged into its parent.
    Element names arrive in Clark notation, and the element count and depth are
    bounded by :mod:`xmlsafe` before an element reaches this receiver.
    """

    def __init__(self) -> None:
        self.frames: list[_Frame] = []
        self.root_tag = ""
        self.root_id: str | None = None
        self.version: str | None = None
        self.test_results = 0
        self.test_attributes: dict[str, str] = {}
        self.benchmark_ref: str | None = None
        self.profile_idref: str | None = None
        self.rule = _RawRule(None, None)
        self.rules: list[tuple[str | None, str | None, str | None]] = []

    def start(self, tag: str, attributes: dict[str, str]) -> None:
        if self.frames:
            parent = self.frames[-1]
            parent.had_child = True
            kind = self._classify(parent.kind, tag, attributes)
        else:
            self.root_tag = tag
            self.root_id = attributes.get("id")
            kind = _ROOT
            if tag == _TEST_RESULT:
                self._open_test(attributes)
                kind = _TEST
        self.frames.append(_Frame(kind))

    def _open_test(self, attributes: dict[str, str]) -> None:
        self.test_results += 1
        if self.test_results == 1:
            self.test_attributes = {
                key: value for key, value in attributes.items() if key in _TEST_ATTRIBUTES
            }

    def _classify(self, parent_kind: str, tag: str, attributes: dict[str, str]) -> str:
        if parent_kind in _LEAVES:
            _fail("a result or ident element may not contain child elements")
        if parent_kind == _TEST:
            return self._classify_test_child(tag, attributes)
        if parent_kind == _RULE:
            return self._classify_rule_child(tag)
        if parent_kind == _ROOT:
            return self._classify_root_child(tag, attributes)
        return _OTHER

    def _classify_root_child(self, tag: str, attributes: dict[str, str]) -> str:
        if tag == _TEST_RESULT:
            self._open_test(attributes)
            return _TEST
        return _VERSION_VALUE if tag == _VERSION else _OTHER

    def _classify_test_child(self, tag: str, attributes: dict[str, str]) -> str:
        if tag == _RULE_RESULT:
            self.rule = _RawRule(attributes.get("idref"), attributes.get("severity"))
            return _RULE
        if tag == _BENCHMARK_REF:
            self.benchmark_ref = self.benchmark_ref or attributes.get("id")
        elif tag == _PROFILE:
            self.profile_idref = self.profile_idref or attributes.get("idref")
        else:
            _reject_foreign(tag, "rule-result")
        return _OTHER

    @staticmethod
    def _classify_rule_child(tag: str) -> str:
        if tag == _RESULT:
            return _RESULT_VALUE
        if tag == _IDENT:
            return _IDENT_VALUE
        _reject_foreign(tag, "result")
        return _OTHER

    def end(self, _name: str) -> None:
        frame = self.frames.pop()
        value = "".join(frame.text).strip() or None
        if frame.kind == _VERSION_VALUE and self.version is None:
            self.version = value
        elif frame.kind == _RESULT_VALUE:
            self.rule.results.append(value)
        elif frame.kind == _RULE:
            results = self.rule.results
            raw = results[0] if len(results) == 1 else None
            self.rules.append((self.rule.idref, self.rule.severity, raw))

    def text(self, data: str) -> None:
        frame = self.frames[-1]
        if frame.kind in _COLLECTING and not frame.had_child:
            frame.text.append(data)


def _bounds(limits: XmlLimits | None) -> xmlsafe.XmlBounds:
    chosen = XmlLimits() if limits is None else limits
    return xmlsafe.XmlBounds(max_elements=chosen.max_elements, max_depth=chosen.max_depth)


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


def _finding(rule_id: str | None, severity: str | None, raw: str | None) -> model.Finding:
    if rule_id is None:
        _fail("a rule-result has no idref")
    mapping = model.map_xccdf_result(raw)
    message = None
    if mapping.outcome is model.Outcome.ERROR and raw != "error":
        message = f"scanner result {_clip(raw)} was mapped to error"
    flags = () if mapping.flag is None else (mapping.flag,)
    try:
        return model.Finding(
            rule_id=rule_id,
            outcome=mapping.outcome,
            evaluated_outcome=mapping.outcome,
            severity=_SEVERITIES.get(severity or "", model.Severity.UNKNOWN),
            message=message,
            evidence=(),
            exception=model.ExceptionStatus.none(),
            remediation=None,
            disabled_by=None,
            flags=flags,
        )
    except model.ModelError as error:
        _fail(f"invalid rule-result: {error}")


def _extract(builder: _Builder) -> ParsedResults:
    if builder.root_tag not in {_BENCHMARK, _TEST_RESULT}:
        _fail("the root element is not an XCCDF 1.2 Benchmark or TestResult")
    if builder.test_results != 1:
        _fail(f"expected exactly one TestResult, found {builder.test_results}")
    findings = tuple(_finding(*raw) for raw in builder.rules)
    rule_ids = [finding.rule_id for finding in findings]
    if len(set(rule_ids)) != len(rule_ids):
        _fail("the results contain a rule more than once")
    attributes = builder.test_attributes
    benchmark_id = builder.benchmark_ref
    if benchmark_id is None and builder.root_tag == _BENCHMARK:
        benchmark_id = builder.root_id
    if benchmark_id is None:
        _fail("the results do not identify the benchmark")
    version = builder.version or attributes.get("version")
    if version is None:
        _fail("the results do not state the benchmark version")
    if builder.profile_idref is None:
        _fail("the results do not identify the profile")
    return ParsedResults(
        benchmark_id=benchmark_id,
        benchmark_version=version,
        profile_id=builder.profile_idref,
        started_at=_utc_timestamp(attributes.get("start-time"), "start-time"),
        finished_at=_utc_timestamp(attributes.get("end-time"), "end-time"),
        findings=findings,
    )


def parse_results(document: str, limits: XmlLimits | None = None) -> ParsedResults:
    """Parse and map an XCCDF 1.2 results document held in memory.

    Args:
        document: Document text.
        limits: Element and depth bounds; the defaults apply when omitted.

    Returns:
        The extracted benchmark, profile, times and findings. Result values go
        through :func:`model.map_xccdf_result`, so unknown values become
        ``error``.

    Raises:
        XccdfParseError: If the document is unsafe, malformed, not XCCDF 1.2
            or lacks required data. A document is never treated as a pass.
    """
    builder = _Builder()
    try:
        xmlsafe.parse_text(document, builder, _bounds(limits))
    except xmlsafe.XmlSafetyError as error:
        raise XccdfParseError(str(error)) from error
    return _extract(builder)


def read_results(path: str, max_bytes: int, limits: XmlLimits | None = None) -> ParsedResults:
    """Stream a results file through the parser with bounds.

    The file must be a regular file that is not a symlink and at most
    ``max_bytes`` long (checked before reading and again while reading). It is
    read in chunks, so memory does not grow with its size. The parser is told
    that the text is UTF-8, so other encodings are malformed, and DOCTYPE and
    ENTITY declarations are rejected before the chunk that holds them is parsed.

    Raises:
        XccdfParseError: For every rejection, including unreadable files.
    """
    builder = _Builder()
    bounds = _bounds(limits)
    try:
        with xmlsafe.open_regular(path, max_bytes, subject=RESULTS_SUBJECT) as handle:
            chunks = xmlsafe.iter_handle_chunks(handle, max_bytes, subject=RESULTS_SUBJECT)
            xmlsafe.parse_chunks(chunks, builder, bounds)
    except xmlsafe.XmlSafetyError as error:
        raise XccdfParseError(str(error)) from error
    return _extract(builder)


@dataclass(frozen=True)
class _Failure:
    status: model.ScanStatus
    message: str


@dataclass(frozen=True)
class _Provenance:
    scanner_version: str
    source: str
    content_sha256: str
    started: datetime
    finished: datetime


def _label_name(path: str, kind: str) -> str:
    name = Path(path).name
    if re.fullmatch(_LABEL_NAME, name) is None:
        message = (
            f"{kind} file name must match [A-Za-z0-9._+-]{{1,{SOURCE_NAME_LENGTH}}}: {_clip(name)}"
        )
        raise scanner.ScanRequestError(message)
    return name


def _source_label(content: str, tailoring: str | None, tailoring_digest: str | None) -> str:
    label = Path(content).name
    if tailoring is None:
        return label
    name = Path(tailoring).name
    return f"{label} tailoring={name} tailoring_sha256={tailoring_digest}"


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
        _label_name(content, "content")
        if tailoring is not None:
            _label_name(tailoring, "tailoring")
        digest = _sha256(content)
        tailoring_digest = None if tailoring is None else _sha256(tailoring)
        output = self._make_output_directory(request.output_dir)
        started = self._clock()
        probe = self._probe_version()
        version = UNKNOWN_VERSION if isinstance(probe, _Failure) else probe
        outcome = (
            probe
            if isinstance(probe, _Failure)
            else self._run_evaluation(request, content, tailoring, output)
        )
        unchanged = _sha256(content) == digest and (
            tailoring is None or _sha256(tailoring) == tailoring_digest
        )
        if isinstance(outcome, ParsedResults) and not unchanged:
            outcome = _Failure(
                model.ScanStatus.FAILED, "content or tailoring file changed during the scan"
            )
        finished = max(started, self._clock())
        source = _source_label(content, tailoring, tailoring_digest)
        provenance = _Provenance(version, source, digest, started, finished)
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
        match = re.search(_VERSION_LINE, result.stdout.decode("utf-8", "replace"))
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

    def _run_evaluation(
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
        expected_ids = set(request.expected_rule_ids)
        kept = tuple(
            finding
            for finding in parsed.findings
            if finding.rule_id in expected_ids or model.ResultFlag.NOTSELECTED not in finding.flags
        )
        reported = {finding.rule_id for finding in kept}
        missing = tuple(
            _error_finding(rule_id, "the results contain no rule-result for this rule")
            for rule_id in request.expected_rule_ids
            if rule_id not in reported
        )
        findings = (*kept, *missing)
        unsatisfied = any(finding.outcome in _ERROR_OUTCOMES for finding in findings)
        unexpected = len(reported - expected_ids)
        problem = None
        if parsed.profile_id != request.profile_id:
            problem = "the results are for a different profile than requested"
        elif parsed.benchmark_id != request.benchmark_id:
            problem = "the results are for a different benchmark than requested"
        elif unexpected:
            problem = f"the results contain {unexpected} rule(s) that the profile does not select"
        elif returncode == EXIT_ALL_PASSED and unsatisfied:
            problem = (
                "oscap reported success but the results contain failed, errored or missing rules"
            )
        elif returncode == EXIT_RULES_FAILED and not unsatisfied:
            problem = "oscap reported failed rules but the results contain none"
        if problem is None:
            return replace(parsed, findings=findings)
        return _Failure(model.ScanStatus.FAILED, problem)

    def _build_run(
        self,
        request: scanner.ScanRequest,
        outcome: ParsedResults | _Failure,
        facts: _Provenance,
    ) -> model.ScanRun:
        info = model.ScannerInfo(BACKEND_NAME, facts.scanner_version)
        source = facts.source
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
