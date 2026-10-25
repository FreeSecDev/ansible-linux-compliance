"""Compliance summary maths, rule deduplication and severity aggregation (ADR 0013, ADR 0016).

Counting rules:

* ``pass`` is the only outcome that counts as passing. ``waived``, ``notchecked``,
  ``error``, ``notapplicable`` and ``disabled`` never count as pass.
* The compliance percentage is ``pass`` divided by every evaluated outcome, which is
  all outcomes except ``notapplicable`` and ``disabled``. ``waived``, ``notchecked``
  and ``error`` stay in the denominator, so they lower the percentage. It is rounded
  down to one decimal, so 100.0 appears only when everything evaluated passed.
* ``notselected`` rule results of XCCDF and ARF files never enter the maths; they are
  reported as a separate ``not_selected`` count.
* A run that did not complete is never summarised as compliant. The run status comes
  first and the percentage is withheld.
* A figure covers one benchmark, one content version and, unless it is an aggregate,
  one host. Figures of different benchmarks or versions are never pooled.
"""

from dataclasses import dataclass
from decimal import ROUND_DOWN, Decimal
from typing import Final, NamedTuple

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting.common import to_json

COMPLETED: Final[str] = model.ScanStatus.COMPLETED.value
NOT_COMPLETED: Final[str] = "not_completed"
ASSESSMENT_RUN_NOT_COMPLETED: Final[str] = "run_not_completed"
ASSESSMENT_NOTHING_EVALUATED: Final[str] = "nothing_evaluated"
ASSESSMENT_ALL_PASSED: Final[str] = "all_evaluated_passed"
ASSESSMENT_FINDINGS_OPEN: Final[str] = "findings_open"

EXCLUDED_FROM_DENOMINATOR: Final[frozenset[model.Outcome]] = frozenset(
    {model.Outcome.NOTAPPLICABLE, model.Outcome.DISABLED}
)
OPEN_OUTCOMES: Final[frozenset[model.Outcome]] = frozenset(
    {model.Outcome.FAIL, model.Outcome.ERROR, model.Outcome.NOTCHECKED}
)
OUTCOME_BADNESS: Final[tuple[model.Outcome, ...]] = (
    model.Outcome.ERROR,
    model.Outcome.FAIL,
    model.Outcome.NOTCHECKED,
    model.Outcome.WAIVED,
    model.Outcome.PASS,
    model.Outcome.NOTAPPLICABLE,
    model.Outcome.DISABLED,
)
SEVERITY_RANK: Final[tuple[model.Severity, ...]] = (
    model.Severity.UNKNOWN,
    model.Severity.INFO,
    model.Severity.LOW,
    model.Severity.MEDIUM,
    model.Severity.HIGH,
)
_PERCENT_STEP: Final[Decimal] = Decimal("0.1")
_HUNDRED: Final[Decimal] = Decimal(100)


class Tally(NamedTuple):
    """One evaluated rule reduced to what the summary counts."""

    outcome: model.Outcome
    severity: model.Severity
    expired_waiver: bool


@dataclass(frozen=True)
class Summary:
    """Counts and verdict for a set of rule outcomes.

    Attributes:
        run_status: ``completed``, ``failed``, ``timed_out`` or, for several runs,
            ``not_completed``. It is shown before any count.
        assessment: ``run_not_completed``, ``nothing_evaluated``,
            ``all_evaluated_passed`` or ``findings_open``. Never a compliance claim.
        compliance_percent: ``pass`` divided by ``evaluated``, rounded down to one
            decimal, or ``None`` when the run did not complete or nothing was evaluated.
        evaluated: The denominator: all outcomes except ``notapplicable`` and ``disabled``.
        counts: Number of rules per outcome, every outcome present.
        not_selected: Rule results the profile did not select. Informational only.
        expired_waivers: Rules whose waiver expired; they count as their evaluated outcome.
        open_by_severity: ``fail``, ``error`` and ``notchecked`` rules per severity.
        runs_total: Number of scan runs summarised.
        runs_not_completed: Number of those runs whose scanner did not complete.
    """

    run_status: str
    assessment: str
    compliance_percent: float | None
    evaluated: int
    counts: dict[str, int]
    not_selected: int
    expired_waivers: int
    open_by_severity: dict[str, int]
    runs_total: int
    runs_not_completed: int


def percent(passed: int, evaluated: int) -> float | None:
    """Return ``passed`` as a percentage of ``evaluated`` rounded down to one decimal."""
    if evaluated == 0:
        return None
    ratio = Decimal(passed) * _HUNDRED / Decimal(evaluated)
    return float(ratio.quantize(_PERCENT_STEP, rounding=ROUND_DOWN))


def _assessment(run_status: str, evaluated: int, passed: int) -> str:
    if run_status != COMPLETED:
        return ASSESSMENT_RUN_NOT_COMPLETED
    if evaluated == 0:
        return ASSESSMENT_NOTHING_EVALUATED
    if passed == evaluated:
        return ASSESSMENT_ALL_PASSED
    return ASSESSMENT_FINDINGS_OPEN


def summarize(
    tallies: list[Tally],
    run_status: str,
    runs_total: int,
    runs_not_completed: int,
    not_selected: int = 0,
) -> Summary:
    """Apply the counting rules to ``tallies``."""
    counts = {outcome.value: 0 for outcome in model.Outcome}
    open_by_severity = {severity.value: 0 for severity in model.Severity}
    for tally in tallies:
        counts[tally.outcome.value] += 1
        if tally.outcome in OPEN_OUTCOMES:
            open_by_severity[tally.severity.value] += 1
    evaluated = sum(
        count
        for name, count in counts.items()
        if model.Outcome(name) not in EXCLUDED_FROM_DENOMINATOR
    )
    passed = counts[model.Outcome.PASS.value]
    completed = run_status == COMPLETED
    return Summary(
        run_status=run_status,
        assessment=_assessment(run_status, evaluated, passed),
        compliance_percent=percent(passed, evaluated) if completed else None,
        evaluated=evaluated,
        counts=counts,
        not_selected=not_selected,
        expired_waivers=sum(1 for tally in tallies if tally.expired_waiver),
        open_by_severity=open_by_severity,
        runs_total=runs_total,
        runs_not_completed=runs_not_completed,
    )


def tally_findings(findings: tuple[model.Finding, ...]) -> list[Tally]:
    """Reduce findings to tallies. An expired exception never changes the outcome."""
    return [
        Tally(
            finding.outcome,
            finding.severity,
            finding.exception.state is model.ExceptionState.EXPIRED,
        )
        for finding in findings
    ]


@dataclass(frozen=True)
class ComplianceData:
    """One compliance input: a scan run or XCCDF results, with its own summary.

    For ``scan_run`` inputs the validated :class:`model.ScanRun` is embedded as is and
    ``findings`` is serialized empty so that no finding appears twice. XCCDF and ARF
    files may name a host (``reported_host``); that name is self-asserted by the file.
    """

    kind: str
    scan_status: str
    error_message: str | None
    benchmark_id: str
    benchmark_version: str | None
    profile_id: str
    started_at: str
    finished_at: str
    host: model.HostIdentity | None
    reported_host: str | None
    input_sha256: str
    content_version: str
    findings: tuple[model.Finding, ...]
    not_selected: int
    scan_run: model.ScanRun | None
    summary: Summary

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        embedded = self.scan_run is not None
        return {
            "benchmark_id": self.benchmark_id,
            "benchmark_version": self.benchmark_version,
            "content_version": self.content_version,
            "error_message": self.error_message,
            "finished_at": self.finished_at,
            "findings": [] if embedded else [finding.to_dict() for finding in self.findings],
            "host": None if self.host is None else self.host.to_dict(),
            "input_sha256": self.input_sha256,
            "kind": self.kind,
            "not_selected": self.not_selected,
            "profile_id": self.profile_id,
            "reported_host": self.reported_host,
            "scan_run": None if self.scan_run is None else self.scan_run.to_dict(),
            "scan_status": self.scan_status,
            "started_at": self.started_at,
            "summary": to_json(self.summary),
        }


@dataclass(frozen=True, order=True)
class HostKey:
    """The identity that groups inputs by host, compared on its fields, never on joined text.

    A named host has a lower-cased ``hostname`` and, for a ScanRun that has one, a
    ``machine_id``. An input that names no host has only ``input_sha256``, the SHA-256
    of its content, so it equals nothing but itself. An empty string means absent.
    """

    hostname: str = ""
    machine_id: str = ""
    input_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping with absent fields as ``None``."""
        return {
            "hostname": self.hostname or None,
            "input_sha256": self.input_sha256 or None,
            "machine_id": self.machine_id or None,
        }


@dataclass(frozen=True)
class RuleSource:
    """Which scan contributed an evaluation of a rule, and what it decided."""

    artifact: str
    benchmark_id: str
    profile_id: str
    outcome: model.Outcome
    expired_waiver: bool


@dataclass(frozen=True)
class RuleRollup:
    """One rule on one host and content version, however many scans evaluated it.

    The outcome is the worst among the scans, so a pass in one scan never hides a
    failure in another. Every originating scan is listed with its own outcome.
    """

    rule_id: str
    host: HostKey
    content_version: str
    outcome: model.Outcome
    severity: model.Severity
    expired_waiver: bool
    sources: tuple[RuleSource, ...]


class _Evaluation(NamedTuple):
    finding: model.Finding
    source: RuleSource


type Entry = tuple[str, ComplianceData]


def host_key(data: ComplianceData) -> HostKey:
    """Return the host identity of an input.

    A ScanRun uses its host name and machine ID. XCCDF and ARF use the validated,
    self-asserted name from the file. Both are lower-cased. An input that names no host
    is its own host, identified by the SHA-256 of its content, and is never merged.
    """
    if data.host is not None:
        return HostKey(data.host.hostname.lower(), data.host.machine_id or "", "")
    if data.reported_host is not None:
        return HostKey(data.reported_host.lower(), "", "")
    return HostKey("", "", data.input_sha256)


def worse(first: model.Outcome, second: model.Outcome) -> model.Outcome:
    """Return the outcome that is worse for compliance."""
    if OUTCOME_BADNESS.index(first) <= OUTCOME_BADNESS.index(second):
        return first
    return second


def higher(first: model.Severity, second: model.Severity) -> model.Severity:
    """Return the more severe of two severities."""
    if SEVERITY_RANK.index(first) >= SEVERITY_RANK.index(second):
        return first
    return second


def _collapse(
    rule_id: str, host: HostKey, content_version: str, evaluations: list[_Evaluation]
) -> RuleRollup:
    outcome = evaluations[0].finding.outcome
    severity = evaluations[0].finding.severity
    for evaluation in evaluations[1:]:
        outcome = worse(outcome, evaluation.finding.outcome)
        severity = higher(severity, evaluation.finding.severity)
    sources = sorted(
        {evaluation.source for evaluation in evaluations},
        key=lambda source: (source.artifact, source.benchmark_id, source.profile_id),
    )
    return RuleRollup(
        rule_id=rule_id,
        host=host,
        content_version=content_version,
        outcome=outcome,
        severity=severity,
        expired_waiver=any(
            evaluation.source.expired_waiver
            for evaluation in evaluations
            if evaluation.finding.outcome is outcome
        ),
        sources=tuple(sources),
    )


def rollup(entries: list[Entry]) -> list[RuleRollup]:
    """Deduplicate rules by rule ID across scans of the same host and content version.

    ``entries`` pairs each input's artifact path with its data. Different hosts and
    different content versions stay separate, and so does any input without a host name.
    """
    groups: dict[tuple[HostKey, str, str], list[_Evaluation]] = {}
    for artifact, data in entries:
        host = host_key(data)
        for finding in data.findings:
            source = RuleSource(
                artifact,
                data.benchmark_id,
                data.profile_id,
                finding.outcome,
                finding.exception.state is model.ExceptionState.EXPIRED,
            )
            key = (host, data.content_version, finding.rule_id)
            groups.setdefault(key, []).append(_Evaluation(finding, source))
    return [
        _collapse(rule_id, host, version, evaluations)
        for (host, version, rule_id), evaluations in sorted(groups.items())
    ]


def _run_status(statuses: list[str]) -> str:
    unfinished = [status for status in statuses if status != COMPLETED]
    if not unfinished:
        return COMPLETED
    return unfinished[0] if len(statuses) == 1 else NOT_COMPLETED


def figure(entries: list[Entry]) -> Summary:
    """Summarise deduplicated rules of ``entries``, which must share benchmark and version.

    The run status is ``completed`` only when every run completed; for several runs
    the status is ``not_completed`` as soon as one did not, and no percentage appears.
    """
    rules = rollup(entries)
    statuses = [data.scan_status for _, data in entries]
    tallies = [Tally(rule.outcome, rule.severity, rule.expired_waiver) for rule in rules]
    unfinished = sum(1 for status in statuses if status != COMPLETED)
    not_selected = sum(data.not_selected for _, data in entries)
    return summarize(tallies, _run_status(statuses), len(statuses), unfinished, not_selected)


@dataclass(frozen=True)
class GroupFigure:
    """The figure of one benchmark and content version on one host."""

    benchmark_id: str
    content_version: str
    host: HostKey
    summary: Summary


@dataclass(frozen=True)
class AggregateFigure:
    """The pooled figure of one benchmark and content version over several hosts."""

    benchmark_id: str
    content_version: str
    host_count: int
    scope: str
    summary: Summary


def group_figures(entries: list[Entry]) -> list[GroupFigure]:
    """Return one figure per (benchmark, content version, host)."""
    groups: dict[tuple[str, str, HostKey], list[Entry]] = {}
    for entry in entries:
        key = (entry[1].benchmark_id, entry[1].content_version, host_key(entry[1]))
        groups.setdefault(key, []).append(entry)
    return [
        GroupFigure(benchmark, version, host, figure(members))
        for (benchmark, version, host), members in sorted(groups.items())
    ]


def pairs(entries: list[Entry]) -> dict[tuple[str, str], list[Entry]]:
    """Group entries by (benchmark, content version)."""
    result: dict[tuple[str, str], list[Entry]] = {}
    for entry in entries:
        result.setdefault((entry[1].benchmark_id, entry[1].content_version), []).append(entry)
    return result


def aggregate_figures(entries: list[Entry], scope: str) -> list[AggregateFigure]:
    """Return one pooled figure per (benchmark, content version), labelled with ``scope``."""
    return [
        AggregateFigure(
            benchmark,
            version,
            len({host_key(entry[1]) for entry in members}),
            scope,
            figure(members),
        )
        for (benchmark, version), members in sorted(pairs(entries).items())
    ]
