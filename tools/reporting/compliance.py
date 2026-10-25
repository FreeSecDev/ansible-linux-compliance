"""Compliance summary maths, rule deduplication and severity aggregation (ADR 0013, ADR 0016).

Counting rules:

* ``pass`` is the only outcome that counts as passing. ``waived``, ``notchecked``,
  ``error``, ``notapplicable`` and ``disabled`` never count as pass.
* The compliance percentage is ``pass`` divided by every evaluated outcome, which is
  all outcomes except ``notapplicable`` and ``disabled``. ``waived``, ``notchecked``
  and ``error`` stay in the denominator, so they lower the percentage.
* A run that did not complete is never summarised as compliant. The run status comes
  first and the percentage is withheld.
"""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
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
_PERCENT_STEP: Final[Decimal] = Decimal("0.01")
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
        compliance_percent: ``pass`` divided by ``evaluated``, rounded half up to two
            decimals, or ``None`` when the run did not complete or nothing was evaluated.
        evaluated: The denominator: all outcomes except ``notapplicable`` and ``disabled``.
        counts: Number of rules per outcome, every outcome present.
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
    expired_waivers: int
    open_by_severity: dict[str, int]
    runs_total: int
    runs_not_completed: int


def percent(passed: int, evaluated: int) -> float | None:
    """Return ``passed`` as a percentage of ``evaluated`` rounded half up, or ``None``."""
    if evaluated == 0:
        return None
    ratio = Decimal(passed) * _HUNDRED / Decimal(evaluated)
    return float(ratio.quantize(_PERCENT_STEP, rounding=ROUND_HALF_UP))


def _assessment(run_status: str, evaluated: int, passed: int) -> str:
    if run_status != COMPLETED:
        return ASSESSMENT_RUN_NOT_COMPLETED
    if evaluated == 0:
        return ASSESSMENT_NOTHING_EVALUATED
    if passed == evaluated:
        return ASSESSMENT_ALL_PASSED
    return ASSESSMENT_FINDINGS_OPEN


def summarize(
    tallies: list[Tally], run_status: str, runs_total: int, runs_not_completed: int
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
    ``findings`` is serialized empty so that no finding appears twice.
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
    content_version: str
    findings: tuple[model.Finding, ...]
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
            "kind": self.kind,
            "profile_id": self.profile_id,
            "scan_run": None if self.scan_run is None else self.scan_run.to_dict(),
            "scan_status": self.scan_status,
            "started_at": self.started_at,
            "summary": to_json(self.summary),
        }


@dataclass(frozen=True)
class RuleSource:
    """Which scan contributed an evaluation of a rule."""

    artifact: str
    benchmark_id: str
    profile_id: str


@dataclass(frozen=True)
class RuleRollup:
    """One rule on one host and content version, however many scans evaluated it.

    The outcome is the worst among the scans, so a pass in one scan never hides a
    failure in another. All originating benchmarks and profiles are kept.
    """

    rule_id: str
    host: str
    content_version: str
    outcome: model.Outcome
    severity: model.Severity
    expired_waiver: bool
    sources: tuple[RuleSource, ...]


class _Evaluation(NamedTuple):
    finding: model.Finding
    source: RuleSource


def _host_key(artifact: str, data: ComplianceData) -> str:
    return artifact if data.host is None else data.host.hostname


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
    rule_id: str, host: str, content_version: str, evaluations: list[_Evaluation]
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
            evaluation.finding.exception.state is model.ExceptionState.EXPIRED
            for evaluation in evaluations
        ),
        sources=tuple(sources),
    )


def rollup(entries: list[tuple[str, ComplianceData]]) -> list[RuleRollup]:
    """Deduplicate rules by rule ID across scans of the same host and content version.

    ``entries`` pairs each input's artifact path with its data. Inputs without a host
    identity (XCCDF and ARF results) are keyed by their artifact path, so two such
    files are never merged into one host. Different content versions stay separate.
    """
    groups: dict[tuple[str, str, str], list[_Evaluation]] = {}
    for artifact, data in entries:
        source = RuleSource(artifact, data.benchmark_id, data.profile_id)
        host = _host_key(artifact, data)
        for finding in data.findings:
            key = (host, data.content_version, finding.rule_id)
            groups.setdefault(key, []).append(_Evaluation(finding, source))
    return [
        _collapse(rule_id, host, version, evaluations)
        for (host, version, rule_id), evaluations in sorted(groups.items())
    ]


def summarize_rollup(rules: list[RuleRollup], run_statuses: list[str]) -> Summary:
    """Summarise deduplicated rules for a set of runs.

    The run status is ``completed`` only when every run completed; otherwise it is
    ``not_completed`` and no percentage is produced.
    """
    unfinished = sum(1 for status in run_statuses if status != COMPLETED)
    tallies = [Tally(rule.outcome, rule.severity, rule.expired_waiver) for rule in rules]
    status = COMPLETED if unfinished == 0 else NOT_COMPLETED
    return summarize(tallies, status, len(run_statuses), unfinished)
