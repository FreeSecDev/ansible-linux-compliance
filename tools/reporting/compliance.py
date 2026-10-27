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
* A figure covers one benchmark, one content version, one profile and, unless it is
  an aggregate, one host. Figures of different benchmarks, versions or profiles are
  never pooled: the CIS and STIG profiles of a ComplianceAsCode benchmark share its
  identifier, so the profile is part of every key.
* An expired waiver counts as its evaluated outcome and is counted in
  ``expired_waivers``, also when it lapsed between the scan start and the
  controller time, which only an exceptions evaluation records.
* Every group built from more than one input gets a ``merged_inputs`` note with its
  key, and every host that is counted as one host in several groups gets a
  ``same_host_across_groups`` note. Both are structured; consumers word them.
* A scan run with an off-platform marker (ADR 0019, amendment of FREES-161) evaluated
  a benchmark made for another platform than the host. Its own summary has no
  percentage and the assessment ``off_platform_benchmark``, and it never enters a
  rule list, a group, a pooled figure or a section summary; the report lists it
  separately (:func:`off_platform_inputs`).
"""

from dataclasses import dataclass, replace
from decimal import ROUND_DOWN, Decimal
from typing import Final, NamedTuple

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    placement,
)
from tools.reporting.common import to_json

COMPLETED: Final[str] = model.ScanStatus.COMPLETED.value
NOT_COMPLETED: Final[str] = "not_completed"
ASSESSMENT_RUN_NOT_COMPLETED: Final[str] = "run_not_completed"
ASSESSMENT_NOTHING_EVALUATED: Final[str] = "nothing_evaluated"
ASSESSMENT_ALL_PASSED: Final[str] = "all_evaluated_passed"
ASSESSMENT_FINDINGS_OPEN: Final[str] = "findings_open"
ASSESSMENT_OFF_PLATFORM: Final[str] = "off_platform_benchmark"
KIND_SCAN_RUN: Final[str] = "scan_run"
KIND_EVALUATION: Final[str] = "exceptions_evaluation"
SCAN_RUN_KINDS: Final[frozenset[str]] = frozenset({KIND_SCAN_RUN, KIND_EVALUATION})
MERGED_INPUTS_NOTE: Final[str] = "merged_inputs"
SAME_HOST_NOTE: Final[str] = "same_host_across_groups"

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
            ``all_evaluated_passed``, ``findings_open`` or, for a completed
            off-platform run, ``off_platform_benchmark``. Never a compliance claim.
        compliance_percent: ``pass`` divided by ``evaluated``, rounded down to one
            decimal, or ``None`` when the run did not complete, nothing was evaluated
            or the run is off-platform.
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


def scan_run_summary(summary: Summary, marker: model.OffPlatform | None) -> Summary:
    """Return the summary of one scan run, withheld when the run is off-platform.

    A completed run with an off-platform marker keeps its counts but gets no
    percentage and the assessment ``off_platform_benchmark``: its counts describe
    the host under the benchmark of another platform, never a compliance figure.
    """
    if marker is None or summary.run_status != COMPLETED:
        return summary
    return replace(summary, assessment=ASSESSMENT_OFF_PLATFORM, compliance_percent=None)


def is_expired_waiver(finding: model.Finding, lapsed: frozenset[str]) -> bool:
    """Return whether the waiver of ``finding`` expired, at the scan start or after it.

    ``lapsed`` holds the rules whose exception lapsed between the scan start and the
    controller time; their findings carry no exception data (ADR 0013).
    """
    return finding.exception.state is model.ExceptionState.EXPIRED or finding.rule_id in lapsed


def tally_findings(
    findings: tuple[model.Finding, ...], lapsed: frozenset[str] = frozenset()
) -> list[Tally]:
    """Reduce findings to tallies. An expired exception never changes the outcome."""
    return [
        Tally(finding.outcome, finding.severity, is_expired_waiver(finding, lapsed))
        for finding in findings
    ]


@dataclass(frozen=True)
class ComplianceData:
    """One compliance input: a scan run or XCCDF results, with its own summary.

    For ``scan_run`` and ``exceptions_evaluation`` inputs the validated
    :class:`model.ScanRun` is embedded as is and ``findings`` is serialized empty so
    that no finding appears twice. ``lapsed_waivers`` lists the rules whose exception
    lapsed between the scan start and the controller time, which only an exceptions
    evaluation records. XCCDF and ARF files may name a host (``reported_host``); that
    name is self-asserted by the file. ``off_platform`` is the marker of a scan run
    that evaluated a benchmark made for another platform; XCCDF and ARF files carry
    none.
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
    lapsed_waivers: tuple[str, ...] = ()
    off_platform: model.OffPlatform | None = None

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
            "lapsed_waivers": list(self.lapsed_waivers),
            "not_selected": self.not_selected,
            "off_platform": None if self.off_platform is None else self.off_platform.to_dict(),
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
    """One rule on one host, benchmark, version and profile, however many scans evaluated it.

    The outcome is the worst among the scans, so a pass in one scan never hides a
    failure in another. Every originating scan is listed with its own outcome.
    ``control`` is the control placement of the rule (report schema 2.3), from the
    first source, by artifact path, whose finding carries one, or ``None``.
    """

    rule_id: str
    host: HostKey
    benchmark_id: str
    content_version: str
    profile_id: str
    outcome: model.Outcome
    severity: model.Severity
    expired_waiver: bool
    sources: tuple[RuleSource, ...]
    control: placement.ControlPlacement | None = None


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


class RuleKey(NamedTuple):
    """What a rule is deduplicated over: one host, benchmark, version and profile."""

    host: HostKey
    benchmark_id: str
    content_version: str
    profile_id: str
    rule_id: str


def _collapse(key: RuleKey, evaluations: list[_Evaluation]) -> RuleRollup:
    outcome = evaluations[0].finding.outcome
    severity = evaluations[0].finding.severity
    for evaluation in evaluations[1:]:
        outcome = worse(outcome, evaluation.finding.outcome)
        severity = higher(severity, evaluation.finding.severity)
    sources = sorted(
        {evaluation.source for evaluation in evaluations},
        key=lambda source: (source.artifact, source.benchmark_id, source.profile_id),
    )
    placed = sorted(
        (evaluation for evaluation in evaluations if evaluation.finding.control is not None),
        key=lambda evaluation: evaluation.source.artifact,
    )
    return RuleRollup(
        rule_id=key.rule_id,
        host=key.host,
        benchmark_id=key.benchmark_id,
        content_version=key.content_version,
        profile_id=key.profile_id,
        outcome=outcome,
        severity=severity,
        expired_waiver=any(
            evaluation.source.expired_waiver
            for evaluation in evaluations
            if evaluation.finding.outcome is outcome
        ),
        sources=tuple(sources),
        control=placed[0].finding.control if placed else None,
    )


def rollup(entries: list[Entry]) -> list[RuleRollup]:
    """Deduplicate rules by rule ID across scans of one host, benchmark, version and profile.

    ``entries`` pairs each input's artifact path with its data. Different hosts,
    benchmarks, content versions and profiles stay separate, and so does any input
    without a host name.
    """
    groups: dict[RuleKey, list[_Evaluation]] = {}
    for artifact, data in entries:
        host = host_key(data)
        lapsed = frozenset(data.lapsed_waivers)
        for finding in data.findings:
            source = RuleSource(
                artifact,
                data.benchmark_id,
                data.profile_id,
                finding.outcome,
                is_expired_waiver(finding, lapsed),
            )
            key = RuleKey(
                host, data.benchmark_id, data.content_version, data.profile_id, finding.rule_id
            )
            groups.setdefault(key, []).append(_Evaluation(finding, source))
    return [_collapse(key, evaluations) for key, evaluations in sorted(groups.items())]


def _run_status(statuses: list[str]) -> str:
    unfinished = [status for status in statuses if status != COMPLETED]
    if not unfinished:
        return COMPLETED
    return unfinished[0] if len(statuses) == 1 else NOT_COMPLETED


def figure(entries: list[Entry]) -> Summary:
    """Summarise deduplicated rules of ``entries``, which must share benchmark, version and profile.

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
    """The figure of one benchmark, content version and profile on one host."""

    benchmark_id: str
    content_version: str
    profile_id: str
    host: HostKey
    summary: Summary


@dataclass(frozen=True)
class AggregateFigure:
    """The pooled figure of one benchmark, content version and profile over several hosts."""

    benchmark_id: str
    content_version: str
    profile_id: str
    host_count: int
    scope: str
    summary: Summary


type Figured = tuple[str, str, str]
type GroupKey = tuple[str, str, str, HostKey]


def _groups(entries: list[Entry]) -> dict[GroupKey, list[Entry]]:
    groups: dict[GroupKey, list[Entry]] = {}
    for entry in entries:
        data = entry[1]
        key = (data.benchmark_id, data.content_version, data.profile_id, host_key(data))
        groups.setdefault(key, []).append(entry)
    return groups


def group_figures(entries: list[Entry]) -> list[GroupFigure]:
    """Return one figure per (benchmark, content version, profile, host)."""
    return [
        GroupFigure(benchmark, version, profile, host, figure(members))
        for (benchmark, version, profile, host), members in sorted(_groups(entries).items())
    ]


def _repeated(members: list[Entry]) -> bool:
    profiles = [data.profile_id for _, data in members if data.scan_status == COMPLETED]
    return len(profiles) != len(set(profiles))


def input_notes(entries: list[Entry]) -> list[dict[str, object]]:
    """Return the structured notes about inputs that were combined or counted as one host.

    A ``merged_inputs`` note is written for every group (benchmark, content version,
    profile, host) built from more than one input, whatever the input types, with the
    group key, the SHA-256 of every input and whether two or more inputs completed
    (``repeated_profile``: the same profile was scanned again). A
    ``same_host_across_groups`` note is written for every host key that has inputs in
    more than one group: those inputs are counted as one host, but their figures stay
    separate per group. Notes never contain input text beyond validated identifiers.
    """
    groups = _groups(entries)
    notes: list[dict[str, object]] = []
    hosts: dict[HostKey, list[GroupKey]] = {}
    for key, members in sorted(groups.items()):
        hosts.setdefault(key[3], []).append(key)
        if len(members) > 1:
            notes.append(
                {
                    "group": {
                        "benchmark_id": key[0],
                        "content_version": key[1],
                        "host": key[3].to_dict(),
                        "profile_id": key[2],
                    },
                    "kind": MERGED_INPUTS_NOTE,
                    "repeated_profile": _repeated(members),
                    "sources": sorted(data.input_sha256 for _, data in members),
                }
            )
    for host, keys in sorted(hosts.items()):
        if len(keys) > 1:
            sources = sorted(data.input_sha256 for key in keys for _, data in groups[key])
            notes.append(
                {
                    "groups": [
                        {
                            "benchmark_id": benchmark,
                            "content_version": version,
                            "profile_id": profile,
                        }
                        for benchmark, version, profile, _ in keys
                    ],
                    "host": host.to_dict(),
                    "kind": SAME_HOST_NOTE,
                    "sources": sources,
                }
            )
    return notes


def repeated_scan_runs(entries: list[Entry]) -> int:
    """Return how many groups (host, benchmark, content version, profile) have several scan runs.

    Only completed ScanRun inputs (``scan_run`` and ``exceptions_evaluation``) count.
    Two completed runs of one group would be merged rule by rule, and a machine ID is not
    a secret, so a forged run could add passing rules to a host.
    """
    seen: dict[GroupKey, int] = {}
    for _, data in entries:
        if data.kind in SCAN_RUN_KINDS and data.scan_status == COMPLETED:
            key = (data.benchmark_id, data.content_version, data.profile_id, host_key(data))
            seen[key] = seen.get(key, 0) + 1
    return sum(1 for count in seen.values() if count > 1)


def figured(entries: list[Entry]) -> dict[Figured, list[Entry]]:
    """Group entries by (benchmark, content version, profile): what one figure may cover."""
    result: dict[Figured, list[Entry]] = {}
    for entry in entries:
        data = entry[1]
        key = (data.benchmark_id, data.content_version, data.profile_id)
        result.setdefault(key, []).append(entry)
    return result


def is_off_platform(entry: Entry) -> bool:
    """Return whether ``entry`` is a scan run with an off-platform marker."""
    return entry[1].off_platform is not None


def off_platform_inputs(entries: list[Entry]) -> list[dict[str, object]]:
    """Return one structured entry per off-platform input, sorted by artifact and digest.

    Each entry names the input, its host key, benchmark, content version and profile,
    the platform of the benchmark and of the host, the run status and the count per
    outcome. It holds no percentage and no assessment: these inputs are never figures.
    """
    marked = sorted(
        (
            (artifact, data, data.off_platform)
            for artifact, data in entries
            if data.off_platform is not None
        ),
        key=lambda item: (item[0], item[1].input_sha256),
    )
    return [
        {
            "artifact": artifact,
            "benchmark_id": data.benchmark_id,
            "benchmark_platform": marker.benchmark_platform.to_dict(),
            "content_version": data.content_version,
            "counts": dict(data.summary.counts),
            "host": host_key(data).to_dict(),
            "input_sha256": data.input_sha256,
            "kind": data.kind,
            "profile_id": data.profile_id,
            "run_status": data.scan_status,
            "target_platform": marker.target_platform.to_dict(),
        }
        for artifact, data, marker in marked
    ]


def aggregate_figures(entries: list[Entry], scope: str) -> list[AggregateFigure]:
    """Return one pooled figure per (benchmark, version, profile), labelled with ``scope``."""
    return [
        AggregateFigure(
            benchmark,
            version,
            profile,
            len({host_key(entry[1]) for entry in members}),
            scope,
            figure(members),
        )
        for (benchmark, version, profile), members in sorted(figured(entries).items())
    ]
