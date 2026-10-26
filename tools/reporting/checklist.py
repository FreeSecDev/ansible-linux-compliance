"""STIG Viewer checklists from normalized findings: the status mapping and the content (FREES-147).

The status of every checklist entry is decided here, by the table of ADR 0020, in this
order:

1. a finding with an off-platform marker, or any finding of a run with one, is Not
   Reviewed, whatever its outcome (ADR 0019, amendment of FREES-161);
2. every finding of a run that did not complete is Not Reviewed;
3. ``pass`` is Not a Finding, unless the scanner reported it as ``fixed``, which is Not
   Reviewed because a remediation result is not a review;
4. ``fail`` is Open, and so is a ``waived`` finding, whose evaluated outcome is always
   ``fail``: the waiver goes into the comments, never into the status;
5. ``notapplicable`` is Not Applicable;
6. ``notchecked``, ``error``, ``disabled`` and a rule of the content without a finding are
   Not Reviewed.

Nothing else is Not a Finding. The finding details name the scanner's result and why a
rule is not reviewed; the comments name every exception and lapsed waiver.

The descriptive fields come from DISA STIG content (:mod:`tools.reporting.stig_content`)
read at export time. A scan run whose rules are not DISA STIG rules (ComplianceAsCode
findings of the OpenSCAP backend) is refused, because the mapping that would give them
DISA group and rule IDs is FREES-146.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting.stig_content import DISA_RULE, StigBenchmark, StigRule

EXPORTER: Final[str] = "freesecdev.linux_compliance (tools.reporting)"
ROLE: Final[str] = "None"
ASSET_TYPE: Final[str] = "Computing"
UUID_NAMESPACE: Final[uuid.UUID] = uuid.UUID("7d3f2a8e-4c1b-5e9a-8f60-2b7c1d0e9a41")
MAPPING_ISSUE: Final[str] = "FREES-146"


class ChecklistError(ValueError):
    """Raised when a checklist cannot be produced without misstating the findings."""


@dataclass(frozen=True)
class Status:
    """A checklist status in both formats.

    Attributes:
        name: The name STIG Viewer shows.
        ckl: The ``STATUS`` value of a CKL file (STIG Viewer 2).
        cklb: The ``status`` value of a CKLB file (STIG Viewer 3).
    """

    name: str
    ckl: str
    cklb: str


NOT_A_FINDING: Final[Status] = Status("Not a Finding", "NotAFinding", "not_a_finding")
OPEN: Final[Status] = Status("Open", "Open", "open")
NOT_APPLICABLE: Final[Status] = Status("Not Applicable", "Not_Applicable", "not_applicable")
NOT_REVIEWED: Final[Status] = Status("Not Reviewed", "Not_Reviewed", "not_reviewed")
STATUSES: Final[tuple[Status, ...]] = (NOT_A_FINDING, OPEN, NOT_APPLICABLE, NOT_REVIEWED)
OUTCOME_STATUSES: Final[Mapping[model.Outcome, Status]] = {
    model.Outcome.PASS: NOT_A_FINDING,
    model.Outcome.FAIL: OPEN,
    model.Outcome.WAIVED: OPEN,
    model.Outcome.NOTAPPLICABLE: NOT_APPLICABLE,
    model.Outcome.NOTCHECKED: NOT_REVIEWED,
    model.Outcome.ERROR: NOT_REVIEWED,
    model.Outcome.DISABLED: NOT_REVIEWED,
}


@dataclass(frozen=True)
class Verdict:
    """The status of one checklist entry and the text that explains it."""

    status: Status
    details: str
    comments: str


@dataclass(frozen=True)
class Entry:
    """One checklist entry: a DISA rule, its verdict and its deterministic UUID."""

    rule: StigRule
    verdict: Verdict
    uuid: str


@dataclass(frozen=True)
class Asset:
    """The asset fields of a checklist; every value comes from the scan, or is empty."""

    host_name: str
    host_ip: str
    host_fqdn: str
    comment: str
    target_key: str


@dataclass(frozen=True)
class Checklist:
    """A checklist of one host and one DISA STIG benchmark, in a format-neutral form."""

    file_stem: str
    uuid: str
    stig_uuid: str
    asset: Asset
    benchmark: StigBenchmark
    filename: str
    timestamp: str
    entries: tuple[Entry, ...]


@dataclass(frozen=True)
class Source:
    """One exportable scan run with the content and context it is exported with.

    Attributes:
        display: The input path, for messages.
        run: The validated scan run (with waivers, when exceptions were applied).
        lapsed: The rules whose waiver lapsed after the scan started.
        benchmark: The DISA STIG content of the run's benchmark.
        own_results: Whether ``benchmark`` is the run's own XCCDF results, whose target
            facts describe the scanned host.
    """

    display: str
    run: model.ScanRun
    lapsed: frozenset[str]
    benchmark: StigBenchmark
    own_results: bool


def off_platform_text(marker: model.OffPlatform) -> str:
    """Return the off-platform label of ADR 0019, for example the 24.04 benchmark on 26.04."""
    bench = marker.benchmark_platform
    target = marker.target_platform
    return (
        f"off-platform: the {bench.distribution_id} {bench.distribution_version} benchmark on an "
        f"{target.distribution_id} {target.distribution_version} host"
    )


def _not_reviewed_reason(run: model.ScanRun, finding: model.Finding | None) -> str | None:
    marker = run.off_platform if finding is None else finding.off_platform or run.off_platform
    if marker is not None:
        return (
            f"Not reviewed: {off_platform_text(marker)}. The results describe the host under a "
            "benchmark made for another release and are never a review of this host."
        )
    if run.status is not model.ScanStatus.COMPLETED:
        return (
            f"Not reviewed: the scan run did not complete (run status {run.status.value}): "
            f"{run.error_message}"
        )
    if finding is None:
        return (
            f"Not reviewed: the scan run has no result for this rule; profile {run.profile_id} "
            "does not select it, or it was not evaluated."
        )
    if model.ResultFlag.FIXED in finding.flags:
        return "Not reviewed: the scanner reported fixed, and a remediation result is not a review."
    return None


def _details(run: model.ScanRun, finding: model.Finding | None, reason: str | None) -> str:
    lines = [] if reason is None else [reason]
    if finding is not None:
        lines.append(f"Scanner result: {finding.evaluated_outcome.value}")
        if finding.outcome is not finding.evaluated_outcome:
            lines.append(f"Reported outcome: {finding.outcome.value}")
        if finding.flags:
            lines.append("Flags: " + ", ".join(flag.value for flag in finding.flags))
        if finding.disabled_by is not None:
            lines.append(f"Disabled by: {finding.disabled_by}")
        if finding.message is not None:
            lines.append(f"Message: {finding.message}")
    lines.append(
        f"Scan run {run.run_id}: {run.scanner.name} {run.scanner.version}, "
        f"{run.started_at} to {run.finished_at}, profile {run.profile_id}"
    )
    return "\n".join(lines)


def _comments(finding: model.Finding | None, *, lapsed: bool) -> str:
    if finding is None:
        return ""
    exception = finding.exception
    lines: list[str] = []
    if exception.state is model.ExceptionState.ACTIVE:
        lines.append(
            f"Waiver: exception {exception.exception_id} was in effect for this scan and "
            f"expires {exception.expires_at}. The scanner's result is "
            f"{finding.evaluated_outcome.value}, so the status stays Open; a waiver is not a "
            "review that the requirement is met."
        )
    if exception.state is model.ExceptionState.EXPIRED:
        lines.append(
            f"Exception {exception.exception_id} expired at {exception.expires_at} and was not "
            "applied; the status is the scanner's result."
        )
    if exception.reason is not None:
        lines.append(f"Exception reason: {exception.reason}")
    if lapsed:
        lines.append(
            "The waiver of this rule lapsed after the scan started and was not applied; the "
            "status is the scanner's result."
        )
    return "\n".join(lines)


def verdict(run: model.ScanRun, finding: model.Finding | None, *, lapsed: bool = False) -> Verdict:
    """Return the checklist status of ``finding`` in ``run``, with its details and comments.

    ``finding`` is ``None`` for a rule of the content that the run has no result for.
    """
    reason = _not_reviewed_reason(run, finding)
    if reason is not None or finding is None:
        status = NOT_REVIEWED
    else:
        status = OUTCOME_STATUSES[finding.outcome]
    return Verdict(status, _details(run, finding, reason), _comments(finding, lapsed=lapsed))


def refuse_unmapped(run: model.ScanRun, display: str) -> None:
    """Refuse a scan run whose rules are not DISA STIG rules.

    Raises:
        ChecklistError: If any finding of ``run`` has a rule ID that is not a DISA STIG
            rule ID, which is the case for ComplianceAsCode findings.
    """
    foreign = [
        finding.rule_id for finding in run.findings if not DISA_RULE.fullmatch(finding.rule_id)
    ]
    if foreign:
        message = (
            f"{display}: scan run {run.run_id} of {run.host.hostname} has {len(foreign)} "
            f"finding(s) that are not DISA STIG rules (for example {foreign[0]}). Their content "
            "carries no DISA group or rule IDs, and the STIG to ComplianceAsCode mapping that "
            f"would supply them is {MAPPING_ISSUE}, which is not built yet; no checklist was "
            "written. Export SCC results, which carry DISA IDs natively"
        )
        raise ChecklistError(message)


def safe_name(text: str) -> str:
    """Return ``text`` with every character outside ``[A-Za-z0-9._-]`` replaced by ``_``."""
    return "".join(c if c.isascii() and (c.isalnum() or c in "._-") else "_" for c in text)


def _matches_host(name: str, hostname: str) -> bool:
    return name.lower().split(".", 1)[0] == hostname.lower().split(".", 1)[0]


def asset(source: Source) -> Asset:
    """Return the asset fields of ``source``.

    The host name is the run's host identity. The IP addresses and the FQDN come from
    the run's own XCCDF results, and only when every name in them is the run's host.
    All of them are self-asserted by the scanned host, which the comment says.
    """
    run = source.run
    target = source.benchmark.target if source.own_results else None
    facts_apply = target is not None and all(
        _matches_host(name, run.host.hostname) for name in (*target.names, *target.fqdns)
    )
    host = run.host
    comment = (
        f"Exported by {EXPORTER} from scan run {run.run_id} ({run.scanner.name} "
        f"{run.scanner.version}, content {run.content.source} {run.content.content_version} "
        f"sha256 {run.content.content_sha256}). The host identity ({host.hostname}, "
        f"{host.distribution_id} {host.distribution_version}, {host.architecture}) and the "
        "addresses are self-asserted by the scanned host."
    )
    if target is not None and not facts_apply:
        comment += " The scanner's target facts name another host and are not used."
    keys = {rule.target_key for rule in source.benchmark.rules}
    return Asset(
        host_name=host.hostname,
        host_ip=", ".join(target.addresses) if target is not None and facts_apply else "",
        host_fqdn=target.fqdns[0] if target is not None and facts_apply and target.fqdns else "",
        comment=comment,
        target_key=keys.pop() if len(keys) == 1 else "",
    )


def _identity(run: model.ScanRun) -> str:
    host = run.host
    return "/".join(
        (host.hostname, host.machine_id or "", run.run_id, run.started_at, run.benchmark_id)
    )


def _timestamp(moment: str) -> str:
    return moment.replace("Z", ".000Z")


def build(source: Source) -> Checklist:
    """Return the checklist of ``source``.

    Raises:
        ChecklistError: If a finding's rule is not in the content.
    """
    run = source.run
    rules = source.benchmark.rule_map()
    unknown = [finding.rule_id for finding in run.findings if finding.rule_id not in rules]
    if unknown:
        message = (
            f"{source.display}: {len(unknown)} finding(s) of scan run {run.run_id} are not rules "
            f"of the content of {run.benchmark_id} (for example {unknown[0]}); supply the content "
            "that the scan evaluated"
        )
        raise ChecklistError(message)
    findings = {finding.rule_id: finding for finding in run.findings}
    identity = _identity(run)
    entries = tuple(
        Entry(
            rule,
            verdict(run, findings.get(rule.rule_id), lapsed=rule.rule_id in source.lapsed),
            str(uuid.uuid5(UUID_NAMESPACE, f"{identity}/{rule.rule_id}")),
        )
        for rule in source.benchmark.rules
    )
    return Checklist(
        file_stem=f"{safe_name(run.host.hostname)}_{safe_name(source.benchmark.stig_id)}",
        uuid=str(uuid.uuid5(UUID_NAMESPACE, identity)),
        stig_uuid=str(uuid.uuid5(UUID_NAMESPACE, f"{identity}/stig")),
        asset=asset(source),
        benchmark=source.benchmark,
        filename=run.content.source,
        timestamp=_timestamp(run.finished_at),
        entries=entries,
    )


def build_all(sources: list[Source]) -> list[Checklist]:
    """Return one checklist per source, refusing two for one host and benchmark.

    Raises:
        ChecklistError: If a finding's rule is not in its content, or two sources give
            the same file name (compared case-insensitively, for Windows file systems).
    """
    checklists: list[Checklist] = []
    seen: dict[str, str] = {}
    for source in sources:
        checklist = build(source)
        key = checklist.file_stem.lower()
        if key in seen:
            message = (
                f"{source.display} and {seen[key]} both give the checklist {checklist.file_stem}: "
                "one checklist is written per host and benchmark, so export the scan runs of "
                "one host and benchmark separately"
            )
            raise ChecklistError(message)
        seen[key] = source.display
        checklists.append(checklist)
    return checklists
