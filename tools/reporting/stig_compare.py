"""Compare an SCC run and an OpenSCAP run of one host by DISA STIG rule (FREES-146).

``--compare-stig FILE`` builds the checklist of every exported scan run exactly as the export
does, pairs, per host and DISA STIG benchmark, the run whose findings are DISA rules (SCC) with
the run whose ComplianceAsCode findings reach the benchmark through the STIG mapping (OpenSCAP),
and writes one JSON document with, for each pair, the status counts of both sides and every DISA
rule on which their checklist statuses differ. Hosts are matched by host name, case-insensitively.

The entries of the two sides are paired by DISA rule ID, never by position, and only when both
sides are the same DISA content: the same release, the same set of rule IDs, and the same STIG ID
for each rule ID. A pair of checklists with another release, another number of rules or other rules
is refused, because a diff of misaligned rules would state results of the wrong rules (FREES-171).

The document holds identifiers and statuses only (group, rule and STIG IDs, ComplianceAsCode rule
IDs and CKL status strings), no benchmark text. A host and benchmark without exactly one run of
each kind is refused, so a comparison never silently covers fewer hosts than were given.
"""

from collections.abc import Sequence
from typing import Final

from tools.reporting.checklist import STATUSES, Checklist, ChecklistError, Entry, Source
from tools.reporting.common import Json
from tools.reporting.stig_mapping import ProfileMapping, release_of

KIND: Final[str] = "stig_comparison"
SCHEMA_VERSION: Final[int] = 1


def _run(source: Source) -> dict[str, Json]:
    run = source.run
    summary: dict[str, Json] = {
        "input": source.display,
        "run_id": run.run_id,
        "scanner": run.scanner.name,
        "scanner_version": run.scanner.version,
        "benchmark_id": run.benchmark_id,
        "profile_id": run.profile_id,
        "status": run.status.value,
    }
    if source.mapping is not None:
        summary["stig_release"] = source.mapping.stig_release
    return summary


def _counts(checklist: Checklist) -> dict[str, Json]:
    values = [entry.verdict.status.ckl for entry in checklist.entries]
    return {status.ckl: values.count(status.ckl) for status in STATUSES}


def _release(checklist: Checklist) -> str:
    benchmark = checklist.benchmark
    return release_of(benchmark.version, benchmark.release_info) or "unknown"


def _aligned(disa: tuple[Source, Checklist], mapped: tuple[Source, Checklist]) -> dict[str, Entry]:
    where = (
        f"host {disa[0].run.host.hostname} and benchmark {disa[1].benchmark.benchmark_id} "
        f"({disa[0].display} and {mapped[0].display})"
    )
    releases = (_release(disa[1]), _release(mapped[1]))
    if releases[0] != releases[1]:
        message = (
            f"--compare-stig: the SCC run and the mapped run of {where} have DISA content of "
            f"different releases ({releases[0]} and {releases[1]}); supply the same DISA content"
        )
        raise ChecklistError(message)
    right = {entry.rule.rule_ref: entry for entry in mapped[1].entries}
    left = {entry.rule.rule_ref: entry for entry in disa[1].entries}
    if left.keys() != right.keys():
        only = sorted(left.keys() ^ right.keys())
        message = (
            f"--compare-stig: the SCC run and the mapped run of {where} have different DISA rule "
            f"sets ({len(left)} and {len(right)} rules; {len(only)} in one side only, for example "
            f"{only[0]}); supply the same DISA content"
        )
        raise ChecklistError(message)
    changed = sorted(
        ref for ref, entry in left.items() if entry.rule.version != right[ref].rule.version
    )
    if changed:
        message = (
            f"--compare-stig: the SCC run and the mapped run of {where} give the DISA rule "
            f"{changed[0]} different STIG IDs; supply the same DISA content"
        )
        raise ChecklistError(message)
    return right


def _pair(
    disa: tuple[Source, Checklist], mapped: tuple[Source, Checklist], mapping: ProfileMapping
) -> dict[str, Json]:
    differences: list[Json] = []
    paired = _aligned(disa, mapped)
    for left in disa[1].entries:
        right = paired[left.rule.rule_ref]
        if left.verdict.status != right.verdict.status:
            rules: list[Json] = list(mapping.rules_of(left.rule.version))
            differences.append(
                {
                    "group_id": left.rule.group_id,
                    "rule_id": left.rule.rule_ref,
                    "stig_id": left.rule.version,
                    "disa": left.verdict.status.ckl,
                    "compliance_as_code": right.verdict.status.ckl,
                    "compliance_as_code_rules": rules,
                }
            )
    total = len(disa[1].entries)
    return {
        "host": disa[0].run.host.hostname,
        "benchmark_id": disa[1].benchmark.benchmark_id,
        "benchmark_version": disa[1].benchmark.version,
        "disa_run": _run(disa[0]),
        "compliance_as_code_run": _run(mapped[0]),
        "rules": total,
        "agree": total - len(differences),
        "disagree": len(differences),
        "statuses": {"disa": _counts(disa[1]), "compliance_as_code": _counts(mapped[1])},
        "disagreements": differences,
    }


def compare(checklists: Sequence[tuple[Source, Checklist]]) -> dict[str, Json]:
    """Return the comparison document of ``checklists``.

    Raises:
        ChecklistError: If a host and benchmark do not have exactly one DISA run and one
            mapped ComplianceAsCode run, or the two have other releases or rules of DISA content.
    """
    groups: dict[tuple[str, str], list[tuple[Source, Checklist]]] = {}
    for item in checklists:
        key = (item[0].run.host.hostname.lower(), item[1].benchmark.benchmark_id)
        groups.setdefault(key, []).append(item)
    comparisons: list[Json] = []
    for (host, benchmark), items in groups.items():
        disa = [item for item in items if item[0].mapping is None]
        mapped = [
            (source, made, source.mapping) for source, made in items if source.mapping is not None
        ]
        if len(disa) != 1 or len(mapped) != 1:
            message = (
                f"--compare-stig needs exactly one SCC run and one mapped ComplianceAsCode run of "
                f"host {host} and benchmark {benchmark}, found {len(disa)} and {len(mapped)}: "
                f"{', '.join(item[0].display for item in items)}"
            )
            raise ChecklistError(message)
        source, made, mapping = mapped[0]
        comparisons.append(_pair(disa[0], (source, made), mapping))
    return {"kind": KIND, "schema_version": SCHEMA_VERSION, "comparisons": comparisons}
