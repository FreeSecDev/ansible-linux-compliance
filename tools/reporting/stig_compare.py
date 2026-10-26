"""Compare an SCC run and an OpenSCAP run of one host by DISA STIG rule (FREES-146).

``--compare-stig FILE`` builds the checklist of every exported scan run exactly as the export
does, pairs, per host and DISA STIG benchmark, the run whose findings are DISA rules (SCC) with
the run whose ComplianceAsCode findings reach the benchmark through the STIG mapping (OpenSCAP),
and writes one JSON document with, for each pair, the status counts of both sides and every DISA
rule on which their checklist statuses differ. Hosts are matched by host name, case-insensitively.

The document holds identifiers and statuses only (group, rule and STIG IDs, ComplianceAsCode rule
IDs and CKL status strings), no benchmark text. A host and benchmark without exactly one run of
each kind is refused, so a comparison never silently covers fewer hosts than were given.
"""

from collections.abc import Sequence
from typing import Final

from tools.reporting.checklist import STATUSES, Checklist, ChecklistError, Source
from tools.reporting.common import Json
from tools.reporting.stig_mapping import ProfileMapping

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


def _pair(
    disa: tuple[Source, Checklist], mapped: tuple[Source, Checklist], mapping: ProfileMapping
) -> dict[str, Json]:
    differences: list[Json] = []
    for left, right in zip(disa[1].entries, mapped[1].entries, strict=True):
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
            mapped ComplianceAsCode run.
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
