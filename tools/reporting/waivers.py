"""The ``exceptions`` section: every exception of the exceptions file and what it did (FREES-132).

The section is built from verified exceptions evaluations, one per scan run. Every
exception of the file is listed once, with its record, a structured scope, its status
on every evaluated scan run, the inventory hosts where its scope matched and one
review verdict (:func:`exceptions.review`). Nothing here changes a compliance figure:
the figures come from the scan runs alone.

Every value comes from the reviewed exceptions file or from the controller (the
inventory host name and the times); the scanned host contributes only the identifiers
of its scan run (run, benchmark, profile and content version), which the findings
model validates. The scope never contains text from a host.
"""

from collections.abc import Sequence
from typing import Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
)
from tools.reporting.parsers.evaluation import EvaluationData

MAX_EXCEPTIONS: Final[int] = exceptions.MAX_EXCEPTIONS

type Evaluated = tuple[str, EvaluationData]


class InconsistentEvaluationsError(ValueError):
    """Raised when evaluations were produced from different exceptions files."""


def scope_summary(scope: exceptions.Scope) -> dict[str, object]:
    """Return the scope with every dimension present; an unset dimension is empty or null."""
    return {
        "benchmark": None if scope.benchmark is None else scope.benchmark.to_dict(),
        "groups": list(scope.groups),
        "hosts": list(scope.hosts),
        "profiles": list(scope.profiles),
    }


def _matched(digest: str, data: EvaluationData, result: exceptions.ExceptionResult) -> object:
    run = data.evaluation.run
    return {
        "benchmark_id": run.benchmark_id,
        "content_version": run.content.content_version,
        "host": data.evaluation.target.host,
        "input_sha256": digest,
        "profile_id": run.profile_id,
        "run_id": run.run_id,
        "status": result.status.value,
        "superseded_by": result.superseded_by,
    }


def _entry(
    record: exceptions.ExceptionRecord,
    rows: list[tuple[str, EvaluationData, exceptions.ExceptionResult]],
    digest: str,
) -> dict[str, object]:
    verdict = exceptions.review([result.status for _, _, result in rows])
    statuses = {status.value: 0 for status in exceptions.Status}
    for _, _, result in rows:
        statuses[result.status.value] += 1
    return {
        "approval_date": record.approved_on.isoformat(),
        "approver": record.approver,
        "created": record.created.isoformat(),
        "expires": record.expires.isoformat(),
        "expires_at": record.expires_at,
        "framework": record.framework.value,
        "host_statuses": statuses,
        "id": record.exception_id,
        "justification": record.justification,
        "lapsed": any(result.expired for _, _, result in rows),
        "matched_hosts": [
            _matched(sha, data, result)
            for sha, data, result in rows
            if result.status is not exceptions.Status.UNMATCHED
        ],
        "owner": record.owner,
        "removal_candidate": verdict in exceptions.REMOVAL_CANDIDATES,
        "risk": record.risk.value,
        "rule_id": record.rule_id,
        "scope": scope_summary(record.scope),
        "source_sha256": digest,
        "status": verdict.value,
    }


def _order(item: Evaluated) -> tuple[str, str, str, str, str, str]:
    evaluation = item[1].evaluation
    run = evaluation.run
    return (
        evaluation.target.host,
        run.benchmark_id,
        run.content.content_version,
        run.profile_id,
        run.run_id,
        item[0],
    )


def exception_entries(
    evaluated: Sequence[Evaluated],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Return one entry per exception and the section summary.

    ``evaluated`` pairs the SHA-256 of each evaluation file with its data; it must not
    be empty. The summary counts the exceptions per review verdict, the removal
    candidates (stale, superseded or not failing everywhere) and the exceptions whose
    expiry had passed at the evaluation time on at least one host (``lapsed``).

    Raises:
        InconsistentEvaluationsError: If the evaluations list different exception
            records or name different exceptions files.
    """
    ordered = sorted(evaluated, key=_order)
    first = ordered[0][1].evaluation
    records = [result.record for result in first.results]
    for _, data in ordered[1:]:
        other = data.evaluation
        if (
            other.source_sha256 != first.source_sha256
            or [result.record for result in other.results] != records
        ):
            message = "the exceptions evaluations come from different exceptions files"
            raise InconsistentEvaluationsError(message)
    entries = [
        _entry(
            record,
            [(sha, data, data.evaluation.results[index]) for sha, data in ordered],
            first.source_sha256,
        )
        for index, record in enumerate(records)
    ]
    by_status = {verdict.value: 0 for verdict in exceptions.Review}
    for entry in entries:
        by_status[str(entry["status"])] += 1
    summary: dict[str, object] = {
        "by_status": by_status,
        "evaluations": len(ordered),
        "lapsed": sum(1 for entry in entries if entry["lapsed"]),
        "removal_candidates": sum(1 for entry in entries if entry["removal_candidate"]),
        "source_sha256": first.source_sha256,
        "total": len(entries),
    }
    return entries, summary
