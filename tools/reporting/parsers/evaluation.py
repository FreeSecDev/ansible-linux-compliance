"""Exceptions evaluation documents written by the ``apply_exceptions`` filter (FREES-132).

An evaluation document holds one scan run with waived and expired findings marked,
the status of every exception of the exceptions file for that run, the inventory
host it was matched against and the times that were used. The document is verified
against the exceptions file (``--exceptions-file``) by
:func:`exceptions.verify_evaluation`: the file's SHA-256 must be the document's
``source_sha256``, the file must be valid, and the scan run evaluated again with that
file must give exactly the document. No status, mark or record can be edited, and an
evaluation made from another exceptions file is refused.

Only the exact SHA-256 of the file as supplied is accepted, so the evaluation must
have been made from the byte-exact file. The ``audit`` role reads it that way
(``lookup('ansible.builtin.file', path, rstrip=false)``); a play that uses the
lookup's default ``rstrip=true`` hashes a different text and its evaluations are
refused.

The scan run feeds the compliance section like a ScanRun JSON file, with one
addition: rules whose exception lapsed between the scan start and the controller
time are counted in ``expired_waivers``. The exception statuses feed the
``exceptions`` section.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
)
from tools.reporting.common import (
    DEFAULT_MAX_BYTES,
    InvalidInputError,
    ParseResult,
    clean_text,
    decode_text,
    load_json,
    run_parser,
    sha256_hex,
)
from tools.reporting.compliance import KIND_EVALUATION, ComplianceData, summarize, tally_findings

FORMAT: Final[str] = "exceptions_evaluation"
EXCEPTIONS_FILE_FORMAT: Final[str] = "exceptions_file"


@dataclass(frozen=True)
class EvaluationData:
    """An exceptions evaluation verified against the exceptions file, and its compliance input."""

    compliance: ComplianceData
    evaluation: exceptions.Evaluation

    def to_dict(self) -> dict[str, object]:
        """Return the view of the ``exceptions`` section: the run, target and times.

        The per-exception results are not repeated here; the section lists them per
        exception. ``statuses`` counts the exceptions per status for this run.
        """
        run = self.evaluation.run
        statuses = {status.value: 0 for status in exceptions.Status}
        for result in self.evaluation.results:
            statuses[result.status.value] += 1
        document: dict[str, object] = {
            "benchmark_id": run.benchmark_id,
            "content_version": run.content.content_version,
            "profile_id": run.profile_id,
            "run_id": run.run_id,
            "source_sha256": self.evaluation.source_sha256,
            "statuses": statuses,
            "target_host": self.evaluation.target.host,
        }
        document.update(self.evaluation.timing.to_dict())
        return document


def _build(data: bytes, text: str) -> EvaluationData:
    try:
        evaluation = exceptions.verify_evaluation(load_json(data), text)
    except exceptions.ExceptionsError as error:
        message = f"exceptions evaluation rejected: {clean_text(str(error), 200)}"
        raise InvalidInputError(message) from None
    return evaluation_data(data, evaluation)


def evaluation_data(data: bytes, evaluation: exceptions.Evaluation) -> EvaluationData:
    """Build the inputs of an evaluation that was verified against its exceptions file.

    Raises:
        InvalidInputError: If the inventory host of the evaluation is not a valid host name.
    """
    if re.fullmatch(exceptions.HOST_PATTERN, evaluation.target.host) is None:
        message = "the inventory host of the evaluation is not a valid host name"
        raise InvalidInputError(message)
    run = evaluation.run
    lapsed = evaluation.lapsed_rule_ids()
    status = run.status.value
    unfinished = 0 if status == "completed" else 1
    compliance = ComplianceData(
        kind=KIND_EVALUATION,
        scan_status=status,
        error_message=run.error_message,
        benchmark_id=run.benchmark_id,
        benchmark_version=None,
        profile_id=run.profile_id,
        started_at=run.started_at,
        finished_at=run.finished_at,
        host=run.host,
        reported_host=None,
        input_sha256=sha256_hex(data),
        content_version=run.content.content_version,
        findings=run.findings,
        not_selected=0,
        scan_run=run,
        summary=summarize(tally_findings(run.findings, frozenset(lapsed)), status, 1, unfinished),
        lapsed_waivers=lapsed,
    )
    return EvaluationData(compliance, evaluation)


def parse_evaluation(
    path: Path, text: str, max_bytes: int = DEFAULT_MAX_BYTES
) -> ParseResult[EvaluationData]:
    """Parse an exceptions evaluation and verify it against the exceptions file ``text``."""
    return run_parser(path, FORMAT, max_bytes, lambda data: _build(data, text))


def parse_exceptions_file(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ParseResult[str]:
    """Read the exceptions file as UTF-8 text, bounded like every input."""
    return run_parser(path, EXCEPTIONS_FILE_FORMAT, max_bytes, decode_text)


def compliance_result(result: ParseResult[EvaluationData]) -> ParseResult[ComplianceData]:
    """Return the compliance input of an evaluation result, with the same status and artifact."""
    data = None if result.data is None else result.data.compliance
    return ParseResult(result.format, result.status, result.reason, result.artifact, data)
