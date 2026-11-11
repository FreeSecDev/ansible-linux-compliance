"""The summary and the operator deviations of an audit.

:func:`summarize` counts the findings of a run for the result of ``compliance_scan``.
It moved here from :mod:`audit`, unchanged but for the deviations, when operator
deviations (ADR 0032 section 4, decisions A and D; FREES-203) took that module past
the module line limit.

When an operator override leaves a value in force that is looser than the profile's,
the remediate role records the rule in the deviation register of the ledger
(:meth:`ledger.Ledger.deviations`). The audit reads that register before it scans. It
does not judge any value again: the remediation judged the value with the family's
reader, and the scanner judges the check.

:func:`from_register` turns the records into :class:`RecordedDeviation` items and
refuses a record that the findings model cannot carry. :func:`stamp` gives the finding
of each recorded rule the flag ``operator_deviation`` and the deviation, but only when
its outcome allows the flag (``pass``, ``fail``, ``waived``); the scanner's outcome is
never changed. :func:`describe` lists the flagged rules and, as ``unflagged``, every
recorded rule whose finding cannot carry the flag (``error``, ``notchecked``,
``notapplicable``, ``disabled``) or that the run does not report at all. None of
those outcomes ever counts as a pass (ADR 0016), and the list keeps the deviation
visible.

The module uses only the standard library and syntax that runs on Python 3.9.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    deviations,
    ledger,
    model,
    vocabulary,
)

if TYPE_CHECKING:
    from collections.abc import Callable

RUN_STATUS_NOT_RUN: Final[str] = "not_run"
ERROR_DEVIATIONS: Final[str] = "deviation_source_invalid"
ERROR_DEVIATION_BACKEND: Final[str] = "deviation_backend_unsupported"
DEVIATION_UNMAPPED_BACKENDS: Final[frozenset[str]] = frozenset({"scc"})
FLAGGED_OUTCOMES: Final[frozenset[model.Outcome]] = vocabulary.FLAG_OUTCOMES[
    model.ResultFlag.OPERATOR_DEVIATION
]


class RegisterError(ValueError):
    """Raised when the deviation register cannot be read or reported.

    Attributes:
        error_type: ``deviation_source_invalid`` or ``deviation_backend_unsupported``.
    """

    def __init__(self, error_type: str, message: str) -> None:
        """Create the error with its stable type."""
        super().__init__(message)
        self.error_type = error_type


@dataclass(frozen=True)
class RecordedDeviation:
    """A rule of the deviation register, with the deviation its finding carries.

    Attributes:
        rule_id: Full XCCDF identifier of the rule.
        deviation: The XCCDF value, the profile value and the value in force.
    """

    rule_id: str
    deviation: model.Deviation

    def to_dict(self, outcome: model.Outcome | None) -> dict[str, object]:
        """Return a JSON-compatible mapping with the outcome of the rule's finding, or null."""
        return {
            "outcome": None if outcome is None else outcome.value,
            "rule_id": self.rule_id,
            **self.deviation.to_dict(),
        }


def from_register(
    records: tuple[ledger.DeviationRecord, ...],
) -> tuple[RecordedDeviation, ...]:
    """Return the deviations of the register, in its order (by rule identifier).

    Raises:
        RegisterError: If a record holds a value the findings model refuses, for
            example a value with surrounding whitespace or a profile value equal to the
            value in force. The register is then not a source the audit can trust.
    """
    recorded: list[RecordedDeviation] = []
    for record in records:
        try:
            deviation = model.Deviation(
                record.value_id, record.profile_value, record.effective_value
            )
        except deviations.DeviationError as error:
            message = f"the record of {record.rule_id} cannot be reported: {error}"
            raise RegisterError(ERROR_DEVIATIONS, message) from error
        recorded.append(RecordedDeviation(record.rule_id, deviation))
    return tuple(recorded)


def _stamped(finding: model.Finding, deviation: model.Deviation | None) -> model.Finding:
    if deviation is None or finding.outcome not in FLAGGED_OUTCOMES:
        return finding
    return replace(
        finding,
        flags=(*finding.flags, model.ResultFlag.OPERATOR_DEVIATION),
        deviation=deviation,
    )


def stamp(
    findings: tuple[model.Finding, ...], recorded: tuple[RecordedDeviation, ...]
) -> tuple[model.Finding, ...]:
    """Flag the findings of recorded rules whose outcome allows ``operator_deviation``."""
    by_rule = {item.rule_id: item.deviation for item in recorded}
    return tuple(_stamped(finding, by_rule.get(finding.rule_id)) for finding in findings)


def count(run: model.ScanRun) -> int:
    """Return the number of findings of ``run`` that carry a deviation."""
    return sum(1 for finding in run.findings if finding.deviation is not None)


def describe(
    recorded: tuple[RecordedDeviation, ...], run: model.ScanRun | None
) -> dict[str, object]:
    """Return the deviations of an audit result.

    ``recorded`` is the number of rules in the register. ``flagged`` lists the rules
    whose finding carries the flag, and ``unflagged`` every other recorded rule with
    the outcome of its finding, or null when the run has no finding of it or no scan
    ran. Each item names the rule, the XCCDF value, the profile value and the value in
    force.
    """
    findings = {} if run is None else {finding.rule_id: finding for finding in run.findings}
    flagged: list[dict[str, object]] = []
    unflagged: list[dict[str, object]] = []
    for item in recorded:
        finding = findings.get(item.rule_id)
        outcome = None if finding is None else finding.outcome
        target = flagged if finding is not None and finding.deviation is not None else unflagged
        target.append(item.to_dict(outcome))
    return {"flagged": flagged, "recorded": len(recorded), "unflagged": unflagged}


def registered(
    reader: Callable[[], tuple[ledger.DeviationRecord, ...]], backend: str, directory: str
) -> tuple[RecordedDeviation, ...]:
    """Read the deviation register of the ledger in ``directory`` with ``reader``.

    The audit reads it before it scans.

    A missing ledger has no deviations. A backend in :data:`DEVIATION_UNMAPPED_BACKENDS`
    reports the rules of another benchmark, which the register does not name, so it is
    refused while the register holds any record.

    Raises:
        RegisterError: ``deviation_source_invalid`` for a corrupt or unsafe ledger or a
            record the findings model refuses, and ``deviation_backend_unsupported``.
    """
    try:
        recorded = from_register(reader())
    except (ledger.LedgerError, RegisterError) as error:
        message = (
            f"the deviation register of the ledger in {directory} cannot be trusted: {error}; "
            "inspect it with freesecdev.linux_compliance.control_state (action list); "
            "nothing was scanned"
        )
        raise RegisterError(ERROR_DEVIATIONS, message) from error
    if recorded and backend in DEVIATION_UNMAPPED_BACKENDS:
        message = (
            f"the deviation register in {directory} holds {len(recorded)} rule(s), and the "
            f"backend {backend} cannot report them on its findings yet; nothing was scanned"
        )
        raise RegisterError(ERROR_DEVIATION_BACKEND, message)
    return recorded


def summarize(run: model.ScanRun | None) -> dict[str, object] | None:
    """Count the findings of a run by outcome, with the run status first.

    The summary never states compliance (AGENTS.md rule 9): it holds ``run_status``, the
    number of findings per outcome, the total, ``deviation``, the number of findings
    flagged ``operator_deviation`` (each also counted under its outcome, so ``pass``
    stays the scanner's count), and ``off_platform``, the off-platform marker of the
    run or ``None``. A run that did not complete has only ``error`` findings, so it can
    never look compliant.
    """
    if run is None:
        return None
    counts: dict[str, object] = {outcome.value: 0 for outcome in model.Outcome}
    for finding in run.findings:
        key = finding.outcome.value
        counts[key] = cast("int", counts[key]) + 1
    counts["total"] = len(run.findings)
    counts["deviation"] = count(run)
    counts["run_status"] = run.status.value
    counts["off_platform"] = None if run.off_platform is None else run.off_platform.to_dict()
    return counts
