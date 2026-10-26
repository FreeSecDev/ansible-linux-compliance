"""Filter that compares a baseline audit with a later audit of the same host."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, NoReturn, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: compare_scans
short_description: Compare a baseline audit with a post-remediation audit of the same host
version_added: "0.1.0"
author:
  - FreeSecDev contributors (@FreeSecDev)
description:
  - Takes two audit results in the shape of the C(linux_compliance_audited) fact of the audit
    role, the baseline and a later audit, and classifies every rule as C(improved), C(regressed),
    C(unchanged), C(newly_applicable), C(newly_failing), C(newly_not_applicable), C(error) or
    C(not_comparable).
  - Both audits must describe the same host, benchmark, content version and digest, profile and
    scanner, must be two different runs, and the later run must start after the baseline
    finished. Any mismatch fails the task; nothing is compared.
  - Classification uses the evaluated outcome of each finding, which is what the scanner decided.
    A waiver therefore never counts as an improvement, and C(waived) and C(disabled) never become
    C(improved). Only an evaluated C(fail) that becomes C(pass) is C(improved).
  - A rule that passed in the baseline and is evaluated as anything but C(pass) or
    C(notapplicable) afterwards, or is missing afterwards, is C(regressed), including C(error),
    C(notchecked) and C(disabled).
  - A rule that was C(notapplicable) or missing in the baseline and fails afterwards is
    C(newly_failing); one that was C(notapplicable) and passes afterwards is C(newly_applicable).
  - Any other transition from or to C(error), and any other rule missing from one of the runs, is
    C(error), never C(improved).
  - When either run did not complete (C(failed), C(timed_out), or C(not_run) in check mode), the
    comparison is C(incomplete). It then reports no counts, no rules, no regressions and no new
    failures, only the reasons, so it cannot be read as an improvement or as the absence of
    regressions.
  - The result is a comparison of two scans of one host. It is evidence, not a claim of
    compliance with any framework.
positional: post, mode, profile_id
options:
  _input:
    description:
      - The baseline audit, the C(linux_compliance_audited) fact captured before remediation.
    type: dict
    required: true
  post:
    description:
      - The later audit, normally the C(linux_compliance_audited) fact after remediation.
    type: dict
    required: true
  mode:
    description:
      - V(raw) compares the raw scan runs (C(scan_run)), which must not carry waivers.
      - V(waived) compares the waived scan runs (C(exceptions.evaluation.scan_run)). Both audits
        must have applied the same exceptions file, identified by its SHA-256; otherwise the task
        fails.
    type: str
    choices:
      - raw
      - waived
    default: raw
  profile_id:
    description:
      - The full XCCDF profile identifier that both scan runs must report, or C(none) to only
        require that they report the same profile.
    type: str
"""

EXAMPLES = r"""
- name: Compare the baseline audit with the audit after remediation
  ansible.builtin.set_fact:
    comparison: >-
      {{ linux_compliance_baseline
         | freesecdev.linux_compliance.compare_scans(linux_compliance_audited, 'raw') }}
"""

RETURN = r"""
_value:
  description:
    - The comparison document.
    - V(mode), V(status) (V(complete) or V(incomplete)), V(complete) and V(incomplete_reasons).
    - V(identity) with the host, benchmark, profile, content and scanner both runs share, or
      C(none) when a run is missing (check mode without a scan).
    - V(exceptions_sha256), the SHA-256 of the exceptions file in V(waived) mode, else C(none).
    - V(baseline) and V(post), each with V(run_id), V(run_status), V(started_at),
      V(finished_at) and V(summary) (the count per outcome of the compared scan run).
    - V(counts), one count per category; V(regressions), the regressed rules; V(new_failures),
      the newly failing rules; V(passed_now_not_applicable), the rules that passed in the baseline
      and are not applicable afterwards; V(rules), every rule with its V(category) and its
      V(baseline) and V(post) V(outcome) and V(evaluated_outcome); V(regression_detected) and
      V(new_failure_detected). All of them are C(none) when the comparison is incomplete.
    - V(message), a summary that starts with the status and never claims compliance.
  type: dict
"""

RAW: Final[str] = "raw"
WAIVED: Final[str] = "waived"
MODES: Final[tuple[str, ...]] = (RAW, WAIVED)
COMPLETED: Final[str] = model.ScanStatus.COMPLETED.value
PASS: Final[str] = model.Outcome.PASS.value
NOT_RUN: Final[str] = "not_run"
RUN_STATUSES: Final[tuple[str, ...]] = (
    *(status.value for status in model.ScanStatus),
    NOT_RUN,
)
IMPROVED: Final[str] = "improved"
REGRESSED: Final[str] = "regressed"
UNCHANGED: Final[str] = "unchanged"
NEWLY_APPLICABLE: Final[str] = "newly_applicable"
NEWLY_FAILING: Final[str] = "newly_failing"
NEWLY_NOT_APPLICABLE: Final[str] = "newly_not_applicable"
ERROR: Final[str] = "error"
NOT_COMPARABLE: Final[str] = "not_comparable"
CATEGORIES: Final[tuple[str, ...]] = (
    IMPROVED,
    REGRESSED,
    UNCHANGED,
    NEWLY_APPLICABLE,
    NEWLY_FAILING,
    NEWLY_NOT_APPLICABLE,
    ERROR,
    NOT_COMPARABLE,
)
STILL_PASSING: Final[frozenset[model.Outcome]] = frozenset(
    {model.Outcome.PASS, model.Outcome.NOTAPPLICABLE}
)
SHA256_PATTERN: Final[str] = r"[0-9a-f]{64}"
RUN_ID_PATTERN: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
MAX_ECHO_LENGTH: Final[int] = 64
MAX_LISTED_RULES: Final[int] = 20


class ComparisonError(ValueError):
    """Raised when two audits cannot be compared."""


@dataclass(frozen=True)
class Side:
    """One audit result, reduced to what the comparison needs."""

    label: str
    run_id: str
    run_status: str
    scan_run: model.ScanRun | None
    exceptions_sha256: str | None


def _fail(message: str) -> NoReturn:
    raise ComparisonError(message)


def _safe(value: object) -> str:
    return repr(str(value)[:MAX_ECHO_LENGTH])


def _load(value: object, where: str) -> model.ScanRun:
    try:
        return exceptions.load_scan_run(value)
    except exceptions.ExceptionsError as error:
        message = f"{where}: {error}"
        raise ComparisonError(message) from error


def _carries_waivers(run: model.ScanRun) -> bool:
    return any(finding.exception.state is not model.ExceptionState.NONE for finding in run.findings)


def _waived_run(audited: Mapping[str, object], raw: model.ScanRun | None, label: str) -> Side:
    """Return the waived side of an audit, checking that it was derived from its raw run."""
    record = audited.get("exceptions")
    if not isinstance(record, Mapping):
        _fail(f"{label}: waived mode needs the exceptions result of the audit role")
    waivers = cast("Mapping[str, object]", record)
    digest = waivers.get("source_sha256")
    if not isinstance(digest, str) or re.fullmatch(SHA256_PATTERN, digest) is None:
        _fail(f"{label}: waived mode needs an audit that applied an exceptions file")
    applied = waivers.get("applied")
    if not isinstance(applied, bool):
        _fail(f"{label}: exceptions.applied must be a boolean")
    run_id = cast("str", audited["run_id"])
    run_status = cast("str", audited["run_status"])
    if applied != (run_status == COMPLETED):
        _fail(f"{label}: waivers must be applied exactly when the scan completed")
    if raw is None or not applied:
        return Side(label, run_id, run_status, raw, digest)
    evaluation = waivers.get("evaluation")
    if not isinstance(evaluation, Mapping):
        _fail(f"{label}: exceptions.evaluation must be the evaluation document")
    document = cast("Mapping[str, object]", evaluation)
    if document.get("source_sha256") != digest:
        _fail(f"{label}: the evaluation was not made from the recorded exceptions file")
    waived = _load(document.get("scan_run"), f"{label} waived scan run")
    if waived.run_id != raw.run_id:
        _fail(f"{label}: the waived scan run is not derived from the raw scan run")
    raw_outcomes = {finding.rule_id: finding.outcome for finding in raw.findings}
    waived_outcomes = {finding.rule_id: finding.evaluated_outcome for finding in waived.findings}
    if raw_outcomes != waived_outcomes:
        _fail(f"{label}: the waived scan run does not have the evaluated outcomes of the raw run")
    return Side(label, run_id, run_status, waived, digest)


def read_side(value: object, label: str, mode: str) -> Side:
    """Validate one audit result and select the scan run that the mode compares.

    Args:
        value: The audit result in the shape of the ``linux_compliance_audited`` fact.
        label: ``baseline`` or ``post``, used in messages.
        mode: ``raw`` or ``waived``.

    Returns:
        The validated side.

    Raises:
        ComparisonError: If the audit result is malformed or does not fit the mode.
    """
    if not isinstance(value, Mapping):
        _fail(f"{label}: the audit result must be a mapping like linux_compliance_audited")
    audited = cast("Mapping[str, object]", value)
    run_id = audited.get("run_id")
    if not isinstance(run_id, str) or re.fullmatch(RUN_ID_PATTERN, run_id) is None:
        _fail(f"{label}: run_id is missing or invalid: {_safe(run_id)}")
    run_status = audited.get("run_status")
    if not isinstance(run_status, str) or run_status not in RUN_STATUSES:
        _fail(f"{label}: run_status must be one of {', '.join(RUN_STATUSES)}: {_safe(run_status)}")
    document = audited.get("scan_run")
    if (document is None) != (run_status == NOT_RUN):
        _fail(f"{label}: scan_run must be null exactly when run_status is not_run")
    raw = None if document is None else _load(document, f"{label} scan run")
    if raw is not None and raw.status.value != run_status:
        _fail(f"{label}: run_status does not match the status of the scan run")
    if raw is not None and raw.run_id != run_id:
        _fail(f"{label}: run_id does not match the run_id of the scan run")
    if raw is not None and _carries_waivers(raw):
        _fail(f"{label}: scan_run carries exception data; the raw scan run must be unchanged")
    if mode == WAIVED:
        return _waived_run(audited, raw, label)
    return Side(label, run_id, run_status, raw, None)


def _identity(run: model.ScanRun) -> dict[str, object]:
    return {
        "benchmark_id": run.benchmark_id,
        "content": {
            "content_sha256": run.content.content_sha256,
            "content_version": run.content.content_version,
        },
        "host": run.host.to_dict(),
        "profile_id": run.profile_id,
        "scanner": run.scanner.to_dict(),
    }


IDENTITY_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("host", "host"),
    ("benchmark_id", "benchmark"),
    ("content", "content version or digest"),
    ("profile_id", "profile"),
    ("scanner", "scanner name or version"),
)


def check_comparable(baseline: Side, post: Side, mode: str, profile_id: str | None) -> None:
    """Refuse to compare audits that are not two runs of the same scan of the same host.

    Raises:
        ComparisonError: On any mismatch.
    """
    if baseline.run_id == post.run_id:
        _fail(f"baseline and post are the same run {_safe(post.run_id)}; audit again first")
    if mode == WAIVED and baseline.exceptions_sha256 != post.exceptions_sha256:
        _fail(
            "waived mode needs both audits to apply the same exceptions file; the SHA-256 "
            f"differs ({baseline.exceptions_sha256} and {post.exceptions_sha256})"
        )
    runs = [side.scan_run for side in (baseline, post) if side.scan_run is not None]
    if profile_id is not None:
        for run in runs:
            if run.profile_id != profile_id:
                _fail(f"a scan run reports profile {_safe(run.profile_id)}, not {profile_id}")
    if baseline.scan_run is None or post.scan_run is None:
        return
    first = _identity(baseline.scan_run)
    second = _identity(post.scan_run)
    for key, label in IDENTITY_FIELDS:
        if first[key] != second[key]:
            _fail(f"baseline and post differ in {label}; only scans of the same kind are compared")
    if post.scan_run.started_at < baseline.scan_run.finished_at:
        _fail("the post scan started before the baseline scan finished; check the argument order")


def _classify_missing(baseline: model.Finding | None, post: model.Finding | None) -> str:
    """Classify a rule that is missing from at least one of the runs."""
    if baseline is not None:
        passed = baseline.evaluated_outcome is model.Outcome.PASS
        return REGRESSED if passed else ERROR
    failing = post is not None and post.evaluated_outcome is model.Outcome.FAIL
    return NEWLY_FAILING if failing else ERROR


def classify(baseline: model.Finding | None, post: model.Finding | None) -> str:
    """Return the category of one rule from its baseline and post findings.

    The evaluated outcome is compared, so a waiver is never an improvement. The first matching
    rule wins, so a passing rule that errors or disappears afterwards is a regression, and a rule
    that was not applicable or missing in the baseline and fails afterwards is newly failing.
    """
    if baseline is None or post is None:
        return _classify_missing(baseline, post)
    before = baseline.evaluated_outcome
    after = post.evaluated_outcome
    was_not_applicable = before is model.Outcome.NOTAPPLICABLE
    rules = (
        (before is model.Outcome.PASS and after not in STILL_PASSING, REGRESSED),
        (model.Outcome.ERROR in (before, after), ERROR),
        (before is after, UNCHANGED),
        (before is model.Outcome.FAIL and after is model.Outcome.PASS, IMPROVED),
        (after is model.Outcome.NOTAPPLICABLE, NEWLY_NOT_APPLICABLE),
        (was_not_applicable and after is model.Outcome.FAIL, NEWLY_FAILING),
        (was_not_applicable and after is model.Outcome.PASS, NEWLY_APPLICABLE),
    )
    return next((category for matched, category in rules if matched), NOT_COMPARABLE)


def _outcomes(finding: model.Finding | None) -> dict[str, object] | None:
    if finding is None:
        return None
    return {
        "evaluated_outcome": finding.evaluated_outcome.value,
        "outcome": finding.outcome.value,
    }


def _summary(run: model.ScanRun | None) -> dict[str, object] | None:
    if run is None:
        return None
    tally: dict[str, object] = {outcome.value: 0 for outcome in model.Outcome}
    for finding in run.findings:
        tally[finding.outcome.value] = cast("int", tally[finding.outcome.value]) + 1
    tally["total"] = len(run.findings)
    tally["run_status"] = run.status.value
    return tally


def _side_report(side: Side) -> dict[str, object]:
    run = side.scan_run
    return {
        "finished_at": None if run is None else run.finished_at,
        "run_id": side.run_id,
        "run_status": side.run_status,
        "started_at": None if run is None else run.started_at,
        "summary": _summary(run),
    }


def _rules(baseline: model.ScanRun, post: model.ScanRun) -> list[dict[str, object]]:
    before = {finding.rule_id: finding for finding in baseline.findings}
    after = {finding.rule_id: finding for finding in post.findings}
    records: list[dict[str, object]] = []
    for rule_id in sorted(set(before) | set(after)):
        old = before.get(rule_id)
        new = after.get(rule_id)
        records.append(
            {
                "baseline": _outcomes(old),
                "category": classify(old, new),
                "post": _outcomes(new),
                "rule_id": rule_id,
            }
        )
    return records


def _listed(rule_ids: list[str]) -> str:
    shown = ", ".join(rule_ids[:MAX_LISTED_RULES])
    hidden = len(rule_ids) - MAX_LISTED_RULES
    return shown if hidden <= 0 else f"{shown} and {hidden} more"


def _complete_message(
    mode: str, counts: dict[str, int], regressed: list[str], newly_failing: list[str]
) -> str:
    figures = ", ".join(f"{counts[category]} {category}" for category in CATEGORIES)
    leads: list[str] = []
    if regressed:
        leads.append(
            f"REGRESSION: {counts[REGRESSED]} rule(s) passed in the baseline and no longer pass: "
            f"{_listed(regressed)}. "
        )
    if newly_failing:
        leads.append(
            f"NEW FAILURE: {counts[NEWLY_FAILING]} rule(s) were not applicable or missing in the "
            f"baseline and fail now: {_listed(newly_failing)}. "
        )
    if not leads:
        leads.append(
            "No regression and no new failure: no rule that passed in the baseline stopped "
            "passing, and no rule started to fail. "
        )
    return (
        f"{''.join(leads)}Verification complete ({mode} results): {figures}. Waived and disabled "
        "results are never counted as improvements. This compares two scans of one host and is "
        "not a claim of compliance."
    )


def _incomplete_reasons(baseline: Side, post: Side) -> list[str]:
    return [
        f"the {side.label} scan did not complete (run_status {side.run_status})"
        for side in (baseline, post)
        if side.run_status != COMPLETED
    ]


def _rule_ids(records: list[dict[str, object]]) -> list[str]:
    return [cast("str", record["rule_id"]) for record in records]


def _figures(baseline: model.ScanRun, post: model.ScanRun, mode: str) -> dict[str, object]:
    rules = _rules(baseline, post)
    counts: dict[str, int] = dict.fromkeys(CATEGORIES, 0)
    for record in rules:
        counts[cast("str", record["category"])] += 1
    regressions = [record for record in rules if record["category"] == REGRESSED]
    new_failures = [record for record in rules if record["category"] == NEWLY_FAILING]
    passed_now_not_applicable = [
        record
        for record in rules
        if record["category"] == NEWLY_NOT_APPLICABLE
        and cast("dict[str, object]", record["baseline"])["evaluated_outcome"] == PASS
    ]
    return {
        "counts": counts,
        "message": _complete_message(mode, counts, _rule_ids(regressions), _rule_ids(new_failures)),
        "new_failure_detected": bool(new_failures),
        "new_failures": new_failures,
        "passed_now_not_applicable": passed_now_not_applicable,
        "regression_detected": bool(regressions),
        "regressions": regressions,
        "rules": rules,
    }


def compare_scans(
    baseline: object,
    post: object,
    mode: object = RAW,
    profile_id: object = None,
) -> dict[str, object]:
    """Compare a baseline audit with a later audit of the same host.

    Args:
        baseline: The audit result before remediation.
        post: The audit result after remediation.
        mode: ``raw`` or ``waived``.
        profile_id: The full profile identifier both runs must report, or ``None``.

    Returns:
        The comparison document.

    Raises:
        ComparisonError: If the inputs are invalid or the audits are not comparable.
    """
    if mode not in MODES:
        _fail(f"mode must be raw or waived: {_safe(mode)}")
    if profile_id is not None:
        try:
            model.validate_xccdf_id(profile_id, "profile_id", "profile")
        except model.ModelError as error:
            message = f"invalid profile_id: {error}"
            raise ComparisonError(message) from error
    chosen = mode
    before = read_side(baseline, "baseline", chosen)
    after = read_side(post, "post", chosen)
    check_comparable(before, after, chosen, cast("str | None", profile_id))
    reasons = _incomplete_reasons(before, after)
    identity = (
        None if before.scan_run is None or after.scan_run is None else _identity(before.scan_run)
    )
    document: dict[str, object] = {
        "baseline": _side_report(before),
        "complete": not reasons,
        "exceptions_sha256": before.exceptions_sha256,
        "identity": identity,
        "incomplete_reasons": reasons,
        "mode": chosen,
        "post": _side_report(after),
        "status": "incomplete" if reasons else "complete",
    }
    if reasons or before.scan_run is None or after.scan_run is None:
        document.update(
            {
                "counts": None,
                "message": (
                    f"Verification incomplete: {'; '.join(reasons)}. No improvement and no "
                    "regression is reported, and the absence of regressions is not established. "
                    "This is not a claim of compliance."
                ),
                "new_failure_detected": None,
                "new_failures": None,
                "passed_now_not_applicable": None,
                "regression_detected": None,
                "regressions": None,
                "rules": None,
            }
        )
        return document
    document.update(_figures(before.scan_run, after.scan_run, chosen))
    return document


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Return the filters this plugin provides."""
        return {"compare_scans": compare_scans}
