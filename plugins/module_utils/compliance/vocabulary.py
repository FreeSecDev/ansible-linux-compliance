"""The vocabulary of the findings model: its enumerations and their tables.

:mod:`model` re-exports every enumeration under its own name, so callers keep
writing ``model.Outcome``. The tables say which evaluation methods a control
class allows (:data:`CLASS_EVALUATION`), on which outcomes a result flag may
appear (:data:`FLAG_OUTCOMES`) and which remediation statuses can never report a
change (:data:`UNCHANGED_STATUSES`). They moved here unchanged from ``model.py``
when operator deviations (FREES-203) took that module past its line limit.

The module uses only the standard library and syntax that runs on Python 3.9.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Mapping

_XCCDF_RESULT_OK: Final[str] = "pass"


class Outcome(Enum):
    """Platform outcome of evaluating one rule on one host."""

    PASS = _XCCDF_RESULT_OK
    FAIL = "fail"
    NOTAPPLICABLE = "notapplicable"
    NOTCHECKED = "notchecked"
    ERROR = "error"
    WAIVED = "waived"
    DISABLED = "disabled"


class ResultFlag(Enum):
    """Qualifier retained when an XCCDF result is folded into an outcome."""

    FIXED = "fixed"
    INFORMATIONAL = "informational"
    NOTSELECTED = "notselected"
    OPERATOR_DEVIATION = "operator_deviation"


class Severity(Enum):
    """Rule severity as published by the benchmark content."""

    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ControlClass(Enum):
    """Classification of a control by what the platform can do with it."""

    DIRECTLY_AUDITABLE = "directly_auditable"
    AUTOMATABLE_REMEDIATION = "automatable_remediation"
    EVIDENCE_ONLY = "evidence_only"
    MANUAL_ORGANIZATIONAL = "manual_organizational"
    UNSUPPORTED = "unsupported"


class EvaluationMethod(Enum):
    """How the scanner evaluates a rule."""

    OVAL = "oval"
    SCE = "sce"
    OCIL = "ocil"
    EVIDENCE = "evidence"
    MANUAL = "manual"
    NONE = "none"


class RemediationMethod(Enum):
    """How the platform remediates a rule."""

    NATIVE_MODULE = "native_module"
    NONE = "none"


class RevertStrategy(Enum):
    """How a remediation is reverted when the rule is disabled (ADR 0011)."""

    OWNED_DROPIN = "owned_dropin"
    RECORDED_VALUE = "recorded_value"
    RECORDED_STATE = "recorded_state"
    IRREVERSIBLE = "irreversible"


class FrameworkId(Enum):
    """Compliance frameworks referenced by rules."""

    CIS = "cis"
    STIG = "stig"
    NIST_800_53 = "nist_800_53"
    NIST_800_171 = "nist_800_171"
    PCI_DSS = "pci_dss"
    ANSSI = "anssi"


class ExceptionState(Enum):
    """State of the exception record that applies to a finding."""

    NONE = "none"
    ACTIVE = "active"
    EXPIRED = "expired"


class RemediationStatus(Enum):
    """Result of a remediation or cleanup attempt for one rule."""

    APPLIED = "applied"
    ALREADY_COMPLIANT = "already_compliant"
    SKIPPED = "skipped"
    FAILED = "failed"
    REVERTED = "reverted"
    CLEANUP_INCOMPLETE = "cleanup_incomplete"
    NOT_REMEDIATED = "not_remediated"
    DEVIATION = "deviation"


class ScanStatus(Enum):
    """Whether the scanner itself ran to completion."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


_AUDITABLE_METHODS: Final[frozenset[EvaluationMethod]] = frozenset(
    {EvaluationMethod.OVAL, EvaluationMethod.SCE, EvaluationMethod.OCIL}
)
CLASS_EVALUATION: Final[Mapping[ControlClass, frozenset[EvaluationMethod]]] = MappingProxyType(
    {
        ControlClass.DIRECTLY_AUDITABLE: _AUDITABLE_METHODS,
        ControlClass.AUTOMATABLE_REMEDIATION: _AUDITABLE_METHODS,
        ControlClass.EVIDENCE_ONLY: frozenset({EvaluationMethod.EVIDENCE}),
        ControlClass.MANUAL_ORGANIZATIONAL: frozenset({EvaluationMethod.MANUAL}),
        ControlClass.UNSUPPORTED: frozenset({EvaluationMethod.NONE}),
    }
)
FLAG_OUTCOMES: Final[Mapping[ResultFlag, frozenset[Outcome]]] = MappingProxyType(
    {
        ResultFlag.FIXED: frozenset({Outcome.PASS}),
        ResultFlag.INFORMATIONAL: frozenset({Outcome.NOTCHECKED}),
        ResultFlag.NOTSELECTED: frozenset({Outcome.NOTCHECKED}),
        ResultFlag.OPERATOR_DEVIATION: frozenset({Outcome.PASS, Outcome.FAIL, Outcome.WAIVED}),
    }
)
UNCHANGED_STATUSES: Final[frozenset[RemediationStatus]] = frozenset(
    {
        RemediationStatus.ALREADY_COMPLIANT,
        RemediationStatus.SKIPPED,
        RemediationStatus.NOT_REMEDIATED,
    }
)
