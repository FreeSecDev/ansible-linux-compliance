from __future__ import annotations

import ast
import copy
import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model

if TYPE_CHECKING:
    from collections.abc import Callable

SHA = "a" * 64
RULE = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
RULE_B = "xccdf_org.ssgproject.content_rule_audit_rules_login_events"
PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"
BENCHMARK = "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04"
START = "2026-10-25T10:00:00Z"
END = "2026-10-25T10:05:00Z"
MODEL_PATH = Path(model.__file__)
STANDARD_LIBRARY_IMPORTS = frozenset(
    {
        "__future__",
        "collections",
        "dataclasses",
        "datetime",
        "enum",
        "json",
        "re",
        "types",
        "typing",
    }
)
UNCHANGED_STATUSES: frozenset[model.RemediationStatus] = frozenset(
    {
        model.RemediationStatus.ALREADY_COMPLIANT,
        model.RemediationStatus.SKIPPED,
        model.RemediationStatus.NOT_REMEDIATED,
    }
)


def provenance(**overrides: Any) -> model.Provenance:
    values: dict[str, Any] = {
        "source": "cis@ubuntu2404",
        "content_version": "0.1.82",
        "content_sha256": SHA,
    }
    return model.Provenance(**{**values, **overrides})


def reference(**overrides: Any) -> model.Reference:
    values: dict[str, Any] = {
        "framework": model.FrameworkId.CIS,
        "control_id": "5.2.10",
        "provenance": provenance(),
    }
    return model.Reference(**{**values, **overrides})


def applicability(**overrides: Any) -> model.Applicability:
    values: dict[str, Any] = {"distribution_id": "ubuntu", "versions": ("24.04",)}
    return model.Applicability(**{**values, **overrides})


def rule(**overrides: Any) -> model.Rule:
    values: dict[str, Any] = {
        "rule_id": RULE,
        "title": "Disable SSH root login",
        "description": "Root must not log in over SSH.\nSet PermitRootLogin to no.",
        "severity": model.Severity.MEDIUM,
        "category": "ssh",
        "control_class": model.ControlClass.AUTOMATABLE_REMEDIATION,
        "applicability": (applicability(),),
        "evaluation_method": model.EvaluationMethod.OVAL,
        "remediation_method": model.RemediationMethod.NATIVE_MODULE,
        "revert_strategy": model.RevertStrategy.OWNED_DROPIN,
        "references": (reference(),),
    }
    return model.Rule(**{**values, **overrides})


def profile(**overrides: Any) -> model.Profile:
    values: dict[str, Any] = {
        "profile_id": PROFILE,
        "title": "CIS Level 1 Server",
        "rule_ids": (RULE,),
    }
    return model.Profile(**{**values, **overrides})


def benchmark(**overrides: Any) -> model.Benchmark:
    framework = model.Framework(model.FrameworkId.CIS, "CIS Benchmarks")
    values: dict[str, Any] = {
        "benchmark_id": BENCHMARK,
        "title": "Ubuntu 24.04",
        "version": "0.1.82",
        "framework_version": model.FrameworkVersion(framework, "1.0.0"),
        "provenance": provenance(),
        "profiles": (profile(),),
        "rules": (rule(),),
    }
    return model.Benchmark(**{**values, **overrides})


def host(**overrides: Any) -> model.HostIdentity:
    values: dict[str, Any] = {
        "hostname": "web-01.example.test",
        "distribution_id": "ubuntu",
        "distribution_version": "24.04",
        "architecture": "x86_64",
        "machine_id": "0123456789abcdef0123456789abcdef",
    }
    return model.HostIdentity(**{**values, **overrides})


def evidence(**overrides: Any) -> model.Evidence:
    values: dict[str, Any] = {
        "kind": "file-content",
        "source": "/etc/ssh/sshd_config",
        "content": "PermitRootLogin no\n",
    }
    return model.Evidence(**{**values, **overrides})


def exception_status(**overrides: Any) -> model.ExceptionStatus:
    values: dict[str, Any] = {
        "state": model.ExceptionState.ACTIVE,
        "exception_id": "EXC-1",
        "reason": "Accepted risk",
        "expires_at": "2027-01-01T00:00:00Z",
    }
    return model.ExceptionStatus(**{**values, **overrides})


def remediation(**overrides: Any) -> model.RemediationResult:
    values: dict[str, Any] = {
        "rule_id": RULE,
        "status": model.RemediationStatus.APPLIED,
        "changed": True,
        "message": "drop-in written",
    }
    return model.RemediationResult(**{**values, **overrides})


def finding(**overrides: Any) -> model.Finding:
    values: dict[str, Any] = {
        "rule_id": RULE,
        "outcome": model.Outcome.FAIL,
        "severity": model.Severity.MEDIUM,
        "message": "PermitRootLogin is yes",
        "evidence": (evidence(),),
        "exception": model.ExceptionStatus.none(),
        "remediation": None,
        "disabled_by": None,
        "flags": (),
    }
    return model.Finding(**{**values, **overrides})


def scan_run(**overrides: Any) -> model.ScanRun:
    values: dict[str, Any] = {
        "run_id": "run-2026-10-25-001",
        "started_at": START,
        "finished_at": END,
        "host": host(),
        "scanner": model.ScannerInfo("openscap", "1.3.9"),
        "content": provenance(source="ssg-ubuntu2404-ds.xml"),
        "benchmark_id": BENCHMARK,
        "profile_id": PROFILE,
        "status": model.ScanStatus.COMPLETED,
        "error_message": None,
        "findings": (finding(), finding(rule_id=RULE_B, outcome=model.Outcome.PASS)),
    }
    return model.ScanRun(**{**values, **overrides})


ENTITY_FACTORIES: dict[str, tuple[Callable[[], Any], Any]] = {
    "provenance": (provenance, model.Provenance),
    "scanner": (lambda: model.ScannerInfo("openscap", "1.3.9"), model.ScannerInfo),
    "framework": (lambda: model.Framework(model.FrameworkId.STIG, "DISA STIG"), model.Framework),
    "framework_version": (
        lambda: model.FrameworkVersion(model.Framework(model.FrameworkId.CIS, "CIS"), "1.0"),
        model.FrameworkVersion,
    ),
    "applicability": (applicability, model.Applicability),
    "reference": (reference, model.Reference),
    "rule": (rule, model.Rule),
    "profile": (profile, model.Profile),
    "benchmark": (benchmark, model.Benchmark),
    "host": (host, model.HostIdentity),
    "evidence": (evidence, model.Evidence),
    "exception_active": (exception_status, model.ExceptionStatus),
    "exception_none": (model.ExceptionStatus.none, model.ExceptionStatus),
    "remediation": (remediation, model.RemediationResult),
    "finding": (finding, model.Finding),
    "scan_run": (scan_run, model.ScanRun),
}


@pytest.mark.parametrize("name", sorted(ENTITY_FACTORIES))
def test_entity_round_trips_through_dict(name: str) -> None:
    factory, cls = ENTITY_FACTORIES[name]
    original = factory()
    data = original.to_dict()
    assert cls.from_dict(data) == original
    assert cls.from_dict(json.loads(json.dumps(data))).to_dict() == data


@pytest.mark.parametrize("name", sorted(ENTITY_FACTORIES))
def test_entity_rejects_unknown_missing_and_non_mapping(name: str) -> None:
    factory, cls = ENTITY_FACTORIES[name]
    data = factory().to_dict()
    with pytest.raises(model.ModelError, match="unknown keys: extra"):
        cls.from_dict({**data, "extra": 1})
    removed = copy.deepcopy(data)
    del removed[min(removed)]
    with pytest.raises(model.ModelError, match="missing keys"):
        cls.from_dict(removed)
    for bad in (None, [], "text", 7, [("a", 1)]):
        with pytest.raises(model.ModelError, match="must be an object"):
            cls.from_dict(bad)


@pytest.mark.parametrize("name", sorted(ENTITY_FACTORIES))
def test_entity_is_frozen_and_hashable(name: str) -> None:
    factory = ENTITY_FACTORIES[name][0]
    entity: Any = factory()
    assert hash(entity) == hash(factory())
    field: str = dataclasses.fields(entity)[0].name
    with pytest.raises(AttributeError):
        setattr(entity, field, None)


def test_from_dict_rejects_nested_unknown_key() -> None:
    data: dict[str, Any] = scan_run().to_dict()
    data["host"]["extra"] = "x"
    with pytest.raises(model.ModelError, match="host has unknown keys: extra"):
        model.ScanRun.from_dict(data)


@pytest.mark.parametrize("bad_key", [1, None, (1, 2)])
def test_from_dict_rejects_non_string_keys(bad_key: object) -> None:
    data: dict[Any, Any] = dict(provenance().to_dict())
    data[bad_key] = "x"
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.Provenance.from_dict(data)


XCCDF_TABLE = [
    ("pass", model.Outcome.PASS, None),
    ("fail", model.Outcome.FAIL, None),
    ("notapplicable", model.Outcome.NOTAPPLICABLE, None),
    ("notchecked", model.Outcome.NOTCHECKED, None),
    ("error", model.Outcome.ERROR, None),
    ("fixed", model.Outcome.PASS, model.ResultFlag.FIXED),
    ("informational", model.Outcome.NOTCHECKED, model.ResultFlag.INFORMATIONAL),
    ("notselected", model.Outcome.NOTCHECKED, model.ResultFlag.NOTSELECTED),
    ("unknown", model.Outcome.ERROR, None),
]


@pytest.mark.parametrize(("value", "outcome", "flag"), XCCDF_TABLE)
def test_xccdf_mapping_table(
    value: str, outcome: model.Outcome, flag: model.ResultFlag | None
) -> None:
    mapped = model.map_xccdf_result(value)
    assert mapped.outcome is outcome
    assert mapped.flag is flag


@pytest.mark.parametrize(
    "value",
    [
        "PASS",
        "Pass",
        " pass",
        "pass ",
        "",
        "waived",
        "disabled",
        "excluded",
        "passed",
        "pass\n",
        "\x00",
        "pass\x00",
        None,
        1,
        True,
        b"pass",
        ["pass"],
        {"pass": 1},
        object(),
    ],
)
def test_unlisted_xccdf_values_map_to_error(value: object) -> None:
    mapped = model.map_xccdf_result(value)
    assert mapped.outcome is model.Outcome.ERROR
    assert mapped.flag is None


def test_xccdf_table_covers_every_documented_value() -> None:
    assert {row[0] for row in XCCDF_TABLE} == {
        "pass",
        "fail",
        "notapplicable",
        "notchecked",
        "error",
        "fixed",
        "informational",
        "notselected",
        "unknown",
    }


def test_outcome_values_are_the_documented_set() -> None:
    assert [item.value for item in model.Outcome] == [
        "pass",
        "fail",
        "notapplicable",
        "notchecked",
        "error",
        "waived",
        "disabled",
    ]


def test_control_classes_are_the_documented_set() -> None:
    assert {item.value for item in model.ControlClass} == {
        "directly_auditable",
        "automatable_remediation",
        "evidence_only",
        "manual_organizational",
        "unsupported",
    }


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_text_must_not_be_blank(value: str) -> None:
    with pytest.raises(model.ModelError, match="must not be empty"):
        provenance(source=value)


def test_single_line_text_rejects_surrounding_whitespace_and_newlines() -> None:
    with pytest.raises(model.ModelError, match="surrounding whitespace"):
        provenance(source=" source")
    with pytest.raises(model.ModelError, match="control characters"):
        provenance(source="a\nb")
    with pytest.raises(model.ModelError, match="control characters"):
        provenance(source="a\x7fb")


def test_multiline_text_allows_newlines_but_not_other_controls() -> None:
    assert evidence(content="line one\r\n\tline two\n").content.endswith("\n")
    with pytest.raises(model.ModelError, match="control characters"):
        evidence(content="a\x00b")
    with pytest.raises(model.ModelError, match="must not be empty"):
        evidence(content="\n \n")


def test_text_length_bounds() -> None:
    assert provenance(source="a" * model.MAX_ID_LENGTH)
    with pytest.raises(model.ModelError, match="exceeds 256 characters"):
        provenance(source="a" * (model.MAX_ID_LENGTH + 1))
    assert evidence(content="a" * model.MAX_EVIDENCE_LENGTH)
    with pytest.raises(model.ModelError, match="exceeds 65536 characters"):
        evidence(content="a" * (model.MAX_EVIDENCE_LENGTH + 1))


@pytest.mark.parametrize("value", [None, 1, b"x", ["x"], True])
def test_text_must_be_a_string(value: object) -> None:
    with pytest.raises(model.ModelError, match="must be a string"):
        provenance(source=value)


@pytest.mark.parametrize("value", ["A" * 64, "a" * 63, "a" * 65, "g" * 64, "sha256:" + SHA])
def test_digest_must_be_lowercase_sha256(value: str) -> None:
    with pytest.raises(model.ModelError):
        provenance(content_sha256=value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "sshd_disable_root_login",
        "xccdf_org.ssgproject.content_profile_x",
        "xccdf_org.ssgproject.content_rule_",
        "xccdf_org.ssgproject.content_rule_a b",
        "xccdf_org.ssgproject.content_rule_a;rm",
        "xccdf_org.ssgproject.content_rule_a\n",
        "XCCDF_org.ssgproject.content_rule_a",
        "xccdf__rule_a",
        None,
        5,
    ],
)
def test_rule_id_must_be_a_full_xccdf_rule_identifier(value: object) -> None:
    with pytest.raises(model.ModelError):
        rule(rule_id=value)


def test_rule_id_length_is_bounded() -> None:
    prefix = "xccdf_org.ssgproject.content_rule_"
    assert rule(rule_id=prefix + "a" * (model.MAX_ID_LENGTH - len(prefix)))
    with pytest.raises(model.ModelError, match="exceeds"):
        rule(rule_id=prefix + "a" * (model.MAX_ID_LENGTH - len(prefix) + 1))


@pytest.mark.parametrize(
    ("builder", "field", "value"),
    [
        (rule, "title", ""),
        (rule, "description", " "),
        (rule, "category", "SSH"),
        (rule, "category", "-ssh"),
        (rule, "severity", "medium"),
        (rule, "control_class", "evidence_only"),
        (rule, "evaluation_method", "oval"),
        (rule, "remediation_method", "none"),
        (rule, "revert_strategy", "owned_dropin"),
        (rule, "applicability", []),
        (rule, "applicability", ()),
        (rule, "applicability", (1,)),
        (rule, "references", [reference()]),
        (rule, "references", (1,)),
        (rule, "references", (reference(), reference())),
        (rule, "applicability", (applicability(), applicability(versions=("22.04",)))),
        (applicability, "versions", ()),
        (applicability, "versions", ["24.04"]),
        (applicability, "versions", ("24.04", "24.04")),
        (applicability, "versions", ("24 04",)),
        (applicability, "versions", (24,)),
        (applicability, "distribution_id", "Ubuntu"),
        (reference, "framework", "cis"),
        (reference, "control_id", ""),
        (reference, "provenance", {}),
        (profile, "rule_ids", [RULE]),
        (profile, "rule_ids", ("sshd_disable_root_login",)),
        (profile, "rule_ids", (RULE, RULE)),
        (profile, "rule_ids", (1,)),
        (profile, "profile_id", RULE),
        (host, "hostname", "bad host"),
        (host, "hostname", "h" * 254),
        (host, "machine_id", "ABCDEF0123456789ABCDEF0123456789"),
        (host, "machine_id", "123"),
        (host, "distribution_id", "Ubuntu 24"),
        (host, "architecture", "x86 64"),
        (evidence, "kind", "File Content"),
        (evidence, "source", ""),
        (benchmark, "benchmark_id", PROFILE),
        (benchmark, "framework_version", "cis"),
        (benchmark, "provenance", None),
        (benchmark, "profiles", [profile()]),
        (benchmark, "rules", [rule()]),
        (benchmark, "profiles", (profile(), profile())),
        (benchmark, "rules", (rule(), rule())),
        (benchmark, "profiles", (profile(rule_ids=(RULE_B,)),)),
    ],
)
def test_entities_reject_invalid_field_values(builder: Any, field: str, value: object) -> None:
    with pytest.raises(model.ModelError):
        builder(**{field: value})


def test_framework_version_requires_a_framework() -> None:
    wrong: Any = "cis"
    with pytest.raises(model.ModelError, match="must be of type Framework"):
        model.FrameworkVersion(wrong, "1.0")
    with pytest.raises(model.ModelError, match="must be of type FrameworkId"):
        model.Framework(wrong, "CIS")


def test_benchmark_accepts_missing_framework_version() -> None:
    assert benchmark(framework_version=None).to_dict()["framework_version"] is None
    assert (
        model.Benchmark.from_dict(benchmark(framework_version=None).to_dict()).framework_version
        is None
    )


def test_collections_are_stored_sorted_regardless_of_input_order() -> None:
    refs = (reference(framework=model.FrameworkId.STIG, control_id="V-1"), reference())
    ordered = rule(
        references=refs,
        applicability=(
            applicability(distribution_id="ubuntu", versions=("24.04", "22.04")),
            applicability(distribution_id="debian"),
        ),
    )
    assert [item.framework for item in ordered.references] == [
        model.FrameworkId.CIS,
        model.FrameworkId.STIG,
    ]
    assert [item.distribution_id for item in ordered.applicability] == ["debian", "ubuntu"]
    assert ordered.applicability[1].versions == ("22.04", "24.04")
    assert rule(references=tuple(reversed(refs))) == rule(references=refs)
    bench = benchmark(
        rules=(rule(rule_id=RULE_B, applicability=(applicability(),), references=()), rule())
    )
    assert [item.rule_id for item in bench.rules] == [RULE_B, RULE]
    two = benchmark(profiles=(profile(profile_id=PROFILE + "_z"), profile()))
    assert [item.profile_id for item in two.profiles] == [PROFILE, PROFILE + "_z"]
    assert profile(rule_ids=(RULE, RULE_B)).rule_ids == (RULE_B, RULE)


def test_rule_references_cover_every_framework_with_provenance() -> None:
    refs = tuple(reference(framework=item, control_id=item.value) for item in model.FrameworkId)
    built = rule(references=refs)
    assert {item.framework for item in built.references} == set(model.FrameworkId)
    assert all(item.provenance.content_sha256 == SHA for item in built.references)


@pytest.mark.parametrize(
    ("control_class", "evaluation"),
    [
        (model.ControlClass.DIRECTLY_AUDITABLE, model.EvaluationMethod.OVAL),
        (model.ControlClass.DIRECTLY_AUDITABLE, model.EvaluationMethod.SCE),
        (model.ControlClass.DIRECTLY_AUDITABLE, model.EvaluationMethod.OCIL),
        (model.ControlClass.EVIDENCE_ONLY, model.EvaluationMethod.EVIDENCE),
        (model.ControlClass.MANUAL_ORGANIZATIONAL, model.EvaluationMethod.MANUAL),
        (model.ControlClass.UNSUPPORTED, model.EvaluationMethod.NONE),
    ],
)
def test_non_remediable_rules_have_no_remediation_or_revert(
    control_class: model.ControlClass, evaluation: model.EvaluationMethod
) -> None:
    built = rule(
        control_class=control_class,
        evaluation_method=evaluation,
        remediation_method=model.RemediationMethod.NONE,
        revert_strategy=None,
    )
    assert built.control_class is control_class
    assert model.Rule.from_dict(built.to_dict()) == built


@pytest.mark.parametrize("strategy", list(model.RevertStrategy))
def test_remediable_rules_accept_every_revert_strategy(strategy: model.RevertStrategy) -> None:
    assert rule(revert_strategy=strategy).revert_strategy is strategy


@pytest.mark.parametrize(
    ("control_class", "evaluation"),
    [
        (model.ControlClass.DIRECTLY_AUDITABLE, model.EvaluationMethod.EVIDENCE),
        (model.ControlClass.AUTOMATABLE_REMEDIATION, model.EvaluationMethod.NONE),
        (model.ControlClass.EVIDENCE_ONLY, model.EvaluationMethod.OVAL),
        (model.ControlClass.MANUAL_ORGANIZATIONAL, model.EvaluationMethod.OVAL),
        (model.ControlClass.UNSUPPORTED, model.EvaluationMethod.MANUAL),
    ],
)
def test_rule_rejects_evaluation_method_that_contradicts_the_class(
    control_class: model.ControlClass, evaluation: model.EvaluationMethod
) -> None:
    with pytest.raises(model.ModelError, match="evaluation_method does not match"):
        rule(control_class=control_class, evaluation_method=evaluation)


def test_rule_rejects_inconsistent_remediation_declarations() -> None:
    with pytest.raises(model.ModelError, match="remediation_method does not match"):
        rule(remediation_method=model.RemediationMethod.NONE)
    with pytest.raises(model.ModelError, match="remediation_method does not match"):
        rule(control_class=model.ControlClass.DIRECTLY_AUDITABLE, revert_strategy=None)
    with pytest.raises(model.ModelError, match="revert_strategy is required"):
        rule(revert_strategy=None)
    with pytest.raises(model.ModelError, match="revert_strategy is required"):
        rule(
            control_class=model.ControlClass.DIRECTLY_AUDITABLE,
            remediation_method=model.RemediationMethod.NONE,
        )


def test_rule_from_dict_rejects_unknown_enum_values_and_types() -> None:
    data: dict[str, Any] = rule().to_dict()
    cases: tuple[tuple[str, Any], ...] = (
        ("severity", "critical"),
        ("severity", 3),
        ("control_class", "other"),
        ("revert_strategy", "guess"),
        ("revert_strategy", 1),
        ("applicability", {}),
        ("applicability", "x"),
        ("references", None),
        ("title", None),
    )
    for key, bad in cases:
        with pytest.raises(model.ModelError):
            model.Rule.from_dict({**data, key: bad})


def test_from_dict_rejects_wrong_container_and_scalar_types() -> None:
    with pytest.raises(model.ModelError, match="must contain only strings"):
        model.Profile.from_dict({**profile().to_dict(), "rule_ids": [RULE, 3]})
    with pytest.raises(model.ModelError, match="must be an array"):
        model.Profile.from_dict({**profile().to_dict(), "rule_ids": RULE})
    with pytest.raises(model.ModelError, match="must be a boolean"):
        model.RemediationResult.from_dict({**remediation().to_dict(), "changed": "yes"})
    with pytest.raises(model.ModelError, match="must be a boolean"):
        model.RemediationResult.from_dict({**remediation().to_dict(), "changed": 1})
    with pytest.raises(model.ModelError, match="must be a string"):
        model.Provenance.from_dict({**provenance().to_dict(), "source": 5})
    with pytest.raises(model.ModelError, match="must contain only strings"):
        model.Finding.from_dict({**finding().to_dict(), "flags": [1]})
    with pytest.raises(model.ModelError, match="unknown value"):
        model.Finding.from_dict({**finding().to_dict(), "flags": ["fixes"]})
    with pytest.raises(model.ModelError, match="unknown value 'PASS'"):
        model.Finding.from_dict({**finding().to_dict(), "outcome": "PASS"})


def test_constructors_reject_wrong_types() -> None:
    for bad in (None, 1, "pass", model.Severity.LOW):
        with pytest.raises(model.ModelError, match="must be of type Outcome"):
            finding(outcome=bad)
    with pytest.raises(model.ModelError, match="must be a tuple"):
        finding(evidence=[evidence()])
    with pytest.raises(model.ModelError, match="items must be Evidence"):
        finding(evidence=("x",))
    with pytest.raises(model.ModelError, match="must be of type ExceptionStatus"):
        finding(exception=None)
    with pytest.raises(model.ModelError, match="must be of type RemediationResult"):
        finding(remediation={})
    with pytest.raises(model.ModelError, match="must be a boolean"):
        remediation(changed=1)
    with pytest.raises(model.ModelError, match="must be of type Provenance"):
        scan_run(content={})
    with pytest.raises(model.ModelError, match="must be of type HostIdentity"):
        scan_run(host=None)
    with pytest.raises(model.ModelError, match="must be of type ScannerInfo"):
        scan_run(scanner="openscap")
    with pytest.raises(model.ModelError, match="must be of type Provenance"):
        reference(provenance=None)


def test_item_count_bounds() -> None:
    many = tuple(evidence(source=f"/etc/file{index}") for index in range(model.MAX_EVIDENCE_ITEMS))
    assert len(finding(evidence=many).evidence) == model.MAX_EVIDENCE_ITEMS
    with pytest.raises(model.ModelError, match="exceeds 64 items"):
        finding(evidence=(*many, evidence()))
    refs = tuple(reference(control_id=str(index)) for index in range(257))
    with pytest.raises(model.ModelError, match="exceeds 256 items"):
        rule(references=refs)


def test_scan_run_finding_count_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(model, "MAX_FINDINGS", 1)
    with pytest.raises(model.ModelError, match="exceeds"):
        scan_run()


def test_exception_status_rules() -> None:
    assert model.ExceptionStatus.none().state is model.ExceptionState.NONE
    assert (
        exception_status(state=model.ExceptionState.EXPIRED).state is model.ExceptionState.EXPIRED
    )
    assert exception_status(expires_at=None).expires_at is None
    for bad in ({"exception_id": "EXC-1"}, {"reason": "r"}, {"expires_at": START}):
        with pytest.raises(model.ModelError, match="require an active or expired"):
            exception_status(
                **{
                    "state": model.ExceptionState.NONE,
                    "exception_id": None,
                    "reason": None,
                    "expires_at": None,
                    **bad,
                }
            )
    with pytest.raises(model.ModelError):
        exception_status(exception_id=None)
    with pytest.raises(model.ModelError):
        exception_status(reason=None)
    with pytest.raises(model.ModelError, match="valid UTC timestamp"):
        exception_status(expires_at="2027-02-30T00:00:00Z")
    with pytest.raises(model.ModelError, match="must be of type ExceptionState"):
        exception_status(state="active")
    with pytest.raises(model.ModelError):
        exception_status(exception_id="has space")


@pytest.mark.parametrize(
    "status", [item for item in model.RemediationStatus if item in UNCHANGED_STATUSES]
)
def test_unchanged_remediation_statuses_cannot_report_changes(
    status: model.RemediationStatus,
) -> None:
    with pytest.raises(model.ModelError, match="cannot report a change"):
        remediation(status=status, changed=True)
    assert remediation(status=status, changed=False, message=None).message is None


@pytest.mark.parametrize(
    "status", [item for item in model.RemediationStatus if item not in UNCHANGED_STATUSES]
)
def test_other_remediation_statuses_may_report_changes(status: model.RemediationStatus) -> None:
    assert remediation(status=status, changed=True).changed is True


def test_remediation_rule_id_and_message_validation() -> None:
    with pytest.raises(model.ModelError):
        remediation(rule_id="x")
    with pytest.raises(model.ModelError):
        remediation(message="")
    with pytest.raises(model.ModelError):
        remediation(message="a" * 4097)


def test_waived_requires_exactly_an_active_exception() -> None:
    waived = finding(outcome=model.Outcome.WAIVED, exception=exception_status())
    assert waived.outcome is model.Outcome.WAIVED
    with pytest.raises(model.ModelError, match="waived requires"):
        finding(outcome=model.Outcome.WAIVED)
    with pytest.raises(model.ModelError, match="waived requires"):
        finding(
            outcome=model.Outcome.WAIVED,
            exception=exception_status(state=model.ExceptionState.EXPIRED),
        )
    with pytest.raises(model.ModelError, match="waived requires"):
        finding(outcome=model.Outcome.FAIL, exception=exception_status())
    assert (
        finding(exception=exception_status(state=model.ExceptionState.EXPIRED)).outcome
        is model.Outcome.FAIL
    )


def test_disabled_requires_exactly_the_controlling_variable() -> None:
    variable = "linux_compliance_rule_sshd_disable_root_login_enabled"
    disabled = finding(outcome=model.Outcome.DISABLED, disabled_by=variable)
    assert disabled.disabled_by == variable
    with pytest.raises(model.ModelError, match="disabled requires"):
        finding(outcome=model.Outcome.DISABLED)
    with pytest.raises(model.ModelError, match="disabled requires"):
        finding(outcome=model.Outcome.PASS, disabled_by=variable)
    with pytest.raises(model.ModelError):
        finding(outcome=model.Outcome.DISABLED, disabled_by="Not A Variable")
    with pytest.raises(model.ModelError):
        finding(outcome=model.Outcome.DISABLED, disabled_by="x" * 129)


def test_disabled_is_never_a_passing_outcome() -> None:
    assert len({model.Outcome.DISABLED, model.Outcome.PASS}) == 2
    assert model.map_xccdf_result("disabled").outcome is model.Outcome.ERROR


def test_remediation_must_belong_to_the_finding_rule() -> None:
    assert finding(remediation=remediation()).remediation is not None
    with pytest.raises(model.ModelError, match="different rule"):
        finding(remediation=remediation(rule_id=RULE_B))


@pytest.mark.parametrize(
    ("flag", "outcome"),
    [
        (model.ResultFlag.FIXED, model.Outcome.PASS),
        (model.ResultFlag.INFORMATIONAL, model.Outcome.NOTCHECKED),
        (model.ResultFlag.NOTSELECTED, model.Outcome.NOTCHECKED),
    ],
)
def test_flags_are_only_valid_with_their_outcome(
    flag: model.ResultFlag, outcome: model.Outcome
) -> None:
    assert finding(outcome=outcome, flags=(flag,)).flags == (flag,)
    wrong = model.Outcome.FAIL
    with pytest.raises(model.ModelError, match="does not match outcome"):
        finding(outcome=wrong, flags=(flag,))


def test_flags_must_be_unique_and_typed() -> None:
    with pytest.raises(model.ModelError, match="duplicates"):
        finding(outcome=model.Outcome.PASS, flags=(model.ResultFlag.FIXED, model.ResultFlag.FIXED))
    with pytest.raises(model.ModelError, match="items must be ResultFlag"):
        finding(flags=("fixed",))


def test_mapped_xccdf_results_build_valid_findings() -> None:
    for value in [row[0] for row in XCCDF_TABLE]:
        mapped = model.map_xccdf_result(value)
        flags = () if mapped.flag is None else (mapped.flag,)
        assert finding(outcome=mapped.outcome, flags=flags).outcome is mapped.outcome


def test_scan_run_timestamps() -> None:
    assert scan_run(started_at=END, finished_at=END).started_at == END
    with pytest.raises(model.ModelError, match="precedes"):
        scan_run(started_at=END, finished_at=START)
    for bad in (
        "2026-10-25 10:00:00Z",
        "2026-10-25T10:00:00",
        "2026-10-25T10:00:00+00:00",
        "2026-13-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-10-25T24:00:00Z",
        "",
        None,
        20261025,
    ):
        with pytest.raises(model.ModelError):
            scan_run(started_at=bad)
        with pytest.raises(model.ModelError):
            scan_run(finished_at=bad)


def test_scan_run_identifier_fields() -> None:
    for field, bad in (
        ("run_id", "has space"),
        ("run_id", ""),
        ("run_id", "r" * 129),
        ("benchmark_id", RULE),
        ("profile_id", BENCHMARK),
        ("status", "completed"),
        ("error_message", ""),
        ("findings", [finding()]),
        ("findings", (1,)),
    ):
        with pytest.raises(model.ModelError):
            scan_run(**{field: bad})


def test_scan_run_rejects_duplicate_rule_ids_so_rules_count_once() -> None:
    with pytest.raises(model.ModelError, match="duplicates"):
        scan_run(findings=(finding(), finding(message="again")))


def test_scan_run_sorts_findings_by_rule_id() -> None:
    run = scan_run(findings=(finding(), finding(rule_id=RULE_B)))
    assert [item.rule_id for item in run.findings] == [RULE_B, RULE]


@pytest.mark.parametrize("status", [model.ScanStatus.FAILED, model.ScanStatus.TIMED_OUT])
def test_scanner_failure_is_never_pass_or_fail(status: model.ScanStatus) -> None:
    failed = scan_run(
        status=status,
        error_message="oscap exited with status 2",
        findings=(
            finding(outcome=model.Outcome.ERROR),
            finding(rule_id=RULE_B, outcome=model.Outcome.ERROR),
        ),
    )
    assert failed.status is status
    assert scan_run(status=status, error_message="timeout", findings=()).findings == ()
    for outcome in (
        model.Outcome.PASS,
        model.Outcome.FAIL,
        model.Outcome.NOTCHECKED,
        model.Outcome.DISABLED,
    ):
        with pytest.raises(model.ModelError, match="only produce error findings"):
            scan_run(
                status=status,
                error_message="boom",
                findings=(
                    finding(
                        outcome=outcome,
                        disabled_by=(
                            "linux_compliance_ssh_enabled"
                            if outcome is model.Outcome.DISABLED
                            else None
                        ),
                    ),
                ),
            )


def test_scan_status_and_error_message_must_agree() -> None:
    with pytest.raises(model.ModelError, match="error_message is required"):
        scan_run(status=model.ScanStatus.FAILED, error_message=None, findings=())
    with pytest.raises(model.ModelError, match="error_message is required"):
        scan_run(status=model.ScanStatus.COMPLETED, error_message="unexpected")


def test_completed_run_may_contain_every_outcome() -> None:
    findings = tuple(
        finding(
            rule_id=f"xccdf_org.ssgproject.content_rule_r{index}",
            outcome=outcome,
            exception=exception_status()
            if outcome is model.Outcome.WAIVED
            else model.ExceptionStatus.none(),
            disabled_by="linux_compliance_ssh_enabled"
            if outcome is model.Outcome.DISABLED
            else None,
        )
        for index, outcome in enumerate(model.Outcome)
    )
    run = scan_run(findings=findings)
    assert {item.outcome for item in run.findings} == set(model.Outcome)


def test_serialization_is_deterministic_and_versioned() -> None:
    first = model.dumps(scan_run())
    second = model.dumps(
        scan_run(findings=(finding(rule_id=RULE_B, outcome=model.Outcome.PASS), finding()))
    )
    assert first == second
    document = json.loads(first)
    assert document["schema_version"] == model.SCHEMA_VERSION == "1.0"
    assert list(document) == sorted(document)
    assert '": ' not in first
    assert '", ' not in first
    assert model.dumps(model.loads(first)) == first
    assert model.loads(first) == scan_run()


def test_serialization_escapes_non_ascii_and_round_trips_it() -> None:
    run = scan_run(findings=(finding(message="Ünïcode ☃ \U0001f512"),))
    text = model.dumps(run)
    assert text.isascii()
    assert model.loads(text) == run


def test_serialized_keys_are_sorted_at_every_level() -> None:
    seen: list[list[str]] = []

    def record(pairs: list[tuple[str, object]]) -> dict[str, object]:
        seen.append([pair[0] for pair in pairs])
        return dict(pairs)

    json.loads(
        model.dumps(scan_run(findings=(finding(remediation=remediation()),))),
        object_pairs_hook=record,
    )
    assert len(seen) > 5
    assert all(keys == sorted(keys) for keys in seen)


def test_loads_rejects_unsupported_schema_versions() -> None:
    data = scan_run().to_dict()
    for bad in ("2.0", "1", "1.1", "", "1.0 "):
        with pytest.raises(model.ModelError, match="unsupported schema_version"):
            model.ScanRun.from_dict({**data, "schema_version": bad})
    with pytest.raises(model.ModelError, match="must be a string"):
        model.ScanRun.from_dict({**data, "schema_version": 1})
    without = {key: value for key, value in data.items() if key != "schema_version"}
    with pytest.raises(model.ModelError, match="missing keys: schema_version"):
        model.ScanRun.from_dict(without)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "{",
        "null",
        "[]",
        "1",
        '"x"',
        '{"a": NaN}',
        '{"a": Infinity}',
        '{"a": -Infinity}',
        '{"schema_version": "1.0", "schema_version": "1.0"}',
        "[" * 100000,
        "\x00",
    ],
)
def test_loads_rejects_malformed_documents(text: str) -> None:
    with pytest.raises(model.ModelError):
        model.loads(text)


def test_loads_rejects_duplicate_nested_keys_and_non_finite_numbers() -> None:
    text = model.dumps(scan_run())
    duplicated = text.replace('"kind":"file-content"', '"kind":"file-content","kind":"x"', 1)
    assert duplicated != text
    with pytest.raises(model.ModelError, match="duplicate key"):
        model.loads(duplicated)
    with pytest.raises(model.ModelError, match="non-finite number NaN"):
        model.loads('{"x":NaN}')


def test_loads_rejects_non_strings_and_oversized_documents(monkeypatch: pytest.MonkeyPatch) -> None:
    wrong: Any = b"{}"
    with pytest.raises(model.ModelError, match="document must be of type str"):
        model.loads(wrong)
    monkeypatch.setattr(model, "MAX_DOCUMENT_CHARS", 10)
    with pytest.raises(model.ModelError, match="size limit"):
        model.loads(model.dumps(scan_run()))


def test_loads_rejects_unknown_keys_deep_in_the_document() -> None:
    data: dict[str, Any] = json.loads(
        model.dumps(scan_run(findings=(finding(remediation=remediation()),)))
    )
    data["findings"][0]["remediation"]["surprise"] = True
    with pytest.raises(model.ModelError, match="remediation has unknown keys: surprise"):
        model.loads(json.dumps(data))


def test_model_error_is_a_value_error() -> None:
    assert issubclass(model.ModelError, ValueError)


def test_model_uses_only_the_standard_library() -> None:
    tree = ast.parse(MODEL_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            imported.add((node.module or "").split(".")[0])
    assert imported
    assert imported <= STANDARD_LIBRARY_IMPORTS


def test_model_parses_with_the_oldest_managed_node_python_grammar() -> None:
    source = MODEL_PATH.read_text(encoding="utf-8")
    ast.parse(source, feature_version=(3, 9))
    assert "slots=True" not in source
    assert "StrEnum" not in source
    assert "kw_only" not in source


def test_model_contains_no_comments() -> None:
    lines = MODEL_PATH.read_text(encoding="utf-8").splitlines()
    assert not [line for line in lines if line.lstrip().startswith("#")]


def test_host_identity_allows_a_missing_machine_id() -> None:
    anonymous = host(machine_id=None)
    assert anonymous.to_dict()["machine_id"] is None
    assert model.HostIdentity.from_dict(anonymous.to_dict()) == anonymous
