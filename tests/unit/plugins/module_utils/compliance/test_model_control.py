"""Control placements on findings and schema version 1.2 of the findings model (FREES-170)."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    placement,
)
from tests.unit.plugins.module_utils.compliance.test_model import finding, scan_run
from tests.unit.plugins.module_utils.compliance.test_model_off_platform import MARKER, marked_run

RULE_A = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
RULE_B = "xccdf_org.ssgproject.content_rule_audit_rules_sshd"


def placed(**overrides: Any) -> placement.ControlPlacement:
    values: dict[str, Any] = {
        "family": "ssh",
        "topic": "ssh",
        "tags": ("auditd",),
        "stig_id": "UBTU-24-100820",
        "mapped_rules": (RULE_B, RULE_A),
        "partially_disabled_by": (),
    }
    return placement.ControlPlacement(**{**values, **overrides})


def placed_run(**overrides: Any) -> model.ScanRun:
    return scan_run(findings=(finding(control=placed()),), **overrides)


def findings_of(document: dict[str, object]) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", document["findings"])


def test_a_placement_is_stored_sorted_and_serializes_every_field() -> None:
    item = placed(tags=("zeta", "auditd"), partially_disabled_by=("linux_compliance_b", "a"))
    assert item.mapped_rules == (RULE_B, RULE_A)
    assert item.tags == ("auditd", "zeta")
    assert item.partially_disabled_by == ("a", "linux_compliance_b")
    assert item.to_dict() == {
        "family": "ssh",
        "mapped_rules": [RULE_B, RULE_A],
        "partially_disabled_by": ["a", "linux_compliance_b"],
        "stig_id": "UBTU-24-100820",
        "tags": ["auditd", "zeta"],
        "topic": "ssh",
    }
    assert placement.ControlPlacement.from_dict(item.to_dict()) == item


def test_an_unmapped_placement_has_no_tags_and_the_unmapped_topic() -> None:
    item = placed(
        family=placement.UNMAPPED_FAMILY,
        topic=placement.UNMAPPED_FAMILY,
        tags=(),
        stig_id=None,
        mapped_rules=(),
    )
    assert item.stig_id is None
    with pytest.raises(placement.PlacementError, match="unmapped control"):
        placed(family=placement.UNMAPPED_FAMILY, tags=())
    with pytest.raises(placement.PlacementError, match="unmapped control"):
        placed(topic=placement.UNMAPPED_FAMILY)
    with pytest.raises(placement.PlacementError, match="unmapped control"):
        placed(family=placement.UNMAPPED_FAMILY, topic=placement.UNMAPPED_FAMILY)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"family": "SSH"}, "control.family has an invalid format"),
        ({"topic": ""}, "control.topic must not be empty"),
        ({"tags": ("ssh",)}, "must not repeat control.family"),
        ({"tags": ("a", "a")}, "control.tags contains duplicates"),
        ({"tags": ["a"]}, "control.tags must be a tuple"),
        ({"tags": ("Bad",)}, "control.tags item has an invalid format"),
        ({"stig_id": "UBTU-24-1"}, "control.stig_id has an invalid format"),
        ({"mapped_rules": ("not_a_rule",)}, "control.mapped_rules item has an invalid format"),
        ({"mapped_rules": (RULE_A,) * 65}, "control.mapped_rules exceeds 64 items"),
        ({"partially_disabled_by": ("Bad-name",)}, "partially_disabled_by item has an invalid"),
        (
            {"mapped_rules": (), "partially_disabled_by": ("linux_compliance_ssh_enabled",)},
            "requires control.mapped_rules",
        ),
    ],
)
def test_a_placement_rejects_invalid_fields(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(placement.PlacementError, match=message):
        placed(**overrides)


def test_a_placement_document_rejects_unknown_and_missing_keys() -> None:
    document = placed().to_dict()
    with pytest.raises(placement.PlacementError, match="unknown keys"):
        placement.ControlPlacement.from_dict({**document, "other": 1})
    del document["stig_id"]
    with pytest.raises(placement.PlacementError, match="missing keys: stig_id"):
        placement.ControlPlacement.from_dict(document)
    with pytest.raises(model.ModelError, match="must be of type ControlPlacement"):
        finding(control={"family": "ssh"})


def test_a_placed_run_serializes_as_one_two_with_control_on_every_finding() -> None:
    other = finding(rule_id="xccdf_org.ssgproject.content_rule_other_unplaced")
    run = scan_run(findings=(finding(control=placed()), other))
    document = json.loads(model.dumps(run))
    assert document["schema_version"] == model.CONTROL_SCHEMA_VERSION
    controls = [item["control"] for item in findings_of(document)]
    assert placed().to_dict() in controls
    assert None in controls
    assert model.OFF_PLATFORM_KEY not in document
    assert model.loads(model.dumps(run)) == run


def test_runs_without_placements_keep_their_schema_versions_byte_for_byte() -> None:
    plain = scan_run()
    assert plain.schema_version == model.SCHEMA_VERSION
    assert placement.CONTROL_KEY not in findings_of(plain.to_dict())[0]
    assert marked_run().schema_version == model.OFF_PLATFORM_SCHEMA_VERSION


def test_a_marked_and_placed_run_round_trips_as_one_two() -> None:
    run = marked_run(findings=(finding(control=placed()),))
    document = json.loads(model.dumps(run))
    assert document["schema_version"] == "1.2"
    assert document["off_platform"] == MARKER.to_dict()
    assert all(item["off_platform"] == MARKER.to_dict() for item in findings_of(document))
    assert model.loads(model.dumps(run)) == run


def test_a_one_two_document_must_hold_control_on_every_finding() -> None:
    document = placed_run().to_dict()
    findings = [dict(item) for item in findings_of(document)]
    del findings[0]["control"]
    with pytest.raises(model.ModelError, match="missing keys: control"):
        model.ScanRun.from_dict({**document, "findings": findings})


def test_a_one_two_document_needs_a_placement_somewhere() -> None:
    document = scan_run().to_dict()
    findings = [{**item, "control": None} for item in findings_of(document)]
    with pytest.raises(model.ModelError, match="does not match the content"):
        model.ScanRun.from_dict({**document, "schema_version": "1.2", "findings": findings})


def test_older_documents_may_not_carry_a_placement() -> None:
    document = placed_run().to_dict()
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.ScanRun.from_dict({**document, "schema_version": "1.0"})
    marked = marked_run(findings=(finding(control=placed()),)).to_dict()
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.ScanRun.from_dict({**marked, "schema_version": "1.1"})


def test_a_one_two_document_marks_the_run_and_its_findings_together() -> None:
    marked = marked_run(findings=(finding(control=placed()),)).to_dict()
    without_run = {key: value for key, value in marked.items() if key != model.OFF_PLATFORM_KEY}
    with pytest.raises(model.ModelError, match="unknown keys"):
        model.ScanRun.from_dict(without_run)
    findings = [dict(item) for item in findings_of(marked)]
    del findings[0][model.OFF_PLATFORM_KEY]
    with pytest.raises(model.ModelError, match="missing keys: off_platform"):
        model.ScanRun.from_dict({**marked, "findings": findings})


def test_a_placement_survives_a_rebuild_of_its_finding() -> None:
    run = placed_run()
    rebuilt = replace(run.findings[0], message="changed")
    assert rebuilt.control == placed()
    assert model.loads(model.dumps(replace(run, findings=(rebuilt,)))).findings[0].control == (
        placed()
    )


def test_a_placement_document_must_be_an_object_with_typed_fields() -> None:
    with pytest.raises(placement.PlacementError, match="control must be an object"):
        placement.ControlPlacement.from_dict([])
    document = placed().to_dict()
    with pytest.raises(placement.PlacementError, match="stig_id must be a string or null"):
        placement.ControlPlacement.from_dict({**document, "stig_id": 1})
    with pytest.raises(placement.PlacementError, match="tags must be an array of strings"):
        placement.ControlPlacement.from_dict({**document, "tags": "ssh"})
    with pytest.raises(placement.PlacementError, match="family must be a string"):
        placed(family=1)
    with pytest.raises(placement.PlacementError, match="exceeds 64 characters"):
        placed(stig_id="A" + "B" * 70 + "-24-000001")


def test_an_invalid_placement_in_a_document_is_a_model_error() -> None:
    document = placed_run().to_dict()
    findings = [dict(item) for item in findings_of(document)]
    findings[0]["control"] = {**placed().to_dict(), "family": "Bad"}
    with pytest.raises(model.ModelError, match=r"control\.family has an invalid format"):
        model.ScanRun.from_dict({**document, "findings": findings})


def test_the_placement_patterns_are_the_model_patterns() -> None:
    assert model.XCCDF_ID_PATTERNS["rule"] == placement.RULE_PATTERN
    assert placement.MAX_ID_LENGTH == model.MAX_ID_LENGTH
    assert placement.MAX_VARIABLES == model.MAX_ITEMS
    assert placement.CONTROL_KEY == "control"
