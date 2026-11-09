"""The results of an audit rule topic, with the effect of a changed rule set (FREES-110)."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import audit_rule_results

APPLY = {
    "rule_id": "applied",
    "family": "auditd_rules_time",
    "parameters": {"path": "/etc/audit/rules.d/50-freesecdev-a.rules"},
}
COMPLIANT = {**APPLY, "rule_id": "compliant"}
REFUSED = {**APPLY, "rule_id": "refused"}
REMOVED = {**APPLY, "rule_id": "removed"}
GONE = {**APPLY, "rule_id": "gone"}
KEPT = {**APPLY, "rule_id": "kept"}
FAMILY = {"apply": [APPLY, COMPLIANT, REFUSED], "cleanup": [REMOVED, GONE, KEPT]}
PLAN = {
    "applied": {"status": "applied", "reason": None},
    "compliant": {"status": "compliant", "reason": None},
    "refused": {"status": "duplicate_rule", "reason": "a.rules already holds it"},
}
CLEANUP = {
    "removed": {"reason": None, "present": True},
    "gone": {"reason": None, "present": False},
    "kept": {"reason": "modified_since_apply", "present": True},
}


def results(outcome: dict[str, object]) -> dict[str, dict[str, object]]:
    found = audit_rule_results.audit_rule_results(
        FAMILY, PLAN, CLEANUP, ["applied", "removed"], outcome
    )
    return {str(item["rule_id"]): item for item in found}


def test_locked_rules_give_every_changed_result_the_reboot_reason() -> None:
    found = results({"changed": True, "loaded": False, "locked": True})
    assert found["applied"]["status"] == "applied"
    assert found["applied"]["reason"] == "locked_until_reboot"
    assert "take effect at the next boot" in str(found["applied"]["message"])
    assert found["removed"]["status"] == "restored"
    assert found["removed"]["reason"] == "locked_until_reboot"
    assert found["gone"]["reason"] is None
    assert found["compliant"]["reason"] is None
    assert found["refused"]["reason"] == "a.rules already holds it"
    assert found["kept"]["status"] == "cleanup_incomplete"
    assert found["kept"]["reason"] == "modified_since_apply"


def test_a_verified_load_has_no_effect_reason() -> None:
    found = results({"changed": True, "loaded": True, "locked": False})
    assert found["applied"]["reason"] is None
    assert found["removed"]["reason"] is None
    assert "checked and loaded" in str(found["applied"]["message"])


def test_without_auditd_the_rules_take_effect_when_it_starts() -> None:
    found = results({"changed": True, "loaded": False, "locked": False})
    assert found["applied"]["reason"] == "takes_effect_at_start"
    assert found["removed"]["reason"] == "takes_effect_at_start"
    assert found["applied"]["changed"] is True
    assert found["compliant"]["changed"] is False


def test_an_unchanged_rule_set_has_no_effect() -> None:
    found = results({"changed": False, "loaded": False, "locked": True})
    assert found["applied"]["reason"] is None
    assert found["applied"]["message"] == "/etc/audit/rules.d/50-freesecdev-a.rules: applied"
    assert audit_rule_results.effect({}) is None


@pytest.mark.parametrize(
    "arguments",
    [
        ("family", PLAN, CLEANUP, [], {}),
        ({"apply": "x"}, PLAN, CLEANUP, [], {}),
        ({"apply": ["x"]}, PLAN, CLEANUP, [], {}),
        (FAMILY, PLAN, CLEANUP, "applied", {}),
        (FAMILY, PLAN, CLEANUP, [], None),
    ],
)
def test_malformed_input_is_refused(arguments: tuple[object, ...]) -> None:
    with pytest.raises(TypeError):
        audit_rule_results.audit_rule_results(*arguments)


def test_the_plugin_names_the_filter() -> None:
    filters = audit_rule_results.FilterModule().filters()
    assert filters == {"audit_rule_results": audit_rule_results.audit_rule_results}
