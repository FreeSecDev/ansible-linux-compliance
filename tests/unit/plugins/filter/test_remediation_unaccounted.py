from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    remediation_unaccounted as unaccounted,
)

CRONTAB = "xccdf_org.ssgproject.content_rule_file_permissions_crontab"
SECOND_RULE = "xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd"
ROOT_LOGIN = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"


def plan(*rules: tuple[str, str]) -> dict[str, object]:
    return {"rules": [{"rule_id": rule_id, "action": action} for rule_id, action in rules]}


def result(rule_id: str, action: str) -> dict[str, object]:
    return {"rule_id": rule_id, "action": action, "status": "applied", "changed": True}


def test_the_filter_is_registered() -> None:
    filters = unaccounted.FilterModule().filters()
    assert filters == {"remediation_unaccounted": unaccounted.remediation_unaccounted}


def test_a_complete_set_of_results_is_accounted_for() -> None:
    work = plan((CRONTAB, "apply"), (SECOND_RULE, "cleanup"), (ROOT_LOGIN, "skip"))
    results = [result(SECOND_RULE, "cleanup"), result(CRONTAB, "apply")]
    assert unaccounted.remediation_unaccounted(results, work) == []


def test_no_work_and_no_results_is_accounted_for() -> None:
    work = plan((CRONTAB, "skip"), (SECOND_RULE, "none"), (ROOT_LOGIN, "manual"))
    assert unaccounted.remediation_unaccounted([], work) == []


def test_a_skipped_family_task_is_reported() -> None:
    work = plan((CRONTAB, "cleanup"), (SECOND_RULE, "apply"))
    assert unaccounted.remediation_unaccounted([], work) == [
        f"{CRONTAB}: planned cleanup but no family task reported a result; was a task skipped?",
        f"{SECOND_RULE}: planned apply but no family task reported a result; was a task skipped?",
    ]


def test_a_result_for_the_wrong_action_is_reported_twice() -> None:
    work = plan((CRONTAB, "cleanup"))
    assert unaccounted.remediation_unaccounted([result(CRONTAB, "apply")], work) == [
        f"{CRONTAB}: planned cleanup but no family task reported a result; was a task skipped?",
        f"{CRONTAB}: a result for apply that the plan does not contain",
    ]


def test_duplicate_results_are_reported() -> None:
    work = plan((CRONTAB, "apply"))
    results = [result(CRONTAB, "apply"), result(CRONTAB, "apply")]
    assert unaccounted.remediation_unaccounted(results, work) == [
        f"{CRONTAB}: 2 results for apply, expected exactly one"
    ]


def test_results_for_unplanned_or_skipped_rules_are_reported() -> None:
    work = plan((ROOT_LOGIN, "skip"))
    results = [result(ROOT_LOGIN, "apply"), result(ROOT_LOGIN, "apply")]
    assert unaccounted.remediation_unaccounted(results, work) == [
        f"{ROOT_LOGIN}: a result for apply that the plan does not contain"
    ]


def test_messages_are_bounded() -> None:
    work = plan(*[(f"{CRONTAB}_{index}", "apply") for index in range(150)])
    assert len(unaccounted.remediation_unaccounted([], work)) == unaccounted.MAX_MESSAGES


@pytest.mark.parametrize(
    "work", [None, "plan", {}, {"rules": "x"}, {"rules": ["x"]}, {"rules": [{"rule_id": CRONTAB}]}]
)
def test_an_invalid_plan_is_reported(work: object) -> None:
    assert unaccounted.remediation_unaccounted([], work) == [
        "the plan must hold a list of rules with rule_id and action"
    ]


@pytest.mark.parametrize(
    "results", [None, "results", [3], [{"rule_id": CRONTAB}], [{"rule_id": 1, "action": "apply"}]]
)
def test_invalid_results_are_reported(results: object) -> None:
    assert unaccounted.remediation_unaccounted(results, plan((CRONTAB, "apply"))) == [
        "the results must be a list of mappings with rule_id and action"
    ]
