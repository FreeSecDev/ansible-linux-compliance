from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
)
from tools.reporting import report
from tools.reporting.common import dumps
from tools.reporting.report import ReportInputs, RunMetadata, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA = json.loads(
    (Path(report.__file__).parent / "schema" / "report-v1.json").read_text(encoding="utf-8")
)
NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.UTC)
VALIDATOR: Any = Draft202012Validator(SCHEMA)


def exceptions_file(kit: Any) -> str:
    rows: list[str] = []
    for identifier, rule, expires in (
        ("EXC-ACTIVE", "waived_rule", "2027-01-31"),
        ("EXC-EXPIRED", "expired_rule", "2026-10-20"),
        ("EXC-ERROR", "error_rule", "2027-01-31"),
    ):
        rows.append(
            f"  - id: {identifier}\n"
            f"    rule: {kit.RULE_PREFIX}{rule}\n"
            "    framework: cis\n"
            "    scope:\n"
            f"      hosts: [{kit.HOST.hostname}]\n"
            "    justification: Accepted while the replacement is built.\n"
            "    owner: platform-team\n"
            "    approval:\n"
            "      approver: security-lead\n"
            "      date: 2026-10-02\n"
            "    created: 2026-10-01\n"
            f"    expires: {expires}\n"
            "    risk: medium\n"
        )
    return "---\nschema_version: '1.0'\nexceptions:\n" + "".join(rows)


def test_applied_exceptions_appear_in_the_report(kit: Any, write_run: Callable[..., Path]) -> None:
    run = kit.scan_run(
        (
            kit.finding("waived_rule", model.Outcome.FAIL),
            kit.finding("expired_rule", model.Outcome.FAIL),
            kit.finding("error_rule", model.Outcome.ERROR),
            kit.finding("passing_rule"),
        )
    )
    parsed = exceptions.parse_exceptions(exceptions_file(kit), NOW)
    target = exceptions.Target(kit.HOST.hostname, ())
    evaluation = exceptions.evaluate_run(run, parsed, target)
    path = write_run("evaluated.json", evaluation.run)
    inputs = ReportInputs(scope=Scope.SINGLE_HOST, metadata=RunMetadata(), scan_run=(path,))
    document = json.loads(dumps(report.build_report(inputs)))
    assert VALIDATOR.is_valid(document)
    section = document["sections"]["compliance"]
    summary = section["summary"]
    assert summary["counts"]["waived"] == 1
    assert summary["counts"]["fail"] == 1
    assert summary["counts"]["error"] == 1
    assert summary["counts"]["pass"] == 1
    assert summary["expired_waivers"] == 1
    assert summary["compliance_percent"] == 25.0
    embedded = section["items"][0]["data"]["scan_run"]["findings"]
    exceptions_by_rule = {
        item["rule_id"].removeprefix(kit.RULE_PREFIX): item["exception"] for item in embedded
    }
    assert exceptions_by_rule["waived_rule"]["state"] == "active"
    assert exceptions_by_rule["waived_rule"]["exception_id"] == "EXC-ACTIVE"
    assert exceptions_by_rule["expired_rule"]["state"] == "expired"
    assert exceptions_by_rule["expired_rule"]["exception_id"] == "EXC-EXPIRED"
    assert exceptions_by_rule["error_rule"]["state"] == "none"
    statuses = {result.record.exception_id: result.status.value for result in evaluation.results}
    assert statuses == {
        "EXC-ACTIVE": "waived",
        "EXC-ERROR": "not_failing",
        "EXC-EXPIRED": "expired",
    }
