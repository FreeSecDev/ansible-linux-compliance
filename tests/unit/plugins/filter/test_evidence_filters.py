from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    evidence_documents,
    evidence_host_files,
    evidence_plan,
    evidence_written,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
    evidence_check,
    model,
)

HOST = "web01"
RUN_ID = "run-1"
DIRECTORY = f"/var/lib/freesecdev/linux_compliance/evidence/{RUN_ID}"
UID = 1000
DISABLED = False


def scan_run() -> model.ScanRun:
    started = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(model.TIMESTAMP_FORMAT)
    finding = model.Finding(
        rule_id="xccdf_org.ssgproject.content_rule_package_telnet_removed",
        outcome=model.Outcome.PASS,
        evaluated_outcome=model.Outcome.PASS,
        severity=model.Severity.LOW,
        message=None,
        evidence=(),
        exception=model.ExceptionStatus.none(),
        remediation=None,
        disabled_by=None,
        flags=(),
    )
    return model.ScanRun(
        run_id=RUN_ID,
        started_at=started,
        finished_at=started,
        host=model.HostIdentity(HOST, "ubuntu", "24.04", "x86_64", None),
        scanner=model.ScannerInfo("openscap", "1.3.9"),
        content=model.Provenance("ssg-ubuntu2404-ds.xml", "0.1.82", "b" * 64),
        benchmark_id="xccdf_org.ssgproject.content_benchmark_UBUNTU2404",
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        status=model.ScanStatus.COMPLETED,
        error_message=None,
        findings=(finding,),
    )


SCAN_RUN = (model.dumps(scan_run()) + "\n").encode("utf-8")


def audited() -> dict[str, object]:
    return {
        "evidence": {
            "directory": DIRECTORY,
            "files": [
                {
                    "kind": "scan_run",
                    "path": f"{DIRECTORY}/scan-run.json",
                    "sha256": hashlib.sha256(SCAN_RUN).hexdigest(),
                    "size": len(SCAN_RUN),
                }
            ],
        },
        "evidence_written": True,
        "gate": {
            "after_waivers": False,
            "basis": "raw",
            "counted": True,
            "deferred": False,
            "enabled": True,
            "enforced": True,
            "error": 0,
            "fail": 1,
            "waived": 0,
        },
        "exceptions": {
            "applied": False,
            "file": None,
            "source_sha256": None,
            "status": "not_requested",
        },
        "run_id": RUN_ID,
        "run_status": "completed",
        "scan_run": json.loads(SCAN_RUN),
    }


def stat_of(data: bytes) -> dict[str, object]:
    return {
        "checksum": hashlib.sha256(data).hexdigest(),
        "isreg": True,
        "islnk": False,
        "mode": "0600",
        "size": len(data),
        "uid": UID,
    }


def test_the_filter_plugins_expose_their_filters() -> None:
    assert evidence_plan.FilterModule().filters() == {"evidence_plan": evidence_plan.evidence_plan}
    assert evidence_documents.FilterModule().filters() == {
        "evidence_documents": evidence_documents.evidence_documents
    }
    assert evidence_written.FilterModule().filters() == {
        "evidence_written": evidence_written.evidence_written
    }
    assert evidence_host_files.FilterModule().filters() == {
        "evidence_host_files": evidence_host_files.evidence_host_files
    }


def test_the_filters_plan_build_and_check_a_bundle() -> None:
    plan = evidence_plan.evidence_plan(audited(), HOST, DISABLED)
    assert plan["directory"] == f"{HOST}/{RUN_ID}"
    on_host = {
        "raw/scan-run.json": {"exists": True, "isreg": True, "islnk": False, "size": len(SCAN_RUN)}
    }
    assert evidence_host_files.evidence_host_files(audited(), HOST, DISABLED, on_host) == [
        "raw/scan-run.json"
    ]
    collected = {
        "collection_version": "0.1.0",
        "controller_uid": UID,
        "exceptions_text": None,
        "host": HOST,
        "include_arf": DISABLED,
        "machine_id": None,
        "observed": {"raw/scan-run.json": stat_of(SCAN_RUN)},
        "scan_run_text": SCAN_RUN.decode("utf-8"),
        "stale": {},
    }
    result = evidence_documents.evidence_documents(audited(), collected)
    documents = cast("dict[str, str]", result["documents"])
    contents = {
        "raw/scan-run.json": SCAN_RUN,
        "SHA256SUMS": documents["SHA256SUMS"].encode("utf-8"),
    }
    observed = {path: stat_of(data) for path, data in contents.items()}
    assert evidence_written.evidence_written(result["expected"], observed, UID) == [
        "SHA256SUMS",
        "raw/scan-run.json",
    ]
    contents["bundle.json"] = cast("str", result["manifest"]).encode("utf-8")
    assert evidence_check.check_bundle(contents).evaluation is None


def test_the_document_filter_refuses_an_incomplete_collected_record() -> None:
    with pytest.raises(evidence.EvidenceError, match="missing keys"):
        evidence_documents.evidence_documents(audited(), {"host": HOST})
