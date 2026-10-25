"""Real ``oscap xccdf eval`` runs against the pinned Ubuntu 24.04 datastream.

These tests run the audit orchestration with the production OpenSCAP backend and
the real process helper, so ``/usr/bin/oscap`` must be installed and root-owned.
The scan only reads the host. ``make test-oscap-integration`` fetches and verifies
the pinned content first. Locally the tests skip when ``oscap`` is absent; CI sets
``FREESECDEV_REQUIRE_OSCAP=1``, which turns every skip into a failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    model,
    openscap,
)
from tools.content import fetch_content as fetch

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTENT_DIRECTORY = Path(
    os.environ.get("FREESECDEV_CONTENT_DIR", str(REPOSITORY_ROOT / "build" / "content"))
).resolve()
REQUIRE_OSCAP = os.environ.get("FREESECDEV_REQUIRE_OSCAP") == "1"
OSCAP = Path("/usr/bin/oscap")
DATASTREAM_NAME = "ubuntu2404"
PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"
RULE = "xccdf_org.ssgproject.content_rule_"
DISABLED = (
    RULE + "file_permissions_unauthorized_world_writable",
    RULE + "file_permissions_ungroupowned",
    RULE + "no_files_unowned_by_user",
)
SCAN_TIMEOUT_SECONDS = 3600.0
MISSING_RESULT = "the results contain no rule-result for this rule"
HOST = model.HostIdentity("oscap-integration", "ubuntu", "24.04", "x86_64", None)
UID = os.getuid()


def report(label: str, data: object) -> None:
    sys.stdout.write(f"\n[oscap-integration] {label}: {json.dumps(data, sort_keys=True)}\n")
    sys.stdout.flush()


def golden_rule_count() -> int:
    document = cast(
        "dict[str, Any]",
        yaml.safe_load(
            (REPOSITORY_ROOT / "tests" / "fixtures" / "catalog" / "golden-rules.yml").read_text(
                encoding="utf-8"
            )
        ),
    )
    for stream in document["datastreams"]:
        if stream["name"] == DATASTREAM_NAME:
            for profile in stream["profiles"]:
                if profile["id"] == PROFILE:
                    return int(profile["rule_count"])
    pytest.fail("the golden file has no entry for the profile")


def pinned_datastream() -> tuple[Path, str]:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    stream = next(item for item in manifest.datastreams if item.name == DATASTREAM_NAME)
    return CONTENT_DIRECTORY / stream.file_name, stream.sha256


@pytest.fixture(scope="module")
def datastream() -> tuple[Path, str]:
    if not OSCAP.is_file():
        if REQUIRE_OSCAP:
            pytest.fail(f"{OSCAP} is missing but FREESECDEV_REQUIRE_OSCAP=1")
        pytest.skip(f"{OSCAP} is not installed")
    path, digest = pinned_datastream()
    if not path.is_file():
        pytest.fail(f"pinned content {path} is missing; run make test-oscap-integration")
    return path, digest


@pytest.fixture
def output_root(tmp_path: Path) -> Path:
    tmp_path.chmod(0o755)
    root = tmp_path / "evidence"
    root.mkdir(mode=0o700)
    return root


def job(content: tuple[Path, str], root: Path, run_id: str, **fields: Any) -> audit.AuditJob:
    values: dict[str, Any] = {
        "backend": "openscap",
        "content_path": str(content[0]),
        "expected_sha256": content[1],
        "profile_id": PROFILE,
        "output_root": str(root),
        "run_id": run_id,
        "host": HOST,
        "timeout_seconds": SCAN_TIMEOUT_SECONDS,
        "max_result_bytes": 512 * 1024 * 1024,
        "disabled_rules": (),
    }
    values.update(fields)
    return audit.AuditJob(**values)


def run(audit_job: audit.AuditJob, *, check_mode: bool) -> dict[str, Any]:
    started = time.monotonic()
    result = cast(
        "dict[str, Any]", audit.Auditor(owner_uid=UID).run(audit_job, check_mode=check_mode)
    )
    report(
        "scan",
        {
            "check_mode": check_mode,
            "duration_seconds": round(time.monotonic() - started, 1),
            "run_status": result["run_status"],
            "scanner": None if result["scan_run"] is None else result["scan_run"]["scanner"],
            "summary": result["summary"],
            "error_message": None
            if result["scan_run"] is None
            else result["scan_run"]["error_message"],
        },
    )
    return result


def test_the_installed_oscap_is_root_owned(datastream: tuple[Path, str]) -> None:
    assert datastream[0].is_file()
    assert OSCAP.stat().st_uid == 0


def test_a_check_mode_scan_without_tailoring_evaluates_the_whole_profile(
    datastream: tuple[Path, str], output_root: Path
) -> None:
    result = run(job(datastream, output_root, "untailored"), check_mode=True)
    assert result["run_status"] == "completed", result["scan_run"]["error_message"]
    assert result["evidence_written"] is False
    findings = result["scan_run"]["findings"]
    assert len(findings) == golden_rule_count() == 408
    assert result["summary"]["total"] == 408
    assert result["summary"]["disabled"] == 0
    missing = [item["rule_id"] for item in findings if item["message"] == MISSING_RESULT]
    assert missing == []
    assert result["scan_run"]["profile_id"] == PROFILE
    assert result["scan_run"]["content"]["content_sha256"] == datastream[1]
    assert result["scan_run"]["content"]["source"] == datastream[0].name
    assert sorted(output_root.rglob("*")) == []


def test_a_tailored_scan_excludes_the_disabled_rules(
    datastream: tuple[Path, str], output_root: Path
) -> None:
    disabled = audit.parse_disabled_rules([{"rule_id": rule_id} for rule_id in DISABLED])
    result = run(
        job(datastream, output_root, "tailored", disabled_rules=disabled), check_mode=False
    )
    assert result["run_status"] == "completed", result["scan_run"]["error_message"]
    run_dir = output_root / "tailored"
    tailoring = run_dir / "tailoring.xml"
    report("tailoring", tailoring.read_text(encoding="utf-8").splitlines())
    tailoring_sha256 = hashlib.sha256(tailoring.read_bytes()).hexdigest()
    scan_run = result["scan_run"]
    assert scan_run["profile_id"] == PROFILE
    assert scan_run["content"]["source"] == (
        f"{datastream[0].name} tailoring=tailoring.xml tailoring_sha256={tailoring_sha256}"
    )
    evidence = {item["kind"]: item for item in result["evidence"]["files"]}
    assert evidence["tailoring"]["sha256"] == tailoring_sha256
    findings = {item["rule_id"]: item for item in scan_run["findings"]}
    assert len(findings) == golden_rule_count()
    for rule_id in DISABLED:
        assert findings[rule_id]["outcome"] == "disabled"
        assert findings[rule_id]["disabled_by"] == audit.rule_toggle(rule_id)
    enabled = {key: value for key, value in findings.items() if key not in DISABLED}
    assert all(item["outcome"] != "disabled" for item in enabled.values())
    assert [key for key, item in enabled.items() if item["message"] == MISSING_RESULT] == []
    raw = openscap.read_results(str(run_dir / "scan" / "results.xml"), 512 * 1024 * 1024)
    assert raw.profile_id == PROFILE + audit.TAILORED_PROFILE_SUFFIX
    by_rule = {finding.rule_id: finding for finding in raw.findings}
    for rule_id in DISABLED:
        assert model.ResultFlag.NOTSELECTED in by_rule[rule_id].flags
    not_evaluated = [
        rule_id
        for rule_id in enabled
        if rule_id not in by_rule or model.ResultFlag.NOTSELECTED in by_rule[rule_id].flags
    ]
    assert not_evaluated == []
    report(
        "raw results",
        {
            "disabled": dict.fromkeys(DISABLED, "notselected"),
            "evaluated_rules": len(enabled),
            "tailoring_sha256": tailoring_sha256,
        },
    )
    for item in result["evidence"]["files"]:
        assert (Path(item["path"]).stat().st_mode & 0o777) == 0o600
