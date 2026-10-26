"""A real SCC scan through ``compliance_scan`` in the CI-only SCC image (FREES-145).

The container has no network. The driver runs the module file with
``backend: scc`` against the stream bundled with the pinned SCC release, once for
real and once in check mode, and records the SHA-256 of every file below
``/opt/scc`` and ``/root`` before and after. This test asserts:

- both runs are ``completed``, by scanner ``scc`` with the pinned version, on the
  pinned stream, and the normalized findings cover every rule of the profile;
- the outcomes are honest: SCC's ``unknown`` becomes ``error`` with a message,
  ``notchecked`` stays ``notchecked``, and nothing else becomes ``pass``;
- the evidence holds the XCCDF and ARF results, and SCC's own tree is not
  recorded;
- the installed ``options.xml``, the installed content and the binaries are
  unchanged, ``/root`` is unchanged, and the only changes to SCC's state are the
  accepted residual of ADR 0019 (its content databases and one session
  database per scan in ``/opt/scc/Local``).
"""

from __future__ import annotations

import re
from typing import cast

import pytest

from tests.system.scc import harness

PROFILE = "xccdf_mil.disa.stig_profile_MAC-1_Classified"
BENCHMARK = "xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG"
PROFILE_RULES = 194
RESIDUAL = (
    r"/opt/scc/Resources/Content/DB/SCC_SCAP12_Content\.db",
    r"/opt/scc/Resources/Content/DB/SCC_SCAP12_Content\.db\.archive",
    r"/opt/scc/Resources/Content/DB/ocil\.db",
    r"/opt/scc/Local",
    r"/opt/scc/Local/[A-Za-z0-9]+_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}-[0-9.]+\.db",
)
HONEST = {"pass", "fail", "notapplicable", "notchecked", "error"}


@pytest.fixture(scope="module")
def scan_report() -> dict[str, object]:
    image = harness.image()
    output = harness.run(
        [
            "run",
            "--rm",
            "--network",
            "none",
            *harness.hardening(),
            *harness.python_mounts(),
            "--entrypoint",
            harness.interpreter(),
            image,
            "-s",
            harness.DRIVER,
            "scan",
            "--repository",
            harness.SOURCE_MOUNT,
            "--site-packages",
            harness.SITE_MOUNT,
            "--content",
            f"{harness.CONTENT_DIRECTORY}/{harness.pin('SCC_CONTENT_FILE')}",
            "--sha256",
            harness.pin("SCC_CONTENT_SHA256"),
        ]
    )
    return harness.driver_report(output)


def _check_run(result: dict[str, object]) -> list[dict[str, object]]:
    assert result["_returncode"] == 0, result.get("msg")
    assert result["run_status"] == "completed", result.get("msg")
    assert result["changed"] is False
    run = cast("dict[str, object]", result["scan_run"])
    assert run["status"] == "completed"
    assert run["error_message"] is None
    assert run["scanner"] == {"name": "scc", "version": harness.pin("SCC_VERSION")}
    assert run["benchmark_id"] == BENCHMARK
    assert run["profile_id"] == PROFILE
    content = cast("dict[str, str]", run["content"])
    assert content["content_sha256"] == harness.pin("SCC_CONTENT_SHA256")
    assert content["source"] == harness.pin("SCC_CONTENT_FILE")
    assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z", cast("str", run["started_at"]))
    findings = cast("list[dict[str, object]]", run["findings"])
    assert len(findings) == PROFILE_RULES
    assert len({finding["rule_id"] for finding in findings}) == PROFILE_RULES
    return findings


def test_a_real_scc_scan_yields_honest_normalized_findings(scan_report: dict[str, object]) -> None:
    report = scan_report
    scan = cast("dict[str, object]", report["scan"])
    findings = _check_run(scan)
    _check_run(cast("dict[str, object]", report["check_mode"]))
    outcomes = [cast("str", finding["outcome"]) for finding in findings]
    counts = {outcome: outcomes.count(outcome) for outcome in sorted(set(outcomes))}
    harness.report_line("outcomes", counts)
    assert set(outcomes) <= HONEST
    assert counts.get("pass", 0) > 0
    assert counts.get("fail", 0) > 0
    for finding in findings:
        if finding["outcome"] == "error":
            assert finding["message"], finding
        assert finding["outcome"] == finding["evaluated_outcome"]
    summary = cast("dict[str, object]", scan["summary"])
    assert summary["run_status"] == "completed"
    assert summary["total"] == PROFILE_RULES
    evidence = cast("dict[str, object]", scan["evidence"])
    files = cast("list[dict[str, object]]", evidence["files"])
    names = sorted(str(item["path"]).rsplit("/", 1)[1] for item in files)
    assert names == ["results-arf.xml", "results.xml", "scan-run.json"]
    skipped = cast("list[dict[str, object]]", evidence["skipped"])
    assert [str(item["path"]).rsplit("/", 1)[1] for item in skipped] == ["scc"]
    check = cast("dict[str, object]", report["check_mode"])
    assert check["evidence_written"] is False


def test_scc_leaves_its_configuration_content_and_binaries_unchanged(
    scan_report: dict[str, object],
) -> None:
    report = scan_report
    state = cast("dict[str, list[str]]", report["state"])
    harness.report_line("state changes", state)
    assert state["removed"] == []
    for path in state["added"] + state["changed"]:
        assert any(re.fullmatch(pattern, path) for pattern in RESIDUAL), path
    touched = state["added"] + state["changed"]
    assert "/opt/scc/options.xml" not in touched
    assert not any(path.startswith("/root") for path in touched)
    assert not any(path.startswith("/opt/scc/Resources/Content/SCAP12_Content") for path in touched)
    assert not any(path.startswith(("/opt/scc/bin", "/opt/scc/lib64")) for path in touched)
    assert "/opt/scc/cscc" not in touched
