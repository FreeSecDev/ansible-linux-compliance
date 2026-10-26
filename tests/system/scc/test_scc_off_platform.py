"""A real off-platform SCC scan of Ubuntu 26.04 with the 24.04 benchmark (FREES-161).

The image is the CI-only SCC image built on the pinned Ubuntu 26.04 base
(``extensions/ci/scc/Containerfile.ubuntu2604``). The container has no network.
The driver runs the module file for a 26.04 host without the opt-in, for a host that
claims 24.04, and with ``allow_off_platform_benchmark``, and then the SCC backend
itself for a host self-asserted as 24.04. This test asserts:

- the image really is Ubuntu 26.04;
- without the opt-in the scan is refused (``invalid_request``);
- a host that claims 24.04 is refused by the module's ``/etc/os-release`` check
  (``host_mismatch``);
- below that check, an unmarked backend scan of the host self-asserted as 24.04 is
  still stopped by SCC's own CPE platform test: SCC writes no results, so the run
  is ``failed`` with every rule ``error`` and no marker. That is the backstop that
  the opt-in must not weaken;
- with the opt-in, the per-run options set SCC's ``ignoreCPEOVALResults`` and the
  backend's confirmation requires SCC's dump to show it as ``1``; SCC's scan log
  says that it ignored the CPE-OVAL platform test of the 24.04 stream;
- the run completes with real results: honest outcomes only, both ``pass`` and
  ``fail``, and at most 50 % ``notapplicable``, the same as SCC's own XCCDF
  results that stay in the evidence;
- the run and every finding carry the off-platform marker and the scan run has
  schema 1.1 (ADR 0019, amendments of FREES-161);
- SCC's state changes stay within the accepted residual of ADR 0019.
"""

from __future__ import annotations

import re
from typing import cast

import pytest

from tests.system.scc import harness
from tests.system.scc.test_scc_integration import HONEST, PROFILE_RULES, RESIDUAL

MARKER = {
    "benchmark_platform": {"distribution_id": "ubuntu", "distribution_version": "24.04"},
    "target_platform": {"distribution_id": "ubuntu", "distribution_version": "26.04"},
}
THRESHOLD_PERCENT = 50


@pytest.fixture(scope="module")
def off_platform_report() -> dict[str, object]:
    image = harness.image(harness.IMAGE_UBUNTU2604_VARIABLE)
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
            "off-platform",
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


def test_the_image_is_ubuntu_2604(off_platform_report: dict[str, object]) -> None:
    assert off_platform_report["version_id"] == "26.04"


def test_a_2604_host_is_refused_without_the_opt_in(off_platform_report: dict[str, object]) -> None:
    refused = cast("dict[str, object]", off_platform_report["refused"])
    assert refused["_returncode"] != 0
    assert refused["error_type"] == "invalid_request"
    assert "unless allow_off_platform_benchmark is true" in cast("str", refused["msg"])


def test_a_host_that_claims_2404_is_refused_by_its_release(
    off_platform_report: dict[str, object],
) -> None:
    mismatch = cast("dict[str, object]", off_platform_report["mismatch"])
    assert mismatch["_returncode"] != 0
    assert mismatch["error_type"] == "host_mismatch"
    assert "VERSION_ID '26.04'" in cast("str", mismatch["msg"])


def test_scc_platform_test_still_stops_an_unmarked_scan_of_2604(
    off_platform_report: dict[str, object],
) -> None:
    backstop = cast("dict[str, object]", off_platform_report["backstop"])
    harness.report_line("backstop", backstop)
    assert backstop["status"] == "failed"
    assert backstop["off_platform"] is False
    assert backstop["outcomes"] == ["error"]
    assert "SCC wrote 0 XCCDF results files" in cast("str", backstop["error_message"])
    assert backstop["rejected_by_platform_test"] is True


def test_an_opted_in_scan_yields_real_marked_results(
    off_platform_report: dict[str, object],
) -> None:
    result = cast("dict[str, object]", off_platform_report["scan"])
    kept = cast("dict[str, int]", off_platform_report["kept_outcomes"])
    run = cast("dict[str, object]", result["scan_run"])
    findings = cast("list[dict[str, object]]", run["findings"])
    outcomes = [cast("str", finding["outcome"]) for finding in findings]
    counts = {outcome: outcomes.count(outcome) for outcome in sorted(set(outcomes))}
    harness.report_line(
        "off-platform run", {"run_status": result["run_status"], "outcomes": counts, "kept": kept}
    )
    assert off_platform_report["ignored_platform_test"] is True
    assert result["run_status"] == "completed", run["error_message"]
    assert run["error_message"] is None
    assert run["schema_version"] == "1.1"
    assert run["off_platform"] == MARKER
    assert run["scanner"] == {"name": "scc", "version": harness.pin("SCC_VERSION")}
    assert len(findings) == PROFILE_RULES
    assert all(finding["off_platform"] == MARKER for finding in findings)
    assert set(outcomes) <= HONEST
    assert counts.get("pass", 0) > 0
    assert counts.get("fail", 0) > 0
    assert counts.get("notapplicable", 0) * 100 <= THRESHOLD_PERCENT * PROFILE_RULES
    assert sum(kept.values()) == PROFILE_RULES
    for outcome in ("pass", "fail", "notapplicable"):
        assert kept.get(outcome, 0) == counts.get(outcome, 0), outcome


def test_the_evidence_keeps_scc_results(off_platform_report: dict[str, object]) -> None:
    result = cast("dict[str, object]", off_platform_report["scan"])
    assert result["evidence_written"] is True
    evidence = cast("dict[str, object]", result["evidence"])
    files = cast("list[dict[str, object]]", evidence["files"])
    names = sorted(str(item["path"]).rsplit("/", 1)[1] for item in files)
    assert names == ["results-arf.off-platform.xml", "results.off-platform.xml", "scan-run.json"]


def test_the_off_platform_scan_changes_only_the_accepted_residual(
    off_platform_report: dict[str, object],
) -> None:
    state = cast("dict[str, list[str]]", off_platform_report["state"])
    harness.report_line("off-platform state changes", state)
    assert state["removed"] == []
    for path in state["added"] + state["changed"]:
        assert any(re.fullmatch(pattern, path) for pattern in RESIDUAL), path
