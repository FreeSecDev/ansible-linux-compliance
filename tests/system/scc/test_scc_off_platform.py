"""A real off-platform SCC scan of Ubuntu 26.04 with the 24.04 benchmark (FREES-161).

The image is the CI-only SCC image built on the pinned Ubuntu 26.04 base
(``extensions/ci/scc/Containerfile.ubuntu2604``). The container has no network.
The driver runs the module file for a 26.04 host twice: without the opt-in, which
must be refused before anything runs, and with ``allow_off_platform_benchmark``.
This test asserts:

- the image really is Ubuntu 26.04;
- without the opt-in the scan is refused (``invalid_request``);
- with the opt-in the run and every finding carry the off-platform marker, the scan
  run has schema 1.1, and the run is never ``completed`` as a clean result: SCC
  5.15 judges the 24.04 stream not applicable to 26.04 by its platform check and
  reports its rules ``notapplicable``, so the backend fails the run with every rule
  ``error`` (ADR 0019, amendment of FREES-161);
- SCC's own results stay in the evidence, and the outcomes that SCC wrote there
  are mostly ``notapplicable``, which is what the 24.04 benchmark's applicability
  checks should say about a 26.04 host;
- SCC's state changes stay within the accepted residual of ADR 0019.
"""

from __future__ import annotations

import re
from typing import cast

import pytest

from tests.system.scc import harness
from tests.system.scc.test_scc_integration import PROFILE_RULES, RESIDUAL

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


def test_an_opted_in_scan_is_marked_and_never_reads_as_clean(
    off_platform_report: dict[str, object],
) -> None:
    result = cast("dict[str, object]", off_platform_report["scan"])
    kept = cast("dict[str, int]", off_platform_report["kept_outcomes"])
    harness.report_line("off-platform run", {"run_status": result["run_status"], "kept": kept})
    run = cast("dict[str, object]", result["scan_run"])
    assert run["schema_version"] == "1.1"
    assert run["off_platform"] == MARKER
    assert run["scanner"] == {"name": "scc", "version": harness.pin("SCC_VERSION")}
    findings = cast("list[dict[str, object]]", run["findings"])
    assert len(findings) == PROFILE_RULES
    assert all(finding["off_platform"] == MARKER for finding in findings)
    assert result["run_status"] == "failed"
    assert {finding["outcome"] for finding in findings} == {"error"}
    message = cast("str", run["error_message"])
    assert re.search(r"[0-9]+ of 194 expected rules as notapplicable, more than 50 %", message)
    assert "do not fit this ubuntu 26.04 host" in message
    assert sum(kept.values()) == PROFILE_RULES
    assert kept.get("notapplicable", 0) * 100 > THRESHOLD_PERCENT * PROFILE_RULES
    assert kept.get("pass", 0) == 0


def test_the_evidence_keeps_scc_results(off_platform_report: dict[str, object]) -> None:
    result = cast("dict[str, object]", off_platform_report["scan"])
    assert result["evidence_written"] is True
    evidence = cast("dict[str, object]", result["evidence"])
    files = cast("list[dict[str, object]]", evidence["files"])
    names = sorted(str(item["path"]).rsplit("/", 1)[1] for item in files)
    assert names == ["results-arf.xml", "results.xml", "scan-run.json"]


def test_the_off_platform_scan_changes_only_the_accepted_residual(
    off_platform_report: dict[str, object],
) -> None:
    state = cast("dict[str, list[str]]", off_platform_report["state"])
    harness.report_line("off-platform state changes", state)
    assert state["removed"] == []
    for path in state["added"] + state["changed"]:
        assert any(re.fullmatch(pattern, path) for pattern in RESIDUAL), path
