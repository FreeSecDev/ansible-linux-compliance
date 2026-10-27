"""A real OpenSCAP STIG-profile scan exported as STIG checklists through the mapping (FREES-146).

The CI-only OpenSCAP image (``extensions/ci/oscap/Containerfile``) has the pinned
``openscap-scanner`` on the same pinned Ubuntu 24.04 base as the SCC image. The driver
scans that container with the ``compliance_scan`` module, ``backend: openscap`` and the
ComplianceAsCode STIG profile of the pinned, digest-verified Ubuntu 24.04 stream, for the
same host name as the real SCC scan of ``test_scc_integration.py``. Both containers run
without a network.

The scan runs then go read-only into the SCC image, where the reporting command exports
the OpenSCAP run as CKL and CKLB through ``content/stig-mapping.json``, with the DISA
stream that SCC ships as ``--checklist-content``: the DISA text never leaves the
container and is never committed. ``checklist_check.py mapped`` reads the files back and
derives every entry's status independently from the findings and the mapping, and the
reporting command compares the OpenSCAP run with the SCC run by DISA STIG rule. This test
asserts:

- the OpenSCAP run is completed and covers every rule of the STIG profile;
- the checklist has one entry per DISA rule, with DISA group IDs, titles and CCIs, mode
  0600 in a 0700 directory, and no entry whose status differs from the aggregation of its
  mapped findings;
- every mapped finding is exported and every DISA rule is either mapped or Not Reviewed
  for lack of a ComplianceAsCode check;
- the comparison covers every DISA rule, its SCC side has the statuses of the SCC
  checklist, and agreements and disagreements add up.
"""

from __future__ import annotations

import json
from typing import cast

import pytest

from tests.system.scc import harness
from tools.content import fetch_content

DATASTREAM = "ubuntu2404"
OSCAP_PROFILE = "xccdf_org.ssgproject.content_profile_stig"
OSCAP_PROFILE_RULES = 239
DISA_RULES = 194
STATUSES = ("NotAFinding", "Open", "Not_Applicable", "Not_Reviewed")


def _stream() -> tuple[str, str]:
    manifest = fetch_content.load_manifest(harness.REPOSITORY_ROOT / "content" / "manifest.yml")
    stream = next(item for item in manifest.datastreams if item.name == DATASTREAM)
    local = harness.REPOSITORY_ROOT / "build" / "content" / stream.file_name
    if not local.is_file():
        pytest.fail(f"pinned content {local} is missing; run make scc-integration")
    return f"{harness.SOURCE_MOUNT}/build/content/{stream.file_name}", stream.sha256


@pytest.fixture(scope="module")
def oscap_report() -> dict[str, object]:
    image = harness.image(harness.OSCAP_IMAGE_VARIABLE)
    content, digest = _stream()
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
            "oscap-scan",
            "--repository",
            harness.SOURCE_MOUNT,
            "--site-packages",
            harness.SITE_MOUNT,
            "--content",
            content,
            "--sha256",
            digest,
        ]
    )
    return harness.driver_report(output)


@pytest.fixture(scope="module")
def export_report(
    oscap_report: dict[str, object], tmp_path_factory: pytest.TempPathFactory
) -> dict[str, object]:
    scc_report = harness.scc_scan_report(harness.image())
    oscap_scan = cast("dict[str, object]", oscap_report["scan"])
    scc_scan = cast("dict[str, object]", scc_report["scan"])
    work = tmp_path_factory.mktemp("oscap-export")
    for name, scan in (("oscap-scan-run.json", oscap_scan), ("scc-scan-run.json", scc_scan)):
        (work / name).write_text(json.dumps(scan["scan_run"], sort_keys=True), encoding="utf-8")
    output = harness.run(
        [
            "run",
            "--rm",
            "--network",
            "none",
            *harness.hardening(),
            *harness.python_mounts(),
            "--volume",
            f"{work}:/work:ro",
            "--entrypoint",
            harness.interpreter(),
            harness.image(),
            "-s",
            harness.DRIVER,
            "oscap-export",
            "--repository",
            harness.SOURCE_MOUNT,
            "--site-packages",
            harness.SITE_MOUNT,
            "--content",
            f"{harness.CONTENT_DIRECTORY}/{harness.pin('SCC_CONTENT_FILE')}",
            "--work",
            "/work",
        ]
    )
    report = harness.driver_report(output)
    report["scc_statuses"] = cast("dict[str, dict[str, object]]", scc_report["checklists"])[
        "stream"
    ].get("statuses")
    return report


def test_a_real_openscap_stig_scan_completes(oscap_report: dict[str, object]) -> None:
    result = cast("dict[str, object]", oscap_report["scan"])
    assert result["_returncode"] == 0, result.get("msg")
    assert result["run_status"] == "completed", result.get("msg")
    run = cast("dict[str, object]", result["scan_run"])
    assert cast("dict[str, str]", run["scanner"])["name"] == "openscap"
    assert run["profile_id"] == OSCAP_PROFILE
    findings = cast("list[dict[str, object]]", run["findings"])
    assert len({finding["rule_id"] for finding in findings}) == OSCAP_PROFILE_RULES
    outcomes: dict[str, int] = {}
    for finding in findings:
        outcome = cast("str", finding["outcome"])
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    harness.report_line("openscap stig outcomes", outcomes)


def test_the_openscap_run_exports_honest_checklists_through_the_mapping(
    export_report: dict[str, object],
) -> None:
    report = export_report
    assert report["returncode"] == 0, report["stderr"]
    assert report["check_returncode"] == 0, report["check_stderr"]
    assert len(cast("list[str]", report["files"])) == 2
    assert report["modes"] == [0o600]
    assert report["directory_mode"] == 0o700
    assert report["entries"] == report["cklb_entries"] == DISA_RULES
    assert report["mismatches"] == []
    assert report["vuln_numbers"] == DISA_RULES
    assert report["titled"] == DISA_RULES
    assert report["with_cci"] == DISA_RULES
    assert report["host_name"] == "scc-integration"
    assert report["findings"] == OSCAP_PROFILE_RULES
    counts = {key: value for key, value in report.items() if isinstance(value, int)}
    assert counts["mapped_entries"] + counts["no_check_entries"] == DISA_RULES
    assert counts["exported_findings"] + counts["unexported_findings"] == OSCAP_PROFILE_RULES
    statuses = cast("dict[str, int]", report["statuses"])
    assert set(statuses) <= set(STATUSES)
    assert sum(statuses.values()) == DISA_RULES
    assert statuses.get("Not_Reviewed", 0) >= counts["no_check_entries"]
    harness.report_line(
        "openscap checklist",
        {
            key: report[key]
            for key in (
                "statuses",
                "mapped_stig_ids",
                "mapped_entries",
                "no_check_entries",
                "exported_findings",
                "unexported_findings",
                "outcomes",
            )
        },
    )


def test_the_comparison_with_the_scc_run_adds_up(export_report: dict[str, object]) -> None:
    comparison = cast("dict[str, object]", export_report["comparison"])
    assert comparison["returncode"] == 0, comparison["stderr"]
    assert comparison["comparisons"] == 1
    assert comparison["host"] == "scc-integration"
    assert comparison["rules"] == DISA_RULES
    agree = cast("int", comparison["agree"])
    disagree = cast("int", comparison["disagree"])
    assert agree + disagree == DISA_RULES
    assert comparison["mode"] == 0o600
    sides = cast("dict[str, dict[str, int]]", comparison["statuses"])
    scc = {key: value for key, value in sides["disa"].items() if value}
    assert scc == export_report["scc_statuses"]
    assert {key: value for key, value in sides["compliance_as_code"].items() if value} == (
        export_report["statuses"]
    )
    by_status = cast("dict[str, int]", comparison["disagreements_by_status"])
    assert sum(by_status.values()) == disagree
    harness.report_line(
        "scc and openscap by stig rule",
        {"agree": agree, "disagree": disagree, "disagreements_by_status": by_status},
    )
