from __future__ import annotations

import datetime as dt
import hashlib
import json
import stat
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
    exceptions,
    model,
)
from tools.reporting import checklist, checklist_export, checklist_formats, cli, stig_content

if TYPE_CHECKING:
    from pathlib import Path

NOW = dt.datetime(2026, 10, 26, 12, 0, tzinfo=dt.UTC)
UID = 1000


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def gate(run: model.ScanRun) -> dict[str, object]:
    counted = run.status is model.ScanStatus.COMPLETED
    outcomes = [finding.outcome for finding in run.findings]
    return {
        "after_waivers": False,
        "basis": "raw",
        "counted": counted,
        "deferred": False,
        "enabled": True,
        "enforced": True,
        "error": outcomes.count(model.Outcome.ERROR) if counted else None,
        "fail": outcomes.count(model.Outcome.FAIL) if counted else None,
        "waived": 0 if counted else None,
    }


def waivers(run: model.ScanRun, host: str, text: str | None) -> dict[str, object]:
    if text is None:
        return {"applied": False, "status": "not_requested"}
    parsed = exceptions.parse_exceptions(text, NOW)
    evaluation = exceptions.evaluate_run(run, parsed, exceptions.Target(host, ("web",)), NOW)
    return {
        "applied": True,
        "evaluation": evaluation.to_dict(),
        "file": "/srv/compliance/exceptions.yml",
        "source_sha256": sha(text.encode("utf-8")),
        "status": "applied",
    }


def received_files(run: model.ScanRun, results: str | None) -> dict[str, bytes]:
    received = {"raw/scan-run.json": (model.dumps(run) + "\n").encode("utf-8")}
    if results is not None:
        name = "results.off-platform.xml" if run.off_platform else "results.xml"
        received[f"raw/scan/{name}"] = results.encode("utf-8")
    return received


def audited_fact(
    run: model.ScanRun, received: dict[str, bytes], host: str, text: str | None
) -> dict[str, object]:
    directory = f"/var/lib/freesecdev/linux_compliance/evidence/{run.run_id}"
    files = [
        {
            "kind": "scan_run" if path.endswith(".json") else "scanner_output",
            "path": f"{directory}/{path.removeprefix('raw/')}",
            "sha256": sha(data),
            "size": len(data),
        }
        for path, data in received.items()
    ]
    return {
        "evidence": {"directory": directory, "files": files},
        "evidence_written": True,
        "gate": gate(run),
        "exceptions": waivers(run, host, text),
        "run_id": run.run_id,
        "run_status": run.status.value,
        "scan_run": run.to_dict(),
    }


def collected_files(
    run: model.ScanRun, received: dict[str, bytes], host: str, text: str | None
) -> evidence.Collected:
    observed: dict[str, object] = {
        path: {
            "checksum": sha(data),
            "isreg": True,
            "islnk": False,
            "mode": "0600",
            "size": len(data),
            "uid": UID,
        }
        for path, data in received.items()
    }
    return evidence.Collected(
        host=host,
        include_arf=False,
        observed=observed,
        scan_run_text=received["raw/scan-run.json"].decode("utf-8"),
        exceptions_text=text,
        stale={},
        machine_id=run.host.machine_id,
        collection_version="0.1.0",
        controller_uid=UID,
    )


def write_bundle(
    root: Path,
    run: model.ScanRun,
    results: str | None,
    host: str = "web01",
    exceptions_text: str | None = None,
) -> Path:
    received = received_files(run, results)
    fact = audited_fact(run, received, host, exceptions_text)
    collected = collected_files(run, received, host, exceptions_text)
    result = evidence.build_documents(fact, collected, NOW)
    contents = dict(received)
    for path, document in cast("dict[str, str]", result["documents"]).items():
        contents[path] = document.encode("utf-8")
    contents[evidence.MANIFEST_NAME] = cast("str", result["manifest"]).encode("utf-8")
    bundle = root / host / run.run_id
    for path, data in contents.items():
        (bundle / path).parent.mkdir(parents=True, exist_ok=True)
        (bundle / path).write_bytes(data)
    return bundle


def run_cli(tmp_path: Path, *arguments: str) -> int:
    return cli.main(
        [
            "--scope",
            "multi_host",
            "--output",
            str(tmp_path / "report.json"),
            "--export-ckl",
            str(tmp_path / "ckl"),
            "--export-cklb",
            str(tmp_path / "cklb"),
            *arguments,
        ]
    )


def own_results(stig: Any, **options: Any) -> str:
    return cast("str", stig.benchmark_xml(test_result=stig.result_xml(**options)))


def test_a_bundle_exports_both_formats_from_its_own_results(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = write_bundle(tmp_path / "bundles", stig.scan_run(), own_results(stig))
    assert run_cli(tmp_path, "--evidence-bundle", str(bundle)) == 0
    ckl = tmp_path / "ckl" / "web01.example_Synthetic_Linux_STIG.ckl"
    cklb = tmp_path / "cklb" / "web01.example_Synthetic_Linux_STIG.cklb"
    for path in (ckl, cklb):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    statuses = checklist_formats.read_ckl(ckl.read_bytes())
    assert statuses["SV-900001r1_rule"] == "NotAFinding"
    assert statuses["SV-900006r1_rule"] == "Open"
    assert checklist_formats.read_cklb(cklb.read_bytes())["SV-900006r1_rule"] == "open"
    assert "CKL checklist written to" in capsys.readouterr().out
    assert json.loads(cklb.read_text())["target_data"]["ip_address"] == "192.0.2.10, 2001:db8::10"


def test_an_off_platform_bundle_exports_only_not_reviewed(stig: Any, tmp_path: Path) -> None:
    run = stig.scan_run(host=stig.OFF_PLATFORM_HOST, off_platform=stig.OFF_PLATFORM)
    results = own_results(stig, target="web26", fqdn="web26.example")
    bundle = write_bundle(tmp_path / "bundles", run, results, host="web26")
    assert run_cli(tmp_path, "--evidence-bundle", str(bundle)) == 0
    cklb = tmp_path / "cklb" / "web26.example_Synthetic_Linux_STIG.cklb"
    assert set(checklist_formats.read_cklb(cklb.read_bytes()).values()) == {"not_reviewed"}
    ckl = (tmp_path / "ckl" / "web26.example_Synthetic_Linux_STIG.ckl").read_text()
    assert "off-platform: the ubuntu 24.04 benchmark on an ubuntu 26.04 host" in ckl


def test_a_failed_run_without_results_uses_the_supplied_content(stig: Any, tmp_path: Path) -> None:
    findings = tuple(stig.finding(number, model.Outcome.ERROR) for number in (1, 2))
    run = stig.scan_run(findings, status=model.ScanStatus.FAILED, version="unknown")
    bundle = write_bundle(tmp_path / "bundles", run, None)
    content = tmp_path / "content.xml"
    content.write_text(stig.data_stream(stig.benchmark_xml()), encoding="utf-8")
    arguments = ("--evidence-bundle", str(bundle), "--checklist-content", str(content))
    assert run_cli(tmp_path, *arguments) == 0
    cklb = tmp_path / "cklb" / "web01.example_Synthetic_Linux_STIG.cklb"
    assert set(checklist_formats.read_cklb(cklb.read_bytes()).values()) == {"not_reviewed"}


def test_scan_run_json_exports_with_the_supplied_content(stig: Any, tmp_path: Path) -> None:
    run_path = tmp_path / "scan-run.json"
    run_path.write_text(model.dumps(stig.scan_run()), encoding="utf-8")
    content = tmp_path / "content.xml"
    content.write_text(stig.benchmark_xml(), encoding="utf-8")
    assert run_cli(tmp_path, "--scan-run", str(run_path), "--checklist-content", str(content)) == 0
    document = json.loads(
        (tmp_path / "cklb" / "web01.example_Synthetic_Linux_STIG.cklb").read_text()
    )
    assert document["target_data"]["ip_address"] == ""
    assert document["stigs"][0]["rules"][0]["status"] == "not_a_finding"


EXCEPTIONS = """---
schema_version: "1.0"
exceptions:
  - id: EXC-STIG-9
    rule: xccdf_mil.disa.stig_rule_SV-900002r1_rule
    framework: stig
    scope:
      hosts: [web01]
    justification: Synthetic accepted risk for the exporter test.
    owner: platform-team
    approval:
      approver: security-lead
      date: "2026-10-02"
    created: "2026-10-01"
    expires: "2027-01-31"
    risk: low
"""


def test_a_bundle_with_applied_exceptions_exports_the_waiver_as_open(
    stig: Any, tmp_path: Path
) -> None:
    findings = (stig.finding(1, model.Outcome.PASS), stig.finding(2, model.Outcome.FAIL))
    bundle = write_bundle(
        tmp_path / "bundles", stig.scan_run(findings), own_results(stig), exceptions_text=EXCEPTIONS
    )
    reviewed = tmp_path / "exceptions.yml"
    reviewed.write_text(EXCEPTIONS, encoding="utf-8")
    arguments = ("--evidence-bundle", str(bundle), "--exceptions-file", str(reviewed))
    assert run_cli(tmp_path, *arguments) == 0
    document = json.loads(
        (tmp_path / "cklb" / "web01.example_Synthetic_Linux_STIG.cklb").read_text()
    )
    rule = document["stigs"][0]["rules"][1]
    assert (rule["rule_id_src"], rule["status"]) == ("SV-900002r1_rule", "open")
    assert "Waiver: exception EXC-STIG-9 was in effect" in rule["comments"]
    assert "Synthetic accepted risk" in rule["comments"]
    assert document["target_data"]["fqdn"] == "web01.example"


def refused(tmp_path: Path, capsys: pytest.CaptureFixture[str], *arguments: str) -> str:
    assert run_cli(tmp_path, *arguments) == 2
    assert not (tmp_path / "ckl").exists()
    assert not (tmp_path / "report.json").exists()
    return capsys.readouterr().err


def test_compliance_as_code_findings_are_refused_naming_the_mapping_issue(
    kit: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_path = tmp_path / "scan-run.json"
    run_path.write_text(model.dumps(kit.scan_run((kit.finding("a"),))), encoding="utf-8")
    error = refused(tmp_path, capsys, "--scan-run", str(run_path))
    assert "error: no checklist was written" in error
    assert "the STIG to ComplianceAsCode mapping of FREES-146" in error
    assert f"has no entry for benchmark {kit.BENCHMARK} and profile {kit.PROFILE}" in error


def test_xccdf_inputs_are_refused(
    kit: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    error = refused(tmp_path, capsys, "--xccdf", str(kit.XCCDF / "one-fail.xml"))
    assert "XCCDF and ARF results carry neither waivers nor the off-platform marker" in error


def test_a_scan_run_without_content_is_refused(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_path = tmp_path / "scan-run.json"
    run_path.write_text(model.dumps(stig.scan_run()), encoding="utf-8")
    error = refused(tmp_path, capsys, "--scan-run", str(run_path))
    assert "exactly one DISA content of benchmark" in error
    assert "(found: none)" in error


def test_content_of_another_version_or_twice_is_refused(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_path = tmp_path / "scan-run.json"
    run_path.write_text(model.dumps(stig.scan_run()), encoding="utf-8")
    old = tmp_path / "old.xml"
    old.write_text(stig.benchmark_xml(version="001.001.000"), encoding="utf-8")
    error = refused(tmp_path, capsys, "--scan-run", str(run_path), "--checklist-content", str(old))
    assert "(found: none)" in error
    first = tmp_path / "a.xml"
    first.write_text(stig.benchmark_xml(), encoding="utf-8")
    second = tmp_path / "b.xml"
    second.write_text(stig.benchmark_xml(rules=9), encoding="utf-8")
    arguments = ("--checklist-content", str(first), "--checklist-content", str(second))
    error = refused(tmp_path, capsys, "--scan-run", str(run_path), *arguments)
    assert "a.xml" in error
    assert "b.xml" in error


def test_unreadable_supplied_content_is_refused(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_path = tmp_path / "scan-run.json"
    run_path.write_text(model.dumps(stig.scan_run()), encoding="utf-8")
    bad = tmp_path / "bad.xml"
    bad.write_text("<x>", encoding="utf-8")
    error = refused(tmp_path, capsys, "--scan-run", str(run_path), "--checklist-content", str(bad))
    assert "--checklist-content" in error
    assert "malformed or unsafe" in error


@pytest.mark.parametrize(
    ("results", "message"),
    [
        ("<x>", "the bundle's XCCDF results cannot be read"),
        ("other-profile", "do not hold exactly one benchmark"),
        ("other-benchmark", "do not hold exactly one benchmark"),
        ("old-version", "the content is version 001.001.000"),
    ],
)
def test_own_results_that_do_not_describe_the_run_are_refused(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str], results: str, message: str
) -> None:
    documents = {
        "other-profile": own_results(stig, profile="xccdf_mil.disa.stig_profile_MAC-2_Public"),
        "other-benchmark": own_results(stig, benchmark="xccdf_mil.disa.stig_benchmark_Other"),
        "old-version": stig.benchmark_xml(version="001.001.000", test_result=stig.result_xml()),
    }
    bundle = write_bundle(tmp_path / "bundles", stig.scan_run(), documents.get(results, results))
    assert message in refused(tmp_path, capsys, "--evidence-bundle", str(bundle))


def test_two_runs_of_one_host_and_benchmark_are_refused(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = write_bundle(tmp_path / "bundles", stig.scan_run(), own_results(stig))
    profile = "xccdf_mil.disa.stig_profile_MAC-2_Public"
    other = replace(stig.scan_run(run_id="run-other"), profile_id=profile)
    second = write_bundle(tmp_path / "bundles", other, own_results(stig, profile=profile))
    arguments = ("--evidence-bundle", str(first), "--evidence-bundle", str(second))
    assert "one checklist is written per host and benchmark" in refused(
        tmp_path, capsys, *arguments
    )


def test_nothing_to_export_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    error = refused(tmp_path, capsys, "--evidence-bundle", str(tmp_path / "missing"))
    assert "no scan run or evidence bundle was read" in error


def test_checklist_content_needs_an_export(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = ["--scope", "fleet", "--output", str(tmp_path / "r.json")]
    assert cli.main([*arguments, "--checklist-content", str(tmp_path / "c.xml")]) == 2
    message = "--checklist-content needs --export-ckl, --export-cklb or --compare-stig"
    assert message in capsys.readouterr().err


def test_an_input_that_does_not_parse_has_no_checklist_and_status_one(
    stig: Any, tmp_path: Path
) -> None:
    good = write_bundle(tmp_path / "bundles", stig.scan_run(), own_results(stig))
    broken = tmp_path / "broken.json"
    broken.write_text("{}", encoding="utf-8")
    assert run_cli(tmp_path, "--evidence-bundle", str(good), "--scan-run", str(broken)) == 1
    assert sorted(path.name for path in (tmp_path / "ckl").iterdir()) == [
        "web01.example_Synthetic_Linux_STIG.ckl"
    ]


def test_only_one_format_can_be_requested(stig: Any, tmp_path: Path) -> None:
    bundle = write_bundle(tmp_path / "bundles", stig.scan_run(), own_results(stig))
    arguments = ["--scope", "single_host", "--output", str(tmp_path / "r.json")]
    exported = [
        *arguments,
        "--export-cklb",
        str(tmp_path / "only"),
        "--evidence-bundle",
        str(bundle),
    ]
    assert cli.main(exported) == 0
    assert [path.suffix for path in (tmp_path / "only").iterdir()] == [".cklb"]


def test_only_the_ckl_format_can_be_requested(stig: Any, tmp_path: Path) -> None:
    bundle = write_bundle(tmp_path / "bundles", stig.scan_run(), own_results(stig))
    arguments = ["--scope", "single_host", "--output", str(tmp_path / "r.json")]
    exported = [
        *arguments,
        "--export-ckl",
        str(tmp_path / "only"),
        "--evidence-bundle",
        str(bundle),
    ]
    assert cli.main(exported) == 0
    assert [path.suffix for path in (tmp_path / "only").iterdir()] == [".ckl"]


def test_a_checklist_that_does_not_read_back_is_never_written(stig: Any) -> None:
    benchmark = stig_content.read_benchmarks(stig.benchmark_xml().encode("utf-8"))[0]
    made = checklist.build(
        checklist.Source("x", stig.scan_run(), frozenset(), benchmark, own_results=False)
    )
    ckl = checklist_formats.render_ckl(made)
    cklb = checklist_formats.render_cklb(made)
    checklist_export.verify_read_back(made, ckl, cklb)
    with pytest.raises(checklist.ChecklistError, match="does not read back"):
        checklist_export.verify_read_back(made, ckl.replace("</CHECKLIST>", ""), cklb)
    with pytest.raises(checklist.ChecklistError, match="reads back with other statuses"):
        checklist_export.verify_read_back(
            made, ckl.replace("<STATUS>Open<", "<STATUS>NotAFinding<"), cklb
        )
