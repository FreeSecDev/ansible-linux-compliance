from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    collection,
    evidence,
)
from tests.unit.tools.reporting.test_bundle import write_bundle
from tools.reporting import cli, dashboard, report
from tools.reporting.common import dumps
from tools.reporting.report import ReportError, ReportInputs, Scope

SCHEMA = json.loads(
    (Path(report.__file__).parent / "schema" / "report-v2.json").read_text(encoding="utf-8")
)
VALIDATOR: Any = Draft202012Validator(SCHEMA)
COLLECTION_ID = "20261026T080001.234567Z"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def manifest_sha(directory: Path) -> str:
    return sha((directory / evidence.MANIFEST_NAME).read_bytes())


def write_collection(
    tmp_path: Path, hosts: dict[str, tuple[str, str | None]], name: str = "collection.json"
) -> Path:
    targets = tuple(
        collection.TargetHost(
            host,
            status,
            None
            if digest is None
            else collection.CollectedBundle(run_id=f"run-{host}", manifest_sha256=digest),
        )
        for host, (status, digest) in sorted(hosts.items())
    )
    summary = collection.Collection(COLLECTION_ID, "2026-10-26T08:00:01Z", "0.1.0", targets)
    path = tmp_path / "evidence" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(evidence.canonical_json(summary.to_dict()), encoding="ascii")
    return path


def build(**inputs: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(report.build_report(ReportInputs(**inputs))))
    assert VALIDATOR.is_valid(document), [e.message[:200] for e in VALIDATOR.iter_errors(document)]
    return document


def two_bundles(kit: Any, tmp_path: Path, *, applied: bool = True) -> tuple[Path, Path]:
    return (
        write_bundle(kit, tmp_path / "bundles", "web01", applied=applied),
        write_bundle(kit, tmp_path / "bundles", "db01", applied=applied),
    )


def test_a_report_without_a_collection_summary_labels_its_coverage_unknown(
    kit: Any, tmp_path: Path
) -> None:
    web, db = two_bundles(kit, tmp_path)
    document = build(
        scope=Scope.FLEET, evidence_bundle=(web, db), exceptions_file=kit.EXCEPTIONS_FILE
    )
    compliance = document["sections"]["compliance"]
    assert document["schema_version"] == "2.2"
    assert compliance["status"] == "available"
    assert compliance["host_coverage"] == {
        "collection": None,
        "hosts": [],
        "reason": (
            "no --evidence-collection was supplied, so the report cannot tell whether a target "
            "host without an input is missing"
        ),
        "status": "unknown",
        "summary": None,
    }


def test_a_complete_collection_keeps_every_figure(kit: Any, tmp_path: Path) -> None:
    web, db = two_bundles(kit, tmp_path)
    summary = write_collection(
        tmp_path,
        {"web01": ("collected", manifest_sha(web)), "db01": ("collected", manifest_sha(db))},
    )
    document = build(
        scope=Scope.FLEET,
        evidence_bundle=(web, db),
        exceptions_file=kit.EXCEPTIONS_FILE,
        evidence_collection=summary,
    )
    compliance = document["sections"]["compliance"]
    coverage = compliance["host_coverage"]
    assert compliance["status"] == "available"
    assert compliance["summary"] is not None
    assert len(compliance["groups"]) == 2
    assert coverage["status"] == "complete"
    assert coverage["reason"] is None
    assert coverage["summary"] == {
        "by_status": {
            "collected": 2,
            "collection_failed": 0,
            "limited_out": 0,
            "no_audit_result": 0,
            "no_evidence_written": 0,
            "unreachable": 0,
        },
        "in_report": 2,
        "missing": 0,
        "target_hosts": 2,
    }
    assert coverage["collection"] == {
        "collected_at": "2026-10-26T08:00:01Z",
        "collection_id": COLLECTION_ID,
        "path": str(summary),
        "sha256": sha(summary.read_bytes()),
        "size": len(summary.read_bytes()),
    }
    assert [host["in_report"] for host in coverage["hosts"]] == [True, True]
    assert {
        "format": "evidence_collection",
        "path": str(summary),
        "sha256": sha(summary.read_bytes()),
        "size": len(summary.read_bytes()),
        "status": "available",
    } in document["raw_artifacts"]
    assert not report.has_gap(document)


def test_every_missing_host_is_named_and_no_figure_covers_the_fleet(
    kit: Any, tmp_path: Path
) -> None:
    web, db = two_bundles(kit, tmp_path)
    summary = write_collection(
        tmp_path,
        {
            "web01": ("collected", manifest_sha(web)),
            "db01": ("collected", manifest_sha(db)),
            "lost01": ("unreachable", None),
            "gated01": ("collection_failed", None),
            "app01": ("no_evidence_written", None),
            "gone01": ("limited_out", None),
            "early01": ("no_audit_result", None),
        },
    )
    document = build(
        scope=Scope.FLEET,
        evidence_bundle=(web,),
        exceptions_file=kit.EXCEPTIONS_FILE,
        evidence_collection=summary,
    )
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "partial"
    assert compliance["summary"] is None
    assert compliance["groups"] == compliance["aggregates"] == compliance["rules"] == []
    assert document["sections"]["exceptions"]["status"] == "partial"
    assert document["sections"]["exceptions"]["summary"] is None
    assert document["overview"]["exceptions"] is None
    directory = summary.parent
    assert {gap["artifact"]: gap["reason"] for gap in compliance["gaps"]} == {
        f"{directory}/app01": (
            "target host app01 has no evidence bundle: its audit wrote no evidence "
            "(check mode or no scan)"
        ),
        f"{directory}/db01/run-db01": (
            "target host db01 was collected as run run-db01, but no bundle of that run that "
            "verified and matches the collection summary was supplied"
        ),
        f"{directory}/early01": (
            "target host early01 has no evidence bundle: it has no audit result "
            "(it failed before the scan)"
        ),
        f"{directory}/gated01": (
            "target host gated01 has no evidence bundle: the collection of its evidence bundle "
            "failed"
        ),
        f"{directory}/gone01": (
            "target host gone01 has no evidence bundle: it was limited out of the run"
        ),
        f"{directory}/lost01": (
            "target host lost01 has no evidence bundle: it was unreachable (it did not complete "
            "fact gathering)"
        ),
    }
    coverage = compliance["host_coverage"]
    assert coverage["status"] == "incomplete"
    assert coverage["reason"] == "6 of 7 target host(s) have no evidence bundle in this report"
    assert coverage["summary"]["missing"] == 6
    assert coverage["summary"]["in_report"] == 1
    assert [host["host"] for host in coverage["hosts"] if host["in_report"]] == ["web01"]
    assert {item["format"] for item in compliance["items"]} == {"exceptions_evaluation"}
    output = tmp_path / "report.json"
    arguments = ["--scope", "fleet", "--output", str(output), "--evidence-bundle", str(web)]
    arguments += ["--exceptions-file", str(kit.EXCEPTIONS_FILE)]
    assert cli.main([*arguments, "--evidence-collection", str(summary)]) == cli.EXIT_SECTION_ERROR
    assert cli.main(arguments) == cli.EXIT_OK


def test_missing_hosts_of_bundles_without_exceptions_are_scan_run_inputs(
    kit: Any, tmp_path: Path
) -> None:
    web, _ = two_bundles(kit, tmp_path, applied=False)
    summary = write_collection(
        tmp_path, {"web01": ("collected", manifest_sha(web)), "lost01": ("unreachable", None)}
    )
    document = build(scope=Scope.FLEET, evidence_bundle=(web,), evidence_collection=summary)
    items = document["sections"]["compliance"]["items"]
    assert [(item["format"], item["status"]) for item in items] == [
        ("scan_run", "available"),
        ("scan_run", "unavailable"),
    ]
    assert document["sections"]["exceptions"]["status"] == "unavailable"
    assert document["sections"]["exceptions"]["items"] == []


def test_a_collection_without_any_bundle_leaves_the_section_unavailable(tmp_path: Path) -> None:
    summary = write_collection(tmp_path, {"lost01": ("unreachable", None)})
    document = build(scope=Scope.FLEET, evidence_collection=summary)
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "unavailable"
    assert compliance["host_coverage"]["status"] == "incomplete"
    assert compliance["gaps"][0]["artifact"] == f"{summary.parent}/lost01"
    assert report.has_gap(document)


def test_a_bundle_that_the_summary_does_not_list_is_an_input_error(
    kit: Any, tmp_path: Path
) -> None:
    web, db = two_bundles(kit, tmp_path)
    summary = write_collection(
        tmp_path, {"web01": ("collected", "b" * 64), "db01": ("collected", manifest_sha(db))}
    )
    document = build(
        scope=Scope.FLEET,
        evidence_bundle=(web, db),
        exceptions_file=kit.EXCEPTIONS_FILE,
        evidence_collection=summary,
    )
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "error"
    assert document["sections"]["exceptions"]["status"] == "error"
    rejected = next(item for item in compliance["items"] if item["status"] == "error")
    assert rejected["format"] == "exceptions_evaluation"
    assert rejected["artifact"] == {
        "path": f"{web}/bundle.json",
        "sha256": manifest_sha(web),
        "size": len((web / evidence.MANIFEST_NAME).read_bytes()),
    }
    assert rejected["reason"] == (
        f"evidence bundle rejected: the collection summary {COLLECTION_ID} does not list run "
        "run-web01 of web01 with the SHA-256 of this bundle.json"
    )
    coverage = compliance["host_coverage"]
    assert [(host["host"], host["in_report"]) for host in coverage["hosts"]] == [
        ("db01", True),
        ("web01", False),
    ]


def test_a_bundle_of_a_host_outside_the_summary_is_an_input_error(kit: Any, tmp_path: Path) -> None:
    web, db = two_bundles(kit, tmp_path, applied=False)
    summary = write_collection(tmp_path, {"web01": ("collected", manifest_sha(web))})
    document = build(scope=Scope.FLEET, evidence_bundle=(web, db), evidence_collection=summary)
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "error"
    assert [(item["format"], item["status"]) for item in compliance["items"]] == [
        ("scan_run", "available"),
        ("scan_run", "error"),
    ]
    assert compliance["host_coverage"]["status"] == "complete"


def test_a_bundle_that_does_not_verify_leaves_its_host_missing(kit: Any, tmp_path: Path) -> None:
    web, _ = two_bundles(kit, tmp_path)
    summary = write_collection(tmp_path, {"web01": ("collected", manifest_sha(web))})
    (web / evidence.SCAN_RUN_PATH).write_bytes(b"{}")
    document = build(
        scope=Scope.FLEET,
        evidence_bundle=(web,),
        exceptions_file=kit.EXCEPTIONS_FILE,
        evidence_collection=summary,
    )
    compliance = document["sections"]["compliance"]
    assert [item["status"] for item in compliance["items"]] == ["error", "unavailable"]
    assert compliance["host_coverage"]["status"] == "incomplete"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "input file does not exist"),
        (b"{", "evidence collection summary rejected: the collection summary is not valid JSON"),
        (b"[]", "evidence collection summary rejected: collection summary must be a mapping"),
        (
            b'{"kind": 1, "kind": 2}',
            "evidence collection summary rejected: the collection summary contains a duplicate key",
        ),
    ],
)
def test_a_summary_that_cannot_be_used_refuses_the_report(
    tmp_path: Path, content: bytes | None, message: str
) -> None:
    path = tmp_path / "collection.json"
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(
        ReportError, match=f"the evidence collection summary cannot be used: {message}"
    ):
        report.build_report(ReportInputs(scope=Scope.FLEET, evidence_collection=path))


@pytest.mark.parametrize("option", ["scan_run", "xccdf", "arf", "exceptions_evaluation"])
def test_a_summary_accounts_for_evidence_bundles_only(tmp_path: Path, option: str) -> None:
    summary = write_collection(tmp_path, {"lost01": ("unreachable", None)})
    fields: dict[str, Any] = {option: (tmp_path / "input",)}
    inputs = ReportInputs(scope=Scope.FLEET, evidence_collection=summary, **fields)
    flag = option.replace("_", "-")
    with pytest.raises(ReportError, match=f"accounts for evidence bundles only.*not --{flag}"):
        report.build_report(inputs)


def test_the_number_of_target_hosts_and_inputs_is_bounded(
    kit: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    web, _ = two_bundles(kit, tmp_path, applied=False)
    summary = write_collection(
        tmp_path, {"lost01": ("unreachable", None), "gone01": ("limited_out", None)}
    )
    monkeypatch.setattr(report, "MAX_INPUTS", 1)
    with pytest.raises(ReportError, match="names more than 1 target hosts"):
        report.build_report(ReportInputs(scope=Scope.FLEET, evidence_collection=summary))
    monkeypatch.setattr(report, "MAX_INPUTS", 2)
    inputs = ReportInputs(scope=Scope.FLEET, evidence_bundle=(web,), evidence_collection=summary)
    with pytest.raises(ReportError, match="counting the missing hosts"):
        report.build_report(inputs)


def test_the_command_line_refuses_an_unusable_summary(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    arguments = ["--scope", "fleet", "--output", str(output)]
    missing = str(tmp_path / "absent.json")
    assert cli.main([*arguments, "--evidence-collection", missing]) == cli.EXIT_USAGE
    assert not output.exists()


def test_the_schema_couples_coverage_with_the_section_and_the_version(
    kit: Any, tmp_path: Path
) -> None:
    web, _ = two_bundles(kit, tmp_path, applied=False)
    summary = write_collection(
        tmp_path, {"web01": ("collected", manifest_sha(web)), "lost01": ("unreachable", None)}
    )
    document = build(scope=Scope.FLEET, evidence_bundle=(web,), evidence_collection=summary)
    compliance = document["sections"]["compliance"]
    forged = copy.deepcopy(document)
    forged["sections"]["compliance"]["status"] = "available"
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(document)
    forged["sections"]["compliance"]["host_coverage"]["status"] = "complete"
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(document)
    forged["sections"]["compliance"]["host_coverage"]["hosts"][0]["run_id"] = "run-lost01"
    assert not VALIDATOR.is_valid(forged)
    forged = copy.deepcopy(document)
    del forged["sections"]["compliance"]["host_coverage"]
    assert not VALIDATOR.is_valid(forged)
    older = copy.deepcopy(forged)
    older["schema_version"] = "2.0"
    without_off_platform(older)
    older["raw_artifacts"] = [
        artifact
        for artifact in older["raw_artifacts"]
        if artifact["format"] != "evidence_collection"
    ]
    assert VALIDATOR.is_valid(older)
    older["sections"]["compliance"]["host_coverage"] = compliance["host_coverage"]
    assert not VALIDATOR.is_valid(older)
    unknown = copy.deepcopy(document)
    unknown["sections"]["compliance"]["host_coverage"]["status"] = "unknown"
    assert not VALIDATOR.is_valid(unknown)


def without_off_platform(document: dict[str, Any]) -> None:
    """Strip the schema 2.2 off-platform keys, which a 2.0 or 2.1 document never has."""
    del document["overview"]["off_platform"]
    compliance = document["sections"]["compliance"]
    del compliance["off_platform"]
    for item in compliance["items"]:
        if isinstance(item["data"], dict):
            del item["data"]["off_platform"]


def test_the_dashboard_reads_2_0_and_2_1_reports(kit: Any, tmp_path: Path) -> None:
    web, _ = two_bundles(kit, tmp_path, applied=False)
    summary = write_collection(
        tmp_path, {"web01": ("collected", manifest_sha(web)), "lost01": ("unreachable", None)}
    )
    document = build(scope=Scope.FLEET, evidence_bundle=(web,), evidence_collection=summary)
    assert "lost01" in dashboard.render_dashboard(document)
    older = build(scope=Scope.FLEET, evidence_bundle=(web,))
    older["schema_version"] = "2.0"
    del older["sections"]["compliance"]["host_coverage"]
    without_off_platform(older)
    assert VALIDATOR.is_valid(older)
    assert dashboard.render_dashboard(older).startswith("<!DOCTYPE html>")


REQUIRED_COVERAGE: dict[str, tuple[int, int, str | None]] = {
    "complete": (cli.EXIT_OK, cli.EXIT_OK, None),
    "incomplete": (
        cli.EXIT_SECTION_ERROR,
        cli.EXIT_SECTION_ERROR,
        (
            "the host coverage is incomplete, not complete: 1 of 2 target host(s) have no "
            "evidence bundle in this report"
        ),
    ),
    "unknown": (
        cli.EXIT_OK,
        cli.EXIT_SECTION_ERROR,
        "the host coverage is unknown, not complete: no --evidence-collection was supplied",
    ),
}


@pytest.mark.parametrize("coverage", sorted(REQUIRED_COVERAGE))
def test_require_host_coverage_fails_every_coverage_but_complete(
    kit: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str], coverage: str
) -> None:
    without, required, message = REQUIRED_COVERAGE[coverage]
    web, db = two_bundles(kit, tmp_path)
    hosts: dict[str, tuple[str, str | None]] = {
        "web01": ("collected", manifest_sha(web)),
        "db01": ("collected", manifest_sha(db)),
    }
    if coverage == "incomplete":
        hosts["db01"] = ("unreachable", None)
    output = tmp_path / "report.json"
    arguments = ["--scope", "fleet", "--output", str(output), "--evidence-bundle", str(web)]
    arguments += ["--exceptions-file", str(kit.EXCEPTIONS_FILE)]
    if coverage != "incomplete":
        arguments += ["--evidence-bundle", str(db)]
    if coverage != "unknown":
        arguments += ["--evidence-collection", str(write_collection(tmp_path, hosts))]
    assert cli.main(arguments) == without
    assert "--require-host-coverage" not in capsys.readouterr().err
    output.unlink()
    assert cli.main([*arguments, "--require-host-coverage"]) == required
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["sections"]["compliance"]["host_coverage"]["status"] == coverage
    error = capsys.readouterr().err
    if message is None:
        assert error == ""
    else:
        assert f"error: --require-host-coverage: {message}" in error
        assert "the report was written, but it does not account for every target host" in error


def test_a_skipped_dashboard_keeps_precedence_over_require_host_coverage(
    kit: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    web, _ = two_bundles(kit, tmp_path, applied=False)
    monkeypatch.setattr(dashboard, "MAX_EMBEDDED_BYTES", 10)
    output, html = tmp_path / "report.json", tmp_path / "report.html"
    arguments = ["--scope", "fleet", "--output", str(output), "--html", str(html)]
    arguments += ["--evidence-bundle", str(web), "--require-host-coverage"]
    assert cli.main(arguments) == cli.EXIT_DASHBOARD_SKIPPED
    assert output.exists()
    assert not html.exists()
    assert "the host coverage is unknown, not complete" in capsys.readouterr().err
