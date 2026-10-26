from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import model
from tools.reporting import cli, dashboard, report
from tools.reporting.common import dumps
from tools.reporting.report import ReportError, ReportInputs, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA = json.loads(
    (Path(report.__file__).parent / "schema" / "report-v2.json").read_text(encoding="utf-8")
)
VALIDATOR: Any = Draft202012Validator(SCHEMA)
MACHINE = "0123456789abcdef0123456789abcdef"
OTHER_PROFILE = "xccdf_org.example.synthetic_profile_stig"


def build(**inputs: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(report.build_report(ReportInputs(**inputs))))
    assert VALIDATOR.is_valid(document), [e.message[:200] for e in VALIDATOR.iter_errors(document)]
    return document


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identified(machine: str | None = MACHINE, name: str = "web01") -> model.HostIdentity:
    return model.HostIdentity(name, "rhel", "9", "x86_64", machine)


def victim_and_forgery(kit: Any, write_run: Callable[..., Path]) -> tuple[Path, Path]:
    victim = kit.scan_run((kit.finding("a", model.Outcome.FAIL),), host=identified())
    forged = kit.scan_run(
        (kit.finding("a"), *(kit.finding(f"extra{index:02d}") for index in range(99))),
        host=identified(),
    )
    return write_run("victim.json", victim), write_run("forged.json", forged)


def test_the_reviewers_forged_scan_run_probe_is_refused(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    victim, forged = victim_and_forgery(kit, write_run)
    alone = build(scope=Scope.SINGLE_HOST, scan_run=(victim,))
    assert alone["sections"]["compliance"]["summary"]["compliance_percent"] == 0.0
    with pytest.raises(ReportError, match="1 host, benchmark version and profile combination"):
        report.build_report(ReportInputs(scope=Scope.SINGLE_HOST, scan_run=(victim, forged)))


def test_an_allowed_repeated_scan_is_merged_and_always_noted(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    victim, forged = victim_and_forgery(kit, write_run)
    document = build(scope=Scope.SINGLE_HOST, scan_run=(victim, forged), allow_repeated_scans=True)
    section = document["sections"]["compliance"]
    assert section["summary"]["compliance_percent"] == 99.0
    host = {"hostname": "web01", "input_sha256": None, "machine_id": MACHINE}
    assert section["notes"] == [
        {
            "group": {"benchmark_id": kit.BENCHMARK, "content_version": "1.0", "host": host},
            "kind": "merged_inputs",
            "repeated_profile": True,
            "sources": sorted([sha(victim), sha(forged)]),
        }
    ]
    rule = next(rule for rule in section["rules"] if rule["rule_id"].endswith("_a"))
    assert rule["outcome"] == "fail"


def test_the_cli_refuses_repeated_scans_unless_allowed(
    kit: Any, write_run: Callable[..., Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    victim, forged = victim_and_forgery(kit, write_run)
    output = tmp_path / "report.json"
    argv = ["--scope", "single_host", "--output", str(output)]
    argv += ["--scan-run", str(victim), "--scan-run", str(forged)]
    assert cli.main(argv) == 2
    assert "--allow-repeated-scans" in capsys.readouterr().err
    assert not output.exists()
    assert cli.main([*argv, "--allow-repeated-scans"]) == 0
    notes = json.loads(output.read_text(encoding="utf-8"))["sections"]["compliance"]["notes"]
    assert [note["kind"] for note in notes] == ["merged_inputs"]


def test_runs_of_different_profiles_are_merged_with_a_note_without_the_flag(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    cis = kit.scan_run((kit.finding("a"),), host=identified())
    stig = kit.scan_run((kit.finding("b", model.Outcome.FAIL),), host=identified())
    stig = dataclasses.replace(stig, profile_id=OTHER_PROFILE)
    paths = (write_run("cis.json", cis), write_run("stig.json", stig))
    document = build(scope=Scope.SINGLE_HOST, scan_run=paths)
    notes = document["sections"]["compliance"]["notes"]
    assert [(note["kind"], note["repeated_profile"]) for note in notes] == [
        ("merged_inputs", False)
    ]
    assert notes[0]["sources"] == sorted(sha(path) for path in paths)


def test_an_unfinished_run_is_never_refused_and_withholds_the_figure(
    kit: Any, write_run: Callable[..., Path]
) -> None:
    good = kit.scan_run((kit.finding("a"),), host=identified())
    failed = kit.scan_run((), status=model.ScanStatus.FAILED, host=identified())
    paths = (write_run("good.json", good), write_run("failed.json", failed))
    document = build(scope=Scope.SINGLE_HOST, scan_run=paths)
    section = document["sections"]["compliance"]
    assert section["summary"]["run_status"] == "not_completed"
    assert section["summary"]["compliance_percent"] is None
    assert [(n["kind"], n["repeated_profile"]) for n in section["notes"]] == [
        ("merged_inputs", False)
    ]


def mixed_inputs(
    kit: Any, write: Callable[..., Path], write_run: Callable[..., Path]
) -> dict[str, Any]:
    """Every pair of input types for one host name, plus single-input groups."""
    unnamed_run = kit.scan_run((kit.finding("a"),), host=identified(None))
    other_version = kit.xccdf_text("web01", "pass", version="2.0")
    arf = (kit.REPORTING / "arf.xml").read_text(encoding="utf-8")
    return {
        "scan_run": (write_run("run.json", unnamed_run),),
        "xccdf": (
            write("one.xml", kit.xccdf_text("WEB01", "fail")),
            write("two.xml", kit.xccdf_text("web01", "pass", results=[("b", "pass")])),
            write("v2.xml", other_version),
            write("solo.xml", kit.xccdf_text("solo", "pass")),
            write("host-example.xml", kit.xccdf_text("host.example", "pass")),
            write("unnamed.xml", kit.xccdf_text(None, "pass")),
        ),
        "arf": (write("arf.xml", arf),),
    }


def test_every_group_built_from_several_inputs_carries_a_note(
    kit: Any, write: Callable[..., Path], write_run: Callable[..., Path]
) -> None:
    document = build(scope=Scope.FLEET, **mixed_inputs(kit, write, write_run))
    section = document["sections"]["compliance"]
    views: Any = dashboard.dashboard_views(document)
    merged = {
        json.dumps(note["group"], sort_keys=True): note
        for note in section["notes"]
        if note["kind"] == "merged_inputs"
    }
    multi = 0
    for group, view in zip(section["groups"], views["groups"], strict=True):
        key = json.dumps(
            {k: group[k] for k in ("benchmark_id", "content_version", "host")}, sort_keys=True
        )
        sources = sorted(source["sha256"] for source in view["sources"])
        if len(sources) > 1:
            multi += 1
            assert merged[key]["sources"] == sources
            assert section["notes"][view["note"]] is not None
        else:
            assert key not in merged
            assert view["note"] is None
    assert multi == len(merged) == 2
    formats = sorted(
        item["format"]
        for item in section["items"]
        if item["artifact"]["sha256"] in {s for note in merged.values() for s in note["sources"]}
    )
    assert formats == ["arf", "scan_run", "xccdf", "xccdf", "xccdf"]


def test_a_host_counted_once_across_groups_has_one_host_level_note(
    kit: Any, write: Callable[..., Path], write_run: Callable[..., Path]
) -> None:
    document = build(scope=Scope.FLEET, **mixed_inputs(kit, write, write_run))
    notes = [
        note
        for note in document["sections"]["compliance"]["notes"]
        if note["kind"] == "same_host_across_groups"
    ]
    assert [note["host"]["hostname"] for note in notes] == ["web01"]
    assert notes[0]["groups"] == [
        {"benchmark_id": kit.BENCHMARK, "content_version": "1.0"},
        {"benchmark_id": kit.BENCHMARK, "content_version": "2.0"},
    ]
    assert len(notes[0]["sources"]) == 4
    assert all("group" not in note for note in notes)


def test_inputs_with_a_single_source_get_no_note(kit: Any, write: Callable[..., Path]) -> None:
    document = build(
        scope=Scope.FLEET,
        xccdf=(write("a.xml", kit.xccdf_text("a")), write("b.xml", kit.xccdf_text("b"))),
    )
    assert document["sections"]["compliance"]["notes"] == []


def test_notes_are_bounded_by_the_number_of_inputs(kit: Any, write: Callable[..., Path]) -> None:
    paths: list[Path] = []
    for index in range(6):
        version = "1.0" if index % 2 else "2.0"
        name = f"host{index // 2}"
        text = kit.xccdf_text(name, "pass", version=version, results=[(f"r{index}", "pass")])
        paths.append(write(f"x{index}.xml", text))
        paths.append(write(f"y{index}.xml", text.replace("<result>pass", "<result>fail")))
    document = build(scope=Scope.FLEET, xccdf=tuple(paths))
    notes = document["sections"]["compliance"]["notes"]
    assert len(notes) <= len(paths)
    assert sum(1 for note in notes if note["kind"] == "merged_inputs") == 6
    assert sum(1 for note in notes if note["kind"] == "same_host_across_groups") == 3
