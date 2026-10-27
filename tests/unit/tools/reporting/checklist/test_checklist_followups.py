from __future__ import annotations

import errno
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    model,
    placement,
)
from tools.reporting import checklist, cli, stig_compare, stig_content, stig_mapping

HOST_NAME = ".".join(("a" * 63, "b" * 63, "c" * 63))
CAC = "xccdf_org.ssgproject.content_rule_"


def source_of(stig: Any, *, benchmark: str) -> checklist.Source:
    content = stig_content.read_benchmarks(stig.benchmark_xml(benchmark=benchmark).encode())[0]
    host = model.HostIdentity(HOST_NAME, "ubuntu", "24.04", "x86_64", None)
    run = replace(stig.scan_run(host=host), benchmark_id=benchmark)
    return checklist.Source("scan-run.json", run, frozenset(), content, own_results=False)


@pytest.mark.parametrize(("extra", "allowed"), [(58, True), (59, False)])
def test_a_checklist_file_name_over_255_bytes_is_refused_before_anything_is_written(
    stig: Any, extra: int, allowed: bool
) -> None:
    source = source_of(stig, benchmark="xccdf_mil.disa.stig_benchmark_" + "S" * extra)
    if allowed:
        built = checklist.build_all([source])
        assert len(f"{built[0].file_stem}.cklb".encode()) == 255
        return
    with pytest.raises(checklist.ChecklistError, match=r"is 256 bytes with its suffix, over the"):
        checklist.build_all([source])


def test_a_name_that_is_too_long_writes_nothing_and_exits_2(
    stig: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    benchmark = "xccdf_mil.disa.stig_benchmark_" + "S" * 59
    run = source_of(stig, benchmark=benchmark).run
    run_path = tmp_path / "scan-run.json"
    run_path.write_text(model.dumps(run), encoding="utf-8")
    content = tmp_path / "content.xml"
    content.write_text(stig.benchmark_xml(benchmark=benchmark), encoding="utf-8")
    status = cli.main(
        [
            "--scope",
            "single_host",
            "--output",
            str(tmp_path / "r.json"),
            "--export-ckl",
            str(tmp_path / "ckl"),
            "--scan-run",
            str(run_path),
            "--checklist-content",
            str(content),
        ]
    )
    assert status == 2
    assert "bytes with its suffix" in capsys.readouterr().err
    assert not (tmp_path / "ckl").exists()
    assert not (tmp_path / "r.json").exists()


def partial_finding(stig: Any, toggles: tuple[str, ...]) -> model.Finding:
    control = placement.ControlPlacement(
        family="ssh",
        topic="ssh",
        tags=(),
        stig_id="SYN-00-000001",
        mapped_rules=(CAC + "a", CAC + "b"),
        partially_disabled_by=toggles,
    )
    return replace(cast("model.Finding", stig.finding(1, model.Outcome.PASS)), control=control)


def test_partially_disabled_toggles_are_named_in_the_comments(stig: Any) -> None:
    toggles = ("linux_compliance_ssh_enabled", "linux_compliance_sshd_enabled")
    made = checklist.verdict(stig.scan_run(), partial_finding(stig, toggles))
    assert made.status is checklist.NOT_A_FINDING
    assert made.comments == (
        "Partially disabled by: linux_compliance_ssh_enabled, linux_compliance_sshd_enabled"
    )


def test_a_placement_without_partial_disables_adds_no_comment(stig: Any) -> None:
    assert checklist.verdict(stig.scan_run(), partial_finding(stig, ())).comments == ""
    assert checklist.verdict(stig.scan_run(), stig.finding(1, model.Outcome.PASS)).comments == ""


def test_the_partial_disable_line_reaches_the_ckl_and_the_cklb(stig: Any, tmp_path: Path) -> None:
    run = stig.scan_run((partial_finding(stig, ("linux_compliance_ssh_enabled",)),))
    run_path = tmp_path / "scan-run.json"
    run_path.write_text(model.dumps(run), encoding="utf-8")
    content = tmp_path / "content.xml"
    content.write_text(stig.benchmark_xml(), encoding="utf-8")
    arguments = [
        "--scope",
        "single_host",
        "--output",
        str(tmp_path / "r.json"),
        "--export-ckl",
        str(tmp_path / "ckl"),
        "--export-cklb",
        str(tmp_path / "cklb"),
        "--scan-run",
        str(run_path),
        "--checklist-content",
        str(content),
    ]
    assert cli.main(arguments) == 0
    name = "web01.example_Synthetic_Linux_STIG"
    line = "Partially disabled by: linux_compliance_ssh_enabled"
    assert line in (tmp_path / "ckl" / f"{name}.ckl").read_text(encoding="utf-8")
    document = json.loads((tmp_path / "cklb" / f"{name}.cklb").read_text(encoding="utf-8"))
    assert line in document["stigs"][0]["rules"][0]["comments"]


def mapped_source(stig: Any, content: stig_content.StigBenchmark) -> checklist.Source:
    mapping = stig_mapping.ProfileMapping(
        datastream="synthetic",
        file_name="ssg-synthetic-ds.xml",
        content_sha256="c" * 64,
        benchmark_id="xccdf_org.ssgproject.content_benchmark_SYNTHETIC",
        benchmark_version="0.1.82",
        profile_id="xccdf_org.ssgproject.content_profile_stig",
        stig_release="V1R2",
        disa_benchmark_id=stig.BENCHMARK,
        checks={"SYN-00-000001": (CAC + "one",), "SYN-00-000002": (CAC + "two",)},
        disa_rules={},
        unmapped_rules=(),
    )
    run = stig.scan_run(
        (
            replace(stig.finding(1, model.Outcome.PASS), rule_id=CAC + "one"),
            replace(stig.finding(2, model.Outcome.PASS), rule_id=CAC + "two"),
        ),
        run_id="run-oscap",
    )
    return checklist.Source(
        "oscap.json",
        run,
        frozenset(),
        content,
        own_results=False,
        mapping=mapping,
        content_name="disa.xml",
    )


def benchmark_of(xml: str) -> stig_content.StigBenchmark:
    return stig_content.read_benchmarks(xml.encode())[0]


def compared(
    stig: Any, disa: stig_content.StigBenchmark, mapped: stig_content.StigBenchmark
) -> dict[str, Any]:
    scc = checklist.Source("scc.json", stig.scan_run(), frozenset(), disa, own_results=False)
    oscap = mapped_source(stig, mapped)
    document = stig_compare.compare([(scc, checklist.build(scc)), (oscap, checklist.build(oscap))])
    return dict(json.loads(json.dumps(document)))


def reordered(stig: Any, order: tuple[int, ...]) -> str:
    groups = "".join(stig.group(number, "medium") for number in order)
    xml = str(stig.benchmark_xml(rules=0))
    return xml.replace("</Benchmark>", f"{groups}</Benchmark>")


def test_the_comparison_pairs_the_rules_by_rule_id_not_by_position(stig: Any) -> None:
    ordered = benchmark_of(reordered(stig, tuple(range(1, 11))))
    shuffled = benchmark_of(reordered(stig, tuple(reversed(range(1, 11)))))
    plain = compared(stig, ordered, ordered)["comparisons"][0]
    swapped = compared(stig, ordered, shuffled)["comparisons"][0]
    assert swapped == plain
    assert swapped["rules"] == 10
    differing = {item["stig_id"]: item for item in swapped["disagreements"]}
    assert differing["SYN-00-000002"]["disa"] == "Open"
    assert differing["SYN-00-000002"]["compliance_as_code"] == "NotAFinding"
    assert differing["SYN-00-000003"]["disa"] == "Not_Applicable"
    assert differing["SYN-00-000003"]["compliance_as_code"] == "Not_Reviewed"
    assert "SYN-00-000001" not in differing


def test_a_different_rule_count_is_refused(stig: Any) -> None:
    full = benchmark_of(stig.benchmark_xml())
    short = benchmark_of(stig.benchmark_xml(rules=9))
    with pytest.raises(checklist.ChecklistError, match=r"rule sets \(10 and 9 rules"):
        compared(stig, full, short)
    with pytest.raises(checklist.ChecklistError, match=r"rule sets \(9 and 10 rules"):
        compared(stig, short, full)


def test_other_rules_of_the_same_count_are_refused(stig: Any) -> None:
    full = benchmark_of(stig.benchmark_xml())
    other = benchmark_of(stig.benchmark_xml().replace("SV-900003r1_rule", "SV-909999r1_rule"))
    with pytest.raises(checklist.ChecklistError, match="2 in one side only, for example SV-9"):
        compared(stig, full, other)


def test_content_of_another_release_is_refused(stig: Any) -> None:
    current = benchmark_of(stig.benchmark_xml())
    newer = benchmark_of(stig.benchmark_xml(version="001.003.000"))
    with pytest.raises(checklist.ChecklistError, match=r"releases \(V1R2 and V1R3\)"):
        compared(stig, current, newer)


def test_content_whose_release_is_unknown_is_refused(stig: Any) -> None:
    current = benchmark_of(stig.benchmark_xml())
    unknown = benchmark_of(stig.benchmark_xml(version="draft"))
    with pytest.raises(checklist.ChecklistError, match=r"releases \(V1R2 and unknown\)"):
        compared(stig, current, unknown)


def test_a_rule_with_another_stig_id_on_one_side_is_refused(stig: Any) -> None:
    current = benchmark_of(stig.benchmark_xml())
    relabelled = benchmark_of(stig.benchmark_xml().replace("SYN-00-000004", "SYN-00-009999"))
    with pytest.raises(checklist.ChecklistError, match="SV-900004r1_rule different STIG IDs"):
        compared(stig, current, relabelled)


def failing_stage(monkeypatch: pytest.MonkeyPatch, failing_call: int) -> list[Path]:
    real = cli.stage
    staged: list[Path] = []

    def stage(path: Path, content: str) -> Path:
        staged.append(path)
        if len(staged) == failing_call:
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        return real(path, content)

    monkeypatch.setattr(cli, "stage", stage)
    return staged


def export_arguments(stig: Any, tmp_path: Path) -> list[str]:
    run_path = tmp_path / "scan-run.json"
    run_path.write_text(model.dumps(stig.scan_run()), encoding="utf-8")
    content = tmp_path / "content.xml"
    content.write_text(stig.benchmark_xml(), encoding="utf-8")
    return [
        "--scope",
        "single_host",
        "--output",
        str(tmp_path / "out" / "report.json"),
        "--export-ckl",
        str(tmp_path / "ckl"),
        "--export-cklb",
        str(tmp_path / "cklb"),
        "--scan-run",
        str(run_path),
        "--checklist-content",
        str(content),
    ]


def written(tmp_path: Path) -> list[str]:
    return sorted(
        path.relative_to(tmp_path).as_posix()
        for path in tmp_path.rglob("*")
        if path.is_file() and path.parent != tmp_path
    )


@pytest.mark.parametrize("failing_call", [1, 2, 3])
def test_a_failed_write_leaves_no_output_and_exits_2(
    stig: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failing_call: int,
) -> None:
    failing_stage(monkeypatch, failing_call)
    assert cli.main(export_arguments(stig, tmp_path)) == 2
    assert "error: cannot write the" in capsys.readouterr().err
    assert written(tmp_path) == []


def test_every_output_is_staged_before_any_is_renamed(
    stig: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    order: list[str] = []
    real_stage = cli.stage
    real_replace = Path.replace

    def stage(path: Path, content: str) -> Path:
        order.append("stage")
        return real_stage(path, content)

    def replace_file(self: Path, target: Path) -> Path:
        order.append("rename")
        return real_replace(self, target)

    monkeypatch.setattr(cli, "stage", stage)
    monkeypatch.setattr(Path, "replace", replace_file)
    assert cli.main(export_arguments(stig, tmp_path)) == 0
    assert order == ["stage"] * 3 + ["rename"] * 3
    assert sorted(path.name for path in (tmp_path / "ckl").iterdir()) == [
        "web01.example_Synthetic_Linux_STIG.ckl"
    ]
    assert not [name for name in written(tmp_path) if Path(name).name.startswith(".fsd-")]


def test_a_failed_rename_removes_the_remaining_temporary_files(
    stig: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    real_replace = Path.replace
    renames: list[Path] = []

    def replace_file(self: Path, target: Path) -> Path:
        renames.append(self)
        if len(renames) == 2:
            raise OSError(errno.EROFS, os.strerror(errno.EROFS))
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", replace_file)
    assert cli.main(export_arguments(stig, tmp_path)) == 2
    assert "error: cannot write the" in capsys.readouterr().err
    assert not [name for name in written(tmp_path) if Path(name).name.startswith(".fsd-")]


def test_a_failed_sync_removes_the_temporary_file(
    stig: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_fsync(_descriptor: int) -> None:
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(os, "fsync", failing_fsync)
    assert cli.main(export_arguments(stig, tmp_path)) == 2
    assert written(tmp_path) == []


def test_a_staged_file_has_a_short_name_and_private_mode(tmp_path: Path) -> None:
    target = tmp_path / ("n" * 255)
    temporary = cli.stage(target, "text")
    assert len(temporary.name) < 40
    assert temporary.stat().st_mode & 0o777 == 0o600
    cli.discard([temporary, temporary])
    assert not temporary.exists()


def test_a_failed_rename_of_one_file_keeps_the_previous_file_and_leaves_no_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.json"
    cli.write_atomic(target, "previous")

    def broken(_self: Path, _target: Path) -> Path:
        raise OSError(errno.EROFS, os.strerror(errno.EROFS))

    monkeypatch.setattr(Path, "replace", broken)
    with pytest.raises(OSError, match="Read-only"):
        cli.write_atomic(target, "new content")
    monkeypatch.undo()
    assert target.read_text(encoding="utf-8") == "previous"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["report.json"]


@pytest.mark.parametrize(
    "evidence",
    [
        model.Evidence("note", "scc", "pass"),
        model.Evidence("scanner_result", "scc", "PASS 1"),
        model.Evidence("scanner_result", "scc", "pass\nfail"),
    ],
)
def test_only_a_plain_scanner_result_replaces_disabled_in_the_details(
    stig: Any, evidence: model.Evidence
) -> None:
    toggled = replace(
        cast("model.Finding", stig.finding(1, model.Outcome.DISABLED, disabled_by="linux_x")),
        evidence=(evidence,),
    )
    details = checklist.verdict(stig.scan_run(), toggled).details.splitlines()
    assert "Scanner result: disabled" in details
    assert not [line for line in details if line.startswith("Reported outcome")]
    assert "Disabled by: linux_x" in details
