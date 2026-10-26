from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from jsonschema import Draft202012Validator

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    evidence,
    model,
)
from tools.reporting import bundle, cli, report
from tools.reporting.common import InvalidInputError, dumps
from tools.reporting.report import ReportError, ReportInputs, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA = json.loads(
    (Path(report.__file__).parent / "schema" / "report-v2.json").read_text(encoding="utf-8")
)
VALIDATOR: Any = Draft202012Validator(SCHEMA)
NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.UTC)
UID = 1000
DISABLED = False


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stat_of(data: bytes) -> dict[str, object]:
    return {
        "checksum": sha(data),
        "isreg": True,
        "islnk": False,
        "mode": "0600",
        "size": len(data),
        "uid": UID,
    }


def build(**inputs: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(dumps(report.build_report(ReportInputs(**inputs))))
    assert VALIDATOR.is_valid(document), [e.message[:200] for e in VALIDATOR.iter_errors(document)]
    return document


def host_identity(name: str) -> model.HostIdentity:
    machine = "e" * 32 if name == "web01" else "d" * 32
    return model.HostIdentity(f"{name}.example", "rhel", "9", "x86_64", machine)


def audited_fact(
    run: model.ScanRun, waivers: dict[str, object], received: dict[str, bytes]
) -> dict[str, object]:
    directory = f"/var/lib/freesecdev/linux_compliance/evidence/{run.run_id}"
    names = {"raw/scan-run.json": ("scan_run", "scan-run.json")}
    names["raw/scan/results.xml"] = ("scanner_output", "scan/results.xml")
    return {
        "evidence": {
            "directory": directory,
            "files": [
                {
                    "kind": names[path][0],
                    "path": f"{directory}/{names[path][1]}",
                    "sha256": sha(data),
                    "size": len(data),
                }
                for path, data in received.items()
            ],
        },
        "evidence_written": True,
        "exceptions": waivers,
        "run_id": run.run_id,
        "run_status": "completed",
        "scan_run": run.to_dict(),
    }


def write_bundle(
    kit: Any,
    root: Path,
    host: str = "web01",
    *,
    applied: bool = True,
    text: str | None = None,
) -> Path:
    run = kit.evaluation_run(host=host_identity(host), run_id=f"run-{host}")
    content = kit.EXCEPTIONS_FILE.read_text(encoding="utf-8") if text is None else text
    received = {
        "raw/scan-run.json": (model.dumps(run) + "\n").encode("utf-8"),
        "raw/scan/results.xml": kit.xccdf_text(f"{host}.example").encode("utf-8"),
    }
    waivers: dict[str, object] = {"applied": False, "status": "not_requested"}
    if applied:
        waivers = {
            "applied": True,
            "evaluation": kit.evaluate(
                run, inventory_host=host, groups=(host[:-2],), text=content
            ).to_dict(),
            "file": "/srv/compliance/exceptions.yml",
            "source_sha256": sha(content.encode("utf-8")),
            "status": "applied",
        }
    collected = evidence.Collected(
        host=host,
        include_arf=DISABLED,
        observed={path: stat_of(data) for path, data in received.items()},
        scan_run_text=received["raw/scan-run.json"].decode("utf-8"),
        exceptions_text=content if applied else None,
        stale={},
        machine_id=run.host.machine_id,
        collection_version="0.1.0",
        controller_uid=UID,
    )
    result = evidence.build_documents(audited_fact(run, waivers, received), collected, NOW)
    contents = dict(received)
    for path, document in cast("dict[str, str]", result["documents"]).items():
        contents[path] = document.encode("utf-8")
    contents[evidence.MANIFEST_NAME] = cast("str", result["manifest"]).encode("utf-8")
    for path, data in contents.items():
        (root / host / path).parent.mkdir(parents=True, exist_ok=True)
        (root / host / path).write_bytes(data)
    return root / host


def test_the_report_reads_waived_findings_and_exception_statuses_from_bundles(
    kit: Any, tmp_path: Path
) -> None:
    first = write_bundle(kit, tmp_path, "web01")
    second = write_bundle(kit, tmp_path, "db01")
    document = build(scope=Scope.MULTI_HOST, evidence_bundle=(first, second))
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "available"
    assert [item["format"] for item in compliance["items"]] == ["exceptions_evaluation"] * 2
    assert [item["artifact"]["path"] for item in compliance["items"]] == [
        f"{first}/exceptions/evaluation.json",
        f"{second}/exceptions/evaluation.json",
    ]
    waived = sum(group["summary"]["counts"]["waived"] for group in compliance["groups"])
    assert waived >= 1
    exceptions_section = document["sections"]["exceptions"]
    assert exceptions_section["status"] == "available"
    assert exceptions_section["exceptions_file"] == {
        "path": f"{first}/exceptions/exceptions.yml",
        "sha256": sha(kit.EXCEPTIONS_FILE.read_bytes()),
        "verified": True,
    }
    assert exceptions_section["summary"]["evaluations"] == 2
    formats = sorted(artifact["format"] for artifact in document["raw_artifacts"])
    assert formats == ["exceptions_evaluation", "exceptions_evaluation", "exceptions_file"]


def test_a_bundle_without_exceptions_contributes_its_raw_scan_run(
    kit: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_bundle(kit, tmp_path, "web01", applied=False)
    monkeypatch.chdir(tmp_path)
    document = build(scope=Scope.SINGLE_HOST, evidence_bundle=(Path("web01"),))
    items = document["sections"]["compliance"]["items"]
    assert [(item["format"], item["status"]) for item in items] == [("scan_run", "available")]
    assert items[0]["artifact"]["path"] == "web01/raw/scan-run.json"
    assert document["sections"]["exceptions"]["status"] == "unavailable"


def test_a_missing_bundle_is_unavailable(tmp_path: Path) -> None:
    document = build(scope=Scope.SINGLE_HOST, evidence_bundle=(tmp_path / "absent",))
    item = document["sections"]["compliance"]["items"][0]
    assert item["status"] == "unavailable"
    assert item["format"] == "exceptions_evaluation"
    assert item["reason"] == "evidence bundle does not exist"
    assert document["sections"]["exceptions"]["status"] == "unavailable"
    assert item["artifact"] == {
        "path": f"{tmp_path}/absent/bundle.json",
        "sha256": None,
        "size": None,
    }


def corrupt(path: str, data: bytes) -> Callable[[Path], None]:
    def change(target: Path) -> None:
        (target / path).write_bytes(data)

    return change


def add_file(path: str) -> Callable[[Path], None]:
    def change(target: Path) -> None:
        (target / path).parent.mkdir(parents=True, exist_ok=True)
        (target / path).write_bytes(b"{}")

    return change


def add_symlink(target: Path) -> None:
    (target / "raw" / "link.json").symlink_to(target / "raw" / "scan-run.json")


def add_fifo(target: Path) -> None:
    os.mkfifo(target / "raw" / "pipe")


def add_many(target: Path) -> None:
    for number in range(bundle.MAX_ENTRIES):
        (target / f"extra-{number}").write_bytes(b"x")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            corrupt("raw/scan/results.xml", b"<changed/>"),
            "checksum mismatch for raw/scan/results.xml",
        ),
        (add_file("bundle.sigstore.json"), "carries a signature"),
        (add_file("raw/notes.txt"), "does not list: 'raw/notes.txt'"),
        (add_file("other/file.json"), "unexpected directory 'other'"),
        (add_symlink, "'raw/link.json' in the bundle is not a regular file or a directory"),
        (add_fifo, "'raw/pipe' in the bundle is not a regular file"),
        (add_many, "more than 64 entries"),
        (
            corrupt("raw/scan/results.xml", b""),
            "'raw/scan/results.xml' in the bundle: input file is empty",
        ),
    ],
)
def test_a_bundle_that_does_not_verify_is_an_input_error_in_both_sections(
    kit: Any, tmp_path: Path, change: Callable[[Path], None], message: str
) -> None:
    target = write_bundle(kit, tmp_path)
    change(target)
    document = build(scope=Scope.SINGLE_HOST, evidence_bundle=(target,))
    compliance = document["sections"]["compliance"]
    assert compliance["status"] == "error"
    assert message in compliance["gaps"][0]["reason"]
    assert compliance["items"][0]["format"] == "exceptions_evaluation"
    assert document["sections"]["exceptions"]["status"] == "error"
    assert document["sections"]["exceptions"]["exceptions_file"] is None


def test_a_tampered_bundle_without_exceptions_is_a_scan_run_error(kit: Any, tmp_path: Path) -> None:
    target = write_bundle(kit, tmp_path, applied=False)
    (target / "raw" / "scan" / "results.xml").write_bytes(b"<changed/>")
    document = build(scope=Scope.SINGLE_HOST, evidence_bundle=(target,))
    item = document["sections"]["compliance"]["items"][0]
    assert (item["format"], item["status"]) == ("scan_run", "error")
    assert item["artifact"]["sha256"] == sha((target / "bundle.json").read_bytes())
    assert document["sections"]["exceptions"]["status"] == "unavailable"


def test_a_file_above_the_size_limit_is_refused(kit: Any, tmp_path: Path) -> None:
    target = write_bundle(kit, tmp_path)
    document = build(scope=Scope.SINGLE_HOST, evidence_bundle=(target,), max_bytes=64)
    assert "is larger than 64 bytes" in document["sections"]["compliance"]["gaps"][0]["reason"]


def test_a_symlinked_or_non_directory_bundle_path_is_refused(kit: Any, tmp_path: Path) -> None:
    target = write_bundle(kit, tmp_path)
    link = tmp_path / "link"
    link.symlink_to(target)
    for path in (link, target / "bundle.json"):
        document = build(scope=Scope.SINGLE_HOST, evidence_bundle=(path,))
        reason = document["sections"]["compliance"]["gaps"][0]["reason"]
        assert "cannot be opened (not a directory, or a symbolic link)" in reason


def test_a_bundle_that_cannot_be_listed_is_refused(
    kit: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = write_bundle(kit, tmp_path)

    def refuse(_directory: int) -> object:
        raise PermissionError

    monkeypatch.setattr(os, "scandir", refuse)
    with pytest.raises(InvalidInputError, match="cannot be read"):
        bundle.read_bundle(target, 1024)


def test_bundles_of_different_exceptions_files_are_refused(kit: Any, tmp_path: Path) -> None:
    first = write_bundle(kit, tmp_path, "web01")
    other = kit.EXCEPTIONS_FILE.read_text(encoding="utf-8") + "\n"
    second = write_bundle(kit, tmp_path, "db01", text=other)
    with pytest.raises(ReportError, match="name 2 different exceptions files"):
        report.build_report(ReportInputs(scope=Scope.FLEET, evidence_bundle=(first, second)))


def test_the_exceptions_file_option_must_match_the_bundles(
    kit: Any, tmp_path: Path, write: Any
) -> None:
    target = write_bundle(kit, tmp_path)
    same = build(
        scope=Scope.SINGLE_HOST, evidence_bundle=(target,), exceptions_file=kit.EXCEPTIONS_FILE
    )
    assert same["sections"]["exceptions"]["exceptions_file"]["path"] == str(kit.EXCEPTIONS_FILE)
    other = write("other.yml", kit.EXCEPTIONS_FILE.read_text(encoding="utf-8") + "\n")
    with pytest.raises(ReportError, match="different exceptions files"):
        report.build_report(
            ReportInputs(scope=Scope.SINGLE_HOST, evidence_bundle=(target,), exceptions_file=other)
        )


def test_the_exceptions_file_option_needs_an_evaluation(kit: Any, tmp_path: Path) -> None:
    target = write_bundle(kit, tmp_path, applied=False)
    with pytest.raises(
        ReportError, match="only used with --exceptions-evaluation or with evidence"
    ):
        report.build_report(
            ReportInputs(
                scope=Scope.SINGLE_HOST,
                evidence_bundle=(target,),
                exceptions_file=kit.EXCEPTIONS_FILE,
            )
        )


def test_supplied_evaluations_are_verified_against_the_exceptions_file_of_a_bundle(
    kit: Any, tmp_path: Path, write: Any
) -> None:
    target = write_bundle(kit, tmp_path, "db01")
    evaluation = write("web01.json", kit.evaluation_json(kit.evaluate()))
    document = build(
        scope=Scope.FLEET, evidence_bundle=(target,), exceptions_evaluation=(evaluation,)
    )
    assert document["sections"]["exceptions"]["status"] == "available"
    assert document["sections"]["exceptions"]["summary"]["evaluations"] == 2


def test_the_command_line_accepts_evidence_bundles(kit: Any, tmp_path: Path) -> None:
    target = write_bundle(kit, tmp_path)
    output = tmp_path / "report.json"
    status = cli.main(
        ["--scope", "single_host", "--output", str(output), "--evidence-bundle", str(target)]
    )
    assert status == cli.EXIT_OK
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["sections"]["exceptions"]["status"] == "available"


def test_a_rejected_bundle_counts_in_the_exceptions_section_unless_its_manifest_says_none(
    kit: Any, tmp_path: Path
) -> None:
    plain = write_bundle(kit, tmp_path / "plain", applied=False)
    add_fifo(plain)
    unreadable = write_bundle(kit, tmp_path / "unreadable", applied=False)
    add_fifo(unreadable)
    (unreadable / "bundle.json").unlink()
    broken = write_bundle(kit, tmp_path / "broken", applied=False)
    (broken / "bundle.json").write_bytes(b"{}")
    formats = {}
    for name, target in (("plain", plain), ("unreadable", unreadable), ("broken", broken)):
        document = build(scope=Scope.SINGLE_HOST, evidence_bundle=(target,))
        item = document["sections"]["compliance"]["items"][0]
        assert item["status"] == "error"
        formats[name] = item["format"]
    assert formats == {
        "plain": "scan_run",
        "unreadable": "exceptions_evaluation",
        "broken": "exceptions_evaluation",
    }
