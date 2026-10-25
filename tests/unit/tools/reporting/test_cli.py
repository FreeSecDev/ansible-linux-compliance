from __future__ import annotations

import json
import runpy
from typing import TYPE_CHECKING, Any

import pytest

from tools.reporting import cli

if TYPE_CHECKING:
    from pathlib import Path

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def run(argv: list[str]) -> int:
    return cli.main(argv)


def test_cli_writes_the_report(
    kit: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "nested" / "report.json"
    status = run(
        [
            "--scope",
            "single_host",
            "--output",
            str(output),
            "--junit",
            str(kit.REPORTING / "junit.xml"),
            "--junit",
            str(kit.REPORTING / "junit.xml"),
            "--commit",
            COMMIT,
            "--pull-request",
            "75",
            "--generated-at",
            "2026-10-25T10:11:00Z",
        ]
    )
    assert status == 0
    assert f"report written to {output}" in capsys.readouterr().out
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["scope"] == "single_host"
    assert document["metadata"]["commit"] == COMMIT
    assert len(document["sections"]["tests"]["items"]) == 2


def test_cli_exits_one_when_a_section_is_in_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.xml"
    bad.write_text("<other/>", encoding="utf-8")
    output = tmp_path / "report.json"
    assert run(["--scope", "fleet", "--output", str(output), "--junit", str(bad)]) == 1
    assert json.loads(output.read_text(encoding="utf-8"))["overview"]["error"] == ["tests"]


def test_cli_without_inputs_still_writes_an_all_unavailable_report(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    assert run(["--scope", "benchmark", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["overview"]["available"] == []


def test_cli_rejects_invalid_metadata(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "report.json"
    status = run(["--scope", "fleet", "--output", str(output), "--commit", "nope"])
    assert status == 2
    assert "commit has an invalid format" in capsys.readouterr().err
    assert not output.exists()


def test_cli_reports_an_unwritable_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    status = run(["--scope", "fleet", "--output", str(blocker / "report.json")])
    assert status == 2
    assert "cannot write the report" in capsys.readouterr().err


def test_cli_requires_scope_and_output() -> None:
    with pytest.raises(SystemExit) as raised:
        run(["--output", "x.json"])
    assert raised.value.code == 2


def test_cli_rejects_unknown_scope() -> None:
    with pytest.raises(SystemExit):
        run(["--scope", "everything", "--output", "x.json"])


def test_module_entry_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        "sys.argv", ["tools.reporting", "--scope", "fleet", "--output", str(output)]
    )
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.reporting", run_name="__main__")
    assert raised.value.code == 0
    assert output.exists()


def test_cli_exits_one_when_a_supplied_input_is_missing(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    argv = [
        "--scope",
        "fleet",
        "--output",
        str(output),
        "--scan-run",
        str(tmp_path / "absent.json"),
    ]
    assert run(argv) == 1
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["overview"]["unavailable"][0] == "codebuild"
    assert document["sections"]["compliance"]["gaps"][0]["status"] == "unavailable"


def test_cli_exits_one_for_a_partial_section(kit: Any, tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    argv = [
        "--scope",
        "fleet",
        "--output",
        str(output),
        "--junit",
        str(kit.REPORTING / "junit.xml"),
        "--junit",
        str(tmp_path / "absent.xml"),
    ]
    assert run(argv) == 1
    assert json.loads(output.read_text(encoding="utf-8"))["overview"]["partial"] == ["tests"]


def test_cli_rejects_a_scope_that_the_data_contradicts(
    kit: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "report.json"
    paths: list[str] = []
    for name in ("a", "b"):
        path = tmp_path / f"{name}.xml"
        path.write_text(kit.xccdf_text(name), encoding="utf-8")
        paths += ["--xccdf", str(path)]
    status = run(["--scope", "single_host", "--output", str(output), *paths])
    assert status == 2
    assert "2 hosts" in capsys.readouterr().err
    assert not output.exists()
    assert run(["--scope", "fleet", "--output", str(output), *paths]) == 0
