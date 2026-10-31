"""Tests of the corpus and the table assembly of ``make pam-reader-verdicts``."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from typing import cast

import pytest

from tools.pam import reader_corpus

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TABLE = REPOSITORY_ROOT / reader_corpus.TABLE


def committed() -> dict[str, object]:
    return cast("dict[str, object]", json.loads(TABLE.read_text(encoding="utf-8")))


def write_outputs(directory: Path, *, skip: str | None = None) -> None:
    """Write the image outputs that would give the committed table."""
    document = committed()
    keys = cast("dict[str, list[str]]", document["reading_keys"])
    platforms = cast("dict[str, dict[str, str]]", document["platforms"])
    directory.mkdir()
    for platform, versions in platforms.items():
        lines = [json.dumps({"platform": platform, **versions})]
        for entry in cast("list[dict[str, object]]", document["cases"]):
            if entry["id"] == skip:
                continue
            values = cast("dict[str, list[int]]", entry["readings"])[platform]
            reading = dict(zip(keys[str(entry["reader"])], values, strict=True))
            lines.append(json.dumps({"id": entry["id"], "reading": reading}))
        (directory / f"{platform}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_the_cases_are_written_with_the_file_the_reader_and_the_arguments(tmp_path: Path) -> None:
    out = tmp_path / "cases"
    assert reader_corpus.write_cases(out) == len(reader_corpus.all_cases())
    case = next(case for case in reader_corpus.all_cases() if case.args)
    folder = out / case.case_id
    assert (folder / "conf").read_bytes() == case.text.encode("utf-8")
    assert (folder / "reader").read_text(encoding="utf-8") == case.reader + "\n"
    assert (folder / "args").read_text(encoding="utf-8").splitlines() == [
        "conf=@conf",
        *case.args,
    ]
    with pytest.raises(FileExistsError):
        reader_corpus.write_cases(out)


def test_the_table_assembled_from_the_outputs_is_the_committed_table(tmp_path: Path) -> None:
    write_outputs(tmp_path / "out")
    table = tmp_path / "table" / "verdicts.json"
    assert reader_corpus.assemble(tmp_path / "out", table) == len(reader_corpus.all_cases())
    assert table.read_text(encoding="utf-8") == TABLE.read_text(encoding="utf-8")


def test_assembly_refuses_outputs_that_miss_a_case_or_every_platform(tmp_path: Path) -> None:
    first = reader_corpus.all_cases()[0].case_id
    write_outputs(tmp_path / "out", skip=first)
    with pytest.raises(SystemExit, match=first):
        reader_corpus.assemble(tmp_path / "out", tmp_path / "table.json")
    (tmp_path / "empty").mkdir()
    with pytest.raises(SystemExit, match="every platform"):
        reader_corpus.assemble(tmp_path / "empty", tmp_path / "table.json")


def test_the_command_line_writes_cases_and_assembles(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    count = len(reader_corpus.all_cases())
    assert reader_corpus.main(["cases", "--out", str(tmp_path / "cases")]) == 0
    assert capsys.readouterr().out == f"cases: {count} cases\n"
    write_outputs(tmp_path / "out")
    table = tmp_path / "table.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["reader_corpus", "assemble", "--outputs", str(tmp_path / "out"), "--table", str(table)],
    )
    sys.modules.pop("tools.pam.reader_corpus", None)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("tools.pam.reader_corpus", run_name="__main__")
    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"assemble: {count} cases\n"
    assert table.read_text(encoding="utf-8") == TABLE.read_text(encoding="utf-8")
