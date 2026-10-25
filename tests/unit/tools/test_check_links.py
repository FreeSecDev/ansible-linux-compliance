from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

from tools.docs import check_links as links


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", []),
        ("[a](b.md)", [(1, "b.md")]),
        ("x\n[a](b.md) and [c](d/e.md#frag)\n", [(2, "b.md"), (2, "d/e.md#frag")]),
        ("[a](<spaced.md>)", [(1, "spaced.md")]),
        ('[a](b.md "title")', [(1, "b.md")]),
        ("[a]( b.md )", [(1, "b.md")]),
        ("`[a](b.md)` text [c](d.md)", [(1, "d.md")]),
        ("```\n[a](b.md)\n```\n[c](d.md)", [(4, "d.md")]),
        ("~~~\n[a](b.md)\n~~~\n[c](d.md)", [(4, "d.md")]),
        ("```\n~~~\n[a](b.md)\n```\n[c](d.md)", [(5, "d.md")]),
        ("```\n[a](b.md)", []),
        ("[a]()", []),
        ("[ünï](ü.md)", [(1, "ü.md")]),
        ("![img](pic.png)", [(1, "pic.png")]),
    ],
)
def test_extract_links(text: str, expected: list[tuple[int, str]]) -> None:
    assert links.extract_links(text) == expected


def test_target_exists(tmp_path: Path) -> None:
    (tmp_path / "a b.md").write_text("x", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    assert links.target_exists(tmp_path, "a%20b.md") is True
    assert links.target_exists(tmp_path, "a%20b.md#anchor") is True
    assert links.target_exists(tmp_path, "sub?query=1") is True
    assert links.target_exists(tmp_path, "sub/") is True
    assert links.target_exists(tmp_path / "sub", "../a%20b.md") is True
    assert links.target_exists(tmp_path, "missing.md") is False
    assert links.target_exists(tmp_path, "#only-anchor-path") is True


@pytest.mark.parametrize("target", ["/etc/passwd", "a%00b", "x" * 5000])
def test_target_exists_rejects_hostile_targets(tmp_path: Path, target: str) -> None:
    assert links.target_exists(tmp_path, target) is False


def test_check_file_reports_only_broken_relative_links(tmp_path: Path) -> None:
    (tmp_path / "ok.md").write_text("x", encoding="utf-8")
    document = tmp_path / "doc.md"
    document.write_text(
        "[ok](ok.md) [web](https://example.org) [mail](mailto:a@b.c) [anchor](#top) "
        "[proto](//cdn.example.org/x) [ftp](ftp://host/x)\n[bad](nope.md)\n",
        encoding="utf-8",
    )
    assert links.check_file(document) == [links.BrokenLink(document, 2, "nope.md")]


def test_check_file_unreadable(tmp_path: Path) -> None:
    assert links.check_file(tmp_path / "missing.md")[0].target == "<unreadable file>"


def test_check_file_invalid_utf8(tmp_path: Path) -> None:
    document = tmp_path / "bad.md"
    document.write_bytes(b"\xff\xfe")
    assert links.check_file(document)[0].target == "<unreadable file>"


def test_check_file_empty(tmp_path: Path) -> None:
    document = tmp_path / "empty.md"
    document.write_bytes(b"")
    assert links.check_file(document) == []


def test_broken_link_string() -> None:
    assert str(links.BrokenLink(Path("a.md"), 3, "x.md")) == "a.md:3: broken relative link 'x.md'"


def test_check_paths_filters_suffix_and_sorts(tmp_path: Path) -> None:
    first = tmp_path / "b.md"
    second = tmp_path / "a.MARKDOWN"
    other = tmp_path / "c.txt"
    first.write_text("[x](gone.md)", encoding="utf-8")
    second.write_text("[x](gone.md)", encoding="utf-8")
    other.write_text("[x](gone.md)", encoding="utf-8")
    found = links.check_paths([first, second, other])
    assert [broken.path.name for broken in found] == ["a.MARKDOWN", "b.md"]


def test_main_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    document = tmp_path / "ok.md"
    document.write_text("[self](ok.md)", encoding="utf-8")
    assert links.main([str(document)]) == 0
    assert "valid in 1 file(s)" in capsys.readouterr().out


def test_main_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    document = tmp_path / "bad.md"
    document.write_text("[x](gone.md)", encoding="utf-8")
    assert links.main([str(document)]) == 1
    error = capsys.readouterr().err
    assert f"{document}:1: broken relative link 'gone.md'" in error
    assert "1 broken relative link(s)" in error


def test_main_without_paths(capsys: pytest.CaptureFixture[str]) -> None:
    assert links.main([]) == 0
    assert "valid in 0 file(s)" in capsys.readouterr().out


def test_script_entry_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    document = tmp_path / "ok.md"
    document.write_text("text", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_links", str(document)])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(links.__file__, run_name="__main__")
    assert raised.value.code == 0
    assert "valid" in capsys.readouterr().out
