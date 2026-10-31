"""The metadata listing of the Molecule lifecycle harness (FREES-180, ADR 0027).

``tree_info`` lists every entry below directories, as ``ansible.builtin.find`` with ``recurse``,
``hidden`` and ``file_type: any`` lists them, without following a symbolic link and without
reading content; a directory or an entry that it cannot read fails the module.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.modules import tree_info

MODULE_FILE = Path(__file__).resolve().parents[4] / "plugins" / "modules" / "tree_info.py"

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


def run(
    capsys: pytest.CaptureFixture[str], arguments: Mapping[str, object]
) -> tuple[int, dict[str, object]]:
    capsys.readouterr()
    with patch_module_args(dict(arguments)), pytest.raises(SystemExit) as raised:
        tree_info.main()
    output = capsys.readouterr().out
    return int(cast("int", raised.value.code)), cast("dict[str, object]", json.loads(output))


def rows(text: object) -> list[list[str]]:
    values = str(text).split(tree_info.SEPARATOR)
    assert values[-1] == ""
    width = len(tree_info.FIELDS)
    return [values[index : index + width] for index in range(0, len(values) - 1, width)]


def tree(base: Path) -> Path:
    top = base / "top"
    (top / "sub" / ".hidden").mkdir(parents=True)
    (top / "file").write_text("content", encoding="utf-8")
    (top / "sub" / ".hidden" / "deep").write_text("x", encoding="utf-8")
    (base / "outside").mkdir()
    (base / "outside" / "not-listed").write_text("x", encoding="utf-8")
    (top / "link-to-outside").symlink_to(base / "outside")
    os.mkfifo(top / "fifo")
    (top / "file").chmod(0o640)
    return top


def test_every_entry_below_the_paths_is_listed_with_its_metadata(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    top = tree(tmp_path)
    code, result = run(capsys, {"paths": [str(top)]})
    assert code == 0
    assert result["changed"] is False
    assert result["fields"] == list(tree_info.FIELDS)
    listed = {row[0]: row for row in rows(result["listing"])}
    names = ("fifo", "file", "link-to-outside", "sub", "sub/.hidden", "sub/.hidden/deep")
    assert sorted(listed) == sorted(str(top / name) for name in names)
    assert result["count"] == len(listed)
    info = (top / "file").lstat()
    assert listed[str(top / "file")] == [
        str(top / "file"),
        "file",
        "0640",
        str(info.st_uid),
        str(info.st_gid),
        "7",
        str(info.st_ino),
        str(info.st_mtime),
        str(info.st_ctime),
    ]
    kinds = {name: row[1] for name, row in listed.items()}
    assert kinds[str(top / "link-to-outside")] == "link"
    assert kinds[str(top / "sub")] == "directory"
    assert kinds[str(top / "fifo")] == "other"


def test_check_mode_lists_the_same_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    top = tree(tmp_path)
    plain_code, plain = run(capsys, {"paths": [str(top)]})
    code, checked = run(capsys, {"paths": [str(top)], "_ansible_check_mode": True})
    assert plain_code == 0
    assert code == 0
    assert checked["listing"] == plain["listing"]


def test_several_paths_are_listed_in_their_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "one").write_text("", encoding="utf-8")
    (second / "two").write_text("", encoding="utf-8")
    code, result = run(capsys, {"paths": [str(second), str(first)]})
    assert code == 0
    assert [row[0] for row in rows(result["listing"])] == [str(second / "two"), str(first / "one")]


def test_an_empty_directory_lists_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, result = run(capsys, {"paths": [str(tmp_path)]})
    assert code == 0
    assert result["listing"] == ""
    assert result["count"] == 0


@pytest.mark.parametrize(
    ("name", "error_type"),
    [
        ("missing", tree_info.UNREADABLE),
        ("file", tree_info.NOT_A_DIRECTORY),
        ("link", tree_info.NOT_A_DIRECTORY),
    ],
)
def test_a_path_that_is_not_a_directory_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str, error_type: str
) -> None:
    (tmp_path / "file").write_text("", encoding="utf-8")
    (tmp_path / "directory").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "directory")
    code, result = run(capsys, {"paths": [str(tmp_path / name)]})
    assert code == 1
    assert result["error_type"] == error_type
    assert result["path"] == str(tmp_path / name)


def test_a_relative_path_is_refused() -> None:
    with pytest.raises(tree_info.TreeError) as raised:
        tree_info.listing(["relative/path"])
    assert raised.value.error_type == tree_info.NOT_ABSOLUTE


def test_a_directory_that_cannot_be_listed_fails_the_module(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    top = tree(tmp_path)
    closed = top / "sub"
    listed = Path.iterdir

    def iterdir(self: Path) -> Iterator[Path]:
        if self == closed:
            raise PermissionError(13, "Permission denied")
        return listed(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    code, result = run(capsys, {"paths": [str(top)]})
    assert code == 1
    assert result["error_type"] == tree_info.UNREADABLE
    assert result["path"] == str(closed)
    assert "cannot be listed: Permission denied" in str(result["msg"])


def test_an_entry_whose_metadata_cannot_be_read_fails_the_module(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    top = tree(tmp_path)
    vanished = top / "file"
    read = Path.lstat

    def lstat(self: Path) -> os.stat_result:
        if self == vanished:
            raise FileNotFoundError(2, "No such file or directory")
        return read(self)

    monkeypatch.setattr(Path, "lstat", lstat)
    code, result = run(capsys, {"paths": [str(top)]})
    assert code == 1
    assert result["error_type"] == tree_info.UNREADABLE
    assert result["path"] == str(vanished)


def test_the_module_runs_as_a_script(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spec = importlib.util.spec_from_file_location("__main__", MODULE_FILE)
    assert spec is not None
    assert spec.loader is not None
    capsys.readouterr()
    with patch_module_args({"paths": [str(tmp_path)]}), pytest.raises(SystemExit) as raised:
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    assert raised.value.code == 0
