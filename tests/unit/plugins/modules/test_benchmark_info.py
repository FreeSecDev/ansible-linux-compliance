from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.modules import benchmark_info

if TYPE_CHECKING:
    from collections.abc import Mapping

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "catalog"
MODULE_FILE = Path(__file__).resolve().parents[4] / "plugins" / "modules" / "benchmark_info.py"
SYNTHETIC = FIXTURES / "synthetic-ds.xml"
SHA256 = hashlib.sha256(SYNTHETIC.read_bytes()).hexdigest()


def run_as_script() -> None:
    spec = importlib.util.spec_from_file_location("__main__", MODULE_FILE)
    assert spec is not None
    assert spec.loader is not None
    spec.loader.exec_module(importlib.util.module_from_spec(spec))


def run(
    capsys: pytest.CaptureFixture[str], arguments: Mapping[str, object]
) -> tuple[int, dict[str, object]]:
    with patch_module_args(dict(arguments)), pytest.raises(SystemExit) as raised:
        benchmark_info.main()
    output = capsys.readouterr().out
    return int(cast("int", raised.value.code)), cast("dict[str, object]", json.loads(output))


def arguments(**overrides: object) -> dict[str, object]:
    return {"content_path": str(SYNTHETIC), "expected_sha256": SHA256, **overrides}


def test_success_reports_benchmark_and_profiles_without_change(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, result = run(capsys, arguments())
    assert code == 0
    assert result["changed"] is False
    assert result["benchmark_id"] == "xccdf_org.example.synthetic_benchmark_demo"
    assert result["benchmark_version"] == "1.2.3"
    assert result["content_sha256"] == SHA256
    profiles = cast("list[dict[str, object]]", result["profiles"])
    assert [item["rule_count"] for item in profiles] == [2, 5, 1]


def test_check_mode_behaves_like_a_normal_run(capsys: pytest.CaptureFixture[str]) -> None:
    normal = run(capsys, arguments())[1]
    code, checked = run(capsys, arguments(_ansible_check_mode=True))
    assert code == 0
    assert checked == normal


def test_a_directory_with_one_datastream_is_accepted(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "copy-ds.xml").write_bytes(SYNTHETIC.read_bytes())
    code, result = run(capsys, arguments(content_path=str(tmp_path)))
    assert code == 0
    assert result["content_path"] == str(tmp_path / "copy-ds.xml")


def test_a_digest_mismatch_is_a_clean_failure(capsys: pytest.CaptureFixture[str]) -> None:
    code, result = run(capsys, arguments(expected_sha256="0" * 64))
    assert code == 1
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["error_type"] == "digest_mismatch"
    assert "benchmark_id" not in result


def test_hostile_content_with_a_wrong_digest_is_never_parsed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    hostile = FIXTURES / "adversarial" / "entity-expansion.xml"
    code, result = run(capsys, arguments(content_path=str(hostile)))
    assert code == 1
    assert result["error_type"] == "digest_mismatch"


def test_hostile_content_with_a_matching_digest_is_invalid(
    capsys: pytest.CaptureFixture[str],
) -> None:
    hostile = FIXTURES / "adversarial" / "doctype.xml"
    sha = hashlib.sha256(hostile.read_bytes()).hexdigest()
    code, result = run(capsys, arguments(content_path=str(hostile), expected_sha256=sha))
    assert code == 1
    assert result["error_type"] == "invalid_content"


def test_a_relative_path_is_a_clean_failure(capsys: pytest.CaptureFixture[str]) -> None:
    code, result = run(capsys, arguments(content_path="relative-ds.xml"))
    assert code == 1
    assert result["error_type"] == "invalid_content"


@pytest.mark.parametrize("missing", ["content_path", "expected_sha256"])
def test_required_arguments(capsys: pytest.CaptureFixture[str], missing: str) -> None:
    given = arguments()
    del given[missing]
    code, result = run(capsys, given)
    assert code == 1
    assert "missing required arguments" in str(result["msg"])


def test_running_the_file_as_a_script_runs_main(capsys: pytest.CaptureFixture[str]) -> None:
    with patch_module_args(arguments()), pytest.raises(SystemExit) as raised:
        run_as_script()
    assert raised.value.code == 0
    assert json.loads(capsys.readouterr().out)["changed"] is False


def content_tree(tmp_path: Path) -> Path:
    """Lay out ``opt`` as a symlink to ``var/opt``, as on image-mode RHEL; return the file."""
    tmp_path.chmod(0o755)
    real = tmp_path / "var" / "opt" / "content"
    real.mkdir(parents=True)
    for folder in (tmp_path / "var", tmp_path / "var" / "opt", real):
        folder.chmod(0o755)
    shutil.copyfile(SYNTHETIC, real / "copy-ds.xml")
    (real / "copy-ds.xml").chmod(0o644)
    (tmp_path / "opt").symlink_to("var/opt")
    return real / "copy-ds.xml"


def owned_by(monkeypatch: pytest.MonkeyPatch, path: Path, uid: int) -> None:
    original = Path.lstat

    def lstat(self: Path) -> os.stat_result:
        info = original(self)
        if self != path:
            return info
        fields = list(info[:10])
        fields[stat.ST_UID] = uid
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", lstat)


def test_a_vetted_symlinked_layout_reports_the_real_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    real = content_tree(tmp_path)
    for given in (tmp_path / "opt" / "content", tmp_path / "opt" / "content" / "copy-ds.xml"):
        code, result = run(capsys, arguments(content_path=str(given)))
        assert code == 0
        assert result["content_path"] == str(real)


@pytest.mark.parametrize("permissions", [0o777, 0o775])
def test_a_writable_content_directory_is_refused_before_it_is_read(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    permissions: int,
) -> None:
    real = content_tree(tmp_path)
    real.parent.chmod(permissions)
    opened: list[str] = []
    original = Path.open

    def recording_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opened.append(str(self))
        return cast("Any", original(self, *args, **kwargs))

    monkeypatch.setattr(Path, "open", recording_open)
    code, result = run(capsys, arguments(content_path=str(tmp_path / "opt" / "content")))
    assert code == 1
    assert result["changed"] is False
    assert result["error_type"] == "unsafe_content_dir"
    assert "writable by group or others" in str(result["msg"])
    assert "benchmark_id" not in result
    assert str(real) not in opened


@pytest.mark.parametrize("target", ["link", "ancestor", "datastream"])
def test_content_that_another_user_owns_is_refused(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    real = content_tree(tmp_path)
    paths = {"link": tmp_path / "opt", "ancestor": tmp_path / "var", "datastream": real}
    owned_by(monkeypatch, paths[target], os.geteuid() + 1)
    code, result = run(capsys, arguments(content_path=str(tmp_path / "opt" / "content")))
    assert code == 1
    assert result["error_type"] == "unsafe_content_dir"
    assert "unexpected owner" in str(result["msg"])


def test_a_group_writable_datastream_is_refused(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    real = content_tree(tmp_path)
    real.chmod(0o664)
    code, result = run(capsys, arguments(content_path=str(real)))
    assert code == 1
    assert result["error_type"] == "unsafe_content_dir"
