from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.modules import profile_info

if TYPE_CHECKING:
    from collections.abc import Mapping

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "catalog"
MODULE_FILE = Path(__file__).resolve().parents[4] / "plugins" / "modules" / "profile_info.py"
SYNTHETIC = FIXTURES / "synthetic-ds.xml"
SHA256 = hashlib.sha256(SYNTHETIC.read_bytes()).hexdigest()
PROFILE = "xccdf_org.example.synthetic_profile_baseline"
RULE = "xccdf_org.example.synthetic_rule_"


def run_as_script() -> None:
    spec = importlib.util.spec_from_file_location("__main__", MODULE_FILE)
    assert spec is not None
    assert spec.loader is not None
    spec.loader.exec_module(importlib.util.module_from_spec(spec))


def run(
    capsys: pytest.CaptureFixture[str], arguments: Mapping[str, object]
) -> tuple[int, dict[str, object]]:
    with patch_module_args(dict(arguments)), pytest.raises(SystemExit) as raised:
        profile_info.main()
    output = capsys.readouterr().out
    return int(cast("int", raised.value.code)), cast("dict[str, object]", json.loads(output))


def arguments(**overrides: object) -> dict[str, object]:
    return {
        "content_path": str(SYNTHETIC),
        "expected_sha256": SHA256,
        "profile_id": PROFILE,
        **overrides,
    }


def test_success_reports_the_selected_rules_without_change(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, result = run(capsys, arguments())
    assert code == 0
    assert result["changed"] is False
    assert result["profile_id"] == PROFILE
    assert result["profile_title"] == "Synthetic baseline"
    assert result["benchmark_version"] == "1.2.3"
    assert result["rule_count"] == 2
    assert result["rule_ids"] == [RULE + "alpha", RULE + "beta"]
    assert result["rules"] == [
        {"rule_id": RULE + "alpha", "severity": "high", "title": "Synthetic alpha rule"},
        {"rule_id": RULE + "beta", "severity": "medium", "title": "Synthetic beta rule"},
    ]


def test_check_mode_behaves_like_a_normal_run(capsys: pytest.CaptureFixture[str]) -> None:
    normal = run(capsys, arguments())[1]
    code, checked = run(capsys, arguments(_ansible_check_mode=True))
    assert code == 0
    assert checked == normal


def test_a_missing_profile_fails_and_nothing_is_substituted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, result = run(capsys, arguments(profile_id="xccdf_org.example.synthetic_profile_absent"))
    assert code == 1
    assert result["error_type"] == "profile_not_found"
    assert "rule_ids" not in result
    assert result["changed"] is False


def test_a_short_profile_identifier_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    code, result = run(capsys, arguments(profile_id="baseline"))
    assert code == 1
    assert result["error_type"] == "invalid_content"


def test_a_digest_mismatch_is_a_clean_failure(capsys: pytest.CaptureFixture[str]) -> None:
    code, result = run(capsys, arguments(expected_sha256="f" * 64))
    assert code == 1
    assert result["error_type"] == "digest_mismatch"
    assert "rule_ids" not in result


def test_a_profile_that_selects_an_undefined_rule_is_invalid(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = FIXTURES / "adversarial" / "profile-selects-unknown-rule.xml"
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    code, result = run(capsys, arguments(content_path=str(path), expected_sha256=sha))
    assert code == 1
    assert result["error_type"] == "unsupported_content"


@pytest.mark.parametrize("missing", ["content_path", "expected_sha256", "profile_id"])
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
    assert json.loads(capsys.readouterr().out)["rule_count"] == 2
