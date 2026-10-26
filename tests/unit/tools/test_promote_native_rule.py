from __future__ import annotations

import runpy
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.roles import generate_toggles
from tools.roles import promote_native_rule as promote

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CATALOGUE = REPOSITORY_ROOT / generate_toggles.CATALOGUE
SSH_RULE = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
SYSCTL_RULE = "xccdf_org.ssgproject.content_rule_sysctl_kernel_dmesg_restrict"
CRONTAB_RULE = "xccdf_org.ssgproject.content_rule_file_permissions_crontab"


def copy_catalogue(tmp_path: Path) -> Path:
    target = tmp_path / "rules.yml"
    shutil.copyfile(CATALOGUE, target)
    return target


def load(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


def test_the_promoted_rule_is_a_native_disruptive_rule_of_its_family(tmp_path: Path) -> None:
    target = copy_catalogue(tmp_path)
    assert promote.main(["--catalogue", str(target), "--rule", SSH_RULE]) == 0
    data = load(target)
    assert target.read_text(encoding="utf-8").startswith("---\n")
    rules = cast("list[dict[str, object]]", data[generate_toggles.RULES_KEY])
    assert rules[-1] == {
        "rule_id": SSH_RULE,
        "family": "ssh",
        "disruptive": True,
        "reversible": True,
        "revert_strategy": "recorded_state",
        "toggle": "linux_compliance_rule_sshd_disable_root_login_enabled",
        "runbook": None,
        "parameters": {},
    }
    audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])
    assert SSH_RULE not in audit_only["ssh"]
    original = load(CATALOGUE)
    original_audit_only = cast("dict[str, list[str]]", original[generate_toggles.AUDIT_ONLY_KEY])
    assert audit_only["ssh"] == [rule for rule in original_audit_only["ssh"] if rule != SSH_RULE]
    assert data[generate_toggles.FAMILIES_KEY] == original[generate_toggles.FAMILIES_KEY]
    catalogue = generate_toggles.load_catalogue(target)
    assert generate_toggles.native_families(catalogue) == ["file_permissions", "ssh"]


def test_the_repository_catalogue_is_never_rewritten(
    capsys: pytest.CaptureFixture[str],
) -> None:
    before = CATALOGUE.read_bytes()
    assert promote.main(["--catalogue", str(CATALOGUE), "--rule", SSH_RULE]) == 2
    assert "promote only in a copy" in capsys.readouterr().err
    assert CATALOGUE.read_bytes() == before


@pytest.mark.parametrize(
    ("rule_id", "message"),
    [
        (CRONTAB_RULE, "is not an audit_only rule of the catalogue"),
        ("xccdf_org.ssgproject.content_rule_unknown", "is not an audit_only rule of the catalogue"),
        (SYSCTL_RULE, "belongs to sysctl, which is not a disruptive family"),
    ],
)
def test_only_an_audit_only_rule_of_a_disruptive_family_is_promoted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], rule_id: str, message: str
) -> None:
    target = copy_catalogue(tmp_path)
    before = target.read_bytes()
    assert promote.main(["--catalogue", str(target), "--rule", rule_id]) == 2
    assert message in capsys.readouterr().err
    assert target.read_bytes() == before


def test_main_runs_as_a_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = copy_catalogue(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["promote_native_rule", "--catalogue", str(target), "--rule", SSH_RULE]
    )
    monkeypatch.delitem(sys.modules, "tools.roles.promote_native_rule", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.roles.promote_native_rule", run_name="__main__")
    assert raised.value.code == 0
    assert f"promoted {SSH_RULE}" in capsys.readouterr().out
