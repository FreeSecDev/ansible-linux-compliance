from __future__ import annotations

import runpy
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.roles import generate_toggles as gen

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCES = (gen.CATALOGUE, gen.DEFAULTS, gen.SPECS, gen.REFERENCE)


def copy_repository(root: Path) -> Path:
    for relative in SOURCES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY_ROOT / relative, target)
    return root


def load(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


def write_catalogue(root: Path, families: object, rules: object) -> None:
    (root / gen.CATALOGUE).write_text(
        yaml.safe_dump({gen.FAMILIES_KEY: families, gen.RULES_KEY: rules}), encoding="utf-8"
    )


def test_the_repository_files_are_up_to_date() -> None:
    generated = gen.outputs(REPOSITORY_ROOT)
    assert gen.drift(REPOSITORY_ROOT, generated) == []
    for relative, content in generated.items():
        assert (REPOSITORY_ROOT / relative).read_text(encoding="utf-8") == content


def test_every_family_and_rule_gets_a_bool_toggle_with_a_description() -> None:
    catalogue = gen.load_catalogue(REPOSITORY_ROOT / gen.CATALOGUE)
    specs = load(REPOSITORY_ROOT / gen.SPECS)
    entry_points = cast("dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]]", specs)
    options = entry_points["argument_specs"]["main"]["options"]
    defaults = load(REPOSITORY_ROOT / gen.DEFAULTS)
    for family, disruptive in catalogue.families.items():
        option = options[f"linux_compliance_{family}_enabled"]
        assert option["type"] == "bool"
        assert option["default"] is True
        description = cast("list[str]", option["description"])
        assert any("disruptive" in line for line in description) is disruptive
        assert defaults[f"linux_compliance_{family}_enabled"] is True
    for rule in catalogue.rules:
        option = options[str(rule["toggle"])]
        assert option["type"] == "bool"
        assert "default" not in option
        assert defaults[str(rule["toggle"])] == gen.rule_default(rule)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("linux_compliance_auditd_enabled", True),
        ("linux_compliance_rule_file_permissions_crontab_enabled", True),
        ("linux_compliance_remediate_enabled", False),
        ("linux_compliance_audit_enabled", False),
        ("linux_compliance_remediate_profile", False),
        ("other", False),
    ],
)
def test_is_generated(name: str, expected: bool) -> None:
    assert gen.is_generated(name) is expected


def test_check_passes_on_an_up_to_date_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = copy_repository(tmp_path)
    assert gen.main(["--root", str(root), "--check"]) == 0
    assert "toggles match" in capsys.readouterr().out


def test_check_reports_drift_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = copy_repository(tmp_path)
    defaults = root / gen.DEFAULTS
    defaults.write_text(
        defaults.read_text(encoding="utf-8").replace(
            "linux_compliance_auditd_enabled: true", "linux_compliance_auditd_enabled: false"
        ),
        encoding="utf-8",
    )
    (root / gen.REFERENCE).unlink()
    before = defaults.read_text(encoding="utf-8")
    assert gen.main(["--root", str(root), "--check"]) == 1
    error = capsys.readouterr().err
    assert "-linux_compliance_auditd_enabled: false" in error
    assert "+linux_compliance_auditd_enabled: true" in error
    assert f"{gen.REFERENCE} (generated)" in error
    assert "run make toggles" in error
    assert defaults.read_text(encoding="utf-8") == before
    assert not (root / gen.REFERENCE).exists()


def test_writing_regenerates_the_files_and_removes_stale_toggles(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = copy_repository(tmp_path)
    defaults = root / gen.DEFAULTS
    defaults.write_text(
        defaults.read_text(encoding="utf-8") + "linux_compliance_rule_removed_enabled: false\n",
        encoding="utf-8",
    )
    assert gen.main(["--root", str(root)]) == 0
    assert "generated" in capsys.readouterr().out
    assert "linux_compliance_rule_removed_enabled" not in load(defaults)
    assert gen.main(["--root", str(root), "--check"]) == 0


def test_a_new_rule_gets_its_toggle_and_its_reference_row(tmp_path: Path) -> None:
    root = copy_repository(tmp_path)
    data = load(root / gen.CATALOGUE)
    rules = cast("list[dict[str, object]]", data[gen.RULES_KEY])
    rules.append(
        {
            "rule_id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
            "family": "ssh",
            "disruptive": True,
            "reversible": True,
            "revert_strategy": "owned_dropin",
            "toggle": "linux_compliance_rule_sshd_disable_root_login_enabled",
            "runbook": None,
            "parameters": {},
        }
    )
    write_catalogue(root, data[gen.FAMILIES_KEY], rules)
    generated = gen.outputs(root)
    defaults = cast("dict[str, object]", yaml.safe_load(generated[gen.DEFAULTS]))
    assert defaults["linux_compliance_rule_sshd_disable_root_login_enabled"] == (
        "{{ linux_compliance_ssh_enabled }}"
    )
    assert "`linux_compliance_rule_sshd_disable_root_login_enabled`" in generated[gen.REFERENCE]


def test_a_catalogue_without_rules_says_so(tmp_path: Path) -> None:
    root = copy_repository(tmp_path)
    write_catalogue(root, [{"name": "sysctl", "disruptive": False}], [])
    reference = gen.outputs(root)[gen.REFERENCE]
    assert "No rule is catalogued yet." in reference
    assert "| `linux_compliance_sysctl_enabled` | `sysctl` | no | `true` | 0 |" in reference


@pytest.mark.parametrize(
    ("families", "rules", "message"),
    [
        ([], [], "the family registry must be a list"),
        (
            [{"name": "sysctl", "disruptive": False}],
            [{"rule_id": "x"}],
            "keys must be exactly",
        ),
    ],
)
def test_an_invalid_catalogue_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    families: object,
    rules: object,
    message: str,
) -> None:
    root = copy_repository(tmp_path)
    write_catalogue(root, families, rules)
    assert gen.main(["--root", str(root), "--check"]) == 2
    assert message in capsys.readouterr().err


def test_unreadable_or_malformed_files_fail(tmp_path: Path) -> None:
    root = copy_repository(tmp_path)
    (root / gen.DEFAULTS).write_text("---\n- a\n", encoding="utf-8")
    with pytest.raises(gen.GenerationError, match="must be a mapping"):
        gen.outputs(root)
    (root / gen.DEFAULTS).write_text("---\n{\n", encoding="utf-8")
    with pytest.raises(gen.GenerationError, match="cannot be read as YAML"):
        gen.outputs(root)
    (root / gen.DEFAULTS).unlink()
    with pytest.raises(gen.GenerationError, match="cannot be read as YAML"):
        gen.outputs(root)


def test_specs_need_a_main_entry_point_with_options(tmp_path: Path) -> None:
    root = copy_repository(tmp_path)
    (root / gen.SPECS).write_text("---\nargument_specs:\n  main: {}\n", encoding="utf-8")
    with pytest.raises(gen.GenerationError, match=r"argument_specs\.main\.options"):
        gen.outputs(root)


def test_render_uses_the_canonical_style() -> None:
    data: dict[str, object] = {
        "plain": "value_1",
        "type": "bool",
        "on": True,
        "with space": None,
        "count": 3,
        "items": ["auditd", "Two words", "yes"],
        "empty_list": [],
        "empty_map": {},
        "nested": {"elements": "str", "default": "cis"},
        "template": "{{ linux_compliance_ssh_enabled }}",
    }
    text = gen.render_yaml(data)
    assert text.startswith("---\n")
    assert '  - "Two words"' in text
    assert "  - auditd" in text
    assert '  - "yes"' in text
    assert '"on": true' in text
    assert '"with space": null' in text
    assert 'plain: "value_1"' in text
    assert "type: bool" in text
    assert "\n  elements: str" in text
    assert '\n  default: "cis"' in text
    assert "empty_list: []" in text
    assert "empty_map: {}" in text
    assert "count: 3" in text
    assert yaml.safe_load(text) == data


def test_long_strings_are_folded_and_overlong_ones_refused() -> None:
    folded = "word " * 23 + "end"
    text = gen.render_yaml({"key": folded})
    assert "key: >-\n  word word" in text
    assert yaml.safe_load(text) == {"key": folded}
    with pytest.raises(gen.GenerationError, match="cannot render within"):
        gen.render_yaml({"key": " " + folded})
    with pytest.raises(gen.GenerationError, match="cannot render within"):
        gen.render_yaml({"key": "x" * 130})
    with pytest.raises(gen.GenerationError, match="cannot render within"):
        gen.render_yaml({"k" * 130: True})


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"key": 1.5}, "cannot render a value of type float"),
        ({"key": [[1]]}, "cannot render a sequence of non-empty collections"),
        ({"key": [{"a": 1}]}, "cannot render a sequence of non-empty collections"),
        ({"key": {1: "a"}}, "cannot render the key 1"),
    ],
)
def test_unsupported_data_is_refused(data: dict[str, object], message: str) -> None:
    with pytest.raises(gen.GenerationError, match=message):
        gen.render_yaml(data)


def test_render_refuses_output_that_does_not_load_back(monkeypatch: pytest.MonkeyPatch) -> None:
    def other(_text: str) -> dict[str, object]:
        return {"other": True}

    monkeypatch.setattr(yaml, "safe_load", other)
    with pytest.raises(gen.GenerationError, match="does not load back"):
        gen.render_yaml({"key": True})


def test_main_runs_as_a_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = copy_repository(tmp_path)
    monkeypatch.setattr(sys, "argv", ["generate_toggles", "--root", str(root), "--check"])
    monkeypatch.delitem(sys.modules, "tools.roles.generate_toggles", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.roles.generate_toggles", run_name="__main__")
    assert raised.value.code == 0
    assert "toggles match" in capsys.readouterr().out
