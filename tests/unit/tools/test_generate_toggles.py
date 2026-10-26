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
SOURCES = (
    gen.CATALOGUE,
    gen.DEFAULTS,
    gen.SPECS,
    gen.AUDIT_DEFAULTS,
    gen.AUDIT_SPECS,
    gen.REFERENCE,
)


def copy_repository(root: Path) -> Path:
    for relative in SOURCES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY_ROOT / relative, target)
    return root


def load(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


def write_catalogue(root: Path, families: object, rules: object, audit_only: object = None) -> None:
    (root / gen.CATALOGUE).write_text(
        yaml.safe_dump(
            {
                gen.FAMILIES_KEY: families,
                gen.RULES_KEY: rules,
                gen.AUDIT_ONLY_KEY: {} if audit_only is None else audit_only,
            }
        ),
        encoding="utf-8",
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
    assert len(catalogue.rules) > 1000
    for rule in catalogue.rules:
        assert str(rule["toggle"]) not in options
        assert str(rule["toggle"]) not in defaults


def test_the_allow_list_choices_follow_the_registry(tmp_path: Path) -> None:
    root = copy_repository(tmp_path)
    write_catalogue(
        root,
        [
            {"name": "sysctl", "disruptive": False},
            {"name": "ssh", "disruptive": True},
            {"name": "auditd", "disruptive": True},
        ],
        [],
    )
    specs = cast("dict[str, object]", yaml.safe_load(gen.outputs(root)[gen.SPECS]))
    main = cast("dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]]", specs)[
        "argument_specs"
    ]
    allow_list = main["main"]["options"][gen.ALLOW_LIST]
    assert allow_list["choices"] == ["auditd", "ssh"]
    audit = cast("dict[str, object]", yaml.safe_load(gen.outputs(root)[gen.AUDIT_SPECS]))
    audit_options = cast("dict[str, dict[str, dict[str, dict[str, object]]]]", audit)[
        "argument_specs"
    ]
    assert gen.ALLOW_LIST not in audit_options["main"]["options"]


def test_both_toggle_roles_carry_the_same_toggles() -> None:
    remediate = load(REPOSITORY_ROOT / gen.DEFAULTS)
    audit = load(REPOSITORY_ROOT / gen.AUDIT_DEFAULTS)
    remediate_toggles = {name: value for name, value in remediate.items() if gen.is_generated(name)}
    audit_toggles = {name: value for name, value in audit.items() if gen.is_generated(name)}
    assert remediate_toggles
    assert remediate_toggles == audit_toggles
    assert audit["linux_compliance_audit_disabled_rules"] == []


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
    audit_only = cast("dict[str, list[str]]", data[gen.AUDIT_ONLY_KEY])
    audit_only["ssh"].remove("xccdf_org.ssgproject.content_rule_sshd_disable_root_login")
    write_catalogue(root, data[gen.FAMILIES_KEY], rules, audit_only)
    generated = gen.outputs(root)
    defaults = cast("dict[str, object]", yaml.safe_load(generated[gen.DEFAULTS]))
    assert "linux_compliance_rule_sshd_disable_root_login_enabled" not in defaults
    assert (
        "| `linux_compliance_rule_sshd_disable_root_login_enabled` | `sshd_disable_root_login` | "
        "`owned_dropin` |"
    ) in generated[gen.REFERENCE]


def test_an_audit_only_rule_gets_a_reference_row_with_its_strategy(tmp_path: Path) -> None:
    root = copy_repository(tmp_path)
    write_catalogue(
        root,
        [{"name": "sysctl", "disruptive": False}],
        [],
        {"sysctl": ["xccdf_org.ssgproject.content_rule_sysctl_kernel_dmesg_restrict"]},
    )
    generated = gen.outputs(root)
    assert (
        "| `linux_compliance_rule_sysctl_kernel_dmesg_restrict_enabled` | "
        "`sysctl_kernel_dmesg_restrict` | `audit_only` |"
    ) in generated[gen.REFERENCE]
    assert (
        "| `linux_compliance_sysctl_enabled` | `sysctl` | none | no | `true` | 1 | 0 | 1 |"
        in (generated[gen.REFERENCE])
    )
    specs = cast("dict[str, object]", yaml.safe_load(generated[gen.SPECS]))
    options = cast("dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]]", specs)[
        "argument_specs"
    ]
    description = cast(
        "list[str]", options["main"]["options"]["linux_compliance_sysctl_enabled"]["description"]
    )
    assert "Rules: 1, native: 0. Generated; see docs/remediation-variables.md." in description


def test_a_catalogue_without_rules_says_so(tmp_path: Path) -> None:
    root = copy_repository(tmp_path)
    write_catalogue(root, [{"name": "sysctl", "disruptive": False}], [])
    reference = gen.outputs(root)[gen.REFERENCE]
    assert "No rule of the pinned profiles belongs to this family." in reference
    assert (
        "| `linux_compliance_sysctl_enabled` | `sysctl` | none | no | `true` | 0 | 0 | 0 |"
        in reference
    )


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


def test_mappings_in_a_sequence_start_on_the_line_of_their_dash() -> None:
    data: dict[str, object] = {
        "rules": [
            {"family": "ssh", "parameters": {"path": "/etc/x"}, "items": ["a"]},
            {"family": "two words", "empty": {}},
        ]
    }
    text = gen.render_yaml(data, frozenset({"family"}))
    assert text == (
        "---\n"
        "rules:\n"
        "  - family: ssh\n"
        "    parameters:\n"
        '      path: "/etc/x"\n'
        "    items:\n"
        "      - a\n"
        '  - family: "two words"\n'
        "    empty: {}\n"
    )


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
        ({"key": [[1]]}, "cannot render a sequence of non-empty sequences"),
        ({"key": [{"a": [[1]]}]}, "cannot render a sequence of non-empty sequences"),
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
