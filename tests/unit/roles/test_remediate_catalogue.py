from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    remediation_plan as plan_filter,
)
from ansible_collections.freesecdev.linux_compliance.plugins.filter import restricted_mode
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)
from tools.roles import generate_toggles

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ROLE = REPOSITORY_ROOT / "roles" / "remediate"
FAMILY_PARAMETERS = {"file_permissions": {"path", "max_mode"}}


def load(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))


def registry() -> list[dict[str, object]]:
    return cast(
        "list[dict[str, object]]",
        load(ROLE / "vars" / "rules.yml")["__linux_compliance_remediate_families"],
    )


def native() -> list[dict[str, object]]:
    return cast(
        "list[dict[str, object]]",
        load(ROLE / "vars" / "rules.yml")["__linux_compliance_remediate_rules"],
    )


def audit_only() -> dict[str, list[str]]:
    return cast(
        "dict[str, list[str]]",
        load(ROLE / "vars" / "rules.yml")["__linux_compliance_remediate_audit_only"],
    )


def rules() -> list[dict[str, object]]:
    errors = toggles.Errors()
    loaded = toggles.load_catalogue(native(), audit_only(), registry(), {}, errors)
    assert errors.items == []
    return loaded.rules


def plan(**overrides: object) -> dict[str, object]:
    options: dict[str, object] = {
        "audit_only": audit_only(),
        "families": registry(),
        "enabled": True,
        "allow_disruptive": [],
        "toggles": {},
        "profile_rule_ids": [rule["rule_id"] for rule in rules()],
        "ledger_entries": [],
    }
    options.update(overrides)
    return plan_filter.remediation_plan(native(), options)


def test_the_catalogue_and_the_registry_are_valid() -> None:
    result = plan()
    assert result["errors"] == []
    assert len(cast("list[object]", result["rules"])) == len(rules())


def test_the_catalogue_file_holds_only_the_catalogue_and_the_registry() -> None:
    assert set(load(ROLE / "vars" / "rules.yml")) == {
        "__linux_compliance_remediate_audit_only",
        "__linux_compliance_remediate_families",
        "__linux_compliance_remediate_rules",
    }


def test_the_native_rules_are_exactly_the_reference_rule() -> None:
    assert [rule["rule_id"] for rule in native()] == [
        "xccdf_org.ssgproject.content_rule_file_permissions_crontab"
    ]
    assert native()[0]["family"] == "file_permissions"
    assert all(toggles.is_native(rule) for rule in native())


def test_the_audit_only_rules_are_listed_per_family_in_registry_order_and_sorted() -> None:
    names = [str(family["name"]) for family in registry()]
    assert list(audit_only()) == names
    for rule_ids in audit_only().values():
        assert rule_ids == sorted(set(rule_ids))
    assert len(rules()) > 1000
    assert sum(not toggles.is_native(rule) for rule in rules()) == len(rules()) - len(native())


def test_the_allow_list_choices_are_exactly_the_disruptive_families() -> None:
    specs = load(ROLE / "meta" / "argument_specs.yml")
    main = cast("dict[str, dict[str, dict[str, object]]]", specs["argument_specs"])["main"]
    option = cast(
        "dict[str, object]", main["options"]["linux_compliance_remediate_allow_disruptive"]
    )
    disruptive = sorted(
        str(family["name"]) for family in registry() if family["disruptive"] is True
    )
    assert option["choices"] == disruptive


def test_every_disruptive_family_of_the_skill_is_disruptive() -> None:
    disruptive = {str(family["name"]) for family in registry() if family["disruptive"] is True}
    assert {
        "ssh",
        "pam",
        "sudo",
        "services",
        "firewall",
        "network",
        "bootloader",
        "mounts",
        "crypto_policy",
        "auditd",
    } <= disruptive


def test_non_disruptive_families_come_first_in_the_dispatch_order() -> None:
    flags = [family["disruptive"] for family in registry()]
    assert flags == sorted(flags, key=bool)


def test_every_family_with_native_rules_has_a_task_file_and_known_parameters() -> None:
    for rule in native():
        family = str(rule["family"])
        assert (ROLE / "tasks" / f"{family}.yml").is_file(), family
        parameters = cast("dict[str, object]", rule["parameters"])
        assert set(parameters) == FAMILY_PARAMETERS[family], rule["rule_id"]


def test_native_file_permission_rules_have_an_absolute_path_and_an_octal_maximum() -> None:
    for rule in native():
        if rule["family"] != "file_permissions":
            continue
        parameters = cast("dict[str, str]", rule["parameters"])
        assert re.fullmatch(r"/[A-Za-z0-9._/-]+", parameters["path"])
        assert ".." not in parameters["path"]
        maximum = parameters["max_mode"]
        assert restricted_mode.restricted_mode(maximum, maximum) == maximum.zfill(4)


def test_the_task_files_are_only_family_files_and_their_helpers() -> None:
    families = {str(family["name"]) for family in registry()}
    role_files = {"main", "dispatch", "internal_variables"}
    assert not families & role_files
    for path in sorted((ROLE / "tasks").glob("*.yml")):
        stem = path.stem
        assert stem in role_files or stem in families or stem.rsplit("_", 1)[0] in families, stem


def test_the_recorded_collection_version_matches_galaxy() -> None:
    galaxy = load(REPOSITORY_ROOT / "galaxy.yml")
    role_vars = load(ROLE / "vars" / "main.yml")
    assert role_vars["__linux_compliance_remediate_collection_version"] == galaxy["version"]


def test_the_toggle_pattern_of_the_role_matches_the_filter() -> None:
    role_vars = load(ROLE / "vars" / "main.yml")
    pattern = str(role_vars["__linux_compliance_remediate_toggle_pattern"])
    assert pattern == "^linux_compliance_.+_enabled$"
    assert re.fullmatch(pattern.strip("^$"), "linux_compliance_ssh_enabled")
    assert toggles.TOGGLE_PATTERN.startswith("linux_compliance_")


def test_the_reserved_namespaces_are_the_roles_of_the_collection() -> None:
    roles = sorted(path.name for path in (REPOSITORY_ROOT / "roles").iterdir() if path.is_dir())
    assert list(toggles.ROLE_NAMESPACES) == roles


def test_the_defaults_keep_remediation_off_and_nothing_allow_listed() -> None:
    defaults = load(ROLE / "defaults" / "main.yml")
    assert defaults["linux_compliance_remediate_enabled"] is False
    assert defaults["linux_compliance_remediate_allow_disruptive"] == []
    others = [
        name
        for name in defaults
        if name.endswith("_enabled") and name != "linux_compliance_remediate_enabled"
    ]
    assert others
    assert all(generate_toggles.is_generated(name) for name in others)


def test_every_family_has_its_topic_toggle_default_and_no_rule_toggle_is_declared() -> None:
    defaults = load(ROLE / "defaults" / "main.yml")
    for family in registry():
        assert defaults[toggles.toggle_name(str(family["name"]))] is True
    expected = {toggles.toggle_name(str(family["name"])) for family in registry()}
    assert {name for name in defaults if generate_toggles.is_generated(name)} == expected
    assert not any(name.startswith("linux_compliance_rule_") for name in defaults)


def test_every_rule_toggle_is_unique_and_a_valid_variable_name() -> None:
    names = [str(rule["toggle"]) for rule in rules()]
    assert len(names) == len(set(names))
    assert all(re.fullmatch(r"linux_compliance_rule_[a-z0-9_]+_enabled", name) for name in names)
    assert (
        toggles.rule_toggle_name(
            "xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled"
        )
        in names
    )


def test_a_disabled_topic_excludes_every_catalogued_rule_of_its_family() -> None:
    result = plan(toggles={"linux_compliance_auditd_enabled": False})
    auditd = {str(rule["rule_id"]) for rule in rules() if rule["family"] == "auditd"}
    disabled = cast("list[dict[str, object]]", result["disabled_rules"])
    assert len(auditd) > 100
    assert {str(item["rule_id"]) for item in disabled} == auditd
    assert {item["disabled_by"] for item in disabled} == {"linux_compliance_auditd_enabled"}


def test_with_the_opt_in_only_the_reference_rule_is_applied_and_the_rest_not_implemented() -> None:
    result = plan()
    summary = cast("dict[str, int]", result["summary"])
    assert summary["apply"] == 1
    assert summary["not_implemented"] == len(rules()) - 1
    assert [family["name"] for family in cast("list[dict[str, object]]", result["families"])] == [
        "file_permissions"
    ]
    results = cast("list[dict[str, object]]", result["not_implemented"])
    assert len(results) == summary["not_implemented"]
    assert {item["status"] for item in results} == {"not_implemented"}
    assert {item["changed"] for item in results} == {False}


def test_the_audit_role_finds_the_toggles_and_the_catalogue_like_the_remediate_role() -> None:
    audit_role = REPOSITORY_ROOT / "roles" / "audit"
    audit_vars = load(audit_role / "vars" / "main.yml")
    remediate_vars = load(ROLE / "vars" / "main.yml")
    assert (
        audit_vars["__linux_compliance_audit_toggle_pattern"]
        == remediate_vars["__linux_compliance_remediate_toggle_pattern"]
        == toggles.TOGGLE_VARIABLE_PATTERN
    )
    tasks = cast(
        "list[dict[str, dict[str, str]]]",
        yaml.safe_load((audit_role / "tasks" / "toggles.yml").read_text(encoding="utf-8")),
    )
    catalogue_file = tasks[0]["ansible.builtin.include_vars"]["file"]
    assert catalogue_file == "{{ role_path }}/../remediate/vars/rules.yml"
    assert (audit_role / "../remediate/vars/rules.yml").resolve() == ROLE / "vars" / "rules.yml"


def test_without_opt_in_the_real_catalogue_only_skips() -> None:
    result = plan(enabled=False, profile_rule_ids=None)
    assert result["families"] == []
    assert {item["action"] for item in cast("list[dict[str, object]]", result["rules"])} == {"skip"}


def test_the_pinned_disruptive_families_are_the_disruptive_families_of_the_registry() -> None:
    disruptive = {str(family["name"]) for family in registry() if family["disruptive"] is True}
    assert disruptive == set(toggles.DISRUPTIVE_FAMILIES)


def test_the_ignored_role_variables_are_the_enabled_options_of_the_role_specs() -> None:
    declared: set[str] = set()
    for path in sorted((REPOSITORY_ROOT / "roles").glob("*/meta/argument_specs.yml")):
        specs = load(path)
        main = cast("dict[str, dict[str, dict[str, object]]]", specs["argument_specs"])["main"]
        declared |= {
            name
            for name in main["options"]
            if name.endswith("_enabled") and not generate_toggles.is_generated(name)
        }
    assert declared == set(toggles.ROLE_TOGGLE_VARIABLES)


def test_only_families_with_native_rules_are_dispatched_and_have_task_files() -> None:
    catalogue = generate_toggles.load_catalogue(ROLE / "vars" / "rules.yml")
    assert generate_toggles.native_families(catalogue) == ["file_permissions"]
    families_with_files = [
        family for family in catalogue.families if (ROLE / "tasks" / f"{family}.yml").is_file()
    ]
    assert families_with_files == generate_toggles.native_families(catalogue)
    planned = cast("list[dict[str, object]]", plan()["families"])
    assert [family["name"] for family in planned] == generate_toggles.native_families(catalogue)
