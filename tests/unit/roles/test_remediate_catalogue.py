from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    remediation_plan as plan_filter,
)
from ansible_collections.freesecdev.linux_compliance.plugins.filter import restricted_mode

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


def rules() -> list[dict[str, object]]:
    return cast(
        "list[dict[str, object]]",
        load(ROLE / "vars" / "rules.yml")["__linux_compliance_remediate_rules"],
    )


def plan(**overrides: object) -> dict[str, object]:
    options: dict[str, object] = {
        "families": registry(),
        "enabled": True,
        "allow_disruptive": [],
        "toggles": {},
        "profile_rule_ids": [rule["rule_id"] for rule in rules()],
        "ledger_entries": [],
    }
    options.update(overrides)
    return plan_filter.remediation_plan(rules(), options)


def test_the_catalogue_and_the_registry_are_valid() -> None:
    result = plan()
    assert result["errors"] == []
    assert len(cast("list[object]", result["rules"])) == len(rules())


def test_the_catalogue_file_holds_only_the_catalogue_and_the_registry() -> None:
    assert set(load(ROLE / "vars" / "rules.yml")) == {
        "__linux_compliance_remediate_families",
        "__linux_compliance_remediate_rules",
    }


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


def test_every_family_with_rules_has_a_task_file_and_known_parameters() -> None:
    for rule in rules():
        family = str(rule["family"])
        assert (ROLE / "tasks" / f"{family}.yml").is_file(), family
        parameters = cast("dict[str, object]", rule["parameters"])
        assert set(parameters) == FAMILY_PARAMETERS[family], rule["rule_id"]


def test_file_permission_rules_have_an_absolute_path_and_an_octal_maximum() -> None:
    for rule in rules():
        if rule["family"] != "file_permissions":
            continue
        parameters = cast("dict[str, str]", rule["parameters"])
        assert re.fullmatch(r"/[A-Za-z0-9._/-]+", parameters["path"])
        assert ".." not in parameters["path"]
        maximum = parameters["max_mode"]
        assert restricted_mode.restricted_mode(maximum, maximum) == maximum.zfill(4)


def test_the_task_files_are_only_family_files_and_their_helpers() -> None:
    families = {str(family["name"]) for family in registry()}
    for path in sorted((ROLE / "tasks").glob("*.yml")):
        stem = path.stem
        assert stem == "main" or stem in families or stem.rsplit("_", 1)[0] in families, stem


def test_the_recorded_collection_version_matches_galaxy() -> None:
    galaxy = load(REPOSITORY_ROOT / "galaxy.yml")
    role_vars = load(ROLE / "vars" / "main.yml")
    assert role_vars["__linux_compliance_remediate_collection_version"] == galaxy["version"]


def test_the_toggle_pattern_of_the_role_matches_the_filter() -> None:
    role_vars = load(ROLE / "vars" / "main.yml")
    pattern = str(role_vars["__linux_compliance_remediate_toggle_pattern"])
    assert pattern == "^linux_compliance_.+_enabled$"
    assert re.fullmatch(pattern.strip("^$"), "linux_compliance_ssh_enabled")
    assert plan_filter.TOGGLE_PATTERN.startswith("linux_compliance_")


def test_the_reserved_namespaces_are_the_roles_of_the_collection() -> None:
    roles = sorted(path.name for path in (REPOSITORY_ROOT / "roles").iterdir() if path.is_dir())
    assert list(plan_filter.ROLE_NAMESPACES) == roles


def test_the_defaults_keep_remediation_off_and_nothing_allow_listed() -> None:
    defaults = load(ROLE / "defaults" / "main.yml")
    assert defaults["linux_compliance_remediate_enabled"] is False
    assert defaults["linux_compliance_remediate_allow_disruptive"] == []
    assert not [
        name
        for name in defaults
        if name.endswith("_enabled") and name != "linux_compliance_remediate_enabled"
    ]


def test_without_opt_in_the_real_catalogue_only_skips() -> None:
    result = plan(enabled=False, profile_rule_ids=None)
    assert result["families"] == []
    assert {item["action"] for item in cast("list[dict[str, object]]", result["rules"])} == {"skip"}


def test_the_pinned_disruptive_families_are_the_disruptive_families_of_the_registry() -> None:
    disruptive = {str(family["name"]) for family in registry() if family["disruptive"] is True}
    assert disruptive == set(plan_filter.DISRUPTIVE_FAMILIES)


def test_the_ignored_role_variables_are_the_enabled_options_of_the_role_specs() -> None:
    declared: set[str] = set()
    for path in sorted((REPOSITORY_ROOT / "roles").glob("*/meta/argument_specs.yml")):
        specs = load(path)
        main = cast("dict[str, dict[str, dict[str, object]]]", specs["argument_specs"])["main"]
        declared |= {name for name in main["options"] if name.endswith("_enabled")}
    assert declared == set(plan_filter.ROLE_TOGGLE_VARIABLES)
