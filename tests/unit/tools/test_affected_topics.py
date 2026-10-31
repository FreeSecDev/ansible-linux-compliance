"""The path-to-topic mapping of the lifecycle legs (FREES-189).

Every case builds a base and a head copy of the parts of the repository that the mapping reads,
changes the head, and checks which topics the change affects or that it plans the full matrix.
The mutation cases change one thing that would let a pull request run fewer legs than it needs
(a shared include, an interleaved catalogue, a symbolic link, a dispatch condition) and check that
the mapping falls back to the full matrix or widens the topics.
"""

from __future__ import annotations

import functools
import json
import runpy
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)
from tools.roles import affected_topics as affected
from tools.roles import check_lifecycle_topics, generate_toggles, molecule_matrix

if TYPE_CHECKING:
    from collections.abc import Callable

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
COPIED = ("roles", "extensions/molecule", "playbooks")
SUDO_DROPIN = "roles/remediate/tasks/sudo_dropin_apply.yml"
SUDO_STATES = "extensions/molecule/shared/tasks/lifecycle_sudo_states.yml"
PWQUALITY_TASKS = "roles/remediate/tasks/pwquality.yml"
SUDO_TASKS = "roles/remediate/tasks/sudo.yml"
SUDO_DECLARATION = "extensions/molecule/shared/vars/topics/sudo.yml"
PWQUALITY_DECLARATION = "extensions/molecule/shared/vars/topics/pwquality.yml"
SPECS = "roles/remediate/meta/argument_specs.yml"


def load_yaml(text: str) -> object:
    return cast("object", yaml.load(text, Loader=yaml.CSafeLoader))


class Trees:
    """A base and a head copy of the files that the mapping reads; tests change the head."""

    def __init__(self, root: Path) -> None:
        self.base = root / "base"
        self.head = root / "head"
        for tree in (self.base, self.head):
            for part in COPIED:
                shutil.copytree(REPOSITORY_ROOT / part, tree / part, symlinks=True)

    def write(self, relative: str, text: str) -> None:
        path = self.head / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def append(self, relative: str, text: str) -> None:
        path = self.head / relative
        path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")

    def load(self, relative: str) -> object:
        return load_yaml((self.head / relative).read_text(encoding="utf-8"))

    def dump(self, relative: str, data: object) -> None:
        self.write(relative, "---\n" + yaml.dump(data, Dumper=yaml.CSafeDumper, sort_keys=False))

    def edit(self, relative: str, change: Callable[[dict[str, object]], None]) -> None:
        data = cast("dict[str, object]", self.load(relative))
        change(data)
        self.dump(relative, data)

    @functools.cached_property
    def context(self) -> affected.Context:
        return affected.Context(affected.Tree(self.base), affected.Tree(self.head))

    def decide(self, *changed: str) -> affected.Decision:
        return affected.decide(self.base, self.head, list(changed))


@pytest.fixture
def trees(tmp_path: Path) -> Trees:
    return Trees(tmp_path)


def topics_of(decision: affected.Decision) -> set[str] | None:
    return None if decision.full else set(decision.topics)


def catalogue() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        load_yaml((REPOSITORY_ROOT / affected.CATALOGUE).read_text(encoding="utf-8")),
    )


def native() -> list[str]:
    return generate_toggles.native_families(
        generate_toggles.load_catalogue(REPOSITORY_ROOT / generate_toggles.CATALOGUE)
    )


def rules_of(data: dict[str, object]) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", data[affected.RULES_KEY])


def first_rule(data: dict[str, object], family: str) -> dict[str, object]:
    return next(rule for rule in rules_of(data) if rule["family"] == family)


@pytest.mark.parametrize(
    "relative",
    [
        "docs/molecule.md",
        "docs/adr/0011-control-toggles-and-cleanup.md",
        "changelogs/fragments/FREES-189-affected-lifecycle-legs.yml",
        "tests/unit/tools/test_molecule_matrix.py",
        "tests/playbooks/remediate-native-check.yml",
        "tests/fixtures/catalog/legacy-families.yml",
        "tests/sanity/ignore-2.20.txt",
        "tools/reporting/dashboard.py",
        "tools/lint/check_repo_rules.py",
        "infra/account/main.tf",
        "extensions/ci/scc/scc.pins",
        ".github/workflows/scc-release-watch.yml",
        ".github/rulesets/main.json",
        "README.md",
        "roles/remediate/README.md",
        "content/catalogue.yml",
        "roles/remediate/tasks/dispatch.yml",
        "roles/remediate/tasks/internal_variables.yml",
        "roles/audit/tasks/internal_variables.yml",
        "playbooks/run_start.yml",
    ],
)
def test_a_path_without_a_lifecycle_effect_plans_no_topic(trees: Trees, relative: str) -> None:
    decision = trees.decide(relative)
    assert not decision.full
    assert decision.topics == frozenset()
    assert decision.reasons[0].startswith(f"{relative}: ")


@pytest.mark.parametrize(
    "relative",
    [
        "Makefile",
        ".github/workflows/ci.yml",
        "pyproject.toml",
        "uv.lock",
        "galaxy.yml",
        "meta/runtime.yml",
        "tools/roles/molecule_matrix.py",
        "tools/roles/affected_topics.py",
        "tools/roles/check_lifecycle_topics.py",
        "tools/roles/generate_toggles.py",
        "tools/molecule/plan-lifecycle.sh",
        "tools/content/fetch_content.py",
        "tools/scc/needs-smoke.sh",
        "plugins/modules/control_state.py",
        "plugins/module_utils/compliance/toggles.py",
        "plugins/filter/scc_toggles.py",
        "content/manifest.yml",
        "content/stig-mapping.json",
        "roles/verify/defaults/main.yml",
        "roles/remediate/tasks/main.yml",
        "roles/audit/tasks/scan.yml",
        "roles/audit/vars/main.yml",
        "extensions/molecule/shared/images/ubuntu.Dockerfile",
        "extensions/molecule/shared/images/cloud-images.pins",
        "extensions/molecule/shared/lifecycle.yml",
        "extensions/molecule/shared/converge.yml",
        "extensions/molecule/shared/vars/target.yml",
        "extensions/molecule/shared/tasks/lifecycle_cycle.yml",
        "extensions/molecule/shared/tasks/find_with_checksums.yml",
        "extensions/molecule/docker-ubuntu-lifecycle/molecule.yml",
        "extensions/molecule/requirements.yml",
        "extensions/molecule/shared/vars/topics/nested/sudo.yml",
        "extensions/molecule/shared/vars/topics/sudo.yaml",
        "tests/integration/new.yml",
        "unknown.txt",
        "a path with spaces.yml",
        "../outside.yml",
        "/etc/passwd",
        "roles/remediate/tasks/./sudo.yml",
    ],
)
def test_a_shared_or_unknown_path_plans_the_full_matrix(trees: Trees, relative: str) -> None:
    decision = trees.decide(relative)
    assert decision.full, decision.reasons
    assert decision.reasons[0].endswith(": full matrix")


def role_task_files() -> list[str]:
    return sorted(
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in (REPOSITORY_ROOT / affected.ROLE_TASKS).glob("*.yml")
        if path.relative_to(REPOSITORY_ROOT).as_posix() not in affected.GENERATED
        and path.stem != "main"
    )


def test_every_role_task_file_belongs_to_the_native_topic_of_its_name(trees: Trees) -> None:
    """A task file belongs to the topic of its name and to those of the family files including it.

    ``sysctl_parameters.yml`` is the engine of ``sysctl``, ``ipv4_parameters`` and
    ``ipv6_parameters`` (FREES-107), whose family files include it.
    """
    files = role_task_files()
    assert files
    families = native()
    for relative in files:
        stem = Path(relative).stem
        expected = {
            family for family in families if stem == family or stem.startswith(family + "_")
        }
        assert len(expected) == 1, relative
        expected |= {
            Path(other).stem
            for other in files
            if Path(other).stem in families
            and f"/tasks/{stem}.yml" in (REPOSITORY_ROOT / other).read_text(encoding="utf-8")
        }
        assert set(trees.context.classify(relative)[0]) == expected, relative


def test_the_kernel_parameter_engine_belongs_to_the_three_kernel_parameter_topics(
    trees: Trees,
) -> None:
    topics = trees.context.classify(f"{affected.ROLE_TASKS}/sysctl_parameters.yml")[0]
    assert set(topics) == {"sysctl", "ipv4_parameters", "ipv6_parameters"}


def test_every_regression_file_belongs_to_the_topics_whose_groups_name_it(trees: Trees) -> None:
    owners: dict[str, set[str]] = {}
    for path in sorted((REPOSITORY_ROOT / affected.TOPICS).glob("*.yml")):
        data = cast("dict[str, object]", load_yaml(path.read_text(encoding="utf-8")))
        for group in cast("list[dict[str, list[str]]]", data.get("regressions", [])):
            for file in group["files"]:
                owners.setdefault(file, set()).add(path.stem)
    assert owners
    for file, topics in owners.items():
        assert set(trees.context.classify(f"{affected.MOLECULE_TASKS}/{file}")[0]) == topics, file


def test_every_topic_declaration_belongs_to_its_topic(trees: Trees) -> None:
    for family in native():
        assert topics_of(trees.decide(f"{affected.TOPICS}/{family}.yml")) == {family}
    trees.write(f"{affected.TOPICS}/newtopic.yml", "---\nfamily: newtopic\n")
    assert topics_of(trees.decide(f"{affected.TOPICS}/newtopic.yml")) == {"newtopic"}


def test_a_role_file_included_by_another_topic_affects_both(trees: Trees) -> None:
    assert topics_of(trees.decide(SUDO_DROPIN)) == {"sudo"}
    trees.append(
        PWQUALITY_TASKS,
        "\n- name: Pwquality | Borrow a sudo file\n  ansible.builtin.include_tasks:\n"
        '    file: "{{ role_path }}/tasks/sudo_dropin_apply.yml"\n',
    )
    assert topics_of(trees.decide(SUDO_DROPIN)) == {"sudo", "pwquality"}


def test_a_role_file_included_by_a_shared_file_plans_the_full_matrix(trees: Trees) -> None:
    trees.append(
        "roles/remediate/tasks/main.yml",
        "\n- name: Remediate | Shared include\n  ansible.builtin.include_tasks:\n"
        "    file: sudo_dropin_apply.yml\n",
    )
    decision = trees.decide(SUDO_DROPIN)
    assert decision.full
    assert decision.reasons[0].endswith("is shared: full matrix")


def test_a_reference_in_the_base_revision_counts_as_well(trees: Trees) -> None:
    path = trees.base / "roles/remediate/tasks/main.yml"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n# sudo_dropin_apply.yml\n", encoding="utf-8"
    )
    assert trees.decide(SUDO_DROPIN).full


@pytest.mark.parametrize(
    "reference",
    [
        "file: sudo.yml",
        "file: ./sudo.yml",
        "file: sub/sudo.yml",
        'file: "{{ directory }}/sudo.yml"',
        "tasks_from: sudo",
        "tasks_from: sudo.yml",
        "tasks_from: 'tasks/sudo'",
    ],
)
def test_every_literal_form_of_an_include_is_a_reference(trees: Trees, reference: str) -> None:
    assert topics_of(trees.decide(SUDO_TASKS)) == {"sudo"}
    trees.append("extensions/molecule/shared/lifecycle.yml", f"\n# {reference}\n")
    assert trees.decide(SUDO_TASKS).full


@pytest.mark.parametrize(
    "text", ["lifecycle_sudo.yml", "sudo.yml.j2", "tasks_from: sudo_other", "the sudo family"]
)
def test_a_longer_name_is_not_a_reference(trees: Trees, text: str) -> None:
    trees.append("extensions/molecule/shared/lifecycle.yml", f"\n# {text}\n")
    assert topics_of(trees.decide(SUDO_TASKS)) == {"sudo"}


def test_a_new_role_file_of_a_family_belongs_to_it_even_if_not_yet_native(trees: Trees) -> None:
    trees.write("roles/remediate/tasks/auditd.yml", "---\n[]\n")
    decision = trees.decide("roles/remediate/tasks/auditd.yml")
    assert topics_of(decision) == {"auditd"}
    docker, libvirt = full_matrices()
    found = affected.plan(decision, docker, libvirt)
    assert found["lifecycle_legs"] == 0
    assert found["docker"] == {"include": []}
    assert all(
        leg["topic"] == ""
        for leg in cast("dict[str, list[dict[str, str]]]", found["libvirt"])["include"]
    )


def test_a_role_file_named_after_two_families_belongs_to_both(trees: Trees) -> None:
    trees.write("roles/remediate/tasks/wireless_modules_apply.yml", "---\n[]\n")
    assert topics_of(trees.decide("roles/remediate/tasks/wireless_modules_apply.yml")) == {
        "wireless",
        "wireless_modules",
    }


def test_a_file_that_no_topic_owns_belongs_to_the_topics_that_include_it(trees: Trees) -> None:
    helper = "roles/remediate/tasks/helpers.yml"
    trees.write(helper, "---\n[]\n")
    assert trees.decide(helper).full
    trees.append(
        SUDO_TASKS,
        "\n- name: Sudo | Helper\n  ansible.builtin.include_tasks:\n    file: helpers.yml\n",
    )
    assert topics_of(trees.decide(helper)) == {"sudo"}


def test_a_regression_helper_belongs_to_the_topic_of_the_file_that_includes_it(
    trees: Trees,
) -> None:
    helper = f"{affected.MOLECULE_TASKS}/lifecycle_sudo_helper.yml"
    trees.write(helper, "---\n[]\n")
    assert trees.decide(helper).full
    trees.append(SUDO_STATES, "\n# lifecycle_sudo_helper.yml\n")
    assert topics_of(trees.decide(helper)) == {"sudo"}


def test_a_regression_file_named_by_two_topics_affects_both(trees: Trees) -> None:
    trees.append(PWQUALITY_DECLARATION, "\n# lifecycle_sudo_states.yml\n")
    assert topics_of(trees.decide(SUDO_STATES)) == {"sudo", "pwquality"}


def test_a_regression_file_included_by_the_shared_harness_plans_the_full_matrix(
    trees: Trees,
) -> None:
    trees.append(
        f"{affected.MOLECULE_TASKS}/lifecycle_topic.yml",
        "\n- name: Lifecycle topic | Shared\n  ansible.builtin.include_tasks:\n"
        "    file: lifecycle_sudo_states.yml\n",
    )
    assert trees.decide(SUDO_STATES).full


def test_includes_that_form_a_cycle_are_followed_once(trees: Trees) -> None:
    first = "roles/remediate/tasks/sudo_first.yml"
    second = "roles/remediate/tasks/sudo_second.yml"
    trees.write(first, "---\n# sudo_second.yml\n")
    trees.write(second, "---\n# sudo_first.yml\n")
    trees.append(PWQUALITY_TASKS, "\n# sudo_second.yml\n")
    assert topics_of(trees.decide(first, second)) == {"sudo", "pwquality"}
    assert topics_of(trees.decide(second)) == {"sudo", "pwquality"}


def test_a_symbolic_link_plans_the_full_matrix(trees: Trees) -> None:
    link = trees.head / "roles/remediate/tasks/sudo_link.yml"
    link.symlink_to("main.yml")
    assert trees.decide("roles/remediate/tasks/sudo_link.yml").full
    decision = trees.decide(SUDO_DROPIN)
    assert not decision.full
    link.unlink()
    (trees.head / "roles/remediate/tasks/sudo_alias.yml").symlink_to("sudo_dropin_apply.yml")
    assert trees.decide(SUDO_DROPIN).full
    (trees.head / "roles/remediate/tasks/sudo_alias.yml").unlink()
    (trees.head / "playbooks/outside.yml").symlink_to("/etc/hostname")
    assert topics_of(trees.decide(SUDO_TASKS)) == {"sudo"}


def test_a_revision_without_a_searched_directory_is_still_searched(trees: Trees) -> None:
    shutil.rmtree(trees.head / "playbooks")
    assert topics_of(trees.decide(SUDO_TASKS)) == {"sudo"}


def test_an_unreadable_file_plans_the_full_matrix(trees: Trees) -> None:
    (trees.head / SUDO_TASKS).write_bytes(b"---\n\xff\xfe\n")
    assert trees.decide(SUDO_DROPIN).full
    assert trees.decide(SUDO_TASKS).full


def test_one_shared_path_plans_the_full_matrix_and_every_path_is_explained(trees: Trees) -> None:
    decision = trees.decide(SUDO_DROPIN, "Makefile", "docs/molecule.md")
    assert decision.full
    assert decision.topics == frozenset({"sudo"})
    assert len(decision.reasons) == 3
    assert decision.reasons[1].startswith("Makefile: ")


def test_an_empty_change_affects_no_topic(trees: Trees) -> None:
    assert trees.decide() == affected.Decision(full=False, topics=frozenset(), reasons=())


def test_a_rule_change_affects_its_family(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        first_rule(data, "sudo")["runbook"] = "changed"

    trees.edit(affected.CATALOGUE, change)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"sudo"}


def test_an_audit_only_change_affects_its_family(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        audit_only = cast("dict[str, list[str]]", data[affected.AUDIT_ONLY_KEY])
        audit_only["auditd"] = audit_only["auditd"][1:]

    trees.edit(affected.CATALOGUE, change)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"auditd"}


def test_a_rule_that_becomes_native_affects_only_its_family(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        audit_only = cast("dict[str, list[str]]", data[affected.AUDIT_ONLY_KEY])
        rule = audit_only["banners"].pop()
        rules = rules_of(data)
        position = max(index for index, item in enumerate(rules) if item["family"] == "banners")
        rules.insert(position + 1, {"rule_id": rule, "family": "banners", "parameters": {}})

    trees.edit(affected.CATALOGUE, change)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"banners"}


def test_a_rule_that_moves_between_families_affects_both(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        first_rule(data, "sudo")["family"] = "pwquality"

    trees.edit(affected.CATALOGUE, change)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"sudo", "pwquality"}


def test_a_registry_entry_change_affects_its_family(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        families = cast("list[dict[str, object]]", data[affected.FAMILIES_KEY])
        next(item for item in families if item["name"] == "banners")["disruptive"] = True

    trees.edit(affected.CATALOGUE, change)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"banners"}


def reorder_families(data: dict[str, object]) -> None:
    families = cast("list[object]", data[affected.FAMILIES_KEY])
    families[0], families[1] = families[1], families[0]


def add_family(data: dict[str, object]) -> None:
    cast("list[object]", data[affected.FAMILIES_KEY]).append({"name": "new", "disruptive": True})


def duplicate_family(data: dict[str, object]) -> None:
    families = cast("list[object]", data[affected.FAMILIES_KEY])
    families.append(families[0])


def add_umbrella_head(data: dict[str, object]) -> None:
    cast("list[object]", data[affected.FAMILIES_KEY]).append(
        {"name": "logging", "disruptive": False}
    )


def remove_umbrella_head(data: dict[str, object]) -> None:
    families = cast("list[dict[str, object]]", data[affected.FAMILIES_KEY])
    families.remove(next(item for item in families if item["name"] == "pam"))


def interleave_rules(data: dict[str, object]) -> None:
    rules = rules_of(data)
    edge = next(
        index
        for index in range(len(rules) - 1)
        if rules[index]["family"] != rules[index + 1]["family"]
    )
    rules[edge], rules[edge + 1] = rules[edge + 1], rules[edge]


def tag_without_family(data: dict[str, object]) -> None:
    cast("dict[str, object]", data[affected.TAGS_KEY])["not_a_family"] = [
        str(first_rule(data, "sudo")["rule_id"])
    ]


def tag_unknown_rule(data: dict[str, object]) -> None:
    cast("dict[str, list[str]]", data[affected.TAGS_KEY])["ssh"].append("xccdf_unknown_rule")


def change_aliases(data: dict[str, object]) -> None:
    data[generate_toggles.ALIASES_KEY] = {"old": "sudo"}


def add_key(data: dict[str, object]) -> None:
    data["__linux_compliance_remediate_new"] = []


def rule_without_family(data: dict[str, object]) -> None:
    del first_rule(data, "sudo")["family"]


def family_without_name(data: dict[str, object]) -> None:
    cast("list[dict[str, object]]", data[affected.FAMILIES_KEY])[0].pop("name")


def no_families(data: dict[str, object]) -> None:
    data[affected.FAMILIES_KEY] = []


def tags_not_a_mapping(data: dict[str, object]) -> None:
    data[affected.TAGS_KEY] = []


def tag_not_a_list(data: dict[str, object]) -> None:
    cast("dict[str, object]", data[affected.TAGS_KEY])["ssh"] = "rule"


def audit_only_not_a_mapping(data: dict[str, object]) -> None:
    data[affected.AUDIT_ONLY_KEY] = []


@pytest.mark.parametrize(
    "change",
    [
        reorder_families,
        duplicate_family,
        add_umbrella_head,
        remove_umbrella_head,
        interleave_rules,
        tag_without_family,
        tag_unknown_rule,
        change_aliases,
        add_key,
        rule_without_family,
        family_without_name,
        no_families,
        tags_not_a_mapping,
        tag_not_a_list,
        audit_only_not_a_mapping,
    ],
)
def test_a_catalogue_change_beyond_families_plans_the_full_matrix(
    trees: Trees, change: Callable[[dict[str, object]], None]
) -> None:
    trees.edit(affected.CATALOGUE, change)
    assert trees.decide(affected.CATALOGUE).full


@pytest.mark.parametrize("text", ["---\n[]\n", "---\nkey: [unclosed\n"])
def test_a_catalogue_that_is_not_one_plans_the_full_matrix(trees: Trees, text: str) -> None:
    trees.write(affected.CATALOGUE, text)
    assert trees.decide(affected.CATALOGUE).full
    assert trees.decide(SUDO_TASKS).full


def test_a_tag_change_affects_the_tag_and_the_families_of_its_rules(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        rule = str(first_rule(data, "pwquality")["rule_id"])
        cast("dict[str, list[str]]", data[affected.TAGS_KEY])["ssh"].append(rule)

    trees.edit(affected.CATALOGUE, change)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"ssh", "pwquality"}

    def reorder(data: dict[str, object]) -> None:
        tags = cast("dict[str, list[str]]", data[affected.TAGS_KEY])
        tags["cron"] = list(reversed(tags["cron"]))

    trees.dump(affected.CATALOGUE, catalogue())
    trees.edit(affected.CATALOGUE, reorder)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"cron"}


def test_a_role_variable_affects_the_topics_that_use_it(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        data["__linux_compliance_remediate_sudo_main"] = "/etc/sudoers.changed"

    trees.edit(affected.ROLE_VARIABLES, change)
    assert topics_of(trees.decide(affected.ROLE_VARIABLES)) == {"sudo"}


def test_a_new_role_variable_used_by_a_topic_file_affects_that_topic(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        data["__linux_compliance_remediate_sudo_new"] = 1

    trees.edit(affected.ROLE_VARIABLES, change)
    assert trees.decide(affected.ROLE_VARIABLES).full
    trees.append(SUDO_TASKS, "\n# __linux_compliance_remediate_sudo_new\n")
    assert topics_of(trees.decide(affected.ROLE_VARIABLES)) == {"sudo"}
    trees.append("roles/remediate/tasks/main.yml", "\n# __linux_compliance_remediate_sudo_new\n")
    assert trees.decide(affected.ROLE_VARIABLES).full


def test_a_role_variable_that_another_variable_uses_plans_the_full_matrix(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        data["__linux_compliance_remediate_sshd_main"] = (
            "{{ __linux_compliance_remediate_sudo_main }}"
        )

    shared = trees.base / affected.ROLE_VARIABLES
    trees.edit(affected.ROLE_VARIABLES, change)
    shared.write_text(
        (trees.head / affected.ROLE_VARIABLES).read_text(encoding="utf-8"), encoding="utf-8"
    )

    def value(data: dict[str, object]) -> None:
        data["__linux_compliance_remediate_sudo_main"] = "/etc/sudoers.changed"

    trees.edit(affected.ROLE_VARIABLES, value)
    decision = trees.decide(affected.ROLE_VARIABLES)
    assert decision.full
    assert "another role variable uses" in decision.reasons[0]


def test_role_variables_that_are_not_a_mapping_plan_the_full_matrix(trees: Trees) -> None:
    trees.write(affected.ROLE_VARIABLES, "---\n- one\n")
    assert trees.decide(affected.ROLE_VARIABLES).full


def test_a_description_change_of_the_argument_specs_affects_no_topic(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        main = cast("dict[str, dict[str, object]]", data["argument_specs"])["main"]
        main["short_description"] = "changed"
        options = cast("dict[str, dict[str, object]]", main["options"])
        for option in options.values():
            option["description"] = ["changed"]

    trees.edit(SPECS, change)
    decision = trees.decide(SPECS)
    assert not decision.full
    assert decision.topics == frozenset()


def test_a_nested_option_description_is_a_description_too(trees: Trees) -> None:
    def nested(description: str) -> Callable[[dict[str, object]], None]:
        def change(data: dict[str, object]) -> None:
            main = cast("dict[str, dict[str, object]]", data["argument_specs"])["main"]
            options = cast("dict[str, object]", main["options"])
            options["linux_compliance_nested"] = {
                "type": "dict",
                "options": {"inner": {"type": "str", "description": description}},
            }
            options["linux_compliance_plain"] = "not a mapping"

        return change

    trees.edit(SPECS, nested("first"))
    shutil.copyfile(trees.head / SPECS, trees.base / SPECS)
    trees.edit(SPECS, nested("second"))
    decision = trees.decide(SPECS)
    assert not decision.full
    assert decision.topics == frozenset()


def specs_type(data: dict[str, object]) -> None:
    main = cast("dict[str, dict[str, object]]", data["argument_specs"])["main"]
    options = cast("dict[str, dict[str, object]]", main["options"])
    next(iter(options.values()))["type"] = "raw"


def specs_without_entries(data: dict[str, object]) -> None:
    data["argument_specs"] = []


def specs_entry_not_a_mapping(data: dict[str, object]) -> None:
    cast("dict[str, object]", data["argument_specs"])["main"] = "text"


def specs_options_not_a_mapping(data: dict[str, object]) -> None:
    cast("dict[str, dict[str, object]]", data["argument_specs"])["main"]["options"] = ["one"]


@pytest.mark.parametrize(
    "change",
    [specs_type, specs_without_entries, specs_entry_not_a_mapping, specs_options_not_a_mapping],
)
def test_any_other_argument_spec_change_plans_the_full_matrix(
    trees: Trees, change: Callable[[dict[str, object]], None]
) -> None:
    trees.edit(SPECS, change)
    assert trees.decide(SPECS).full


def test_removed_argument_specs_plan_the_full_matrix(trees: Trees) -> None:
    (trees.head / SPECS).unlink()
    assert trees.decide(SPECS).full


def dispatch(trees: Trees) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", trees.load(affected.REGRESSION_DISPATCH))


def include(file: str) -> dict[str, object]:
    return {
        "name": f"Lifecycle regressions | Run {file}",
        affected.INCLUDE_TASKS: {"file": file},
        "when": f"'{file}' in lifecycle_regression.files",
    }


def test_a_new_include_of_the_regression_dispatch_affects_the_topic_that_names_it(
    trees: Trees,
) -> None:
    file = "lifecycle_sudo_extra.yml"
    tasks = dispatch(trees)
    tasks.insert(1, include(file))
    trees.dump(affected.REGRESSION_DISPATCH, tasks)
    trees.write(f"{affected.MOLECULE_TASKS}/{file}", "---\n[]\n")
    assert trees.decide(affected.REGRESSION_DISPATCH).full
    trees.append(SUDO_DECLARATION, f"\n# {file}\n")
    assert topics_of(trees.decide(affected.REGRESSION_DISPATCH)) == {"sudo"}


def test_a_removed_include_affects_the_topic_that_named_it(trees: Trees) -> None:
    tasks = [
        task
        for task in dispatch(trees)
        if task.get(affected.INCLUDE_TASKS) != {"file": "lifecycle_pwquality_regressions.yml"}
    ]
    trees.dump(affected.REGRESSION_DISPATCH, tasks)
    assert topics_of(trees.decide(affected.REGRESSION_DISPATCH)) == {"pwquality"}


def broaden_condition(tasks: list[dict[str, object]]) -> None:
    tasks[0]["when"] = "true"


def add_tags(tasks: list[dict[str, object]]) -> None:
    tasks[0]["tags"] = ["never"]


def change_record(tasks: list[dict[str, object]]) -> None:
    tasks[-1]["name"] = "changed"


def reorder_includes(tasks: list[dict[str, object]]) -> None:
    tasks[0], tasks[1] = tasks[1], tasks[0]


def template_file(tasks: list[dict[str, object]]) -> None:
    tasks[0][affected.INCLUDE_TASKS] = {"file": "{{ lifecycle_family }}.yml"}
    tasks[0]["when"] = "'{{ lifecycle_family }}.yml' in lifecycle_regression.files"


def add_apply(tasks: list[dict[str, object]]) -> None:
    tasks[0][affected.INCLUDE_TASKS] = {"file": "lifecycle_pwquality_regressions.yml", "apply": {}}


def free_form(tasks: list[dict[str, object]]) -> None:
    tasks[0][affected.INCLUDE_TASKS] = "lifecycle_pwquality_regressions.yml"


@pytest.mark.parametrize(
    "change",
    [
        broaden_condition,
        add_tags,
        change_record,
        reorder_includes,
        template_file,
        add_apply,
        free_form,
    ],
)
def test_a_dispatch_change_beyond_exact_includes_plans_the_full_matrix(
    trees: Trees, change: Callable[[list[dict[str, object]]], None]
) -> None:
    tasks = dispatch(trees)
    change(tasks)
    trees.dump(affected.REGRESSION_DISPATCH, tasks)
    assert trees.decide(affected.REGRESSION_DISPATCH).full


def test_a_dispatch_that_is_not_a_list_plans_the_full_matrix(trees: Trees) -> None:
    trees.write(affected.REGRESSION_DISPATCH, "---\nkey: value\n")
    assert trees.decide(affected.REGRESSION_DISPATCH).full
    (trees.head / affected.REGRESSION_DISPATCH).unlink()
    assert trees.decide(affected.REGRESSION_DISPATCH).full


@functools.cache
def full_matrices() -> tuple[dict[str, object], dict[str, object]]:
    return (
        {"include": molecule_matrix.legs(REPOSITORY_ROOT, "docker")},
        {"include": molecule_matrix.legs(REPOSITORY_ROOT, "libvirt")},
    )


def test_the_plan_keeps_the_legs_of_the_affected_topics_and_the_standard_legs() -> None:
    docker, libvirt = full_matrices()
    decision = affected.Decision(full=False, topics=frozenset({"sudo"}), reasons=("why",))
    found = affected.plan(decision, docker, libvirt)
    docker_legs = cast("dict[str, list[dict[str, str]]]", found["docker"])["include"]
    libvirt_legs = cast("dict[str, list[dict[str, str]]]", found["libvirt"])["include"]
    assert found["scope"] == affected.SCOPE_AFFECTED
    assert found["topics"] == ["sudo"]
    assert found["reasons"] == ["why"]
    assert docker_legs
    assert {leg["topic"] for leg in docker_legs} == {"sudo"}
    assert found["lifecycle_legs"] == len(docker_legs)
    expected = [
        leg for leg in cast("list[dict[str, str]]", docker["include"]) if leg["topic"] == "sudo"
    ]
    assert docker_legs == expected
    assert [leg for leg in libvirt_legs if leg["topic"] == ""] == [
        leg for leg in cast("list[dict[str, str]]", libvirt["include"]) if leg["topic"] == ""
    ]
    assert {leg["topic"] for leg in libvirt_legs} <= {"", "sudo"}


def test_the_full_plan_keeps_every_leg() -> None:
    docker, libvirt = full_matrices()
    decision = affected.Decision(full=True, topics=frozenset({"sudo"}), reasons=())
    found = affected.plan(decision, docker, libvirt)
    assert found["scope"] == affected.SCOPE_FULL
    assert found["docker"] == docker
    assert found["libvirt"] == libvirt


@pytest.mark.parametrize(
    "matrix",
    [
        [],
        {"include": "legs"},
        {"include": ["leg"]},
        {"include": [{"platform": "ubuntu", "scenario": "s", "topic": "t"}]},
        {"include": [{"platform": "ubuntu", "scenario": "s", "topic": "t", "mode": 1}]},
    ],
)
def test_a_matrix_that_is_not_one_is_an_error(matrix: object) -> None:
    decision = affected.Decision(full=False, topics=frozenset(), reasons=())
    with pytest.raises(affected.GenerationError):
        affected.plan(decision, matrix, {"include": []})


def write_inputs(tmp_path: Path, changed: list[str]) -> list[str]:
    docker, libvirt = full_matrices()
    (tmp_path / "changed").write_text("".join(f"{item}\0" for item in changed), encoding="utf-8")
    (tmp_path / "docker.json").write_text(json.dumps(docker), encoding="utf-8")
    (tmp_path / "libvirt.json").write_text(json.dumps(libvirt), encoding="utf-8")
    return [
        "--changed",
        str(tmp_path / "changed"),
        "--docker",
        str(tmp_path / "docker.json"),
        "--libvirt",
        str(tmp_path / "libvirt.json"),
    ]


def test_the_command_line_prints_one_line_of_json(
    trees: Trees, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = write_inputs(tmp_path, [SUDO_DROPIN, "docs/molecule.md"])
    status = affected.main(
        ["--base-root", str(trees.base), "--head-root", str(trees.head), *arguments]
    )
    assert status == 0
    output = capsys.readouterr().out
    assert output.count("\n") == 1
    found = cast("dict[str, object]", json.loads(output))
    assert found["scope"] == "affected"
    assert found["topics"] == ["sudo"]
    assert len(cast("list[str]", found["reasons"])) == 2


def test_the_command_line_reports_unreadable_inputs(
    trees: Trees, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = write_inputs(tmp_path, [SUDO_DROPIN])
    roots = ["--base-root", str(trees.base), "--head-root", str(trees.head)]
    (tmp_path / "docker.json").write_text("{", encoding="utf-8")
    assert affected.main([*roots, *arguments]) == 2
    assert "cannot be read as JSON" in capsys.readouterr().err
    (tmp_path / "changed").write_bytes(b"\xff")
    assert affected.main([*roots, *arguments]) == 2
    assert "cannot be read" in capsys.readouterr().err
    (tmp_path / "changed").unlink()
    assert affected.main([*roots, *arguments]) == 2


def test_the_module_runs_as_a_script(
    trees: Trees, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = write_inputs(tmp_path, [])
    monkeypatch.setattr(
        "sys.argv",
        [
            "affected_topics",
            "--base-root",
            str(trees.base),
            "--head-root",
            str(trees.head),
            *arguments,
        ],
    )
    monkeypatch.delitem(sys.modules, "tools.roles.affected_topics", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.roles.affected_topics", run_name="__main__")
    assert raised.value.code == 0


GOLDEN = "tests/unit/tools/test_content_golden_{family}.py"
DEFAULTS = generate_toggles.DEFAULTS.as_posix()
AUDIT_DEFAULTS = generate_toggles.AUDIT_DEFAULTS.as_posix()
AUDIT_SPECS = generate_toggles.AUDIT_SPECS.as_posix()
OTHER_TOPICS_OFF = f"{affected.MOLECULE_TASKS}/other_topics_off.yml"
GENERATED_BY_THE_CATALOGUE = (
    "content/catalogue.yml",
    "roles/remediate/tasks/dispatch.yml",
    "roles/remediate/tasks/internal_variables.yml",
)


def regression_text(file: str) -> str:
    record = f"{{{{ lifecycle_regression_files_run + ['{file}'] }}}}"
    return (
        "---\n- name: Synthetic regressions | Record that this regression file ran to its end\n"
        f'  ansible.builtin.set_fact:\n    lifecycle_regression_files_run: "{record}"\n'
    )


def declaration(family: str, regression: str, *, disruptive: bool) -> dict[str, object]:
    found: dict[str, object] = {"family": family, "disruptive": disruptive}
    if disruptive:
        found["containment"] = "The synthetic topic writes one file and reaches nothing else."
    found["state"] = {"files": [{"path": f"/etc/fsd-{family}"}]}
    found["applied"] = {"files": [{"path": f"/etc/fsd-{family}", "exists": True}]}
    found["regressions"] = [{"name": "changes", "files": [regression]}]
    return found


def changed_paths(trees: Trees) -> list[str]:
    """Return every file that differs between the two trees, as ``git diff --name-only`` would."""
    found: set[str] = set()
    for tree in (trees.base, trees.head):
        found.update(
            path.relative_to(tree).as_posix() for path in tree.rglob("*") if path.is_file()
        )
    return sorted(
        relative
        for relative in found
        if not (trees.base / relative).is_file()
        or not (trees.head / relative).is_file()
        or (trees.base / relative).read_bytes() != (trees.head / relative).read_bytes()
    )


def registry(data: dict[str, object]) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", data[affected.FAMILIES_KEY])


def add_topic(trees: Trees, family: str, source: str, entry: dict[str, object] | None) -> list[str]:
    """Make ``family`` native as a topic pull request does, with every file it touches.

    The first ``audit_only`` rule of ``source`` becomes a native rule of ``family``; ``entry``
    is a registry entry to insert before ``source`` for a family that the registry gains. The
    toggles are regenerated by the generator of ``make toggles``, and the topic gets its task
    file, its declaration, a regression group with its dispatch include, its documentation, a
    golden test and a changelog fragment.
    """
    regression = f"lifecycle_{family}_regressions.yml"
    flags: dict[str, bool] = {}

    def change(data: dict[str, object]) -> None:
        families = registry(data)
        if entry is not None:
            position = next(index for index, item in enumerate(families) if item["name"] == source)
            families.insert(position, entry)
        flags[family] = bool(
            next(item for item in families if item["name"] == family)["disruptive"]
        )
        audit_only = cast("dict[str, list[str]]", data[affected.AUDIT_ONLY_KEY])
        rule_id = audit_only[source].pop(0)
        rules_of(data).append(
            {
                **first_rule(data, "banners"),
                "rule_id": rule_id,
                "family": family,
                "disruptive": flags[family],
                "toggle": toggles.rule_toggle_name(rule_id),
            }
        )

    trees.edit(affected.CATALOGUE, change)
    for relative, content in generate_toggles.outputs(trees.head).items():
        trees.write(relative.as_posix(), content)
    trees.write(
        f"{affected.ROLE_TASKS}/{family}.yml",
        f"---\n- name: Synthetic {family} | Apply the topic\n  ansible.builtin.debug:\n"
        "    msg: synthetic\n",
    )
    trees.dump(
        f"{affected.TOPICS}/{family}.yml",
        declaration(family, regression, disruptive=flags[family]),
    )
    trees.write(f"{affected.MOLECULE_TASKS}/{regression}", regression_text(regression))
    tasks = dispatch(trees)
    tasks.append(include(regression))
    trees.dump(affected.REGRESSION_DISPATCH, tasks)
    return [
        *changed_paths(trees),
        f"docs/remediation-{family}.md",
        GOLDEN.format(family=family),
        f"changelogs/fragments/FREES-195-{family}.yml",
        *GENERATED_BY_THE_CATALOGUE,
    ]


Matrices = tuple[list[dict[str, str]], list[dict[str, str]]]


def repository_legs() -> Matrices:
    docker, libvirt = full_matrices()
    return (
        cast("list[dict[str, str]]", docker["include"]),
        cast("list[dict[str, str]]", libvirt["include"]),
    )


def head_legs(trees: Trees) -> Matrices:
    return molecule_matrix.legs(trees.head, "docker"), molecule_matrix.legs(trees.head, "libvirt")


def planned(decision: affected.Decision, matrices: Matrices) -> Matrices:
    found = affected.plan(decision, {"include": matrices[0]}, {"include": matrices[1]})
    return (
        cast("dict[str, list[dict[str, str]]]", found["docker"])["include"],
        cast("dict[str, list[dict[str, str]]]", found["libvirt"])["include"],
    )


def test_a_new_topic_plans_only_the_legs_of_that_topic(trees: Trees) -> None:
    family = "kernel_build_config"
    changed = add_topic(trees, family, family, None)
    assert DEFAULTS not in changed
    assert SPECS in changed
    decision = trees.decide(*changed)
    assert not decision.full, decision.reasons
    assert decision.topics == frozenset({family})
    head = head_legs(trees)
    docker, libvirt = planned(decision, head)
    assert docker == [leg for leg in head[0] if leg["topic"] == family]
    assert {leg["mode"] for leg in docker} == {"topic", "rule", "regressions-changes"}
    assert {leg["platform"] for leg in docker} == check_lifecycle_topics.platforms(trees.head)
    assert [leg for leg in head[0] if leg["topic"] != family] == repository_legs()[0]
    assert libvirt == [leg for leg in head[1] if leg["topic"] == ""]


def test_a_new_family_with_its_own_toggles_plans_only_its_legs(trees: Trees) -> None:
    family = "auditd_synthetic"
    entry: dict[str, object] = {"name": family, "disruptive": True, "umbrella": "auditd"}
    changed = add_topic(trees, family, "auditd", entry)
    assert {DEFAULTS, AUDIT_DEFAULTS, SPECS, AUDIT_SPECS} <= set(changed)
    decision = trees.decide(*changed)
    assert not decision.full, decision.reasons
    assert decision.topics == frozenset({family, "auditd"})
    reasons = {reason.split(":", 1)[0]: reason for reason in decision.reasons}
    for relative in (DEFAULTS, AUDIT_DEFAULTS, SPECS, AUDIT_SPECS):
        assert reasons[relative].endswith(f": {family}"), reasons[relative]
    head = head_legs(trees)
    docker, _ = planned(decision, head)
    assert docker
    assert {leg["topic"] for leg in docker} == {family}
    assert [leg for leg in head[0] if leg["topic"] != family] == repository_legs()[0]


def test_a_catalogue_entry_change_of_one_topic_plans_only_its_legs(trees: Trees) -> None:
    def change(data: dict[str, object]) -> None:
        parameters = cast("dict[str, object]", first_rule(data, "login_defs")["parameters"])
        parameters["synthetic"] = "changed"

    trees.edit(affected.CATALOGUE, change)
    decision = trees.decide(affected.CATALOGUE)
    assert decision == affected.Decision(
        full=False,
        topics=frozenset({"login_defs"}),
        reasons=(f"{affected.CATALOGUE}: catalogue entries: login_defs",),
    )
    docker, _ = planned(decision, repository_legs())
    assert docker == [leg for leg in repository_legs()[0] if leg["topic"] == "login_defs"]
    assert {leg["mode"] for leg in docker} >= {"topic", "rule"}


@pytest.mark.parametrize(
    "relative",
    [
        "extensions/molecule/shared/converge.yml",
        "extensions/molecule/shared/vars/target.yml",
        OTHER_TOPICS_OFF,
        "extensions/molecule/shared/tasks/lifecycle_topic.yml",
        "roles/remediate/tasks/main.yml",
    ],
)
def test_a_shared_file_plans_every_leg(trees: Trees, relative: str) -> None:
    trees.append(relative, "\n# changed\n")
    decision = trees.decide(relative)
    assert decision.full, decision.reasons
    assert planned(decision, repository_legs()) == repository_legs()


@pytest.mark.parametrize("relative", ["unknown.txt", "extensions/molecule/shared/new/file.yml"])
def test_an_unknown_path_plans_every_leg(trees: Trees, relative: str) -> None:
    trees.write(relative, "---\n[]\n")
    decision = trees.decide(relative)
    assert decision.full
    assert len(decision.reasons) == 1
    assert decision.reasons[0].startswith(f"{relative}: ")
    assert planned(decision, repository_legs()) == repository_legs()


def test_the_converge_and_verify_plays_take_the_other_topics_from_the_catalogue() -> None:
    shared = REPOSITORY_ROOT / "extensions/molecule/shared"
    target = cast(
        "dict[str, object]",
        load_yaml((shared / "vars/target.yml").read_text(encoding="utf-8")),
    )
    assert "__linux_compliance_remediate_rules" in str(target["molecule_other_native_topics"])
    for name in ("converge.yml", "verify.yml", "converge_libvirt.yml", "verify_libvirt.yml"):
        text = (shared / name).read_text(encoding="utf-8")
        assert "file: tasks/other_topics_off.yml" in text, name
        for family in native():
            assert toggles.toggle_name(family) not in text, (name, family)


def test_a_gained_family_affects_it_and_a_lost_one_affects_it_and_its_umbrella(
    trees: Trees,
) -> None:
    trees.edit(affected.CATALOGUE, add_family)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"new"}

    def remove(data: dict[str, object]) -> None:
        families = registry(data)
        families.remove(next(item for item in families if item["name"] == "journald"))

    trees.dump(affected.CATALOGUE, catalogue())
    trees.edit(affected.CATALOGUE, remove)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"journald", "logging"}

    def move(data: dict[str, object]) -> None:
        next(item for item in registry(data) if item["name"] == "aide")["umbrella"] = "logging"

    trees.dump(affected.CATALOGUE, catalogue())
    trees.edit(affected.CATALOGUE, move)
    assert topics_of(trees.decide(affected.CATALOGUE)) == {"aide", "integrity", "logging"}


def controlled_by(topic: str) -> set[str]:
    """Return the families whose rules the toggle of ``topic`` controls, by the role's own rule."""
    data = catalogue()
    families = registry(data)
    umbrellas = {
        str(item["name"]): str(item["umbrella"]) for item in families if "umbrella" in item
    }
    tags = cast("dict[str, list[str]]", data[affected.TAGS_KEY])
    audit_only = cast("dict[str, list[str]]", data[affected.AUDIT_ONLY_KEY])
    rules = [(str(rule["rule_id"]), str(rule["family"])) for rule in rules_of(data)]
    rules.extend((rule, family) for family, listed in audit_only.items() for rule in listed)
    found = {
        str(item["name"])
        for item in families
        if topic in (item["name"], umbrellas.get(str(item["name"])))
    }
    found.update(
        family
        for rule, family in rules
        if topic
        in toggles.controlling_topics(
            family, [tag for tag, listed in tags.items() if rule in listed], umbrellas
        )
    )
    return found


@pytest.mark.parametrize("relative", [DEFAULTS, AUDIT_DEFAULTS])
@pytest.mark.parametrize("topic", ["ssh", "pam", "services", "banners"])
def test_a_toggle_default_affects_every_family_that_the_toggle_controls(
    trees: Trees, relative: str, topic: str
) -> None:
    def change(data: dict[str, object]) -> None:
        data[toggles.toggle_name(topic)] = False

    trees.edit(relative, change)
    expected = controlled_by(topic)
    assert expected
    assert topics_of(trees.decide(relative)) == expected


def test_the_toggle_of_a_tag_affects_the_families_of_its_rules(trees: Trees) -> None:
    tagged = {
        str(rule["family"])
        for rule in rules_of(catalogue())
        if rule["rule_id"] in cast("dict[str, list[str]]", catalogue()[affected.TAGS_KEY])["ssh"]
    }
    trees.edit(DEFAULTS, lambda data: data.update({toggles.toggle_name("ssh"): False}))
    found = topics_of(trees.decide(DEFAULTS))
    assert found is not None
    assert found >= {"ssh"} | tagged
    assert found > {"ssh"}


def test_a_removed_or_added_toggle_default_affects_its_family(trees: Trees) -> None:
    def remove(data: dict[str, object]) -> None:
        del data[toggles.toggle_name("banners")]

    trees.edit(DEFAULTS, remove)
    assert topics_of(trees.decide(DEFAULTS)) == {"banners"}
    trees.edit(affected.CATALOGUE, add_family)
    trees.edit(DEFAULTS, lambda data: data.update({toggles.toggle_name("new"): True}))
    assert topics_of(trees.decide(DEFAULTS)) == {"banners", "new"}


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("linux_compliance_banners_enabled", 1),
        ("linux_compliance_banners_enabled", "{{ true }}"),
        ("linux_compliance_remediate_enabled", True),
        ("linux_compliance_rule_banner_etc_issue_cis_enabled", False),
        ("linux_compliance_nothing_enabled", True),
        ("linux_compliance_remediate_banner_text", "changed"),
        ("linux_compliance_Banners_enabled", True),
    ],
)
def test_a_default_that_is_no_generated_topic_toggle_plans_the_full_matrix(
    trees: Trees, name: str, value: object
) -> None:
    trees.edit(DEFAULTS, lambda data: data.update({name: value}))
    decision = trees.decide(DEFAULTS)
    assert decision.full, decision.reasons


def test_defaults_that_are_not_a_mapping_plan_the_full_matrix(trees: Trees) -> None:
    trees.write(AUDIT_DEFAULTS, "---\n- one\n")
    assert trees.decide(AUDIT_DEFAULTS).full
    (trees.head / AUDIT_DEFAULTS).unlink()
    assert trees.decide(AUDIT_DEFAULTS).full


def test_a_toggle_of_a_tag_that_names_an_unknown_rule_plans_the_full_matrix(
    trees: Trees,
) -> None:
    def change(data: dict[str, object]) -> None:
        cast("dict[str, list[str]]", data[affected.TAGS_KEY])["ssh"].append("xccdf_unknown")

    trees.edit(affected.CATALOGUE, change)
    shutil.copyfile(trees.head / affected.CATALOGUE, trees.base / affected.CATALOGUE)
    trees.edit(DEFAULTS, lambda data: data.update({toggles.toggle_name("ssh"): False}))
    decision = trees.decide(DEFAULTS)
    assert decision.full
    assert "which no family catalogues" in decision.reasons[0]


def options_of(data: dict[str, object], entry: str = "main") -> dict[str, object]:
    specs = cast("dict[str, dict[str, object]]", data["argument_specs"])
    return cast("dict[str, object]", specs[entry]["options"])


def test_a_toggle_option_affects_every_family_that_the_toggle_controls(trees: Trees) -> None:
    def remove(data: dict[str, object]) -> None:
        del options_of(data)[toggles.toggle_name("pam")]

    trees.edit(SPECS, remove)
    assert topics_of(trees.decide(SPECS)) == controlled_by("pam")

    def add(data: dict[str, object]) -> None:
        options_of(data, "evaluate.yml")[toggles.toggle_name("new")] = {
            "type": "bool",
            "default": True,
            "description": ["Topic toggle of the new family."],
        }

    trees.edit(affected.CATALOGUE, add_family)
    trees.edit(AUDIT_SPECS, add)
    assert topics_of(trees.decide(AUDIT_SPECS)) == {"new"}


def allowed(data: dict[str, object]) -> dict[str, object]:
    return cast("dict[str, object]", options_of(data)[affected.ALLOW_LIST])


def test_a_gained_or_lost_disruptive_choice_affects_the_families_it_allows(
    trees: Trees,
) -> None:
    def gain(data: dict[str, object]) -> None:
        choices = cast("list[str]", allowed(data)["choices"])
        choices.remove("kernel_modules")
        choices.append("new")

    trees.edit(affected.CATALOGUE, add_family)
    trees.edit(SPECS, gain)
    assert topics_of(trees.decide(SPECS)) == {"new"} | controlled_by("kernel_modules")


def reorder_choices(option: dict[str, object]) -> None:
    choices = cast("list[str]", option["choices"])
    choices[0], choices[1] = choices[1], choices[0]


def choices_not_a_list(option: dict[str, object]) -> None:
    option["choices"] = "ssh"


def choice_not_text(option: dict[str, object]) -> None:
    cast("list[object]", option["choices"]).append(1)


def allow_default(option: dict[str, object]) -> None:
    option["default"] = ["ssh"]


def unknown_choice(option: dict[str, object]) -> None:
    cast("list[object]", option["choices"]).append("nothing")


def reserved_choice(option: dict[str, object]) -> None:
    cast("list[object]", option["choices"]).append("remediate")


@pytest.mark.parametrize(
    "change",
    [
        reorder_choices,
        choices_not_a_list,
        choice_not_text,
        allow_default,
        unknown_choice,
        reserved_choice,
    ],
)
def test_any_other_change_of_the_disruptive_choices_plans_the_full_matrix(
    trees: Trees, change: Callable[[dict[str, object]], None]
) -> None:
    trees.edit(SPECS, lambda data: change(allowed(data)))
    assert trees.decide(SPECS).full


def allow_list_removed(data: dict[str, object]) -> None:
    options_of(data).pop(affected.ALLOW_LIST)


def allow_list_text(data: dict[str, object]) -> None:
    options_of(data)[affected.ALLOW_LIST] = "text"


def toggle_option_type(data: dict[str, object]) -> None:
    cast("dict[str, object]", options_of(data)[toggles.toggle_name("ssh")])["type"] = "raw"


def toggle_option_default(data: dict[str, object]) -> None:
    cast("dict[str, object]", options_of(data)[toggles.toggle_name("ssh")])["default"] = False


def specs_entry_added(data: dict[str, object]) -> None:
    cast("dict[str, object]", data["argument_specs"])["extra.yml"] = {"options": {}}


def specs_key_added(data: dict[str, object]) -> None:
    data["extra"] = True


def specs_entry_key(data: dict[str, object]) -> None:
    cast("dict[str, dict[str, object]]", data["argument_specs"])["main"]["author"] = ["someone"]


@pytest.mark.parametrize(
    "change",
    [
        allow_list_removed,
        allow_list_text,
        toggle_option_type,
        toggle_option_default,
        specs_entry_added,
        specs_key_added,
        specs_entry_key,
    ],
)
def test_an_option_that_is_no_generated_toggle_plans_the_full_matrix(
    trees: Trees, change: Callable[[dict[str, object]], None]
) -> None:
    trees.edit(SPECS, change)
    assert trees.decide(SPECS).full


@pytest.mark.parametrize(
    "text", ["{1: one, two: 2}", "&loop [*loop]"], ids=["mixed keys", "recursive alias"]
)
def test_a_default_that_cannot_be_compared_plans_the_full_matrix(trees: Trees, text: str) -> None:
    for tree in (trees.base, trees.head):
        path = tree / DEFAULTS
        path.write_text(
            path.read_text(encoding="utf-8") + f"linux_compliance_banners_enabled: {text}\n",
            encoding="utf-8",
        )
    decision = trees.decide(DEFAULTS)
    assert decision.full, decision.reasons
