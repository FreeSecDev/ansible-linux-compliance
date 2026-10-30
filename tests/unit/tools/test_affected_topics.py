"""The path-to-topic mapping of the lifecycle legs (FREES-189).

Every case builds a base and a head copy of the parts of the repository that the mapping reads,
changes the head, and checks which topics the change affects or that it plans the full matrix.
The mutation cases change one thing that would let a pull request run fewer legs than it needs
(a shared include, an interleaved catalogue, a symbolic link, a dispatch condition) and check that
the mapping falls back to the full matrix or widens the topics.
"""

from __future__ import annotations

import json
import runpy
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
import yaml

from tools.roles import affected_topics as affected
from tools.roles import generate_toggles, molecule_matrix

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


class Trees:
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
        return cast("object", yaml.safe_load((self.head / relative).read_text(encoding="utf-8")))

    def dump(self, relative: str, data: object) -> None:
        self.write(relative, "---\n" + yaml.safe_dump(data, sort_keys=False))

    def edit(self, relative: str, change: Callable[[dict[str, object]], None]) -> None:
        data = cast("dict[str, object]", self.load(relative))
        change(data)
        self.dump(relative, data)

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
        yaml.safe_load((REPOSITORY_ROOT / affected.CATALOGUE).read_text(encoding="utf-8")),
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
        "tools/scc/needs-smoke.sh",
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
        "plugins/modules/control_state.py",
        "plugins/module_utils/compliance/toggles.py",
        "plugins/filter/scc_toggles.py",
        "content/manifest.yml",
        "content/stig-mapping.json",
        "roles/remediate/defaults/main.yml",
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
    files = role_task_files()
    assert files
    families = native()
    for relative in files:
        stem = Path(relative).stem
        expected = {
            family for family in families if stem == family or stem.startswith(family + "_")
        }
        assert len(expected) == 1, relative
        assert topics_of(trees.decide(relative)) == expected, relative


def test_every_regression_file_belongs_to_the_topics_whose_groups_name_it(trees: Trees) -> None:
    owners: dict[str, set[str]] = {}
    for path in sorted((REPOSITORY_ROOT / affected.TOPICS).glob("*.yml")):
        data = cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))
        for group in cast("list[dict[str, list[str]]]", data.get("regressions", [])):
            for file in group["files"]:
                owners.setdefault(file, set()).add(path.stem)
    assert owners
    for file, topics in owners.items():
        assert topics_of(trees.decide(f"{affected.MOLECULE_TASKS}/{file}")) == topics, file


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
    assert "roles/remediate/tasks/main.yml" in decision.reasons[0]


def test_a_reference_in_the_base_revision_counts_as_well(trees: Trees) -> None:
    path = trees.base / "roles/remediate/tasks/main.yml"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n# sudo_dropin_apply.yml\n", encoding="utf-8"
    )
    assert trees.decide(SUDO_DROPIN).full


def test_a_same_named_file_of_another_directory_is_not_a_reference(trees: Trees) -> None:
    trees.append(
        "extensions/molecule/shared/lifecycle.yml",
        "\n# vars/topics/sudo.yml and roles/remediate/defaults/sudo.yml\n",
    )
    assert topics_of(trees.decide(SUDO_TASKS)) == {"sudo"}
    trees.append("extensions/molecule/shared/lifecycle.yml", "\n# tasks/sudo.yml\n")
    assert trees.decide(SUDO_TASKS).full


def test_a_new_role_file_of_a_family_belongs_to_it_even_if_not_yet_native(trees: Trees) -> None:
    trees.write("roles/remediate/tasks/auditd.yml", "---\n[]\n")
    decision = trees.decide("roles/remediate/tasks/auditd.yml")
    assert topics_of(decision) == {"auditd"}
    docker = {"include": molecule_matrix.legs(REPOSITORY_ROOT, "docker")}
    libvirt = {"include": molecule_matrix.legs(REPOSITORY_ROOT, "libvirt")}
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
        add_family,
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
