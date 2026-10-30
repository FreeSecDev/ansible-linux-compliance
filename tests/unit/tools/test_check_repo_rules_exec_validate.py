from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tools.lint import check_repo_rules as rules
from tools.lint.repo_rules import exec_modules

ALLOWED_FILE = "roles/remediate/tasks/sudo_dropin_apply.yml"
VISUDO = "/usr/sbin/visudo -cf %s"
REFUSED = "parameter 'validate' of"


def found(root: Path, text: str, name: str = ALLOWED_FILE) -> list[str]:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return [violation.message for violation in rules.check_paths([target], root)]


def task(module: str = "ansible.builtin.copy", value: str = VISUDO) -> str:
    return (
        "---\n- name: Probe\n"
        f"  {module}:\n    content: x\n    dest: /etc/sudoers.d/50-x\n    validate: {value}\n"
    )


def test_the_allow_list_is_exactly_the_visudo_check_of_the_sudo_drop_ins() -> None:
    expected = frozenset({(Path(ALLOWED_FILE), "copy", "validate", VISUDO)})
    assert expected == exec_modules.ALLOWED_PARAMETERS


def test_the_reviewed_validate_is_used_by_its_file() -> None:
    text = (rules.REPO_ROOT / ALLOWED_FILE).read_text(encoding="utf-8")
    assert f"validate: {VISUDO}\n" in text
    assert text.count("validate:") == 1


@pytest.mark.parametrize("module", ["copy", "ansible.builtin.copy", "ansible.legacy.copy"])
def test_the_reviewed_visudo_check_is_allowed_in_its_file(tmp_path: Path, module: str) -> None:
    assert found(tmp_path, task(module)) == []


@pytest.mark.parametrize(
    ("text", "name"),
    [
        (task(value="/usr/sbin/visudo -cf %s -x"), ALLOWED_FILE),
        (task(value="/bin/sh -c id %s"), ALLOWED_FILE),
        (task(value="'/usr/sbin/visudo -cf %s'"), ALLOWED_FILE),
        (task(value='"{{ visudo }} -cf %s"'), ALLOWED_FILE),
        (task(module="ansible.builtin.template"), ALLOWED_FILE),
        (task(module="ansible.builtin.lineinfile"), ALLOWED_FILE),
        (task(), "roles/remediate/tasks/sudo_dropin_cleanup.yml"),
        (task(), "roles/r/tasks/main.yml"),
        (
            (
                "---\n- name: Probe\n  ansible.builtin.copy:\n    content: x\n    dest: /x\n"
                f"  args:\n    validate: {VISUDO}\n"
            ),
            ALLOWED_FILE,
        ),
        (
            f"---\n- name: Probe\n  ansible.builtin.copy: content=x dest=/x validate={VISUDO}\n",
            ALLOWED_FILE,
        ),
        (
            (
                "---\n- name: Probe\n  module_defaults:\n    ansible.builtin.copy:\n"
                f"      validate: {VISUDO}\n  ansible.builtin.debug:\n    msg: x\n"
            ),
            ALLOWED_FILE,
        ),
    ],
)
def test_every_other_form_of_validate_is_refused(tmp_path: Path, text: str, name: str) -> None:
    assert any(message.startswith(REFUSED) for message in found(tmp_path, text, name))


YAML_FORMS = (
    task(value=f"|\n      {VISUDO}"),
    task(value=f">-\n      {VISUDO}"),
    (
        "---\n- name: Probe\n  vars:\n    other: &other /bin/sh -c id %s\n"
        "  ansible.builtin.copy:\n    content: x\n    dest: /x\n    validate: *other\n"
    ),
    (
        "---\n- name: Probe\n  ansible.builtin.copy:\n"
        f"    <<: {{validate: {VISUDO}}}\n    content: x\n    dest: /x\n"
    ),
    (
        "---\n- name: Probe\n  vars:\n"
        f"    base: &base {{validate: {VISUDO}}}\n"
        "  ansible.builtin.copy:\n    <<: *base\n    content: x\n    dest: /x\n"
    ),
    f"---\n- name: Probe\n  action: ansible.builtin.copy content=x dest=/x validate={VISUDO}\n",
)


@pytest.mark.parametrize("text", YAML_FORMS)
def test_block_scalars_aliases_merge_keys_and_free_form_actions_are_refused(
    tmp_path: Path, text: str
) -> None:
    assert any(message.startswith(REFUSED) for message in found(tmp_path, text))


def test_without_a_repository_path_nothing_is_allowed(tmp_path: Path) -> None:
    loader = yaml.SafeLoader(task())
    try:
        document = loader.get_single_node()
    finally:
        loader.dispose()
    assert document is not None
    assert exec_modules.module_parameter_findings(tmp_path / "x.yml", [document]) != []
