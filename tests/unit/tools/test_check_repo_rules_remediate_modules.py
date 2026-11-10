"""The modules that ``roles/remediate`` may run (FREES-203, ADR 0032 §1).

A task of the remediate role may use ``ansible.builtin`` modules, this collection's modules and the
community modules of an allow list that starts empty. An allow-listed module also needs its
collection pinned at one exact version in ``galaxy.yml``, the Molecule requirements and the
collection pins.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.lint import check_repo_rules as rules
from tools.lint.repo_rules import remediate_modules as remediate

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ADR = "(ADR 0032 §1)"
NOT_ALLOWED = "is not allowed in roles/remediate"
TEMPLATED = "templated module name"
NOT_PINNED = "needs its collection"
TASK_FILE = "roles/remediate/tasks/example.yml"
MAKE = "community.general.make"
DIGEST = "0" * 64
GALAXY = "---\ndependencies:\n  community.general: 10.1.0\n"
REQUIREMENTS = "---\ncollections:\n  - name: community.general\n    version: 10.1.0\n"
PINS = f"collection community.general 10.1.0 {DIGEST} 1234\n"


def documents(text: str) -> list[yaml.Node]:
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        return list(iter(loader.get_node, None))
    finally:
        loader.dispose()


def check(
    text: str,
    relative: str = TASK_FILE,
    allowed: frozenset[str] = remediate.ALLOWED_COMMUNITY_MODULES,
    root: Path = REPOSITORY_ROOT,
) -> list[str]:
    return [
        violation.message
        for violation in remediate.check_remediate_modules(
            Path(relative), Path(relative), documents(text), allowed=allowed, root=root
        )
    ]


def write_pins(
    root: Path,
    galaxy: str | None = GALAXY,
    requirements: str | None = REQUIREMENTS,
    pins: str | None = PINS,
) -> Path:
    for relative, content in (
        ("galaxy.yml", galaxy),
        ("extensions/molecule/requirements.yml", requirements),
        ("extensions/molecule/collections.pins", pins),
    ):
        if content is not None:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    return root


ACCEPTED = [
    pytest.param(
        "---\n- name: Copy\n  ansible.builtin.copy:\n    content: x\n    dest: /tmp/x\n",
        id="builtin",
    ),
    pytest.param(
        "---\n- name: Record\n  freesecdev.linux_compliance.control_state:\n    action: record\n",
        id="own-module",
    ),
    pytest.param(
        "---\n- name: Include\n  ansible.builtin.include_tasks:\n    file: family.yml\n",
        id="include",
    ),
    pytest.param(
        "---\n- name: Block\n  when: true\n  block:\n    - name: Inner\n"
        "      ansible.builtin.debug:\n        msg: x\n  rescue:\n    - name: Rescue\n"
        "      ansible.builtin.fail:\n        msg: x\n"
        "  always:\n    - name: Always\n      ansible.builtin.meta: noop\n",
        id="block",
    ),
    pytest.param(
        "---\n- &base\n  name: Base\n  ansible.builtin.debug:\n    msg: x\n"
        "- <<: *base\n  name: Merged\n  tags: [x]\n",
        id="merge-key",
    ),
    pytest.param(
        "---\n- name: Loop\n  ansible.builtin.debug:\n    msg: '{{ item }}'\n  with_items: [1]\n"
        "  loop_control:\n    label: x\n  register: out\n  changed_when: false\n",
        id="keywords",
    ),
    pytest.param(
        "---\n- name: Action\n  action: ansible.builtin.debug msg=x\n"
        "- name: Local\n  local_action:\n    module: freesecdev.linux_compliance.audit_control\n",
        id="action",
    ),
    pytest.param(
        "---\n- name: Handler\n  listen: restart\n  ansible.builtin.debug:\n    msg: x\n",
        id="handler",
    ),
    pytest.param(
        "---\n- name: Defaults\n  module_defaults:\n    community.general.make:\n      chdir: /\n"
        "  ansible.builtin.debug:\n    msg: x\n",
        id="module-defaults-data",
    ),
]


@pytest.mark.parametrize("text", ACCEPTED)
def test_accepted_tasks(text: str) -> None:
    assert check(text) == []


REFUSED = [
    pytest.param("---\n- name: Make\n  community.general.make:\n    chdir: /\n", MAKE, id="make"),
    pytest.param(
        "---\n- name: At\n  ansible.posix.at:\n    command: x\n", "ansible.posix.at", id="at"
    ),
    pytest.param("---\n- name: Copy\n  copy:\n    dest: /tmp/x\n", "'copy'", id="short-name"),
    pytest.param(
        "---\n- name: Legacy\n  ansible.legacy.copy:\n    dest: /tmp/x\n",
        "ansible.legacy.copy",
        id="legacy",
    ),
    pytest.param(
        "---\n- name: Action\n  action: community.general.make chdir=/\n", MAKE, id="action"
    ),
    pytest.param(
        "---\n- name: Action\n  local_action:\n    module: community.general.make\n",
        MAKE,
        id="local-action-mapping",
    ),
    pytest.param("---\n- name: Empty\n  action: ''\n", "''", id="empty-action"),
    pytest.param(
        "---\n- name: Nested\n  block:\n    - name: Inner\n      community.general.make: {}\n",
        MAKE,
        id="nested-block",
    ),
    pytest.param(
        "---\n- &base\n  community.general.make: {}\n- <<: *base\n  name: Merged\n",
        MAKE,
        id="merged",
    ),
    pytest.param(
        "---\n- name: Case\n  Ansible.Builtin.copy: {}\n", "Ansible.Builtin.copy", id="case"
    ),
]


@pytest.mark.parametrize(("text", "name"), REFUSED)
def test_refused_modules(text: str, name: str) -> None:
    messages = check(text)
    assert any(NOT_ALLOWED in message and name in message for message in messages), messages
    assert all(ADR in message for message in messages)


@pytest.mark.parametrize(
    "text",
    [
        "---\n- name: Templated\n  '{{ module }}': {}\n",
        "---\n- name: Templated\n  action: '{{ module }} x=1'\n",
    ],
)
def test_templated_module_names_are_refused(text: str) -> None:
    messages = check(text)
    assert len(messages) == 1
    assert TEMPLATED in messages[0]


def test_the_line_is_the_line_of_the_module_key() -> None:
    violations = remediate.check_remediate_modules(
        Path(TASK_FILE),
        Path(TASK_FILE),
        documents("---\n- name: One\n  ansible.builtin.debug: {}\n- name: Two\n  make: {}\n"),
    )
    assert [violation.line for violation in violations] == [5]


@pytest.mark.parametrize(
    "relative",
    [
        "roles/remediate/tasks/main.yml",
        "roles/remediate/handlers/main.yaml",
        "Roles/Remediate/tasks/main.YML",
        "roles/remediate/tasks/nested/family.yml",
    ],
)
def test_every_yaml_file_below_the_role_is_checked(relative: str) -> None:
    assert check("---\n- name: Make\n  community.general.make: {}\n", relative)


@pytest.mark.parametrize(
    "relative",
    [
        "roles/audit/tasks/main.yml",
        "extensions/molecule/shared/converge.yml",
        "tests/playbooks/remediate.yml",
        "roles/remediate/README.md",
        "roles/remediate.yml",
    ],
)
def test_files_outside_the_role_are_not_checked(relative: str) -> None:
    assert check("---\n- name: Make\n  community.general.make: {}\n", relative) == []


def test_relative_none_is_not_checked() -> None:
    found = remediate.check_remediate_modules(
        Path("x.yml"), None, documents("---\n- community.general.make: {}\n")
    )
    assert found == []


def test_documents_that_are_not_task_lists_are_not_read() -> None:
    text = "---\ncommunity.general.make: x\nvalues:\n  - copy: 1\n"
    assert check(text, "roles/remediate/vars/rules.yml") == []


def test_allow_listed_module_with_pinned_collection_is_accepted(tmp_path: Path) -> None:
    root = write_pins(tmp_path)
    text = "---\n- name: Make\n  community.general.make: {}\n"
    assert check(text, allowed=frozenset({MAKE}), root=root) == []


def test_allow_listed_module_by_action_is_accepted(tmp_path: Path) -> None:
    root = write_pins(tmp_path)
    text = f"---\n- name: Make\n  action: {MAKE} chdir=/\n"
    assert check(text, allowed=frozenset({MAKE}), root=root) == []


def test_allow_list_does_not_cover_other_modules_of_the_collection(tmp_path: Path) -> None:
    root = write_pins(tmp_path)
    text = "---\n- name: Other\n  community.general.ini_file: {}\n"
    messages = check(text, allowed=frozenset({MAKE}), root=root)
    assert len(messages) == 1
    assert NOT_ALLOWED in messages[0]


def test_allow_list_entry_that_is_not_a_module_name_is_refused(tmp_path: Path) -> None:
    root = write_pins(tmp_path)
    messages = check("---\n- name: Short\n  make: {}\n", allowed=frozenset({"make"}), root=root)
    assert len(messages) == 1
    assert NOT_ALLOWED in messages[0]


UNPINNED = [
    pytest.param({"galaxy": None}, id="no-galaxy"),
    pytest.param({"galaxy": "---\n- not a mapping\n"}, id="galaxy-not-mapping"),
    pytest.param({"galaxy": "---\ndependencies: {}\n"}, id="galaxy-missing"),
    pytest.param({"galaxy": "---\ndependencies: []\n"}, id="galaxy-dependencies-list"),
    pytest.param({"galaxy": "---\ndependencies:\n  community.general: '>=10.1.0'\n"}, id="range"),
    pytest.param({"galaxy": "---\ndependencies:\n  community.general: '*'\n"}, id="star"),
    pytest.param({"galaxy": "---\ndependencies:\n  community.general: 10\n"}, id="integer"),
    pytest.param({"galaxy": "---\ndependencies:\n  community.general: 10.2.0\n"}, id="mismatch"),
    pytest.param({"galaxy": "---\ndependencies: [\n"}, id="galaxy-invalid-yaml"),
    pytest.param({"requirements": None}, id="no-requirements"),
    pytest.param({"requirements": "---\ncollections: {}\n"}, id="requirements-not-list"),
    pytest.param(
        {"requirements": "---\ncollections:\n  - community.general\n"}, id="requirements-string"
    ),
    pytest.param(
        {"requirements": REQUIREMENTS + "  - name: community.general\n    version: 10.1.0\n"},
        id="requirements-twice",
    ),
    pytest.param(
        {"requirements": "---\ncollections:\n  - name: community.general\n    version: 10.2.0\n"},
        id="requirements-mismatch",
    ),
    pytest.param(
        {"requirements": "---\ncollections:\n  - name: community.general\n"},
        id="requirements-no-version",
    ),
    pytest.param({"pins": None}, id="no-pins"),
    pytest.param({"pins": ""}, id="pins-empty"),
    pytest.param({"pins": PINS + PINS}, id="pins-twice"),
    pytest.param({"pins": f"collection community.general 10.2.0 {DIGEST} 1\n"}, id="pins-mismatch"),
    pytest.param({"pins": "collection community.general 10.1.0 abc 1\n"}, id="pins-bad-digest"),
]


@pytest.mark.parametrize("files", UNPINNED)
def test_allow_listed_module_needs_exact_equal_pins(
    tmp_path: Path, files: dict[str, str | None]
) -> None:
    contents: dict[str, str | None] = {
        "galaxy": GALAXY,
        "requirements": REQUIREMENTS,
        "pins": PINS,
        **files,
    }
    root = write_pins(tmp_path, contents["galaxy"], contents["requirements"], contents["pins"])
    messages = check(
        "---\n- name: Make\n  community.general.make: {}\n", allowed=frozenset({MAKE}), root=root
    )
    assert len(messages) == 1
    assert NOT_PINNED in messages[0]
    assert "community.general" in messages[0]


@pytest.mark.parametrize(
    "relative",
    ["galaxy.yml", "extensions/molecule/requirements.yml", "extensions/molecule/collections.pins"],
)
def test_a_pin_file_that_is_not_utf8_pins_nothing(tmp_path: Path, relative: str) -> None:
    root = write_pins(tmp_path)
    (root / relative).write_bytes(b"\xff\xfe")
    messages = check(
        "---\n- name: Make\n  community.general.make: {}\n", allowed=frozenset({MAKE}), root=root
    )
    assert len(messages) == 1
    assert NOT_PINNED in messages[0]


def test_pinned_version_reads_the_three_files(tmp_path: Path) -> None:
    root = write_pins(tmp_path)
    sources = remediate.pin_sources("community.general", root)
    assert remediate.pinned_version(sources) == "10.1.0"
    assert remediate.pinned_version(remediate.pin_sources("community.crypto", root)) is None


def field_attributes(module: str, name: str) -> set[str]:
    playbook_class = getattr(importlib.import_module(module), name)
    return set(cast("dict[str, object]", playbook_class.fattributes))


def test_task_keywords_match_ansible_core() -> None:
    keywords = (
        field_attributes("ansible.playbook.task", "Task")
        | field_attributes("ansible.playbook.block", "Block")
        | field_attributes("ansible.playbook.handler", "Handler")
    )
    assert keywords == remediate.TASK_KEYWORDS


def test_allow_list_names_community_modules_only() -> None:
    for name in remediate.ALLOWED_COMMUNITY_MODULES:
        match = remediate.COMMUNITY_MODULE.fullmatch(name)
        assert match is not None, name
        assert match.group("collection") not in {
            "ansible.builtin",
            "ansible.legacy",
            "freesecdev.linux_compliance",
        }


def test_allow_listed_modules_are_pinned_in_the_repository() -> None:
    for name in remediate.ALLOWED_COMMUNITY_MODULES:
        match = remediate.COMMUNITY_MODULE.fullmatch(name)
        assert match is not None, name
        sources = remediate.pin_sources(match.group("collection"))
        assert remediate.pinned_version(sources) is not None, sources


def test_check_file_refuses_a_community_module_in_the_role(tmp_path: Path) -> None:
    target = tmp_path / TASK_FILE
    target.parent.mkdir(parents=True)
    target.write_text("---\n- name: Make\n  community.general.make:\n    chdir: /\n")
    messages = [violation.message for violation in rules.check_file(target, tmp_path)]
    assert any(NOT_ALLOWED in message and ADR in message for message in messages), messages


def test_check_file_ignores_the_same_task_outside_the_role(tmp_path: Path) -> None:
    target = tmp_path / "tests/playbooks/example.yml"
    target.parent.mkdir(parents=True)
    target.write_text("---\n- name: Make\n  community.general.make:\n    chdir: /\n")
    messages = [violation.message for violation in rules.check_file(target, tmp_path)]
    assert not any(ADR in message for message in messages), messages


def test_the_remediate_role_passes() -> None:
    files = sorted((REPOSITORY_ROOT / "roles" / "remediate").rglob("*.yml"))
    assert files
    for path in files:
        relative = path.relative_to(REPOSITORY_ROOT)
        found = remediate.check_remediate_modules(
            path, relative, documents(path.read_text(encoding="utf-8"))
        )
        assert found == [], found
