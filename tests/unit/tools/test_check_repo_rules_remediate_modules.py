"""The modules that ``roles/remediate`` may run and the files it holds (FREES-203, ADR 0032 §1).

A task of the remediate role may use ``ansible.builtin`` modules, this collection's modules and the
community modules of an allow list that starts empty. An allow-listed module also needs its
collection pinned at one exact version in ``galaxy.yml``, the Molecule requirements and the
collection pins. Every file that Ansible may load as a task, handler or metadata of the role
must be one that the rule reads.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import inspect
import operator
import re
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.lint import check_repo_rules as rules
from tools.lint.repo_rules import remediate_files as role_files
from tools.lint.repo_rules import remediate_modules as remediate
from tools.lint.repo_rules import remediate_routing as routing

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
ROUTED_BUILTINS = ("make", "at", "sysctl", "pam_limits")


def documents(text: str) -> list[yaml.Node]:
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        return list(iter(loader.get_node, None))
    finally:
        loader.dispose()


DELEGATION = "are refused on its tasks and blocks"


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


def module_messages(text: str) -> list[str]:
    return [message for message in check(text) if DELEGATION not in message]


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
        "---\n- name: Include\n  ansible.builtin.include_tasks:\n"
        "    file: '{{ role_path }}/tasks/family.yml'\n"
        "- name: Import\n  ansible.builtin.import_tasks: '{{ role_path }}/tasks/nested/x.yaml'\n",
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
        "- name: Mapping\n  action:\n    module: freesecdev.linux_compliance.audit_control\n",
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
    *[
        pytest.param(
            f"---\n- name: Routed\n  ansible.builtin.{module}:\n    name: x\n",
            f"ansible.builtin.{module}",
            id=f"builtin-routed-{module}",
        )
        for module in ROUTED_BUILTINS
    ],
    *[
        pytest.param(
            f"---\n- name: Routed\n  action: ansible.builtin.{module} name=x\n",
            f"ansible.builtin.{module}",
            id=f"builtin-routed-action-{module}",
        )
        for module in ROUTED_BUILTINS
    ],
    *[
        pytest.param(
            f"---\n- name: Routed\n  local_action:\n    module: ansible.builtin.{module}\n",
            f"ansible.builtin.{module}",
            id=f"builtin-routed-local-action-{module}",
        )
        for module in ROUTED_BUILTINS
    ],
    pytest.param(
        "---\n- name: Removed\n  ansible.builtin.include: x.yml\n",
        "ansible.builtin.include",
        id="builtin-tombstone",
    ),
    pytest.param(
        "---\n- name: Unknown\n  ansible.builtin.no_such_module: {}\n",
        "ansible.builtin.no_such_module",
        id="builtin-unknown",
    ),
    pytest.param(
        "---\n- name: Missing\n  freesecdev.linux_compliance.no_such_module: {}\n",
        "freesecdev.linux_compliance.no_such_module",
        id="own-missing",
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


@pytest.mark.parametrize("version", [">=10.1.0", "*", "10.1", "10.1.0-rc1", "v10.1.0"])
def test_three_pins_that_agree_on_an_inexact_version_pin_nothing(
    tmp_path: Path, version: str
) -> None:
    root = write_pins(
        tmp_path,
        f"---\ndependencies:\n  community.general: '{version}'\n",
        f"---\ncollections:\n  - name: community.general\n    version: '{version}'\n",
        f"collection community.general {version} {DIGEST} 1\n",
    )
    sources = remediate.pin_sources("community.general", root)
    assert all(entries == [version] for entries in sources.values()), sources
    assert remediate.pinned_version(sources) is None
    messages = check(
        "---\n- name: Make\n  community.general.make: {}\n", allowed=frozenset({MAKE}), root=root
    )
    assert len(messages) == 1
    assert NOT_PINNED in messages[0]


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
        match = remediate.QUALIFIED_NAME.fullmatch(name)
        assert match is not None, name
        assert match.group("collection") not in {
            "ansible.builtin",
            "ansible.legacy",
            "freesecdev.linux_compliance",
        }


def test_allow_listed_modules_are_pinned_in_the_repository() -> None:
    for name in remediate.ALLOWED_COMMUNITY_MODULES:
        match = remediate.QUALIFIED_NAME.fullmatch(name)
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


def ansible_core_root() -> Path:
    spec = importlib.util.find_spec("ansible")
    assert spec is not None
    assert spec.origin is not None
    return Path(spec.origin).parent


def ansible_core_routing() -> dict[str, dict[str, dict[str, object]]]:
    text = (ansible_core_root() / "config" / "ansible_builtin_runtime.yml").read_text("utf-8")
    loaded = cast("dict[str, object]", yaml.safe_load(text))
    return cast("dict[str, dict[str, dict[str, object]]]", loaded["plugin_routing"])


def routed_builtin_names() -> set[str]:
    core = ansible_core_routing()
    return {
        name
        for section in routing.ROUTING_SECTIONS
        for name, entry in core[section].items()
        if entry.keys() - routing.ROUTING_NOTES
    }


def test_builtin_modules_match_the_pinned_ansible_core() -> None:
    files = {
        path.stem
        for path in (ansible_core_root() / "modules").glob("*.py")
        if path.stem != "__init__"
    }
    assert files - routed_builtin_names() == remediate.BUILTIN_MODULES


@pytest.mark.parametrize(
    ("module", "target"),
    [
        ("make", "community.general.make"),
        ("at", "ansible.posix.at"),
        ("sysctl", "ansible.posix.sysctl"),
        ("pam_limits", "community.general.pam_limits"),
    ],
)
def test_ansible_core_sends_the_refused_builtin_names_elsewhere(module: str, target: str) -> None:
    assert ansible_core_routing()["modules"][module] == {"redirect": target}
    assert module not in remediate.BUILTIN_MODULES


def test_the_tombstoned_include_is_not_a_builtin_module() -> None:
    assert "tombstone" in ansible_core_routing()["action"]["include"]
    assert "include" not in remediate.BUILTIN_MODULES


OWN = "freesecdev.linux_compliance.example"
ROUTING = "---\nplugin_routing:\n"
REDIRECT = "      redirect: community.general.make\n"


def own_root(
    tmp_path: Path, directory: str = "plugins/modules", runtime: str | None = None
) -> Path:
    plugin = tmp_path / directory / "example.py"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("", encoding="utf-8")
    if runtime is not None:
        target = tmp_path / "meta" / "runtime.yml"
        target.parent.mkdir(parents=True)
        target.write_text(runtime, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("directory", "runtime"),
    [
        pytest.param("plugins/modules", None, id="module-no-runtime"),
        pytest.param("plugins/action", None, id="action-no-runtime"),
        pytest.param("plugins/modules", "", id="empty-runtime"),
        pytest.param("plugins/modules", "---\nrequires_ansible: '>=2.20.0'\n", id="no-routing"),
        pytest.param(
            "plugins/modules",
            "---\nplugin_routing:\n  modules:\n    example:\n      deprecation:\n"
            "        removal_version: 2.0.0\n",
            id="deprecated-only",
        ),
        pytest.param(
            "plugins/modules",
            f"{ROUTING}  modules:\n    other:\n{REDIRECT}",
            id="other-module-routed",
        ),
        pytest.param(
            "plugins/modules",
            f"{ROUTING}  lookup:\n    example:\n{REDIRECT}",
            id="other-plugin-type-routed",
        ),
    ],
)
def test_own_module_with_its_file_and_no_routing_is_accepted(
    tmp_path: Path, directory: str, runtime: str | None
) -> None:
    root = own_root(tmp_path, directory, runtime)
    assert check(f"---\n- name: Own\n  {OWN}: {{}}\n", root=root) == []


@pytest.mark.parametrize(
    "runtime",
    [
        pytest.param(
            f"{ROUTING}  modules:\n    example:\n{REDIRECT}",
            id="module-redirect",
        ),
        pytest.param(
            "---\nplugin_routing:\n  action:\n    example:\n      redirect: ansible.posix.at\n",
            id="action-redirect",
        ),
        pytest.param(
            "---\nplugin_routing:\n  modules:\n    example:\n      tombstone:\n"
            "        removal_version: 1.0.0\n",
            id="tombstone",
        ),
        pytest.param(
            "---\nplugin_routing:\n  modules:\n    example:\n      action_plugin: zz.evil.pwn\n",
            id="action-plugin",
        ),
        pytest.param(
            "---\nplugin_routing:\n  action:\n    example:\n      future_key: x\n",
            id="unknown-routing-key",
        ),
        pytest.param("---\nplugin_routing: [\n", id="invalid-yaml"),
        pytest.param("---\n- plugin_routing\n", id="not-a-mapping"),
        pytest.param(b"\xff\xfe", id="not-utf8"),
    ],
)
def test_own_module_that_meta_runtime_may_route_is_refused(
    tmp_path: Path, runtime: str | bytes
) -> None:
    root = own_root(tmp_path)
    target = root / "meta" / "runtime.yml"
    target.parent.mkdir(parents=True)
    if isinstance(runtime, bytes):
        target.write_bytes(runtime)
    else:
        target.write_text(runtime, encoding="utf-8")
    for text in (f"---\n- name: Own\n  {OWN}: {{}}\n", f"---\n- name: Own\n  action: {OWN}\n"):
        messages = check(text, root=root)
        assert len(messages) == 1, messages
        assert "meta/runtime.yml routes it with an entry other than deprecation" in messages[0]
        assert OWN in messages[0]


def test_own_module_without_its_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "plugins" / "modules").mkdir(parents=True)
    (tmp_path / "plugins" / "modules" / "example").mkdir()
    messages = check(f"---\n- name: Own\n  {OWN}: {{}}\n", root=tmp_path)
    assert len(messages) == 1
    assert "no file example.py" in messages[0]


def test_the_collection_routes_none_of_its_modules() -> None:
    for path in sorted((REPOSITORY_ROOT / "plugins" / "modules").glob("*.py")):
        assert not routing.is_routed(REPOSITORY_ROOT, path.stem), path


ROLE_INCLUDE = "the tasks of another role are not checked"
INCLUDE_TARGET = "use {{ role_path }}/tasks/ followed by a literal relative path"
INCLUDE_ACTION = "in action or local_action is not allowed"


@pytest.mark.parametrize(
    "text",
    [
        "---\n- name: Role\n  ansible.builtin.include_role:\n    name: other.collection.role\n",
        pytest.param(
            "---\n- name: Role\n  ansible.builtin.import_role:\n"
            "    name: freesecdev.linux_compliance.audit\n",
            id="own-role",
        ),
        "---\n- name: Role\n  ansible.builtin.include_role: name=other.collection.role\n",
        pytest.param(
            "---\n- name: Block\n  block:\n    - name: Role\n      ansible.builtin.import_role:\n"
            "        name: x\n",
            id="nested",
        ),
    ],
)
def test_role_includes_are_refused(text: str) -> None:
    messages = check(text)
    assert len(messages) == 1, messages
    assert ROLE_INCLUDE in messages[0]


@pytest.mark.parametrize(
    "text",
    [
        "---\n- name: Role\n  action: ansible.builtin.include_role name=x\n",
        "---\n- name: Role\n  local_action:\n    module: ansible.builtin.import_role\n",
    ],
)
def test_role_includes_in_action_are_refused(text: str) -> None:
    messages = module_messages(text)
    assert len(messages) == 1, messages
    assert ROLE_INCLUDE in messages[0]


@pytest.mark.parametrize(
    "text",
    [
        "---\n- name: Include\n  action: ansible.builtin.include_tasks x.yml\n",
        "---\n- name: Include\n  local_action:\n    module: ansible.builtin.import_tasks\n",
    ],
)
def test_task_includes_in_action_are_refused(text: str) -> None:
    messages = module_messages(text)
    assert len(messages) == 1, messages
    assert INCLUDE_ACTION in messages[0]


@pytest.mark.parametrize(
    ("text", "target"),
    [
        pytest.param("---\n- name: I\n  ansible.builtin.include_tasks: family.yml\n", "family.yml"),
        pytest.param(
            "---\n- name: I\n  ansible.builtin.import_tasks:\n    file: tasks/family.yml\n",
            "tasks/family.yml",
        ),
        pytest.param(
            "---\n- name: I\n  ansible.builtin.include_tasks:\n    _raw_params: family.yml\n",
            "family.yml",
        ),
        pytest.param(
            "---\n- name: I\n  ansible.builtin.include_tasks: '{{ role_path }}/../x/tasks/a.yml'\n",
            "{{ role_path }}/../x/tasks/a.yml",
        ),
        pytest.param(
            "---\n- name: I\n  ansible.builtin.include_tasks: '{{ role_path }}/handlers/a.yml'\n",
            "{{ role_path }}/handlers/a.yml",
        ),
        pytest.param(
            "---\n- name: I\n  ansible.builtin.include_tasks: ' {{ role_path }}/tasks/a.yml'\n",
            " {{ role_path }}/tasks/a.yml",
        ),
        pytest.param(
            "---\n- name: I\n  ansible.builtin.include_tasks: '{{ playbook_dir }}/tasks/a.yml'\n",
            "{{ playbook_dir }}/tasks/a.yml",
        ),
        pytest.param(
            "---\n- name: I\n  ansible.builtin.include_tasks:\n    file: [a.yml]\n", "None"
        ),
        pytest.param("---\n- name: I\n  ansible.builtin.include_tasks: [a.yml]\n", "None"),
        pytest.param(
            "---\n- name: I\n  ansible.builtin.include_tasks:\n    apply:\n      tags: [x]\n",
            "None",
        ),
    ],
)
def test_task_includes_outside_the_role_path_are_refused(text: str, target: str) -> None:
    messages = check(text)
    assert len(messages) == 1, messages
    assert INCLUDE_TARGET in messages[0]
    assert target in messages[0]


META = "roles/remediate/meta/main.yml"
DEPENDENCY = "role dependencies are not allowed"


@pytest.mark.parametrize(
    "text",
    [
        "---\ngalaxy_info:\n  role_name: remediate\ndependencies: []\n",
        "---\ngalaxy_info:\n  role_name: remediate\n",
        "---\n- not a mapping\n",
        "---\nplain\n",
    ],
)
def test_role_metadata_without_dependencies_is_accepted(text: str) -> None:
    assert check(text, META) == []


@pytest.mark.parametrize(
    "text",
    [
        "---\ndependencies:\n  - role: other.collection.role\n",
        "---\ndependencies:\n  - freesecdev.linux_compliance.audit\n",
        "---\ndependencies:\n",
        "---\ndependencies: other\n",
        "---\n<<: {dependencies: [x]}\n",
    ],
)
def test_role_metadata_with_dependencies_is_refused(text: str) -> None:
    for relative in (META, "Roles/Remediate/Meta/main.yaml"):
        messages = check(text, relative)
        assert len(messages) == 1, messages
        assert DEPENDENCY in messages[0]


def test_dependencies_of_other_files_are_not_read() -> None:
    text = "---\ndependencies:\n  - role: other.collection.role\n"
    assert check(text, "roles/remediate/meta/argument_specs.yml") == []
    assert check(text, "roles/audit/meta/main.yml") == []


def test_the_role_metadata_of_the_repository_passes() -> None:
    path = REPOSITORY_ROOT / META
    found = remediate.check_remediate_modules(
        path, Path(META), documents(path.read_text(encoding="utf-8"))
    )
    assert found == []


ROLE_TASK = '[{"name": "Write key", "listen": "go", "community.crypto.openssl_privatekey": {}}]\n'
TAB_JSON = '[\n\t{"name": "Make",\t"community.general.make":\t{}}\n]\n'
SUFFIX = "only .yml and .yaml files may be there"
UNREADABLE = "cannot be read as YAML"
ROOT = "must be empty or"


def ansible_loads(
    root: Path, directory: str, main: str | None = None, secret: bytes | None = None
) -> object:
    """Return what ansible-core's role loader reads from ``directory`` of the role at ``root``.

    ``_load_role_yaml`` finds and reads a role's ``tasks``, ``handlers``, ``meta``, ``vars`` and
    ``defaults`` entry points; ``main`` is a ``tasks_from`` or ``handlers_from`` value. It needs
    only the role path, the role name and a ``DataLoader``, so no play, inventory or plugin loader
    is set up. ``secret`` is the vault password.
    """
    loader = importlib.import_module("ansible.parsing.dataloader").DataLoader()
    if secret is not None:
        vault = importlib.import_module("ansible.parsing.vault")
        loader.set_vault_secrets([("default", vault.VaultSecret(secret))])
    role: object = object.__new__(importlib.import_module("ansible.playbook.role").Role)
    vars(role).update({"_role_path": str(root), "_role_name": "remediate", "_loader": loader})
    return operator.methodcaller("_load_role_yaml", directory, main=main)(role)


def role_findings(relative: str, data: bytes) -> list[str]:
    return [
        violation.message
        for violation in role_files.role_file_findings(Path(relative), Path(relative), data)
    ]


def write_role_file(root: Path, relative: str, data: bytes) -> Path:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


ENTRY_POINT_FORMS = [
    pytest.param("handlers/main.json", "handlers", None, id="handlers-main-json"),
    pytest.param("handlers/main", "handlers", None, id="handlers-main-no-suffix"),
    pytest.param("tasks/main.json", "tasks", None, id="tasks-main-json"),
    pytest.param("tasks/main", "tasks", None, id="tasks-main-no-suffix"),
    pytest.param("tasks/extra.txt", "tasks", "extra.txt", id="tasks-from-other-suffix"),
    pytest.param("tasks/nested/extra", "tasks", "nested/extra", id="tasks-from-nested-no-suffix"),
    pytest.param("handlers/extra.json", "handlers", "extra.json", id="handlers-from-json"),
    pytest.param("handlers/extra.yml~", "handlers", "extra.yml~", id="handlers-from-backup"),
]


@pytest.mark.parametrize(("relative", "directory", "main"), ENTRY_POINT_FORMS)
def test_ansible_loads_task_files_of_every_suffix(
    tmp_path: Path, relative: str, directory: str, main: str | None
) -> None:
    write_role_file(tmp_path, relative, ROLE_TASK.encode())
    loaded = ansible_loads(tmp_path, directory, main)
    assert loaded == [
        {"name": "Write key", "listen": "go", "community.crypto.openssl_privatekey": {}}
    ]


@pytest.mark.parametrize(("relative", "directory", "main"), ENTRY_POINT_FORMS)
def test_task_files_without_a_yaml_suffix_are_refused(
    tmp_path: Path, relative: str, directory: str, main: str | None
) -> None:
    del main
    full = f"roles/remediate/{relative}"
    messages = role_findings(full, ROLE_TASK.encode())
    assert len(messages) == 1, messages
    assert SUFFIX in messages[0]
    assert f"roles/remediate/{directory}/" in messages[0]
    assert ADR in messages[0]
    target = write_role_file(tmp_path, full, ROLE_TASK.encode())
    found = [violation.message for violation in rules.check_file(target, tmp_path)]
    assert messages[0] in found, found
    swept = [violation.message for violation in rules.check_paths([target], tmp_path)]
    assert messages[0] in swept, swept


def test_ansible_loads_role_metadata_without_a_yaml_suffix(tmp_path: Path) -> None:
    for relative in ("meta/main.json", "meta/main"):
        role = tmp_path / relative.replace("/", "_")
        write_role_file(role, relative, b'{"dependencies": ["other.collection.role"]}\n')
        loaded = ansible_loads(role, "meta")
        assert loaded == {"dependencies": ["other.collection.role"]}


@pytest.mark.parametrize(
    "relative",
    [
        "roles/remediate/meta/main.json",
        "roles/remediate/meta/main",
        "roles/remediate/meta/argument_specs.json",
        "Roles/Remediate/Handlers/main.JSON",
        "roles/remediate/TASKS/main",
    ],
)
def test_metadata_and_case_variants_without_a_yaml_suffix_are_refused(
    tmp_path: Path, relative: str
) -> None:
    data = b'{"dependencies": ["other.collection.role"]}\n'
    messages = role_findings(relative, data)
    assert len(messages) == 1, messages
    assert SUFFIX in messages[0]
    target = write_role_file(tmp_path, relative, data)
    assert messages[0] in [violation.message for violation in rules.check_file(target, tmp_path)]


def test_ansible_loads_json_that_pyyaml_cannot_read(tmp_path: Path) -> None:
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(TAB_JSON)
    write_role_file(tmp_path, "tasks/tabs.yml", TAB_JSON.encode())
    loaded = ansible_loads(tmp_path, "tasks", "tabs.yml")
    assert loaded == [{"name": "Make", "community.general.make": {}}]


@pytest.mark.parametrize(
    ("relative", "data"),
    [
        ("roles/remediate/tasks/tabs.yml", TAB_JSON.encode()),
        ("roles/remediate/handlers/main.yml", TAB_JSON.encode()),
        ("roles/remediate/meta/main.yml", b'{"dependencies":\t["a.b.c"]}\n'),
        ("roles/remediate/tasks/latin1.yml", b"---\n- name: caf\xe9\n"),
    ],
)
def test_role_files_that_pyyaml_cannot_read_are_refused(
    tmp_path: Path, relative: str, data: bytes
) -> None:
    messages = role_findings(relative, data)
    assert len(messages) == 1, messages
    assert UNREADABLE in messages[0]
    assert ADR in messages[0]
    target = write_role_file(tmp_path, relative, data)
    assert messages[0] in [violation.message for violation in rules.check_file(target, tmp_path)]


def test_ansible_loads_a_vaulted_task_file(tmp_path: Path) -> None:
    vault = importlib.import_module("ansible.parsing.vault")
    secret = vault.VaultSecret(b"probe")
    encrypted = cast("bytes", vault.VaultLib([("default", secret)]).encrypt(ROLE_TASK, secret))
    write_role_file(tmp_path, "handlers/main.yml", encrypted)
    loaded = ansible_loads(tmp_path, "handlers", secret=b"probe")
    assert loaded == [
        {"name": "Write key", "listen": "go", "community.crypto.openssl_privatekey": {}}
    ]
    messages = role_findings("roles/remediate/handlers/main.yml", encrypted)
    assert len(messages) == 1, messages
    assert ROOT in messages[0]
    assert check(encrypted.decode(), "roles/remediate/handlers/main.yml") == []


@pytest.mark.parametrize(
    ("relative", "text", "line"),
    [
        ("roles/remediate/tasks/x.yml", "---\ncommunity.general.make: {}\n", 2),
        ("roles/remediate/handlers/main.yml", "---\nplain\n", 2),
        ("roles/remediate/tasks/x.yml", "---\n- name: x\n---\nplain\n", 4),
        ("roles/remediate/meta/main.yml", "---\n- dependencies: [a.b.c]\n", 2),
        ("roles/remediate/meta/argument_specs.yml", "---\nplain\n", 2),
    ],
)
def test_role_documents_with_another_root_are_refused(relative: str, text: str, line: int) -> None:
    found = role_files.role_file_findings(Path(relative), Path(relative), text.encode())
    assert [violation.line for violation in found] == [line]
    assert ROOT in found[0].message
    assert ADR in found[0].message


@pytest.mark.parametrize(
    ("relative", "text"),
    [
        ("roles/remediate/tasks/x.yml", "---\n- name: x\n  ansible.builtin.debug: {}\n"),
        ("roles/remediate/handlers/main.yaml", "---\n- name: x\n  listen: go\n"),
        ("roles/remediate/tasks/nested/x.YML", "---\n[]\n"),
        ("roles/remediate/tasks/empty.yml", ""),
        ("roles/remediate/tasks/null.yml", "---\n"),
        ("roles/remediate/handlers/tilde.yml", "---\n~\n"),
        ("roles/remediate/meta/main.yml", "---\ndependencies: []\n"),
        ("roles/remediate/meta/argument_specs.yml", "---\nargument_specs: {}\n"),
    ],
)
def test_role_files_that_the_rule_reads_pass(relative: str, text: str) -> None:
    assert role_findings(relative, text.encode()) == []


@pytest.mark.parametrize(
    "relative",
    [
        "roles/remediate/README.md",
        "roles/remediate/vars/main.json",
        "roles/remediate/defaults/main",
        "roles/remediate/templates/x.j2",
        "roles/remediate/tasks",
        "roles/remediate.json",
        "roles/audit/handlers/main.json",
        "tests/roles/remediate/tasks/x.json",
    ],
)
def test_files_outside_the_role_load_directories_are_not_refused(relative: str) -> None:
    assert role_files.role_load_directory(Path(relative)) is None
    assert role_findings(relative, ROLE_TASK.encode()) == []


def test_relative_none_is_not_a_role_file() -> None:
    assert role_files.role_file_findings(Path("main.json"), None, ROLE_TASK.encode()) == []


def test_role_load_directories_match_ansible_core() -> None:
    role_class = importlib.import_module("ansible.playbook.role").Role
    include_class = importlib.import_module("ansible.playbook.role_include").IncludeRole
    loaded = set(re.findall(r"_load_role_yaml\('(\w+)'", inspect.getsource(role_class)))
    variables = {"vars", "defaults"}
    assert loaded - variables == role_files.ROLE_LOAD_DIRECTORIES
    entry_points = {
        str(key).removesuffix("_from") for key in cast("frozenset[str]", include_class.FROM_ARGS)
    }
    assert entry_points - variables == role_files.TASK_LIST_DIRECTORIES


def test_ansible_core_tries_these_role_file_forms() -> None:
    source = inspect.getsource(importlib.import_module("ansible.playbook.role").Role)
    assert "extensions = ['.yml', '.yaml', '.json']" in source
    assert "extensions.append('')" in source
    assert "extensions.insert(0, '')" in source


def test_the_remediate_role_files_are_all_read() -> None:
    role = REPOSITORY_ROOT / "roles" / "remediate"
    files = [path for path in role.rglob("*") if path.is_file()]
    assert files
    for path in files:
        relative = path.relative_to(REPOSITORY_ROOT)
        assert role_files.role_file_findings(path, relative, path.read_bytes()) == [], relative


DISPATCH = "chooses while the play runs"


def dispatching_forms(module: str) -> list[str]:
    name = f"ansible.builtin.{module}"
    return [
        f"---\n- name: Key\n  {name}:\n    name: x\n",
        f"---\n- name: Action\n  action: {name} name=x\n",
        f"---\n- name: Local\n  local_action:\n    module: {name}\n    name: x\n",
    ]


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(text, id=f"{module}-{index}")
        for module in sorted(remediate.DISPATCHING_MODULES)
        for index, text in enumerate(dispatching_forms(module))
    ],
)
def test_builtins_that_choose_their_module_at_run_time_are_refused(text: str) -> None:
    messages = module_messages(text)
    assert len(messages) == 1, messages
    assert DISPATCH in messages[0]
    assert NOT_ALLOWED in messages[0]
    assert ADR in messages[0]


@pytest.mark.parametrize(
    "text",
    [
        "---\n- name: Gather\n  ansible.builtin.gather_facts:\n    network_os: cisco.ios.ios\n",
        (
            "---\n- name: Gather\n  ansible.builtin.gather_facts:\n  vars:\n"
            "    ansible_network_os: ios\n"
        ),
        (
            "---\n- name: Pick\n  ansible.builtin.set_fact:\n    x: 1\n"
            "- name: Install\n  ansible.builtin.package:\n    name: foo\n"
        ),
        "---\n- name: Reload\n  ansible.builtin.service:\n    name: foo\n    state: reloaded\n",
    ],
)
def test_the_reviewed_probes_of_dispatching_builtins_are_refused(text: str) -> None:
    assert any(DISPATCH in message for message in check(text))


def test_check_file_refuses_a_dispatching_builtin_in_the_role(tmp_path: Path) -> None:
    target = tmp_path / TASK_FILE
    target.parent.mkdir(parents=True)
    target.write_text("---\n- name: Reload\n  ansible.builtin.service:\n    name: foo\n")
    messages = [violation.message for violation in rules.check_file(target, tmp_path)]
    assert any(DISPATCH in message for message in messages), messages


def test_the_systemd_modules_that_replace_service_are_accepted() -> None:
    text = (
        "---\n- name: Reload\n  ansible.builtin.systemd_service:\n    name: sshd\n"
        "    state: reloaded\n- name: Services\n  ansible.builtin.service_facts:\n"
    )
    assert check(text) == []


def test_dispatching_modules_are_reviewed_builtin_modules() -> None:
    reviewed = remediate.DISPATCHING_MODULES | remediate.BOUNDED_DISPATCHING_MODULES
    assert reviewed <= remediate.BUILTIN_MODULES
    assert not remediate.DISPATCHING_MODULES & remediate.BOUNDED_DISPATCHING_MODULES


def _is_execute_module(call: ast.Call) -> bool:
    function = call.func
    return isinstance(function, ast.Attribute) and function.attr == "_execute_module"


def _module_name_argument(call: ast.Call) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == "module_name":
            return keyword.value
    return call.args[0] if call.args else None


def chooses_its_module(source: str) -> bool:
    """Return whether ``source`` calls ``_execute_module`` with a module name that is not literal.

    A call without ``module_name`` runs the task's own module, which the rule reads.
    """
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and _is_execute_module(node):
            argument = _module_name_argument(node)
            if argument is not None and not (
                isinstance(argument, ast.Constant) and isinstance(argument.value, str)
            ):
                return True
    return False


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("self._execute_module(task_vars=v)", False),
        ("self._execute_module(module_name='ansible.legacy.copy', task_vars=v)", False),
        ("self._execute_module('ansible.legacy.uri', task_vars=v)", False),
        ("self._execute_module(module_name=module, task_vars=v)", True),
        ("self._execute_module(name, task_vars=v)", True),
        ("self._execute_module(module_name=None)", True),
        ("other(module_name=module)", False),
        ("self._execute(module_name=module)", False),
    ],
)
def test_the_drift_scan_finds_non_literal_module_names(source: str, expected: bool) -> None:
    assert chooses_its_module(source) is expected


def test_dispatching_action_plugins_match_ansible_core() -> None:
    """Keep the dispatching action plugins of ansible-core equal to the reviewed lists.

    The scan sees only ``_execute_module`` calls whose module name is not a literal. A module
    chosen through ``meta/runtime.yml`` routing (``action_plugin``, see
    ``test_check_repo_rules_remediate_routing.py``) or through a variable that a play-level task
    reads (``ansible_network_os`` for the play's fact gathering) is outside what it can see, so a
    passing scan is not proof that no other dispatch exists (ADR 0032, boundary of 2026-11-10).
    """
    directory = ansible_core_root() / "plugins" / "action"
    choosing = {
        path.stem
        for path in directory.glob("*.py")
        if chooses_its_module(path.read_text(encoding="utf-8"))
    }
    assert choosing == remediate.DISPATCHING_MODULES | remediate.BOUNDED_DISPATCHING_MODULES


def test_the_dnf_backends_stay_in_ansible_core() -> None:
    """``dnf`` runs ``ansible.legacy.dnf`` or ``dnf5``; ``yum`` names no module and fails."""
    backends = cast(
        "frozenset[str]", importlib.import_module("ansible.plugins.action.dnf").VALID_BACKENDS
    )
    assert backends == {"yum", "yum4", "dnf", "dnf4", "dnf5"}
    source = inspect.getsource(importlib.import_module("ansible.plugins.action.dnf"))
    assert 'module = "dnf"' in source
    assert "module = 'ansible.legacy.' + module" in source
    routing = ansible_core_routing()["modules"]
    modules = ansible_core_root() / "modules"
    found = {
        backend for backend in backends - {"yum4", "dnf4"} if backend in remediate.BUILTIN_MODULES
    }
    assert found == {"dnf", "dnf5"}
    assert "yum" not in routing
    assert not (modules / "yum.py").exists()


MARKER_ACTIONS = [
    pytest.param(
        '[{"name": "x", "action": {"__ansible_unsafe": "zz.evil.pwn"}}]\n',
        "action",
        id="action-unsafe",
    ),
    pytest.param(
        '[{"name": "x", "local_action": {"__ansible_unsafe": "zz.evil.pwn"}}]\n',
        "local_action",
        id="local-action-unsafe",
    ),
    pytest.param(
        '[{"name": "x", "action": {"module": {"__ansible_unsafe": "zz.evil.pwn"}}}]\n',
        "action",
        id="action-module-unsafe",
    ),
    pytest.param(
        '[{"name": "x", "local_action": {"module": {"__ansible_vault": "x"}}}]\n',
        "local_action",
        id="local-action-module-vault",
    ),
]


@pytest.mark.parametrize(("text", "keyword"), MARKER_ACTIONS[:3])
def test_ansible_reads_a_load_marker_as_the_module_name(text: str, keyword: str) -> None:
    loader = importlib.import_module("ansible.parsing.dataloader").DataLoader()
    loaded = cast("list[dict[str, object]]", loader.load(text))
    value = loaded[0][keyword]
    module = value if isinstance(value, str) else cast("dict[str, object]", value)["module"]
    assert module == "zz.evil.pwn"


@pytest.mark.parametrize(("text", "keyword"), MARKER_ACTIONS)
def test_actions_whose_module_is_not_a_string_are_refused(text: str, keyword: str) -> None:
    messages = check(text)
    assert any(
        f"{keyword} must be a module string" in message and ADR in message for message in messages
    ), messages
    found = role_findings(TASK_FILE, text.encode())
    assert any("__ansible_" in message for message in found), found


@pytest.mark.parametrize(
    "text",
    [
        "---\n- name: Sequence\n  action: [ansible.builtin.debug]\n",
        "---\n- name: No module\n  local_action:\n    msg: x\n",
        "---\n- name: Module list\n  action:\n    module: [ansible.builtin.debug]\n",
        (
            "---\n- name: Second module\n  action:\n    module: ansible.builtin.debug\n"
            "    module: {x: 1}\n"
        ),
    ],
)
def test_action_values_of_another_shape_are_refused(text: str) -> None:
    messages = check(text)
    assert any("must be a module string" in message for message in messages), messages


def test_load_markers_match_ansible_core() -> None:
    legacy = importlib.import_module("ansible._internal._json._profiles._legacy")
    markers = cast("dict[str, object]", vars(legacy)["_Profile"].deserialize_map)
    assert markers
    assert all(key.startswith(role_files.LOAD_MARKER_PREFIX) for key in markers)


@pytest.mark.parametrize(
    ("relative", "text", "line"),
    [
        (
            "roles/remediate/tasks/x.yml",
            "---\n- name: x\n  ansible.builtin.debug:\n    msg:\n      __ansible_unsafe: x\n",
            5,
        ),
        (
            "roles/remediate/handlers/main.yml",
            "---\n- &a\n  name: x\n  when: {__ansible_type: x}\n- *a\n",
            4,
        ),
        ("roles/remediate/meta/main.yml", "---\ngalaxy_info:\n  __ansible_vault: x\n", 3),
    ],
)
def test_role_files_with_load_marker_keys_are_refused(relative: str, text: str, line: int) -> None:
    found = role_files.role_file_findings(Path(relative), Path(relative), text.encode())
    assert [violation.line for violation in found] == [line]
    assert "__ansible_" in found[0].message
    assert ADR in found[0].message


DELEGATIONS = [
    pytest.param(
        "---\n- name: Plant\n  ansible.builtin.copy:\n    src: x\n    dest: /tmp/x\n"
        "  delegate_to: localhost\n",
        "delegate_to",
        6,
        id="delegate-to",
    ),
    pytest.param(
        "---\n- name: Facts\n  ansible.builtin.setup:\n  delegate_facts: true\n",
        "delegate_facts",
        4,
        id="delegate-facts",
    ),
    pytest.param(
        "---\n- name: Local\n  local_action:\n"
        "    module: freesecdev.linux_compliance.audit_control\n",
        "local_action",
        3,
        id="local-action",
    ),
    pytest.param(
        "---\n- name: Local\n  local_action: ansible.builtin.debug msg=x\n",
        "local_action",
        3,
        id="local-action-string",
    ),
    pytest.param(
        "---\n- name: Connection\n  connection: local\n  ansible.builtin.debug:\n    msg: x\n",
        "connection",
        3,
        id="connection",
    ),
    pytest.param(
        "---\n- name: Block\n  delegate_to: localhost\n  block:\n    - name: Inner\n"
        "      ansible.builtin.debug:\n        msg: x\n",
        "delegate_to",
        3,
        id="block",
    ),
    pytest.param(
        "---\n- name: Block\n  block:\n    - name: Inner\n      connection: local\n"
        "      ansible.builtin.debug:\n        msg: x\n",
        "connection",
        5,
        id="nested",
    ),
    pytest.param(
        "---\n- &base\n  delegate_to: localhost\n  name: Base\n- <<: *base\n"
        "  ansible.builtin.debug:\n    msg: x\n",
        "delegate_to",
        3,
        id="merge-key",
    ),
]


@pytest.mark.parametrize(("text", "keyword", "line"), DELEGATIONS)
def test_tasks_that_run_elsewhere_are_refused(text: str, keyword: str, line: int) -> None:
    violations = remediate.check_remediate_modules(
        Path(TASK_FILE), Path(TASK_FILE), documents(text)
    )
    delegations = [violation for violation in violations if DELEGATION in violation.message]
    assert [violation.line for violation in delegations] == [line]
    assert delegations[0].message.startswith(f"{keyword} {NOT_ALLOWED}")
    assert ADR in delegations[0].message
    assert "never" not in delegations[0].message
    assert "ansible.builtin.fetch are left to the review of ADR 0033" in delegations[0].message
    assert all(DELEGATION in violation.message for violation in violations)


def test_check_file_refuses_a_delegated_task_in_the_role(tmp_path: Path) -> None:
    target = tmp_path / TASK_FILE
    target.parent.mkdir(parents=True)
    target.write_text(
        "---\n- name: Plant\n  ansible.builtin.file:\n    path: /tmp/x\n  delegate_to: localhost\n",
        encoding="utf-8",
    )
    messages = [violation.message for violation in rules.check_file(target, tmp_path)]
    assert any(DELEGATION in message for message in messages), messages


def test_delegation_keywords_are_task_keywords_of_ansible_core() -> None:
    assert remediate.DELEGATION_KEYWORDS.issubset(remediate.TASK_KEYWORDS | {"local_action"})


def test_the_same_keywords_outside_the_role_are_not_refused() -> None:
    text = "---\n- name: Local\n  ansible.builtin.debug:\n    msg: x\n  delegate_to: localhost\n"
    assert check(text, "roles/audit/tasks/main.yml") == []
