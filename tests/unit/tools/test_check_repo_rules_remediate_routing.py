"""The routing that ``meta/runtime.yml`` may hold for the module rule (FREES-203, ADR 0032 §1).

The module rule of ``roles/remediate`` reads ``redirect``, ``tombstone`` and ``deprecation`` of a
module or action plugin of this collection. ansible-core also honours ``action_plugin`` there, a
``redirect`` of ``module_utils`` and ``import_redirection``, which run other code under the
collection's names, so ``meta/runtime.yml`` may hold no routing for modules, action plugins and
``module_utils`` other than the forms the rule reads, and no ``import_redirection``.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest
import yaml

from tools.lint import check_repo_rules as rules
from tools.lint.repo_rules import remediate_routing as routing

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RUNTIME = "meta/runtime.yml"
ADR = "(ADR 0032 §1)"
OWN_TASK = "---\n- name: Own\n  freesecdev.linux_compliance.example: {}\n"


def documents(text: str) -> list[yaml.Node]:
    loader = yaml.SafeLoader(text)
    try:
        loader.check_node()
        return list(iter(loader.get_node, None))
    finally:
        loader.dispose()


def check(text: str, relative: str | None = RUNTIME) -> list[tuple[int, str]]:
    path = Path(relative or RUNTIME)
    return [
        (violation.line, violation.message)
        for violation in routing.check_runtime_routing(
            path, None if relative is None else Path(relative), documents(text)
        )
    ]


ACCEPTED = [
    pytest.param("---\nrequires_ansible: '>=2.20.0'\n", id="repository-form"),
    pytest.param("", id="empty"),
    pytest.param("---\n- a list\n", id="not-a-mapping"),
    pytest.param(
        "---\nplugin_routing:\n  modules:\n    old:\n"
        "      redirect: freesecdev.linux_compliance.new\n"
        "      deprecation:\n        removal_version: 2.0.0\n"
        "    gone:\n      tombstone:\n        removal_version: 1.0.0\n",
        id="module-redirect-tombstone-deprecation",
    ),
    pytest.param(
        "---\nplugin_routing:\n  action:\n    old:\n"
        "      redirect: freesecdev.linux_compliance.new\n",
        id="action-redirect",
    ),
    pytest.param(
        "---\nplugin_routing:\n  module_utils:\n    old:\n      deprecation:\n"
        "        removal_version: 2.0.0\n",
        id="module-utils-deprecation",
    ),
    pytest.param(
        "---\nplugin_routing:\n  filter:\n    f:\n      redirect: zz.evil.f\n  lookup: [x]\n",
        id="other-plugin-types-not-read",
    ),
    pytest.param(
        "---\naction_groups:\n  group:\n    - freesecdev.linux_compliance.example\n",
        id="action-groups",
    ),
]


@pytest.mark.parametrize("text", ACCEPTED)
def test_routing_that_the_rule_reads_is_accepted(text: str) -> None:
    assert check(text) == []


ENTRY = "is not allowed in meta/runtime.yml"
SHAPE = "must be a mapping in meta/runtime.yml"
IMPORT = "import_redirection is not allowed in meta/runtime.yml"

REFUSED = [
    pytest.param(
        "---\nplugin_routing:\n  modules:\n    tree_info:\n      action_plugin: zz.evil.pwn\n",
        5,
        "plugin_routing.modules.tree_info.action_plugin " + ENTRY,
        id="module-action-plugin",
    ),
    pytest.param(
        "---\nplugin_routing:\n  action:\n    x:\n      action_plugin: zz.evil.pwn\n",
        5,
        "plugin_routing.action.x.action_plugin " + ENTRY,
        id="action-action-plugin",
    ),
    pytest.param(
        "---\nplugin_routing:\n  modules:\n    x:\n      future_key: zz.evil.pwn\n",
        5,
        "plugin_routing.modules.x.future_key " + ENTRY,
        id="unknown-key",
    ),
    pytest.param(
        "---\nplugin_routing:\n  module_utils:\n    compliance.ledger:\n"
        "      redirect: zz.evil.evil\n",
        5,
        "plugin_routing.module_utils.compliance.ledger.redirect " + ENTRY,
        id="module-utils-redirect",
    ),
    pytest.param(
        "---\nplugin_routing:\n  module_utils:\n    x:\n      tombstone:\n"
        "        removal_version: 1.0.0\n",
        5,
        "plugin_routing.module_utils.x.tombstone " + ENTRY,
        id="module-utils-tombstone",
    ),
    pytest.param(
        "---\nimport_redirection:\n  ansible_collections.freesecdev.x:\n    redirect: zz.evil\n",
        2,
        IMPORT,
        id="import-redirection",
    ),
    pytest.param("---\nimport_redirection: {}\n", 2, IMPORT, id="empty-import-redirection"),
    pytest.param("---\nplugin_routing: [x]\n", 2, "plugin_routing " + SHAPE, id="routing-list"),
    pytest.param(
        "---\nplugin_routing:\n  modules: [x]\n",
        3,
        "plugin_routing.modules " + SHAPE,
        id="section-list",
    ),
    pytest.param(
        "---\nplugin_routing:\n  module_utils:\n    x: zz.evil.evil\n",
        4,
        "plugin_routing.module_utils.x " + SHAPE,
        id="entry-scalar",
    ),
    pytest.param(
        "---\nplugin_routing:\n  modules:\n    x:\n      redirect: freesecdev.linux_compliance.y\n"
        "    x:\n      action_plugin: zz.evil.pwn\n",
        7,
        "plugin_routing.modules.x.action_plugin " + ENTRY,
        id="duplicate-entry",
    ),
]


@pytest.mark.parametrize(("text", "line", "message"), REFUSED)
def test_routing_that_the_rule_cannot_judge_is_refused(text: str, line: int, message: str) -> None:
    found = check(text)
    assert len(found) == 1, found
    assert found[0][0] == line
    assert found[0][1].startswith(message)
    assert ADR in found[0][1]


@pytest.mark.parametrize("relative", ["META/Runtime.yml", "meta/runtime.yml"])
def test_the_runtime_file_is_found_case_folded(relative: str) -> None:
    assert check("---\nimport_redirection: {}\n", relative)


@pytest.mark.parametrize(
    "relative", [None, "roles/remediate/meta/runtime.yml", "meta/main.yml", "meta/runtime.yaml"]
)
def test_other_files_are_not_read_as_the_runtime_file(relative: str | None) -> None:
    assert check("---\nimport_redirection: {}\n", relative) == []


def test_check_file_refuses_routing_of_the_runtime_file(tmp_path: Path) -> None:
    target = tmp_path / RUNTIME
    target.parent.mkdir(parents=True)
    target.write_text(
        "---\nplugin_routing:\n  modules:\n    tree_info:\n      action_plugin: zz.evil.pwn\n",
        encoding="utf-8",
    )
    messages = [violation.message for violation in rules.check_paths([target], tmp_path)]
    assert any("action_plugin " + ENTRY in message for message in messages), messages


def test_the_runtime_file_of_the_repository_passes() -> None:
    path = REPOSITORY_ROOT / RUNTIME
    text = path.read_text(encoding="utf-8")
    assert routing.check_runtime_routing(path, Path(RUNTIME), documents(text)) == []
    assert [violation for violation in rules.check_file(path) if ENTRY in violation.message] == []


def test_an_action_plugin_entry_routes_the_module(tmp_path: Path) -> None:
    target = tmp_path / RUNTIME
    target.parent.mkdir(parents=True)
    target.write_text(
        "---\nplugin_routing:\n  modules:\n    example:\n      action_plugin: zz.evil.pwn\n",
        encoding="utf-8",
    )
    assert routing.is_routed(tmp_path, "example")
    assert not routing.is_routed(tmp_path, "other")


def loader_routing_keys() -> set[str]:
    spec = importlib.util.find_spec("ansible.plugins.loader")
    assert spec is not None
    assert spec.origin is not None
    tree = ast.parse(Path(spec.origin).read_text(encoding="utf-8"))
    return {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "routing_metadata"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }


def test_the_plugin_loader_reads_the_routing_keys_the_rule_knows() -> None:
    keys = loader_routing_keys()
    assert keys == {"deprecation", "tombstone", "redirect", "action_plugin"}
    assert routing.CHECKED_ROUTING["modules"] == keys - {"action_plugin"}
    assert routing.CHECKED_ROUTING["action"] == routing.CHECKED_ROUTING["modules"]
    assert routing.CHECKED_ROUTING["module_utils"] == routing.ROUTING_NOTES
