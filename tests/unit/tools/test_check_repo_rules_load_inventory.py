from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.lint import check_repo_rules as rules
from tools.lint.repo_rules import load_config, load_locations

LOADER_SUBDIRECTORIES = frozenset(
    {
        "doc_fragments",
        "action_plugins",
        "cache_plugins",
        "callback_plugins",
        "connection_plugins",
        "shell_plugins",
        "library",
        "module_utils",
        "lookup_plugins",
        "filter_plugins",
        "test_plugins",
        "strategy_plugins",
        "terminal_plugins",
        "vars_plugins",
        "cliconf_plugins",
        "netconf_plugins",
        "inventory_plugins",
        "httpapi_plugins",
        "become_plugins",
    }
)


def ansible_source(relative: str) -> str:
    spec = importlib.util.find_spec("ansible")
    assert spec is not None
    assert spec.submodule_search_locations is not None
    package = Path(next(iter(spec.submodule_search_locations)))
    return (package / relative).read_text(encoding="utf-8")


def plugin_loaders() -> list[tuple[str, ast.expr, str]]:
    found: list[tuple[str, ast.expr, str]] = []
    for node in ast.parse(ansible_source("plugins/loader.py")).body:
        if not (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id.endswith("_loader")
            and len(node.value.args) >= 4
        ):
            continue
        subdirectory = node.value.args[3]
        assert isinstance(subdirectory, ast.Constant)
        assert isinstance(subdirectory.value, str)
        found.append((node.targets[0].id, node.value.args[2], subdirectory.value))
    return found


def ansible_settings() -> list[dict[str, object]]:
    loaded = cast("dict[str, dict[str, object]]", yaml.safe_load(ansible_source("config/base.yml")))
    return list(loaded.values())


def setting_entries(setting: dict[str, object], kind: str) -> list[dict[str, str]]:
    entries = setting.get(kind)
    if not isinstance(entries, list):
        return []
    return [
        cast("dict[str, str]", entry)
        for entry in cast("list[object]", entries)
        if isinstance(entry, dict)
    ]


def test_ansible_core_is_the_pinned_release() -> None:
    version = re.search(r"^__version__ = '([^']+)'$", ansible_source("release.py"), re.MULTILINE)
    assert version is not None
    assert version.group(1).startswith("2.21.")


def test_every_subdirectory_that_ansible_adds_for_a_playbook_or_role_is_a_load_directory() -> None:
    loaders = plugin_loaders()
    assert len(loaders) == 20
    subdirectories = {subdirectory for _, _, subdirectory in loaders}
    assert subdirectories == LOADER_SUBDIRECTORIES
    assert all(load_locations.is_load_directory_name(name) for name in subdirectories)
    source = ansible_source("plugins/loader.py")
    assert "plugin_path = os.path.join(b_path, to_bytes(obj.subdir))" in source


def test_every_relative_default_plugin_path_is_a_load_directory() -> None:
    relative = {
        config.value
        for _, config, _ in plugin_loaders()
        if isinstance(config, ast.Constant) and isinstance(config.value, str)
    }
    assert relative == {"shell_plugins"}
    assert all(load_locations.is_load_directory_name(name) for name in relative)


def test_the_collection_finder_searches_collections_next_to_a_playbook() -> None:
    source = ansible_source("utils/collection_loader/_collection_finder.py")
    assert "os.path.join(_to_text(p), 'collections') for p in playbook_paths" in source
    assert {"collections", "ansible_collections"} <= load_locations.LOAD_DIRECTORY_NAMES


def test_every_search_path_setting_of_ansible_core_is_refused() -> None:
    settings = ansible_settings()
    searched = [setting for setting in settings if setting.get("type") == "pathspec"]
    pathspec = {entry["key"] for setting in searched for entry in setting_entries(setting, "ini")}
    assert pathspec == load_config.PLUGIN_PATH_SETTINGS | {"roles_path", "collections_path"}
    assert pathspec | {"home", "playbook_dir"} <= load_config.CONFIG_PATH_SETTINGS
    containers = [
        setting
        for setting in settings
        if any(
            entry["key"] in {"home", "playbook_dir"} for entry in setting_entries(setting, "ini")
        )
    ]
    environment = {
        entry["name"]
        for setting in searched + containers
        for entry in setting_entries(setting, "env")
    }
    assert {"ANSIBLE_LIBRARY", "ANSIBLE_HOME", "ANSIBLE_PLAYBOOK_DIR"} <= environment
    assert environment <= load_config.PATH_ENVIRONMENT_VARIABLES
    assert {"ANSIBLE_CONFIG", "ANSIBLE_CONNECTION_PATH"} <= load_config.PATH_ENVIRONMENT_VARIABLES


def new_style_pattern() -> bytes:
    assignments = {
        node.targets[0].id: node.value
        for node in ast.parse(ansible_source("executor/module_common.py")).body
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
    }
    call = assignments["NEW_STYLE_PYTHON_MODULE_RE"]
    assert isinstance(call, ast.Call)
    pattern = call.args[0]
    assert isinstance(pattern, ast.Constant)
    assert isinstance(pattern.value, bytes)
    return pattern.value


def test_the_new_style_module_pattern_is_the_one_ansible_core_uses() -> None:
    assert load_locations.NEW_STYLE_MODULE.pattern == new_style_pattern()


def test_a_control_byte_is_what_ansible_core_treats_as_binary() -> None:
    source = ansible_source("executor/module_common.py")
    textchars = (
        "textchars = bytearray(set([7, 8, 9, 10, 12, 13, 27]) | set(range(0x20, 0x100)) - "
        "set([0x7f]))"
    )
    assert textchars in source
    assert "start = b_module_data[:1024]" in source
    expected = bytes(sorted({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}))
    assert expected == load_locations.TEXT_BYTES


def test_every_allowed_symlink_is_a_tracked_symlink() -> None:
    for name in load_locations.SYMLINK_ALLOW_LIST:
        assert (rules.REPO_ROOT / name).is_symlink(), name


def test_every_non_loading_directory_exists_below_a_python_only_tree() -> None:
    for directory in load_locations.NON_LOADING_DIRECTORIES:
        assert (rules.REPO_ROOT / directory).is_dir(), directory
        assert any(tree in directory.parents for tree in load_locations.PYTHON_ONLY_TREES)


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("plugins/modules/x.py", None),
        ("plugins/module_utils/library/x.py", None),
        ("plugins", None),
        ("roles/r/library/x.py", "roles/r/library"),
        ("roles/r/library", None),
        ("a/b_plugins/c/x.py", "a/b_plugins"),
        ("tests/unit/plugins/module_utils/x.py", None),
        (
            "tests/unit/plugins/module_utils/c/library/x.py",
            "tests/unit/plugins/module_utils/c/library",
        ),
        ("tests/plugins/x.py", "tests/plugins"),
    ],
)
def test_load_location(relative: str, expected: str | None) -> None:
    found = load_locations.load_location(Path(relative))
    assert found == (None if expected is None else Path(expected))


def test_a_configured_directory_is_a_load_location_even_under_plugins() -> None:
    configured = frozenset({Path("plugins/extra")})
    assert load_locations.load_location(Path("plugins/extra/x.py"), configured) == Path(
        "plugins/extra"
    )


def test_a_path_outside_the_root_has_no_repository_path(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    assert load_locations.repository_path(tmp_path / "x.py", root) is None
    assert load_locations.repository_path(root / "a" / "x.py", root) == Path("a/x.py")


def test_location_findings_of_a_missing_file_are_empty(tmp_path: Path) -> None:
    missing = tmp_path / "plugins" / "modules" / "gone"
    assert load_locations.location_findings(missing, Path("plugins/modules/gone")) == []


def test_configured_directories_ignore_paths_outside_the_root_and_empty_entries(
    tmp_path: Path,
) -> None:
    (tmp_path / "ansible.cfg").write_text(
        "[defaults]\nlibrary = ::../outside:/abs/elsewhere:inside\nroles_path = roles\n",
        encoding="utf-8",
    )
    found = load_config.configured_load_directories([tmp_path / "x.py"], tmp_path)
    assert found == frozenset({Path("inside")})


def test_configured_directories_ignore_an_unparsable_ansible_cfg(tmp_path: Path) -> None:
    (tmp_path / "ansible.cfg").write_text("library = x\n", encoding="utf-8")
    assert load_config.configured_load_directories([tmp_path / "x.py"], tmp_path) == frozenset()


def test_configured_directories_include_the_root_itself(tmp_path: Path) -> None:
    (tmp_path / "ansible.cfg").write_text("[defaults]\nlibrary = .\n", encoding="utf-8")
    assert load_config.configured_load_directories([], tmp_path) == frozenset({Path()})


def test_yaml_setting_findings_ignore_unparsable_yaml_and_recursive_aliases(
    tmp_path: Path,
) -> None:
    path = tmp_path / "probe.yml"
    assert load_config.yaml_setting_findings(path, "a: [", executed=True) == []
    recursive = "---\n&a [*a, {ANSIBLE_LIBRARY: x}]\n"
    found = load_config.yaml_setting_findings(path, recursive, executed=False)
    assert [violation.line for violation in found] == [2]
    assert load_config.yaml_setting_findings(path, "", executed=True) == []


def test_an_aliased_scalar_used_as_a_key_is_checked(tmp_path: Path) -> None:
    text = "---\na: &name ANSIBLE_LIBRARY\nb: {*name : x}\n"
    found = load_config.yaml_setting_findings(tmp_path / "probe.yml", text, executed=False)
    assert [violation.message.split(":")[0] for violation in found] == [
        "environment variable ANSIBLE_LIBRARY is not allowed"
    ]


def test_ordinary_yaml_values_are_not_command_text(tmp_path: Path) -> None:
    path = tmp_path / "probe.yml"
    text = "---\nsummary: set ANSIBLE_LIBRARY with -M\nlibrary: x\n"
    assert load_config.yaml_setting_findings(path, text, executed=False) == []


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ansible.cfg", True),
        ("Makefile", True),
        ("GNUmakefile", True),
        ("rules.mk", True),
        ("run.SH", True),
        ("run.py", False),
        ("README.md", False),
    ],
)
def test_configuration_text_files(name: str, expected: bool) -> None:
    assert load_config.is_configuration_text(Path(name)) is expected
