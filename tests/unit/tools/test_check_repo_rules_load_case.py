from __future__ import annotations

from pathlib import Path

import pytest

from tools.lint import check_repo_rules as rules

SNEAKY = '"""Helpers."""\ngetattr(__import__("o"+"s"), "sys"+"tem")("true")\n'
OS_SYSTEM = '"""Helpers."""\nimport os\nos.system("true")\n'
LOAD = "file in the Ansible load location"
DENY = "use of __import__ is not allowed in plugins"
EXECUTABLE = "executable file is not allowed outside tools/**/*.sh"
SYMLINK = "symbolic link is not allowed"
LOAD_NAMES = (
    "library",
    "module_utils",
    "doc_fragments",
    "action_plugins",
    "become_plugins",
    "cache_plugins",
    "callback_plugins",
    "cliconf_plugins",
    "connection_plugins",
    "filter_plugins",
    "httpapi_plugins",
    "inventory_plugins",
    "lookup_plugins",
    "netconf_plugins",
    "shell_plugins",
    "strategy_plugins",
    "terminal_plugins",
    "test_plugins",
    "vars_plugins",
    "collections",
    "ansible_collections",
)
VARIANTS = tuple(
    sorted(
        {
            variant
            for name in LOAD_NAMES
            for variant in (name.upper(), name.title(), name.capitalize())
        }
    )
)


def write(root: Path, name: str, text: str, mode: int = 0o644) -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    target.chmod(mode)
    return target


def messages(root: Path, *targets: Path) -> list[str]:
    return [violation.message for violation in rules.check_paths(targets, root)]


def has(found: list[str], fragment: str) -> bool:
    return any(fragment in message for message in found)


@pytest.mark.parametrize("variant", VARIANTS)
def test_a_case_variant_of_a_load_directory_is_a_load_location(
    tmp_path: Path, variant: str
) -> None:
    found = messages(tmp_path, write(tmp_path, f"roles/remediate/{variant}/sneaky.py", SNEAKY))
    assert has(found, f"{LOAD} roles/remediate/{variant}/"), found
    assert has(found, DENY), found


@pytest.mark.parametrize(
    "name",
    [
        "roles/remediate/Library/sneaky.py",
        "roles/remediate/Filter_Plugins/sneaky.py",
        "playbooks/LIBRARY/sneaky.py",
        "playbooks/Collections/ansible_collections/evil/probe/plugins/modules/sneaky.py",
        "extensions/molecule/shared/Module_Utils/sneaky.py",
        "tests/playbooks/plugins/Modules/sneaky.py",
    ],
)
def test_the_reviewed_case_variants_are_refused(tmp_path: Path, name: str) -> None:
    found = messages(tmp_path, write(tmp_path, name, OS_SYSTEM))
    assert has(found, LOAD), found
    assert has(found, "attribute 'system' is not allowed in plugins"), found


@pytest.mark.parametrize("name", ["Plugins/modules/sneaky.py", "PLUGINS/filter/sneaky.py"])
def test_a_case_variant_of_the_root_plugins_directory_is_refused(tmp_path: Path, name: str) -> None:
    found = messages(tmp_path, write(tmp_path, name, SNEAKY))
    assert has(found, LOAD), found
    assert has(found, DENY), found


@pytest.mark.parametrize("name", ["Plugins/modules/evil", "PLUGINS/modules/evil.sh"])
def test_a_non_python_file_under_a_case_variant_of_plugins_is_refused(
    tmp_path: Path, name: str
) -> None:
    found = messages(tmp_path, write(tmp_path, name, "#!/bin/sh\ntrue\n"))
    assert has(found, "only Python source (.py) may live under plugins/"), found


def test_a_module_in_a_case_variant_of_plugins_modules_must_be_new_style(tmp_path: Path) -> None:
    found = messages(tmp_path, write(tmp_path, "plugins/Modules/polyglot.py", '"""":\ntrue\n"""\n'))
    assert has(found, "module must import ansible.module_utils"), found


@pytest.mark.parametrize(
    "name",
    ["Tests/unit/plugins/playbook.yml", "tests/Unit/plugins/tasks/main.yml", "TYPINGS/x.yml"],
)
def test_a_case_variant_of_a_python_only_tree_holds_only_python(tmp_path: Path, name: str) -> None:
    found = messages(tmp_path, write(tmp_path, name, "---\n- hosts: all\n  tasks: []\n"))
    assert has(found, "only Python source and stubs may live under"), found


def test_a_case_variant_of_a_non_loading_directory_is_not_exempt(tmp_path: Path) -> None:
    target = write(tmp_path, "tests/unit/plugins/Module_Utils/test_probe.py", OS_SYSTEM)
    assert has(messages(tmp_path, target), LOAD)


@pytest.mark.parametrize("config_name", ["Ansible.cfg", "ANSIBLE.CFG", "ansible.CFG"])
def test_a_case_variant_of_ansible_cfg_is_parsed(tmp_path: Path, config_name: str) -> None:
    config = write(tmp_path, config_name, "[defaults]\nlibrary = custom\n")
    sneaky = write(tmp_path, "custom/sneaky.py", SNEAKY)
    found = rules.check_paths([config, sneaky], tmp_path)
    assert has([v.message for v in found if v.path == config], "setting 'library' is not allowed")
    assert has([v.message for v in found if v.path == sneaky], LOAD)
    assert has([v.message for v in rules.check_file(sneaky, tmp_path)], LOAD)


def test_a_case_variant_of_a_configured_directory_is_a_load_location(tmp_path: Path) -> None:
    write(tmp_path, "ansible.cfg", "[defaults]\nlibrary = custom\n")
    sneaky = write(tmp_path, "Custom/sneaky.py", SNEAKY)
    assert has(messages(tmp_path, sneaky), LOAD)


@pytest.mark.parametrize("name", ["Molecule.yml", "MOLECULE.YAML"])
def test_a_case_variant_of_molecule_yml_is_checked(tmp_path: Path, name: str) -> None:
    text = "---\nansible:\n  cfg:\n    defaults:\n      library: ../library\n"
    found = messages(tmp_path, write(tmp_path, f"extensions/molecule/probe/{name}", text))
    assert has(found, "Molecule setting 'library' is not allowed"), found


@pytest.mark.parametrize("name", ["MAKEFILE", "GNUmakefile", "rules.MK"])
def test_a_case_variant_of_a_makefile_is_checked(tmp_path: Path, name: str) -> None:
    found = messages(tmp_path, write(tmp_path, name, "export ANSIBLE_LIBRARY := x\n"))
    assert has(found, "environment variable ANSIBLE_LIBRARY is not allowed"), found


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (".env", "ANSIBLE_LIBRARY=roles/x\n"),
        (".envrc", "export ANSIBLE_LIBRARY=roles/x\n"),
        (".env.local", "ANSIBLE_FILTER_PLUGINS=x\n"),
        ("tox.ini", "[testenv]\nsetenv =\n    ANSIBLE_LIBRARY = {toxinidir}/x\n"),
        ("setup.cfg", "[tool:pytest]\nenv = ANSIBLE_MODULE_UTILS=x\n"),
        ("pyproject.toml", '[tool.pytest.ini_options]\nenv = ["ANSIBLE_ROLES_PATH=x"]\n'),
        ("tests/pytest.INI", "[pytest]\nenv = ANSIBLE_CONFIG=x\n"),
        ("probe.env", "ANSIBLE_LIBRARY=x\n"),
    ],
)
def test_a_load_path_in_a_configuration_file_is_refused(
    tmp_path: Path, name: str, text: str
) -> None:
    found = messages(tmp_path, write(tmp_path, name, text))
    assert has(found, "is not allowed: it adds a location from which Ansible loads code"), found


def test_tox_commands_may_not_pass_a_module_path(tmp_path: Path) -> None:
    text = "[testenv]\ncommands = ansible-playbook --module-path x site.yml\n"
    found = messages(tmp_path, write(tmp_path, "tox.ini", text))
    assert has(found, "option --module-path is not allowed"), found


def test_configuration_files_without_load_paths_are_accepted(tmp_path: Path) -> None:
    targets = [
        write(tmp_path, ".env", "PROBE=1\n"),
        write(tmp_path, "pyproject.toml", '[project]\nname = "probe"\n'),
        write(tmp_path, "tox.ini", "[testenv]\nsetenv =\n    PROBE = 1\n"),
    ]
    assert messages(tmp_path, *targets) == []


@pytest.mark.parametrize(
    "name", ["ansible-navigator.yml", ".ansible-navigator.yaml", "Ansible-Navigator.yml"]
)
def test_a_navigator_configuration_that_is_not_ansible_cfg_is_refused(
    tmp_path: Path, name: str
) -> None:
    text = "---\nansible-navigator:\n  ansible:\n    config:\n      path: ./custom.ini\n"
    found = messages(tmp_path, write(tmp_path, name, text))
    expected = (
        "ansible-navigator configuration './custom.ini' is not allowed: only a file named "
        "ansible.cfg, which the guard checks, may configure Ansible"
    )
    assert found == [expected]


def test_a_navigator_configuration_named_ansible_cfg_is_accepted(tmp_path: Path) -> None:
    text = "---\nansible-navigator:\n  ansible:\n    config:\n      path: ./ansible.cfg\n"
    assert messages(tmp_path, write(tmp_path, "ansible-navigator.yml", text)) == []


def test_a_navigator_file_without_a_configuration_path_is_accepted(tmp_path: Path) -> None:
    text = "---\nansible-navigator:\n  ansible:\n    config: {}\n  mode: stdout\n"
    assert messages(tmp_path, write(tmp_path, "ansible-navigator.yml", text)) == []
    other = "---\n- not a mapping\n"
    assert messages(tmp_path, write(tmp_path, "ansible-navigator.yaml", other)) == []


def index_listing(root: Path, entries: dict[str, str]) -> Path:
    listing = root.parent / f"{root.name}-index"
    records = [f"{mode} {'0' * 40} 0\t{name}".encode() for name, mode in entries.items()]
    listing.write_bytes(b"\0".join(records) + b"\0")
    return listing


def test_an_executable_bit_that_only_the_index_records_is_refused(tmp_path: Path) -> None:
    target = write(tmp_path, "content/run", "#!/bin/sh\ntrue\n", 0o644)
    allowed = write(tmp_path, "tools/run.sh", "#!/bin/sh\ntrue\n", 0o644)
    listing = index_listing(tmp_path, {"content/run": "100755", "tools/run.sh": "100755"})
    index = rules.index_modes(listing.read_bytes())
    assert index == {Path("content/run"): "100755", Path("tools/run.sh"): "100755"}
    found = rules.check_paths([target, allowed], tmp_path, index)
    assert [(v.path, v.message.split(":")[0]) for v in found] == [(target, EXECUTABLE)]
    assert messages(tmp_path, target, allowed) == []


def test_the_command_line_reads_the_index_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = rules.REPO_ROOT / "README.md"
    assert not readme.stat().st_mode & 0o111
    listing = index_listing(tmp_path, {"README.md": "100755"})
    assert rules.main(["--index-modes", str(listing), str(readme)]) == 1
    assert f"{readme}:1: {EXECUTABLE}" in capsys.readouterr().err
    assert rules.main([str(readme)]) == 0


def test_a_symbolic_link_that_only_the_index_records_is_refused(tmp_path: Path) -> None:
    target = write(tmp_path, "plugins/modules/linked.py", "../../tools/helper.py")
    index = {Path("plugins/modules/linked.py"): "120000"}
    found = [v.message for v in rules.check_paths([target], tmp_path, index)]
    assert has(found, SYMLINK), found
