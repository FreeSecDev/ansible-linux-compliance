from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tools.lint import check_repo_rules as rules

SNEAKY = 'getattr(__import__("o"+"s"), "sys"+"tem")("true")\n'
DOCSTRING = '"""Helpers."""\n'
SHELL_MODULE = "#!/bin/sh\necho '{\"changed\": false}'\n"
LOAD = "file in the Ansible load location"
DENY = "use of __import__ is not allowed in plugins"
NOT_PYTHON = "only Python source (.py) may live under plugins/"
EXECUTABLE = "executable file is not allowed outside tools/**/*.sh"
SYMLINK = "symbolic link is not allowed"
SHEBANG = "is not allowed: a Python file may only name a Python interpreter"
OLD_STYLE = "module must import ansible.module_utils or the collection's module_utils"
BINARY = "module contains a control byte"
PYTHON_ONLY = "only Python source and stubs may live under"
SETTING = "setting 'library' is not allowed"
MODULE = (
    "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance "
    "import model\n"
)
SUBDIRECTORIES = (
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
)
BASES = (
    "roles/remediate",
    "playbooks",
    "playbooks/roles/local",
    "extensions/molecule/shared",
    "extensions/molecule/selftest",
    "extensions/molecule/docker-ubuntu",
    "tests/playbooks",
    "tests/integration/targets/probe",
    "",
)
COLLECTION_LOCATIONS = (
    "collections/ansible_collections/evil/probe/plugins/modules",
    "playbooks/collections/ansible_collections/evil/probe/plugins/module_utils",
    "extensions/molecule/shared/collections/ansible_collections/evil/probe/plugins/filter",
    "ansible_collections/evil/probe/plugins/action",
    "roles/remediate/collections/ansible_collections/evil/probe/plugins/modules",
    "build/ansible-home/plugins/modules",
    "playbooks/plugins/modules",
    "tests/unit/plugins/probe/library",
    "tests/unit/plugins/module_utils/compliance/filter_plugins",
)
LOCATIONS = (
    *(
        "/".join(part for part in (base, subdirectory) if part)
        for base in BASES
        for subdirectory in SUBDIRECTORIES
    ),
    *COLLECTION_LOCATIONS,
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


@pytest.mark.parametrize("location", LOCATIONS)
def test_the_obfuscated_module_is_refused_in_every_load_location(
    tmp_path: Path, location: str
) -> None:
    package = write(tmp_path, f"{location}/__init__.py", DOCSTRING)
    sneaky = write(tmp_path, f"{location}/sneaky.py", DOCSTRING + SNEAKY)
    found = messages(tmp_path, sneaky)
    assert has(found, LOAD), found
    assert has(found, DENY), found
    assert has(found, "getattr, setattr and delattr need a literal attribute name"), found
    assert has(messages(tmp_path, package), LOAD)


def test_the_reviewed_role_library_reproduction_is_refused(tmp_path: Path) -> None:
    package = write(tmp_path, "roles/remediate/library/__init__.py", DOCSTRING)
    sneaky = write(tmp_path, "roles/remediate/library/sneaky.py", DOCSTRING + SNEAKY)
    violations = rules.check_paths([package, sneaky], tmp_path)
    load = (
        "file in the Ansible load location roles/remediate/library/ is not allowed: "
        "the collection's code belongs in plugins/ (ADR 0004)"
    )
    assert (package, 1, load) in {(v.path, v.line, v.message) for v in violations}
    assert (sneaky, 1, load) in {(v.path, v.line, v.message) for v in violations}
    assert (sneaky, 2, DENY) in {(v.path, v.line, v.message) for v in violations}


@pytest.mark.parametrize(
    ("name", "mode", "expected"),
    [
        ("plugins/modules/evil", 0o755, (NOT_PYTHON, EXECUTABLE)),
        ("plugins/modules/evil.sh", 0o755, (NOT_PYTHON, EXECUTABLE)),
        ("plugins/modules/evil.sh", 0o644, (NOT_PYTHON,)),
        ("plugins/modules/nested/evil", 0o755, (NOT_PYTHON, EXECUTABLE)),
        ("roles/remediate/library/evil.sh", 0o755, (LOAD, EXECUTABLE)),
        ("roles/remediate/library/evil", 0o644, (LOAD,)),
        ("playbooks/library/evil", 0o755, (LOAD, EXECUTABLE)),
        ("extensions/molecule/shared/library/evil.sh", 0o755, (LOAD, EXECUTABLE)),
    ],
)
def test_a_shell_module_is_refused(
    tmp_path: Path, name: str, mode: int, expected: tuple[str, ...]
) -> None:
    found = messages(tmp_path, write(tmp_path, name, SHELL_MODULE, mode))
    assert all(has(found, fragment) for fragment in expected), found


@pytest.mark.parametrize("text", [SHELL_MODULE, "true\n", ""])
def test_a_non_executable_file_without_a_suffix_in_plugins_modules_is_refused(
    tmp_path: Path, text: str
) -> None:
    found = messages(tmp_path, write(tmp_path, "plugins/modules/evil", text))
    expected = (
        "only Python source (.py) may live under plugins/, not a file without a suffix: "
        "Ansible runs a module of any type"
    )
    assert found == [expected]


@pytest.mark.parametrize(
    "name",
    [
        "plugins/modules/win_probe.ps1",
        "plugins/modules/win_probe.PS1",
        "plugins/modules/probe.yml",
        "plugins/modules/probe.PY",
        "plugins/module_utils/Ansible.ModuleUtils.Probe.psm1",
        "plugins/module_utils/csharp/Ansible.Probe.cs",
        "plugins/filter/probe.rb",
    ],
)
def test_a_non_python_plugin_file_is_refused(tmp_path: Path, name: str) -> None:
    found = messages(tmp_path, write(tmp_path, name, "---\nWrite-Output 'x'\n"))
    assert has(found, NOT_PYTHON), found


@pytest.mark.parametrize(
    "source",
    [
        '"""":\ntouch /tmp/pwned\nexit\n"""\n',
        '#!/usr/bin/python\n"""":\ntouch /tmp/pwned\nexit\n"""\n',
        '"""Doc."""\nimport json\nVALUE = json.dumps(\'#Requires -Module Ansible\')\n',
    ],
)
def test_an_old_style_module_in_plugins_modules_is_refused(tmp_path: Path, source: str) -> None:
    found = messages(tmp_path, write(tmp_path, "plugins/modules/polyglot.py", source))
    assert has(found, OLD_STYLE), found


def test_a_module_with_a_shell_shebang_is_refused(tmp_path: Path) -> None:
    source = f'#!/bin/sh\n"""":\ntouch /tmp/pwned\nexit\n"""\n{MODULE}'
    found = messages(tmp_path, write(tmp_path, "plugins/modules/polyglot.py", source))
    assert found == [
        "shebang '#!/bin/sh' is not allowed: a Python file may only name a Python interpreter"
    ]


@pytest.mark.parametrize("name", ["tools/probe.py", "plugins/filter/probe.py", "probe.py"])
@pytest.mark.parametrize("shebang", ["#!/bin/bash", "#!/usr/bin/env -S sh -c true", "#!sh"])
def test_a_non_python_shebang_is_refused_in_any_python_file(
    tmp_path: Path, name: str, shebang: str
) -> None:
    found = messages(tmp_path, write(tmp_path, name, f"{shebang}\n{DOCSTRING}"))
    assert has(found, SHEBANG), found


def test_a_module_with_a_control_byte_is_refused(tmp_path: Path) -> None:
    source = f'"""Doc."""\n{MODULE}VALUE = "\x01"\n'
    found = messages(tmp_path, write(tmp_path, "plugins/modules/binary.py", source))
    assert found == ["module contains a control byte: Ansible would run it as a binary module"]


def test_a_symlink_into_plugins_modules_is_refused_and_not_read(tmp_path: Path) -> None:
    helper = write(tmp_path, "tools/helper.py", f'"""Doc."""\nimport subprocess\n{MODULE}')
    link = tmp_path / "plugins/modules/linked.py"
    link.parent.mkdir(parents=True)
    link.symlink_to(Path("../../tools/helper.py"))
    found = messages(tmp_path, link)
    expected = (
        "symbolic link is not allowed: Ansible and the guard would follow it to a file that no "
        "rule checked at this path"
    )
    assert found == [expected]
    assert messages(tmp_path, helper) == []


@pytest.mark.parametrize(
    "name",
    [
        "roles/remediate/library",
        "playbooks/filter_plugins",
        "extensions/molecule/shared/collections",
    ],
)
def test_a_symlink_named_like_a_load_directory_is_refused(tmp_path: Path, name: str) -> None:
    write(tmp_path, "tools/payload/sneaky.py", DOCSTRING + SNEAKY)
    link = tmp_path / name
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(tmp_path / "tools/payload", target_is_directory=True)
    assert has(messages(tmp_path, link), SYMLINK)


@pytest.mark.parametrize(
    "name",
    [
        "tests/playbooks/inventory/dynamic.py",
        "tests/playbooks/inventory/hosts",
        "content/vault-password",
        "tools/lint/probe.py",
        "extensions/ci/scc/run",
    ],
)
def test_an_executable_file_outside_the_allow_list_is_refused(tmp_path: Path, name: str) -> None:
    text = f"#!/usr/bin/python\n{DOCSTRING}" if name.endswith(".py") else "#!/bin/sh\ntrue\n"
    found = messages(tmp_path, write(tmp_path, name, text, 0o755))
    assert has(found, EXECUTABLE), found


@pytest.mark.parametrize(
    ("config_name", "config", "module_name"),
    [
        ("ansible.cfg", "[defaults]\nlibrary = ./custom_modules\n", "custom_modules/sneaky.py"),
        ("ansible.cfg", "[defaults]\nLIBRARY = custom_modules\n", "custom_modules/sneaky.py"),
        (
            "ansible.cfg",
            "[defaults]\nfilter_plugins = /usr/share/x:helpers/filters\n",
            "helpers/filters/sneaky.py",
        ),
        (
            "extensions/molecule/probe/ansible.cfg",
            "[defaults]\nlibrary = ../../../helpers\n",
            "helpers/sneaky.py",
        ),
        (
            "tests/playbooks/ansible.cfg",
            "[defaults]\nmodule_utils =\n  utils\n",
            "tests/playbooks/utils/nested/sneaky.py",
        ),
    ],
)
def test_a_module_in_a_path_that_ansible_cfg_names_is_refused(
    tmp_path: Path, config_name: str, config: str, module_name: str
) -> None:
    config_file = write(tmp_path, config_name, config)
    sneaky = write(tmp_path, module_name, DOCSTRING + SNEAKY)
    together = rules.check_paths([config_file, sneaky], tmp_path)
    assert {violation.path for violation in together} == {config_file, sneaky}
    assert has([v.message for v in together if v.path == config_file], "is not allowed")
    alone = [violation.message for violation in rules.check_file(sneaky, tmp_path)]
    if config_file.parent in sneaky.parents:
        assert has(alone, LOAD), alone
        assert has(alone, DENY), alone
    assert has([v.message for v in together if v.path == sneaky], DENY)


@pytest.mark.parametrize(
    "setting",
    [
        "library",
        "module_utils",
        "action_plugins",
        "filter_plugins",
        "roles_path",
        "collections_path",
        "home",
        "playbook_dir",
    ],
)
def test_every_load_path_setting_in_ansible_cfg_is_refused(tmp_path: Path, setting: str) -> None:
    config = write(tmp_path, "ansible.cfg", f"[defaults]\nforks = 5\n{setting} = elsewhere\n")
    expected = (
        f"ansible.cfg setting {setting!r} is not allowed: it adds a location from which "
        "Ansible loads code; the collection's code belongs in plugins/ (ADR 0004)"
    )
    assert [(v.line, v.message) for v in rules.check_paths([config], tmp_path)] == [(3, expected)]


def test_an_ansible_cfg_without_load_paths_is_accepted_and_garbage_is_refused(
    tmp_path: Path,
) -> None:
    config = write(tmp_path, "ansible.cfg", "[defaults]\nforks = 5\n")
    assert messages(tmp_path, config) == []
    broken = write(tmp_path, "nested/ansible.cfg", "library = x\n")
    assert has(messages(tmp_path, broken), "cannot parse ansible.cfg")


def test_a_molecule_ansible_cfg_load_path_is_refused(tmp_path: Path) -> None:
    scenario = {
        "ansible": {
            "cfg": {"defaults": {"library": "../library", "forks": 5}},
            "env": {"ANSIBLE_FILTER_PLUGINS": "../filters"},
            "executor": {"args": {"ansible_playbook": ["--module-path=../library"]}},
        }
    }
    target = write(
        tmp_path, "extensions/molecule/probe/molecule.yml", "---\n" + yaml.safe_dump(scenario)
    )
    found = messages(tmp_path, target)
    assert has(found, "Molecule setting 'library' is not allowed"), found
    assert has(found, "environment variable ANSIBLE_FILTER_PLUGINS is not allowed"), found
    assert has(found, "option --module-path is not allowed"), found


@pytest.mark.parametrize(
    ("name", "text", "fragment"),
    [
        (
            ".github/workflows/probe.yml",
            "---\njobs:\n  probe:\n    env:\n      ANSIBLE_LIBRARY: roles/x\n",
            "environment variable ANSIBLE_LIBRARY is not allowed",
        ),
        (
            ".github/workflows/probe.yml",
            "---\njobs:\n  probe:\n    steps:\n      - run: ANSIBLE_CONFIG=x make ci\n",
            "environment variable ANSIBLE_CONFIG is not allowed",
        ),
        (
            "tests/playbooks/probe.yml",
            "---\n- hosts: all\n  environment:\n    ANSIBLE_MODULE_UTILS: x\n  tasks: []\n",
            "environment variable ANSIBLE_MODULE_UTILS is not allowed",
        ),
        ("Makefile", "export ANSIBLE_LIBRARY := x\n", "ANSIBLE_LIBRARY is not allowed"),
        ("Makefile", "probe:\n\tansible-playbook -M x p.yml\n", "option -M is not allowed"),
        ("tools/probe.sh", "ANSIBLE_ROLES_PATH=x ansible\n", "ANSIBLE_ROLES_PATH is not allowed"),
        ("tools/probe.sh", "ANSIBLE_HOME=x ansible\n", "ANSIBLE_HOME is not allowed"),
    ],
)
def test_a_load_path_set_through_the_environment_is_refused(
    tmp_path: Path, name: str, text: str, fragment: str
) -> None:
    found = messages(tmp_path, write(tmp_path, name, text))
    assert has(found, fragment), found


def test_the_makefile_may_name_the_per_checkout_ansible_home(tmp_path: Path) -> None:
    text = "ANSIBLE_HOME ?= build/h\nANSIBLE_COLLECTIONS_PATH ?= build/c\nprobe:\n\tsort -n x\n"
    assert messages(tmp_path, write(tmp_path, "Makefile", text)) == []


@pytest.mark.parametrize(
    "name",
    [
        "tests/unit/plugins/module_utils/compliance/test_probe.py",
        "tests/unit/plugins/modules/test_probe.py",
        "tests/unit/plugins/filter/test_probe.py",
        "typings/ansible/module_utils/basic.pyi",
    ],
)
def test_the_unit_tests_and_stubs_that_mirror_the_layout_are_not_load_locations(
    tmp_path: Path, name: str
) -> None:
    source = '"""Doc."""\nimport subprocess\n\n\ndef test_probe() -> None:\n    assert subprocess\n'
    assert messages(tmp_path, write(tmp_path, name, source)) == []


@pytest.mark.parametrize(
    "name",
    [
        "tests/unit/plugins/playbook.yml",
        "tests/unit/plugins/tasks/main.yml",
        "tests/unit/plugins/module_utils/evil",
        "typings/ansible/playbook.yaml",
    ],
)
def test_the_mirrored_trees_hold_only_python(tmp_path: Path, name: str) -> None:
    found = messages(tmp_path, write(tmp_path, name, "---\n- hosts: all\n  tasks: []\n"))
    assert has(found, PYTHON_ONLY), found


@pytest.mark.parametrize(
    "name",
    [
        "tools/scc/fetch-scc.sh",
        "tools/lint/fetch-hadolint.sh",
        "plugins/modules/probe.py",
        "plugins/module_utils/compliance/probe.py",
        "roles/remediate/tasks/main.yml",
        "tools/reporting/collections.py",
        "tools/library.py",
    ],
)
def test_ordinary_files_stay_accepted(tmp_path: Path, name: str) -> None:
    if name.endswith(".sh"):
        target = write(tmp_path, name, "#!/usr/bin/env bash\ntrue\n", 0o755)
    elif name.endswith(".yml"):
        target = write(tmp_path, name, "---\n- name: Probe\n  ansible.builtin.debug:\n")
    else:
        target = write(tmp_path, name, f'#!/usr/bin/python\n"""Doc."""\n{MODULE}')
    assert messages(tmp_path, target) == []


def test_the_allowed_symlinks_are_not_followed(tmp_path: Path) -> None:
    (tmp_path / ".agents/skills").mkdir(parents=True)
    link = tmp_path / ".claude/skills"
    link.parent.mkdir()
    link.symlink_to(Path("../.agents/skills"), target_is_directory=True)
    assert messages(tmp_path, link) == []


def test_make_lint_repo_passes_every_tracked_file_to_the_guard() -> None:
    makefile = (rules.REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    lint_repo = makefile.split("\nlint-repo:", 1)[1].split("\n\n", 1)[0]
    assert "\t$(TRACKED) | xargs -0 -r $(RUN) python tools/lint/check_repo_rules.py" in lint_repo
    assert "$(TRACKED) --" not in lint_repo
    assert "TRACKED := git ls-files -z --cached --others --exclude-standard\n" in makefile


def test_the_pre_commit_hook_passes_every_file_and_symlink_to_the_guard() -> None:
    config = yaml.safe_load(
        (rules.REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    hook = next(
        hook for repo in config["repos"] for hook in repo["hooks"] if hook["id"] == "repo-rules"
    )
    assert hook["types_or"] == ["file", "symlink"]
    assert "files" not in hook
    assert "types" not in hook
    assert "exclude" not in hook
    assert hook["entry"] == "uv run --frozen python tools/lint/check_repo_rules.py"
