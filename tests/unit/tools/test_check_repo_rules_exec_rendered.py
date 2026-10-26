from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path

RUNS = "lookup 'pipe' runs a command on the controller"
PIPE = "{{ lookup('pipe', 'id') }}"


def write(root: Path, name: str, data: bytes) -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def found(root: Path, name: str, text: str) -> list[str]:
    target = write(root, name, text.encode("utf-8"))
    return [violation.message for violation in rules.check_paths([target], root)]


def has(messages: list[str], fragment: str) -> bool:
    return any(fragment in message for message in messages)


@pytest.mark.parametrize(
    "name",
    [
        "roles/r/files/motd",
        "roles/r/files/motd.txt",
        "roles/r/files/sshd_config.conf",
        "roles/r/files/nested/banner.md",
        "roles/r/vars/data.txt",
        "playbooks/files/notes.txt",
        "tests/playbooks/files/fixture.cfg.in",
        "extensions/molecule/shared/files/x.txt",
        "Roles/r/files/motd.txt",
    ],
)
def test_a_command_lookup_in_a_file_that_a_template_can_render_is_refused(
    tmp_path: Path, name: str
) -> None:
    assert has(found(tmp_path, name, f"Welcome\n{PIPE}\n"), RUNS)


def test_a_file_included_from_a_template_is_scanned(tmp_path: Path) -> None:
    template = write(tmp_path, "roles/r/templates/a.j2", b"{% include 'banner.txt' %}\n")
    included = write(tmp_path, "roles/r/files/banner.txt", PIPE.encode())
    messages = [v.message for v in rules.check_paths([template, included], tmp_path)]
    assert has(messages, RUNS)


@pytest.mark.parametrize(
    "name",
    [
        "roles/r/vars/extra.json",
        "roles/r/defaults/main.json",
        "playbooks/vars/extra.json",
        "tests/playbooks/vars/extra.json",
        "vars/extra.json",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        PIPE,
        '{{ lookup(\\"pipe\\", \\"id\\") }}',
        "{{ lookup('\\u0070ipe', 'id') }}",
    ],
)
def test_a_command_lookup_in_a_json_vars_file_is_refused(
    tmp_path: Path, name: str, value: str
) -> None:
    messages = found(tmp_path, name, f'{{"probe": "{value}"}}\n')
    assert has(messages, "lookup") or has(messages, "cannot be checked"), messages


@pytest.mark.parametrize(
    "name",
    [
        "group_vars/all",
        "group_vars/web.json",
        "host_vars/h1",
        "host_vars/h1.json",
        "inventory/group_vars/all",
        "tests/playbooks/inventory/host_vars/h1.json",
        "inventories/prod/group_vars/web/main.json",
    ],
)
def test_a_command_lookup_in_group_or_host_vars_without_a_yaml_suffix_is_refused(
    tmp_path: Path, name: str
) -> None:
    text = f'{{"probe": "{PIPE}"}}\n' if name.endswith(".json") else f'---\nprobe: "{PIPE}"\n'
    assert has(found(tmp_path, name, text), RUNS)


@pytest.mark.parametrize("name", ["group_vars/all", "host_vars/h1.json", "roles/r/vars/x.json"])
def test_an_execution_altering_variable_in_vars_without_a_yaml_suffix_is_refused(
    tmp_path: Path, name: str
) -> None:
    text = (
        '{"ansible_ssh_common_args": "-o ProxyCommand=id"}\n'
        if name.endswith(".json")
        else "---\nansible_ssh_common_args: -o ProxyCommand=id\n"
    )
    assert has(found(tmp_path, name, text), "setting 'ansible_ssh_common_args'")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("inventory/hosts", f'[web]\nh1 probe="{PIPE}"\n'),
        ("inventory/hosts.ini", f"[web:vars]\nprobe={PIPE}\n"),
        ("hosts", f"h1 probe='{PIPE}'\n"),
        ("tests/playbooks/inventory/hosts", f'[all:vars]\nprobe="{PIPE}"\n'),
        ("inventories/prod/hosts", "[db]\nh2 a=1 probe=\"{{ q('lines', 'id') }}\"\n"),
    ],
)
def test_a_command_lookup_in_an_ini_inventory_value_is_refused(
    tmp_path: Path, name: str, text: str
) -> None:
    messages = found(tmp_path, name, text)
    assert has(messages, "runs a command on the controller"), messages


def test_an_escaped_ini_inventory_value_is_refused(tmp_path: Path) -> None:
    text = '[web]\nh1 probe="{{ lookup(\\x27pipe\\x27, \\x27id\\x27) }}"\n'
    assert has(found(tmp_path, "inventory/hosts", text), "cannot be checked for lookups")


@pytest.mark.parametrize(
    "template",
    [
        "{% include name %}",
        "{% include 'a' ~ name %}",
        "{% include ['a.j2', name] %}",
        "{% import name as m %}",
        "{% extends parent %}",
        "{% from name import m %}",
        "{% include 'a' 'b' %}",
        "{%- include name -%}",
    ],
)
def test_a_computed_template_name_is_refused(tmp_path: Path, template: str) -> None:
    messages = found(tmp_path, "roles/r/templates/x.j2", template + "\n")
    assert has(messages, "must name a literal template"), messages


@pytest.mark.parametrize(
    "template",
    [
        "{% include '/etc/x.j2' %}",
        "{% include '~/x.j2' %}",
        "{% include '../../x.j2' %}",
        "{% import '{{ x }}.j2' as m %}",
    ],
)
def test_a_template_name_outside_the_search_path_is_refused(tmp_path: Path, template: str) -> None:
    messages = found(tmp_path, "roles/r/templates/x.j2", template + "\n")
    assert has(messages, "must be a relative path without '..'"), messages


def test_a_computed_include_in_a_yaml_value_is_refused(tmp_path: Path) -> None:
    text = '---\n- ansible.builtin.debug:\n    msg: "{% include name %}"\n'
    assert has(found(tmp_path, "roles/r/tasks/main.yml", text), "must name a literal template")


@pytest.mark.parametrize(
    "template",
    [
        "{% include 'banner.txt' %}",
        "{% include 'a.j2' ignore missing %}",
        "{% include 'a.j2' with context %}",
        "{% import 'macros.j2' as m %}{{ m.f() }}",
        "{% from 'macros.j2' import f %}",
        "{% extends 'base.j2' %}",
        "{% if include %}x{% endif %}",
        "{{ include }}",
    ],
)
def test_a_literal_template_name_passes(tmp_path: Path, template: str) -> None:
    assert found(tmp_path, "roles/r/templates/x.j2", template + "\n") == []


def test_a_binary_file_in_a_role_is_not_a_template(tmp_path: Path) -> None:
    target = write(tmp_path, "roles/r/files/blob.bin", b"\x00\xff{{ lookup('pipe', 'id') }}")
    assert rules.check_paths([target], tmp_path) == []


def test_undecodable_text_in_a_role_is_refused(tmp_path: Path) -> None:
    target = write(tmp_path, "roles/r/files/latin1.txt", b"caf\xe9 {{ x }}\n")
    messages = [v.message for v in rules.check_paths([target], tmp_path)]
    assert has(messages, "template is not valid UTF-8")


def test_a_python_file_in_a_role_is_read_as_a_template_too(tmp_path: Path) -> None:
    assert has(found(tmp_path, "roles/r/files/x.py", f'"""{PIPE}"""\n'), RUNS)


def test_ordinary_text_in_the_ansible_trees_passes(tmp_path: Path) -> None:
    assert found(tmp_path, "roles/r/files/motd.txt", "Authorised use only.\n") == []
    assert found(tmp_path, "roles/r/README.md", "Set `x: {{ y }}`.\n") == []
    assert found(tmp_path, "extensions/ci/x/Containerfile", "FROM scratch\n") == []
    assert found(tmp_path, "roles/r/vars/x.json", '{"a": "{{ b }}"}\n') == []
    assert found(tmp_path, "group_vars/all", "[not yaml\n") == []
    assert found(tmp_path, "docs/notes.txt", PIPE) == []


@pytest.mark.parametrize(
    "name", ["vars/x.txt", "files/motd", "defaults/main.json", "a/templates/b", "x.jinja"]
)
def test_a_rendered_directory_outside_the_ansible_trees_is_scanned(
    tmp_path: Path, name: str
) -> None:
    assert has(found(tmp_path, name, PIPE + "\n"), RUNS)


def test_a_binary_json_file_is_not_variables(tmp_path: Path) -> None:
    target = write(tmp_path, "roles/r/vars/blob.json", b'{"a": "\x00{{ lookup(\'pipe\') }}"}')
    assert rules.check_paths([target], tmp_path) == []
