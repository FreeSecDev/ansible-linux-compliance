from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path

OPEN = "{" * 2
CLOSE = "}" * 2
PIPE = OPEN + " lookup('pipe', 'id') " + CLOSE
RUNS = "lookup 'pipe' runs a command on the controller"
NUL_REFUSED = "NUL byte in a text file is not allowed"
TARGET = "must be a literal relative path inside the repository"
SUFFIX = "must be a .yml, .yaml or .json file"
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"


def write(root: Path, name: str, data: bytes) -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def found(root: Path, name: str, data: bytes | str) -> list[str]:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return [violation.message for violation in rules.check_paths([write(root, name, raw)], root)]


def has(messages: list[str], fragment: str) -> bool:
    return any(fragment in message for message in messages)


@pytest.mark.parametrize(
    "name",
    [
        "roles/r/files/motd.txt",
        "roles/r/files/motd",
        "roles/r/templates/a.j2",
        "docs/notes.txt",
        "docs/vars.txt",
        "README.md",
        "tests/unit/x.py",
        "tools/x.sh",
        "roles/r/files/logo.png",
    ],
)
def test_a_nul_byte_does_not_exempt_a_text_file(tmp_path: Path, name: str) -> None:
    messages = found(tmp_path, name, b"\x00\n" + PIPE.encode() + b"\n")
    assert has(messages, NUL_REFUSED), messages


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("roles/r/files/logo.png", PNG + b"\x00\xff"),
        ("roles/r/files/photo.JPG", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"),
        ("roles/r/files/a.gif", b"GIF89a\x01\x00\x01\x00\x00"),
        ("roles/r/files/a.ico", b"\x00\x00\x01\x00\x01\x00"),
        ("roles/r/files/a.tar.gz", b"\x1f\x8b\x08\x00\x00\x00"),
        ("roles/r/files/a.zip", b"PK\x03\x04\x14\x00\x00"),
        ("roles/r/files/a.tar", b"x" * 257 + b"ustar\x00" + b"\x00" * 10),
        ("docs/a.pdf", b"%PDF-1.7\n\x00\xff"),
        ("docs/a.woff2", b"wOF2\x00\x01\x00\x00"),
        ("docs/a.webp", b"RIFF\x00\x00\x00\x00WEBPVP8 "),
        ("build/a.qcow2", b"QFI\xfb\x00\x00\x00\x03"),
    ],
)
def test_a_real_binary_is_skipped(tmp_path: Path, name: str, data: bytes) -> None:
    assert found(tmp_path, name, data) == []


def test_a_binary_with_a_template_is_still_checked(tmp_path: Path) -> None:
    messages = found(tmp_path, "roles/r/files/logo.png", PNG + b"\x00" + PIPE.encode())
    assert has(messages, RUNS), messages


def test_a_binary_whose_template_does_not_lex_renders_nothing(tmp_path: Path) -> None:
    data = PNG + b"\x00" + OPEN.encode() + b" & " + CLOSE.encode()
    assert found(tmp_path, "roles/r/files/logo.png", data) == []


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("roles/r/files/logo.txt", PNG),
        ("roles/r/files/logo.png", b"GIF89a\x00"),
        ("roles/r/files/x.bin", b"\x7fELF\x02\x01\x01\x00"),
    ],
)
def test_magic_bytes_without_the_matching_suffix_are_not_binary(
    tmp_path: Path, name: str, data: bytes
) -> None:
    assert has(found(tmp_path, name, data), NUL_REFUSED)


@pytest.mark.parametrize("name", ["docs/vars.txt", "docs/x.cfg.in", "LICENSE", "tests/x.py"])
def test_a_command_lookup_in_any_repository_file_is_refused(tmp_path: Path, name: str) -> None:
    assert has(found(tmp_path, name, f"probe: '{PIPE}'\n"), RUNS)


def test_a_github_file_is_not_jinja(tmp_path: Path) -> None:
    assert found(tmp_path, ".github/notes.txt", f"{PIPE}\n\x00") == []


def test_a_file_that_does_not_lex_outside_a_vars_location_renders_nothing(
    tmp_path: Path,
) -> None:
    text = f"x = {OPEN} a && b {CLOSE}\ny = {PIPE}\n"
    assert found(tmp_path, "docs/notes.md", text) == []
    assert has(found(tmp_path, "roles/r/files/notes.md", text), "cannot be checked")


@pytest.mark.parametrize(
    "play",
    [
        "  vars_files:\n    - ../docs/vars.txt\n",
        "  vars_files:\n    - ../docs/vars\n",
        "  vars_files:\n    - [../docs/vars.txt, other.yml]\n",
    ],
)
def test_a_non_yaml_vars_file_is_refused(tmp_path: Path, play: str) -> None:
    write(tmp_path, "docs/vars.txt", b"probe: x\n")
    text = f"---\n- hosts: all\n{play}  tasks: []\n"
    assert has(found(tmp_path, "playbooks/p.yml", text), SUFFIX)


@pytest.mark.parametrize(
    "task",
    [
        "  ansible.builtin.include_vars:\n    dir: ../../docs\n    extensions: [txt]\n",
        "  ansible.builtin.include_vars:\n    file: vars.txt\n",
        "  include_vars: vars.txt\n",
        "  ansible.legacy.include_vars: dir=vars extensions=txt\n",
        "  action: ansible.builtin.include_vars dir=vars extensions=txt\n",
        "  ansible.builtin.include_vars:\n    dir: vars\n  args:\n    extensions: [txt]\n",
    ],
)
def test_include_vars_may_not_load_a_non_yaml_file(tmp_path: Path, task: str) -> None:
    messages = found(tmp_path, "roles/r/tasks/main.yml", f"---\n- name: Probe\n{task}")
    assert has(messages, "parameter 'extensions'") or has(messages, SUFFIX), messages


@pytest.mark.parametrize(
    "task",
    [
        "  ansible.builtin.include_vars:\n    file: '{{ name }}.yml'\n",
        "  ansible.builtin.include_vars: '{{ name }}'\n",
        "  ansible.builtin.include_vars:\n    dir: '{{ directory }}'\n",
        "  ansible.builtin.include_vars:\n    file: /etc/ansible/x.yml\n",
        "  ansible.builtin.include_vars:\n    file: ../../../../x.yml\n",
        "  ansible.builtin.include_vars:\n    file: '{{ role_path }}/../../../x.yml'\n",
        "  ansible.builtin.include_vars:\n    file: '{{ role_path }}/../../.github/x.yml'\n",
        "  ansible.builtin.include_vars:\n    file: '{{ playbook_dir }}/x.yml'\n",
        "  ansible.builtin.template:\n    src: '{{ name }}'\n    dest: /srv/x\n",
        "  ansible.builtin.template: src=~/x.j2 dest=/srv/x\n",
        "  ansible.builtin.template:\n    src: ../../../x.j2\n    dest: /srv/x\n",
        "  action:\n    module: ansible.builtin.template\n    src: '{{ x }}'\n",
        "  ansible.builtin.template:\n    dest: /srv/x\n  args:\n    src: '{{ x }}'\n",
    ],
)
def test_a_computed_or_escaping_target_is_refused(tmp_path: Path, task: str) -> None:
    messages = found(tmp_path, "roles/r/tasks/main.yml", f"---\n- name: Probe\n{task}")
    assert has(messages, TARGET) or has(messages, SUFFIX), messages


@pytest.mark.parametrize(
    "entry",
    ["'{{ name }}.yml'", "/etc/x.yml", "../../../x.yml", "'{{ playbook_dir }}/../../x.yml'"],
)
def test_a_computed_or_escaping_vars_files_entry_is_refused(tmp_path: Path, entry: str) -> None:
    text = f"---\n- hosts: all\n  vars_files:\n    - {entry}\n  tasks: []\n"
    assert has(found(tmp_path, "playbooks/p.yml", text), TARGET)


def test_a_mapping_vars_files_entry_is_refused(tmp_path: Path) -> None:
    text = "---\n- hosts: all\n  vars_files:\n    - {a: b}\n  tasks: []\n"
    assert has(found(tmp_path, "playbooks/p.yml", text), "vars_files entry must be a literal path")


def test_role_path_outside_a_role_is_refused(tmp_path: Path) -> None:
    text = "---\n- ansible.builtin.include_vars:\n    file: '{{ role_path }}/vars/x.yml'\n"
    assert has(found(tmp_path, "playbooks/tasks/x.yml", text), TARGET)


@pytest.mark.parametrize(
    "expression",
    [
        "lookup('template', name)",
        "lookup('ansible.builtin.template', 'a' ~ name)",
        "query('template')",
        "lookup('template', '/etc/x.j2')",
        "lookup('template', '../../../x.j2')",
    ],
)
def test_a_computed_or_escaping_template_lookup_is_refused(tmp_path: Path, expression: str) -> None:
    text = f'---\n- ansible.builtin.debug:\n    msg: "{OPEN} {expression} {CLOSE}"\n'
    messages = found(tmp_path, "roles/r/tasks/main.yml", text)
    assert has(messages, "template lookup"), messages


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (
            "roles/audit/tasks/toggles.yml",
            (
                "---\n- ansible.builtin.include_vars:\n"
                "    file: '{{ role_path }}/../remediate/vars/rules.yml'\n"
            ),
        ),
        (
            "tests/playbooks/p.yml",
            (
                "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.include_vars:\n"
                "        file: '{{ playbook_dir }}/../../roles/remediate/vars/rules.yml'\n"
            ),
        ),
        (
            "extensions/molecule/selftest/a.yml",
            "---\n- hosts: localhost\n  vars_files:\n    - ../shared/vars/versions.yml\n",
        ),
        ("roles/r/tasks/main.yml", "---\n- ansible.builtin.include_vars: rules.yml\n"),
        ("roles/r/tasks/main.yml", "---\n- ansible.builtin.include_vars:\n    dir: vars\n"),
        (
            "roles/r/tasks/main.yml",
            "---\n- ansible.builtin.template:\n    src: motd.j2\n    dest: /etc/motd\n",
        ),
        (
            "roles/r/tasks/main.yml",
            "---\n- ansible.builtin.debug:\n    msg: \"{{ lookup('template', 'motd.j2') }}\"\n",
        ),
        ("roles/r/tasks/main.yml", "---\n- action: ansible.builtin.template src=a.j2 dest=/x\n"),
        ("roles/r/tasks/main.yml", "---\n- ansible.builtin.include_vars:\n    name: x\n"),
        ("roles/r/tasks/main.yml", "---\n- ansible.builtin.include_vars:\n    - x\n"),
    ],
)
def test_a_literal_target_inside_the_repository_passes(
    tmp_path: Path, name: str, text: str
) -> None:
    assert found(tmp_path, name, text) == []
