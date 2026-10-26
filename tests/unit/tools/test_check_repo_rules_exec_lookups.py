from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path

COMMAND_LOOKUP_NAMES = tuple(
    f"{prefix}{name}"
    for name in ("pipe", "lines")
    for prefix in ("", "ansible.builtin.", "ansible.legacy.")
)
FUNCTIONS = ("lookup", "query", "q")
RUNS = "runs a command on the controller"
COMPUTED = "must be called with a literal lookup name"
UNREVIEWED = "is not an ansible-core lookup that this guard reviewed"


def write(root: Path, name: str, text: str) -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def found(root: Path, name: str, text: str) -> list[str]:
    return [violation.message for violation in rules.check_paths([write(root, name, text)], root)]


def lines_found(root: Path, name: str, text: str) -> list[tuple[int, str]]:
    target = write(root, name, text)
    return [(violation.line, violation.message) for violation in rules.check_paths([target], root)]


def has(messages: list[str], fragment: str) -> bool:
    return any(fragment in message for message in messages)


def task(body: str) -> str:
    return f"---\n- name: Probe\n{body}"


def debug(expression: str) -> str:
    return task(f'  ansible.builtin.debug:\n    msg: "{expression}"\n')


@pytest.mark.parametrize("function", FUNCTIONS)
@pytest.mark.parametrize("name", COMMAND_LOOKUP_NAMES)
def test_a_command_lookup_in_a_task_is_refused(tmp_path: Path, function: str, name: str) -> None:
    text = debug(f"{{{{ {function}('{name}', 'id') }}}}")
    assert lines_found(tmp_path, "roles/r/tasks/main.yml", text) == [(4, f"lookup {name!r} {RUNS}")]


@pytest.mark.parametrize("name", COMMAND_LOOKUP_NAMES)
@pytest.mark.parametrize(
    ("file_name", "template"),
    [
        ("roles/r/defaults/main.yml", '---\nprobe: "{expr}"\n'),
        ("roles/r/vars/main.yml", '---\nprobe: "{expr}"\n'),
        ("group_vars/all.yml", '---\nprobe: "{expr}"\n'),
        ("inventory/hosts.yml", '---\nall:\n  hosts:\n    h:\n      probe: "{expr}"\n'),
        ("playbooks/p.yml", '---\n- hosts: all\n  vars:\n    probe: "{expr}"\n  tasks: []\n'),
        (
            "roles/r/tasks/main.yml",
            (
                "---\n- block:\n    - ansible.builtin.debug:\n        msg: hi\n"
                '  vars:\n    probe: "{expr}"\n'
            ),
        ),
        (
            "roles/r/tasks/main.yml",
            (
                "---\n- ansible.builtin.include_tasks:\n    file: x.yml\n"
                '  vars:\n    probe: "{expr}"\n'
            ),
        ),
        ("roles/r/tasks/main.yml", '---\n- ansible.builtin.set_fact:\n    probe: "{expr}"\n'),
        (
            "roles/r/tasks/main.yml",
            '---\n- ansible.builtin.debug:\n    msg: "{{{{ item }}}}"\n  loop: "{expr}"\n',
        ),
        ("extensions/molecule/s/converge.yml", '---\n- hosts: all\n  tasks:\n    - x: "{expr}"\n'),
    ],
)
def test_a_command_lookup_is_refused_wherever_ansible_templates_a_value(
    tmp_path: Path, name: str, file_name: str, template: str
) -> None:
    text = template.format(expr=f"{{{{ lookup('{name}', 'id') }}}}")
    assert has(found(tmp_path, file_name, text), f"lookup {name!r} {RUNS}")


@pytest.mark.parametrize("key", ["when", "changed_when", "failed_when", "until"])
@pytest.mark.parametrize("function", FUNCTIONS)
def test_a_command_lookup_in_a_bare_conditional_is_refused(
    tmp_path: Path, key: str, function: str
) -> None:
    text = task(f"  ansible.builtin.debug:\n    msg: hi\n  {key}: {function}('pipe', 'id')\n")
    assert has(found(tmp_path, "roles/r/tasks/main.yml", text), f"lookup 'pipe' {RUNS}")


def test_a_command_lookup_in_a_conditional_list_and_an_assertion_is_refused(
    tmp_path: Path,
) -> None:
    text = task(
        "  ansible.builtin.assert:\n    that:\n      - true\n      - q('lines', 'id')\n"
        "  when:\n    - lookup('ansible.builtin.pipe', 'id')\n"
    )
    messages = found(tmp_path, "roles/r/tasks/main.yml", text)
    assert has(messages, f"lookup 'lines' {RUNS}")
    assert has(messages, f"lookup 'ansible.builtin.pipe' {RUNS}")


def test_a_command_lookup_in_debug_var_is_refused(tmp_path: Path) -> None:
    text = task("  ansible.builtin.debug:\n    var: lookup('pipe', 'id')\n")
    assert has(found(tmp_path, "roles/r/tasks/main.yml", text), f"lookup 'pipe' {RUNS}")


@pytest.mark.parametrize(
    "loop", ["with_pipe", "with_lines", "with_ansible.builtin.pipe", "with_ansible.legacy.lines"]
)
def test_a_with_loop_over_a_command_lookup_is_refused(tmp_path: Path, loop: str) -> None:
    text = task(f"  ansible.builtin.debug:\n    msg: hi\n  {loop}:\n    - id\n")
    assert has(found(tmp_path, "roles/r/tasks/main.yml", text), f"loop {loop!r}")


@pytest.mark.parametrize(
    "name",
    ["roles/r/templates/motd.j2", "roles/r/templates/motd", "templates/x.conf", "a/b.jinja2"],
)
@pytest.mark.parametrize("function", FUNCTIONS)
def test_a_command_lookup_in_a_template_file_is_refused(
    tmp_path: Path, name: str, function: str
) -> None:
    text = f"line one\n{{{{ {function}('ansible.legacy.pipe', 'id') }}}}\n"
    assert lines_found(tmp_path, name, text) == [(2, f"lookup 'ansible.legacy.pipe' {RUNS}")]


@pytest.mark.parametrize(
    "expression",
    [
        "{{ lookup(name, 'id') }}",
        "{{ query(name) }}",
        "{{ q(lookup_name, 'id') }}",
        "{{ lookup('pi' 'pe', 'id') }}",
        "{{ lookup('pi' ~ 'pe', 'id') }}",
        "{{ lookup('pipe' | lower, 'id') }}",
        "{{ (lookup)('pipe', 'id') }}",
        "{{ lookup(*names) }}",
        "{{ lookup(name='pipe') }}",
        "{% set run = lookup %}{{ run('pipe', 'id') }}",
        "{{ lookup }}",
        "{{ x.lookup('pipe', 'id') }}",
    ],
)
def test_a_computed_or_indirect_lookup_is_refused(tmp_path: Path, expression: str) -> None:
    messages = found(tmp_path, "roles/r/tasks/main.yml", debug(expression))
    assert has(messages, COMPUTED) or has(messages, RUNS), messages


def test_a_computed_lookup_in_a_template_file_is_refused(tmp_path: Path) -> None:
    assert has(found(tmp_path, "roles/r/templates/x.j2", "{{ lookup(kind, 'id') }}\n"), COMPUTED)


def test_a_computed_lookup_in_a_conditional_is_refused(tmp_path: Path) -> None:
    text = task("  ansible.builtin.debug:\n    msg: hi\n  when: query(kind, 'id')\n")
    assert has(found(tmp_path, "roles/r/tasks/main.yml", text), COMPUTED)


@pytest.mark.parametrize("escaped", ["\\\\x70ipe", "\\\\u0070ipe", "\\\\160ipe"])
def test_an_escaped_lookup_name_is_read_as_jinja_reads_it(tmp_path: Path, escaped: str) -> None:
    text = task(f'  ansible.builtin.debug:\n    msg: \'{{{{ lookup("{escaped}", "id") }}}}\'\n')
    messages = found(tmp_path, "roles/r/tasks/main.yml", text)
    assert has(messages, RUNS) or has(messages, UNREVIEWED), messages


def test_a_template_inside_a_string_constant_is_checked(tmp_path: Path) -> None:
    text = task(
        "  ansible.builtin.debug:\n    msg: >-\n      {{ \"{{ lookup('pipe', 'id') }}\" }}\n"
    )
    assert has(found(tmp_path, "roles/r/tasks/main.yml", text), f"lookup 'pipe' {RUNS}")


def test_a_deeply_nested_template_is_refused(tmp_path: Path) -> None:
    inner = "{{ 1 }}"
    for _ in range(10):
        inner = "{{ " + repr(inner) + " }}"
    target = write(tmp_path, "roles/r/templates/deep.j2", inner + "\n")
    messages = [violation.message for violation in rules.check_paths([target], tmp_path)]
    assert has(messages, "templates nested too deeply to be checked")


@pytest.mark.parametrize(
    "name",
    [
        "community.general.passwordstore",
        "passwordstore",
        "dig",
        "community.general.onepassword",
        "freesecdev.linux_compliance.anything",
    ],
)
def test_a_lookup_outside_the_reviewed_ansible_core_set_is_refused(
    tmp_path: Path, name: str
) -> None:
    messages = found(tmp_path, "roles/r/tasks/main.yml", debug(f"{{{{ lookup('{name}') }}}}"))
    assert has(messages, f"lookup {name!r} {UNREVIEWED}")


def test_a_with_loop_over_an_unreviewed_lookup_is_refused(tmp_path: Path) -> None:
    text = task("  ansible.builtin.debug:\n    msg: hi\n  with_community.general.dig: x\n")
    assert has(found(tmp_path, "roles/r/tasks/main.yml", text), UNREVIEWED)


@pytest.mark.parametrize(
    "name",
    [
        "env",
        "ansible.builtin.env",
        "ansible.builtin.file",
        "ansible.legacy.vars",
        "ansible.builtin.password",
        "ansible.builtin.inventory_hostnames",
        "ansible.builtin.varnames",
        "ansible.builtin.template",
    ],
)
@pytest.mark.parametrize("function", FUNCTIONS)
def test_a_reviewed_lookup_with_a_literal_name_passes(
    tmp_path: Path, name: str, function: str
) -> None:
    text = debug(f"{{{{ {function}('{name}', 'x', wantlist=True) }}}}")
    assert found(tmp_path, "roles/r/tasks/main.yml", text) == []


@pytest.mark.parametrize(
    "loop", ["with_items", "with_dict", "with_fileglob", "with_ansible.builtin.file"]
)
def test_a_with_loop_over_a_reviewed_lookup_passes(tmp_path: Path, loop: str) -> None:
    text = task(f"  ansible.builtin.debug:\n    msg: hi\n  {loop}: []\n")
    assert found(tmp_path, "roles/r/tasks/main.yml", text) == []


def test_prose_that_mentions_a_lookup_is_not_a_template(tmp_path: Path) -> None:
    text = task("  ansible.builtin.debug:\n    msg: Use the pipe lookup(name) only in docs\n")
    assert found(tmp_path, "roles/r/tasks/main.yml", text) == []


def test_an_unsafe_or_vaulted_value_is_never_templated_as_a_variable(tmp_path: Path) -> None:
    text = "---\nprobe: !unsafe \"{{ q('pipe', 'id') }}\"\nother: !vault x\n"
    assert found(tmp_path, "roles/r/vars/main.yml", text) == [f"lookup 'pipe' {RUNS}"]
    text = '---\nprobe: !unsafe "{{ x }}"\nother: !vault x\n'
    assert found(tmp_path, "roles/r/vars/main.yml", text) == []


def test_a_conditional_that_does_not_lex_runs_nothing(tmp_path: Path) -> None:
    text = task('  ansible.builtin.debug:\n    msg: hi\n  when: "a \'"\n')
    assert found(tmp_path, "roles/r/tasks/main.yml", text) == []


def test_a_template_that_does_not_lex_is_refused(tmp_path: Path) -> None:
    messages = found(tmp_path, "roles/r/tasks/main.yml", debug("{{ a && b }}"))
    assert has(messages, "template cannot be checked for lookups")


def test_github_expressions_are_not_jinja(tmp_path: Path) -> None:
    text = "---\non: push\njobs:\n  a:\n    if: ${{ a && b }}\n    runs-on: x\n    steps: []\n"
    assert found(tmp_path, ".github/workflows/w.yml", text) == []


@pytest.mark.parametrize("name", ["roles/r/tasks/main.yml", "roles/r/templates/x.j2"])
def test_a_jinja_override_header_is_refused(tmp_path: Path, name: str) -> None:
    header = "#jinja2: variable_start_string:'[[', variable_end_string:']]'"
    payload = "[[ lookup('pipe', 'id') ]]"
    if name.endswith(".j2"):
        text = f"{header}\n{payload}\n"
    else:
        text = task(f'  ansible.builtin.debug:\n    msg: "{header}\\n{payload}"\n')
    assert has(found(tmp_path, name, text), "'#jinja2:' header is not allowed")


def test_a_jinja_override_header_inside_a_string_constant_is_refused(tmp_path: Path) -> None:
    text = "{{ \"#jinja2: variable_start_string:'[['\\n[[ 1 ]]\" }}\n"
    assert has(found(tmp_path, "roles/r/templates/x.j2", text), "'#jinja2:' header")


@pytest.mark.parametrize(
    "option",
    [
        "variable_start_string",
        "block_start_string",
        "comment_start_string",
        "line_statement_prefix",
    ],
)
def test_a_delimiter_option_of_the_template_module_is_refused(tmp_path: Path, option: str) -> None:
    text = task(
        f"  ansible.builtin.template:\n    src: a.j2\n    dest: /srv/probe/a\n    {option}: '[['\n"
    )
    assert has(found(tmp_path, "roles/r/tasks/main.yml", text), f"Jinja option {option!r}")


@pytest.mark.parametrize(
    "expression",
    [
        "{{ lookup('ansible.builtin.template', 'a.j2', variable_start_string='[[') }}",
        "{{ lookup('ansible.builtin.file', 'a', allow_unsafe=True) }}",
    ],
)
def test_a_delimiter_or_unsafe_option_of_a_lookup_is_refused(
    tmp_path: Path, expression: str
) -> None:
    assert has(found(tmp_path, "roles/r/tasks/main.yml", debug(expression)), "Jinja option")


def test_a_template_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "roles/r/templates/x.j2"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\xff\xfe")
    messages = [violation.message for violation in rules.check_paths([target], tmp_path)]
    assert has(messages, "template is not valid UTF-8")


def test_a_regular_expression_escape_in_a_template_is_not_a_lex_error(tmp_path: Path) -> None:
    text = task(
        "  ansible.builtin.debug:\n    msg: \"{{ x is match('^a\\\\.b$') }}\"\n"
        "  when: x is match('^a\\.b$')\n"
    )
    assert found(tmp_path, "roles/r/tasks/main.yml", text) == []


def test_an_aliased_value_is_checked_once(tmp_path: Path) -> None:
    text = "---\na: &x\n  k: \"{{ lookup('pipe', 'id') }}\"\nb: *x\nc: *x\n"
    assert lines_found(tmp_path, "roles/r/vars/main.yml", text) == [(3, f"lookup 'pipe' {RUNS}")]
