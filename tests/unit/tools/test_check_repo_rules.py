from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest
import yaml

from tools.lint import check_repo_rules as rules

SHA = "a" * 40


def comment_texts(text: str) -> list[tuple[int, str]]:
    return [(comment.line, comment.text) for comment in rules.scan_yaml_comments(text)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", []),
        ("---\nkey: value\n", []),
        ("# top\n", [(1, "# top")]),
        ("---\nkey: value # trailing\n", [(2, "# trailing")]),
        ("key:   value   #   spaced   \n", [(1, "#   spaced")]),
        ('key: "a # b"\n', []),
        ("key: 'a # b'\n", []),
        ("key: 'it''s # still quoted'\n", []),
        ('key: "esc \\" # still quoted"\n', []),
        ('key: "multi\n  # inside quote\n  end" # real\n', [(3, "# real")]),
        ("key: 'multi\n  # inside quote\n  end'\n", []),
        ("key: it's # comment\n", [(1, "# comment")]),
        ("url: http://example.org/#fragment\n", []),
        ("key: a#b\n", []),
        ("list: [a, 'b # c', \"d # e\"] # tail\n", [(1, "# tail")]),
        ("map: {a: 'x # y', b: z}\n", []),
        ("map: {a: [1, 2], 'k # k': v}\n", []),
        ("key: !!str 'a # b'\n", []),
        ("key: &anchor 'a # b'\n", []),
        ("key: *alias # c\n", [(1, "# c")]),
        ("- 'a # b'\n- \"c # d\"\n", []),
        ("? 'a # b'\n: v\n", []),
        ('"quoted # key": value # note\n', [(1, "# note")]),
        ('ключ: "значение # ü"  # коментар\n', [(1, "# коментар")]),
        ("key: |\n  text # not a comment\n  # also text\nnext: v # c\n", [(4, "# c")]),
        ("key: >-\n  folded # text\n\n  more # text\nnext: v\n", []),
        ("key: |2\n   # content\nnext: 1\n", []),
        ("- |\n  # content\n- b # c\n", [(3, "# c")]),
        ("- key: |\n    # content\n  other: v # c\n", [(3, "# c")]),
        ("- - |\n    # content\n", []),
        ("key: !!str |\n  # content\n", []),
        ("|\n# content-at-root\n", [(2, "# content-at-root")]),
        ("key: |\n  # content\n# after block\n", [(3, "# after block")]),
        ("key: a >\n  # continuation\n", [(2, "# continuation")]),
        ("key: ]\n", []),
        ("key: a, 'b # c'\n", [(1, "# c'")]),
        ("key: {a: 1}, x # c\n", [(1, "# c")]),
        ("a:\n- b\n", []),
        ("a:\r\n  - b # c\r\n", [(2, "# c")]),
    ],
)
def test_scan_yaml_comments(text: str, expected: list[tuple[int, str]]) -> None:
    assert comment_texts(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("x: a - |\n  # c\n", [(2, "# c")]),
        ("x: a >\n  # c\n", [(2, "# c")]),
        ("key: - |\n  # c\n", [(2, "# c")]),
        ("a:\n  b: |\n      text\n    # less indented\n  d: 1\n", [(4, "# less indented")]),
        ("k: |\n\n   first\n  # less indented\n", [(4, "# less indented")]),
        ("k: |\n     deep\n  # not content\n", [(3, "# not content")]),
        ("k: |2\n    # x\n  # y\n# z\n", [(4, "# z")]),
        ("k: |\n# empty scalar\n", [(2, "# empty scalar")]),
        ("k: | # header\n  body # text\n", [(1, "# header")]),
        ("k: >-  # header\n  body\n", [(1, "# header")]),
        ("k: |+\n  a\n\n# after\n", [(4, "# after")]),
        ("{a: 1, # c\n b: 2}\n", [(1, "# c")]),
        ("{a: \"x # y\", b: 'p # q'} # t\n", [(1, "# t")]),
        ("[a, b] # t\n", [(1, "# t")]),
        ("a: b#c\n", []),
        ('a: "x"#c\n', []),
        ("a: 'x#y' # z\n", [(1, "# z")]),
        ("key: v\t# c\n", [(1, "# c")]),
        ("key:\t# c\n", [(1, "# c")]),
        ("\t# c\n", [(1, "# c")]),
        ("k: |\r\n  # in\r\n# out\r\n", [(3, "# out")]),
        ("a: 1 # x\rb: 2 # y\r", [(1, "# x"), (2, "# y")]),
        ("a: 1\x85# x\n", [(2, "# x")]),
        ("a: 1\u2028# x\n", [(2, "# x")]),
        ("---\x07\n# c\n", [(2, "# c")]),
        ("- a\n- |\n  # in\n- 'x # y'\n# out\n", [(5, "# out")]),
    ],
)
def test_scan_regressions_and_adversarial(text: str, expected: list[tuple[int, str]]) -> None:
    assert comment_texts(text) == expected


def test_invalid_yaml_with_unprintable_character_is_reported() -> None:
    violations = rules.check_banned_modules(Path("f.yml"), "---\n\x07\n")
    assert len(violations) == 1
    assert violations[0].message.startswith("invalid YAML")


def test_scan_reports_code_before_comment() -> None:
    comments = rules.scan_yaml_comments("  - uses: a/b@x # v1.0.0\n")
    assert [comment.code for comment in comments] == ["  - uses: a/b@x "]


@pytest.mark.parametrize(
    ("line", "allowed"),
    [
        (f"      - uses: actions/checkout@{SHA} # v7.0.1", True),
        (f"uses: actions/checkout@{SHA}  # v7.0.1", True),
        (f"      - uses: github/codeql-action/analyze@{SHA} # v3.1.0", True),
        (f"  - repo: x\n    rev: {SHA}  # v0.17.2", True),
        (f"    rev: {SHA}  # v0.17.2", True),
        (f"    - rev: {SHA} # v1.2.3", True),
        (f"      - uses: actions/checkout@{SHA} # v7.0", False),
        (f"      - uses: actions/checkout@{SHA} # v7.0.1-rc1", False),
        (f"      - uses: actions/checkout@{SHA} # v7.0.1 extra", False),
        (f"      - uses: actions/checkout@{SHA} # 7.0.1", False),
        (f"      - uses: actions/checkout@{SHA} #v7.0.1", False),
        ("      - uses: actions/checkout@v4 # v4.0.0", False),
        (f"      - uses: actions/checkout@{'a' * 39} # v4.0.0", False),
        (f"      - uses: actions/checkout@{'A' * 40} # v4.0.0", False),
        (f"    rev: {'a' * 39} # v1.0.0", False),
        (f"    revision: {SHA} # v1.0.0", False),
        (f"    name: x@{SHA} # v1.0.0", False),
        ("# v1.0.0", False),
    ],
)
def test_annotation_allowance(line: str, allowed: bool) -> None:
    violations = rules.check_yaml_comments(Path("f.yml"), f"---\n{line}\n")
    assert (violations == []) is allowed


def test_comment_violation_message_and_line() -> None:
    violations = rules.check_yaml_comments(Path("f.yml"), "---\nkey: v\n# bad\n")
    assert [str(violation) for violation in violations] == [
        "f.yml:3: comment is not allowed: '# bad'"
    ]


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("---\n", True),
        ("---\nkey: v\n", True),
        ("", False),
        ("key: v\n", False),
        ("---", False),
        ("--- \nkey: v\n", False),
        ("---\r\nkey: v\r\n", False),
        ("\ufeff---\n", False),
        ("\n---\n", False),
    ],
)
def test_document_start(text: str, ok: bool) -> None:
    assert (rules.check_document_start(Path("f.yml"), text) == []) is ok


@pytest.mark.parametrize(
    "module",
    [
        "shell",
        "command",
        "raw",
        "script",
        "win_shell",
        "win_command",
        "ansible.builtin.shell",
        "ansible.builtin.command",
        "ansible.builtin.raw",
        "ansible.builtin.script",
        "ansible.legacy.shell",
        "ansible.legacy.command",
        "ansible.windows.win_shell",
        "ansible.windows.win_command",
        "community.windows.win_shell",
        "community.windows.win_command",
    ],
)
def test_banned_task_keys(module: str) -> None:
    text = f"---\n- name: x\n  hosts: all\n  tasks:\n    - name: run\n      {module}: echo hi\n"
    violations = rules.check_banned_modules(Path("f.yml"), text)
    assert [(violation.line, violation.message) for violation in violations] == [
        (6, f"banned module: {module!r}")
    ]


@pytest.mark.parametrize(
    "text",
    [
        "---\n- name: x\n  action: ansible.builtin.shell echo hi\n",
        "---\n- name: x\n  local_action: command echo hi\n",
        "---\n- name: x\n  action:\n    module: ansible.legacy.raw\n    args: x\n",
        "---\n- name: x\n  action:\n    module: shell\n",
    ],
)
def test_banned_action_forms(text: str) -> None:
    violations = rules.check_banned_modules(Path("f.yml"), text)
    assert len(violations) == 1


@pytest.mark.parametrize(
    "text",
    [
        "---\n- ansible.builtin.copy:\n    dest: /tmp/x\n    content: shell\n",
        "---\n- name: shell\n  ansible.builtin.debug:\n    msg: command\n",
        "---\n- action: ansible.builtin.copy dest=/x\n",
        "---\n- action:\n    module: ansible.builtin.copy\n",
        "---\n- action:\n    other: shell\n",
        "---\n- action:\n    module:\n      - shell\n",
        "---\n- action: ''\n",
        "---\n- action:\n    - shell\n",
        "---\n- ? [shell]\n  : v\n",
        "---\n- shellcheck: true\n",
        "---\n- ansible.builtin.shellx: a\n",
        "---\n",
        "",
        "---\n- just a string\n",
    ],
)
def test_allowed_yaml(text: str) -> None:
    assert rules.check_banned_modules(Path("f.yml"), text) == []


def test_banned_modules_in_nested_and_multiple_documents() -> None:
    text = "---\na:\n  - b:\n      command: x\n---\nraw: y\n"
    violations = rules.check_banned_modules(Path("f.yml"), text)
    assert sorted(violation.line for violation in violations) == [4, 6]


def test_banned_modules_with_alias_cycle_terminates() -> None:
    text = "---\nroot: &a\n  self: *a\n  shell: x\n"
    violations = rules.check_banned_modules(Path("f.yml"), text)
    assert [violation.line for violation in violations] == [4]


def test_banned_modules_via_alias_reported_once() -> None:
    text = "---\nbase: &t\n  shell: x\nuse: *t\n"
    violations = rules.check_banned_modules(Path("f.yml"), text)
    assert [violation.line for violation in violations] == [3]


def test_invalid_yaml_is_reported_with_line() -> None:
    violations = rules.check_banned_modules(Path("f.yml"), "---\nkey: [unclosed\nother: v\n")
    assert len(violations) == 1
    assert violations[0].message.startswith("invalid YAML")
    assert violations[0].line >= 2


def test_invalid_yaml_without_mark_defaults_to_line_one() -> None:
    violations = rules.check_banned_modules(Path("f.yml"), "---\n\tkey: v\n")
    assert len(violations) == 1
    assert violations[0].line >= 1


def test_yaml_error_without_problem_mark(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_loader: object) -> object:
        message = "boom"
        raise yaml.YAMLError(message)

    monkeypatch.setattr(yaml.SafeLoader, "get_node", fail)
    violations = rules.check_banned_modules(Path("f.yml"), "---\n")
    assert [(violation.line, violation.message) for violation in violations] == [
        (1, "invalid YAML: boom")
    ]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (b"", []),
        (b"x = 1\n", []),
        (b"#!/usr/bin/env python3\nx = 1\n", []),
        (b"x = 1\n#!/usr/bin/env python3\n", [(2, "#!/usr/bin/env python3")]),
        (b"# comment\nx = 1\n", [(1, "# comment")]),
        (b"x = 1  # trailing\n", [(1, "# trailing")]),
        (b"x = '# not a comment'\n", []),
        (b's = """\n# inside docstring\n"""\n', []),
        (b"x = 1  # type: ignore\n", [(1, "# type: ignore")]),
        (b"# -*- coding: utf-8 -*-\nx = 1\n", [(1, "# -*- coding: utf-8 -*-")]),
        ("x = 'ü'  # коментар\n".encode(), [(1, "# коментар")]),
        (b"def f():\n    return 1  # noqa\n", [(2, "# noqa")]),
    ],
)
def test_python_comments(source: bytes, expected: list[tuple[int, str]]) -> None:
    violations = rules.check_python_comments(Path("f.py"), source)
    assert [(violation.line, violation.message) for violation in violations] == [
        (line, f"comment is not allowed: {text!r}") for line, text in expected
    ]


@pytest.mark.parametrize(
    "source",
    [
        b"x = (1,\n",
        b"def f():\n  x = 1\n y = 2\n",
        b"# coding: nosuchcodec\nx = 1\n",
        b"x = '\xff'\n# coding: ascii\n",
    ],
)
def test_python_tokenize_failures_are_reported(source: bytes) -> None:
    violations = rules.check_python_comments(Path("f.py"), source)
    assert any(violation.message.startswith("cannot tokenize Python") for violation in violations)


def test_check_file_ignores_other_suffixes(tmp_path: Path) -> None:
    target = tmp_path / "notes.md"
    target.write_text("# heading\n", encoding="utf-8")
    assert rules.check_file(target) == []


def test_check_file_yaml_reports_every_rule(tmp_path: Path) -> None:
    target = tmp_path / "play.YAML"
    target.write_text("- shell: x # no\n", encoding="utf-8")
    violations = rules.check_file(target)
    assert sorted(violation.message for violation in violations) == [
        "YAML file must start with '---' followed by a newline",
        "banned module: 'shell'",
        "comment is not allowed: '# no'",
    ]


def test_check_file_clean_yaml(tmp_path: Path) -> None:
    target = tmp_path / "ok.yml"
    target.write_text(f"---\nuses: a/b@{SHA}  # v1.2.3\n", encoding="utf-8")
    assert rules.check_file(target) == []


def test_check_file_empty_yaml(tmp_path: Path) -> None:
    target = tmp_path / "empty.yml"
    target.write_bytes(b"")
    assert [violation.message for violation in rules.check_file(target)] == [
        "YAML file must start with '---' followed by a newline"
    ]


def test_check_file_invalid_utf8(tmp_path: Path) -> None:
    target = tmp_path / "bad.yml"
    target.write_bytes(b"---\nkey: \xff\n")
    violations = rules.check_file(target)
    assert len(violations) == 1
    assert violations[0].message.startswith("file is not valid UTF-8")


def test_check_file_unreadable(tmp_path: Path) -> None:
    violations = rules.check_file(tmp_path / "missing.yml")
    assert len(violations) == 1
    assert violations[0].message.startswith("cannot read file")


def test_check_file_directory_named_like_yaml(tmp_path: Path) -> None:
    directory = tmp_path / "dir.yml"
    directory.mkdir()
    assert rules.check_file(directory)[0].message.startswith("cannot read file")


def test_check_file_python(tmp_path: Path) -> None:
    target = tmp_path / "mod.py"
    target.write_text("x = 1  # c\n", encoding="utf-8")
    assert [violation.line for violation in rules.check_file(target)] == [1]


def test_check_paths_sorted(tmp_path: Path) -> None:
    first = tmp_path / "b.py"
    second = tmp_path / "a.py"
    first.write_text("# one\n# two\n", encoding="utf-8")
    second.write_text("# three\n", encoding="utf-8")
    violations = rules.check_paths([first, second])
    assert [(violation.path.name, violation.line) for violation in violations] == [
        ("a.py", 1),
        ("b.py", 1),
        ("b.py", 2),
    ]


def test_extensions_and_tests_trees_are_scanned(tmp_path: Path) -> None:
    for relative in ("extensions/molecule/default/converge.yml", "tests/integration/play.yml"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True)
        target.write_text("---\n- ansible.builtin.shell: id\n", encoding="utf-8")
    violations = rules.check_paths(tmp_path.rglob("*.yml"))
    assert len(violations) == 2


def test_main_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "ok.yml"
    target.write_text("---\nkey: value\n", encoding="utf-8")
    assert rules.main([str(target)]) == 0
    assert "satisfied in 1 file(s)" in capsys.readouterr().out


def test_main_without_paths(capsys: pytest.CaptureFixture[str]) -> None:
    assert rules.main([]) == 0
    assert "satisfied in 0 file(s)" in capsys.readouterr().out


def test_main_failure_output_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "bad.yml"
    target.write_text("key: v\n", encoding="utf-8")
    assert rules.main([str(target)]) == 1
    error = capsys.readouterr().err
    assert f"{target}:1: YAML file must start with '---' followed by a newline" in error
    assert "1 repository rule violation(s)" in error


def test_script_entry_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "ok.yml"
    target.write_text("---\nkey: value\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_repo_rules", str(target)])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(rules.__file__, run_name="__main__")
    assert raised.value.code == 0
    assert "satisfied" in capsys.readouterr().out


def test_comment_hidden_by_malformed_block_scalar_still_fails_the_file(tmp_path: Path) -> None:
    target = tmp_path / "bad.yml"
    target.write_text("---\nx: 'a' |\n  # c\n", encoding="utf-8")
    messages = [violation.message for violation in rules.check_file(target)]
    assert any(message.startswith("invalid YAML") for message in messages)
