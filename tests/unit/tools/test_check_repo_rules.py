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


def plugin_file(root: Path, source: str, name: str = "plugins/modules/other.py") -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return target


def process_messages(root: Path, source: str, name: str = "plugins/modules/other.py") -> list[str]:
    target = plugin_file(root, source, name)
    return [violation.message for violation in rules.check_file(target, root)]


CRAFTED_BYPASSES = {
    "getattr-os-system": "import os\ngetattr(os, 'system')('id')\n",
    "getattr-concatenated-name": "import os\ngetattr(os, 'sys' + 'tem')('id')\n",
    "importlib-concatenated-module": (
        "import importlib\nimportlib.import_module('sub' + 'process')\n"
    ),
    "import-module-alias": "from importlib import import_module as im\nim('subprocess')\n",
    "star-import-os": "from os import *\nsystem('id')\n",
    "os-alias-variable": "import os\nx = os\nx.system('id')\n",
    "sys-modules-os": "import sys\nsys.modules['os'].system('id')\n",
    "posix-system": "import posix\nposix.system('id')\n",
    "posixsubprocess": "import _posixsubprocess\n",
    "asyncio-exec": ("import asyncio\nasyncio.create_subprocess_exec('id')\n"),
    "asyncio-subprocess-module": "import asyncio.subprocess\n",
    "ctypes-system": "import ctypes\nctypes.CDLL(None).system(b'id')\n",
    "exec-builtin": "exec('import os')\n",
    "eval-builtin": "eval('1')\n",
    "os-fork": "import os\nos.fork()\n",
    "multiprocessing-popen-fork": "import multiprocessing.popen_fork\n",
    "run-command-unsafe-shell": (
        "def f(module):\n    return module.run_command('id', use_unsafe_shell=True)\n"
    ),
    "subprocess-import": "import subprocess\n",
    "subprocess-from-import": "from subprocess import run\n",
    "pty-import": "import pty\n",
    "os-system": "import os\nos.system('id')\n",
    "shell-true": "def f(x):\n    return x(shell=True)\n",
}

OTHER_BYPASSES = {
    "compile-builtin": "compile('1', 'f', 'eval')\n",
    "dunder-import-call": "__import__('os')\n",
    "dunder-import-reference": "loader = __import__\n",
    "exec-reference": "run = exec\n",
    "builtins-module": "__builtins__\n",
    "getattr-reference": "g = getattr\ng(object, 'x')\n",
    "setattr-reference": "s = setattr\n",
    "getattr-without-name": "getattr(object)\n",
    "getattr-variable-name": "def f(name):\n    return getattr(object, name)\n",
    "getattr-keyword": "getattr(object, name='system')\n",
    "setattr-banned-name": "setattr(object, 'run_command', 1)\n",
    "delattr-dynamic": "def f(n):\n    delattr(object, n)\n",
    "getattr-literal-banned": "getattr(object, 'run_command')\n",
    "getattr-literal-prefix": "getattr(object, 'spawnv')\n",
    "run-command": "module.run_command(['id'])\n",
    "use-unsafe-shell-only": "f(use_unsafe_shell=False)\n",
    "popen-attribute": "thing.Popen(['id'])\n",
    "popen-os": "import os.path\nos.popen('id')\n",
    "os-bare-import": "import os\n",
    "os-bare-import-alias": "import os as o\n",
    "os-attribute": "import os.path\nos.getcwd()\n",
    "os-reference": "import os.path\nx = os\n",
    "os-environ": "import os.path\nos.environ\n",
    "from-os-system": "from os import system\n",
    "from-os-popen": "from os import path, popen\n",
    "from-os-execv": "from os import execv\n",
    "from-os-spawn": "from os import spawnv\n",
    "from-os-fork": "from os import fork\n",
    "star-allowed-module": "from json import *\n",
    "star-relative": "from .helper import *\n",
    "from-ansible-run-command": "from ansible.module_utils.basic import run_command\n",
    "import-sys": "import sys\n",
    "import-ctypes-from": "from ctypes import CDLL\n",
    "import-importlib": "import importlib\n",
    "import-importlib-util": "import importlib.util\n",
    "import-socket": "import socket\n",
    "import-asyncio": "import asyncio\n",
    "import-multiprocessing": "import multiprocessing\n",
    "import-shlex": "import shlex\n",
    "import-prefix-lookalike": "import ansible.module_utils_evil\n",
    "import-collection-lookalike": "import ansible_collections.freesecdev.linux_compliance_evil\n",
    "import-other-collection": "import ansible_collections.other.collection.plugins\n",
    "import-nested-forbidden": "import subprocess.x\n",
    "execvpe-attribute": "libc.execvpe('id', [], {})\n",
    "spawn-attribute": "libc.spawnlp(0, 'id')\n",
    "posix-spawn-attribute": "libc.posix_spawnp('id')\n",
    "prefix-over-approximation-spawner": "x.spawner\n",
    "prefix-over-approximation-fork": "x.fork_choice\n",
    "forkpty-attribute": "libc.forkpty()\n",
    "create-subprocess-shell": "loop.create_subprocess_shell('id')\n",
    "class-walk-subclasses": "().__class__.__base__.__subclasses__()\n",
    "mro-walk": "type(x).__mro__\n",
    "globals-attribute": "f.__globals__\n",
    "code-attribute": "f.__code__\n",
}

BENIGN_PLUGIN_SOURCES = {
    "future": "from __future__ import annotations\n",
    "typing": "from typing import TYPE_CHECKING, Final, cast\n",
    "stdlib": (
        "import json\nimport re\nimport unicodedata\nfrom dataclasses import dataclass\n"
        "from datetime import datetime\nfrom enum import Enum\nfrom types import MappingProxyType\n"
        "import hashlib\nimport functools\nimport itertools\nimport stat\n"
        "from pathlib import Path\nimport collections\nfrom collections import abc\n"
        "from collections.abc import Mapping\nimport xml.etree.ElementTree\n"
    ),
    "os-path-import": "import os.path\nos.path.join('a', 'b')\n",
    "os-path-from-import": "from os import path\npath.join('a', 'b')\n",
    "os-path-module": "from os.path import join\n",
    "ansible-module-utils": (
        "from ansible.module_utils.basic import AnsibleModule\nimport ansible.module_utils\n"
    ),
    "collection": (
        "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance "
        "import model\n"
    ),
    "relative": "from . import helper\nfrom .helper import thing\nfrom .. import other\n",
    "object-setattr": "object.__setattr__(x, 'field', 1)\n",
    "getattr-literal": "getattr(x, 'field')\nsetattr(x, 'field', 1)\ngetattr(x, 'field', None)\n",
    "shell-false": "f(shell=False)\nf(shell=flag)\nf(other=True)\nf(*args, **kwargs)\n",
    "plain-calls": "factory()()\nobj.system_name\nobj.executable\nobj.execute\n",
    "unrelated-name": "x = 'subprocess'\nosmosis = 1\n",
    "relative-lookalike": "from .subprocess import thing\n",
    "empty": "",
}


@pytest.mark.parametrize("source", CRAFTED_BYPASSES.values(), ids=CRAFTED_BYPASSES.keys())
def test_guard_flags_every_crafted_bypass(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize("source", OTHER_BYPASSES.values(), ids=OTHER_BYPASSES.keys())
def test_guard_denies_other_constructs_by_default(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize("source", BENIGN_PLUGIN_SOURCES.values(), ids=BENIGN_PLUGIN_SOURCES.keys())
def test_guard_allows_permitted_constructs(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source) == []


def test_guard_covers_all_twenty_two_crafted_bypass_cases() -> None:
    assert len(CRAFTED_BYPASSES) == 22


def test_guard_messages_and_lines(tmp_path: Path) -> None:
    target = plugin_file(tmp_path, "import os\n\nos.system('id')\nfrom subprocess import run\n")
    violations = rules.check_file(target, tmp_path)
    assert [(violation.line, violation.message) for violation in violations] == [
        (1, "import of 'os' is not allowed in plugins outside " + str(rules.PROCESS_HELPER)),
        (3, "attribute 'system' is not allowed in plugins"),
        (3, "os may only be used as os.path in plugins"),
        (
            4,
            "import of 'subprocess' is not allowed in plugins outside " + str(rules.PROCESS_HELPER),
        ),
    ]


def test_guard_reports_shell_true_and_unsafe_shell_keywords(tmp_path: Path) -> None:
    assert process_messages(tmp_path, "run(x, shell=True)\n") == ["shell=True is forbidden"]
    assert process_messages(tmp_path, "run(x, use_unsafe_shell=True)\n") == [
        "keyword 'use_unsafe_shell' is not allowed in plugins"
    ]


def test_process_helper_is_exempt(tmp_path: Path) -> None:
    source = "import subprocess\nimport os\nos.system('x')\nexec('1')\n"
    assert process_messages(tmp_path, source, "plugins/module_utils/compliance/process.py") == []


def test_same_file_name_elsewhere_is_not_exempt(tmp_path: Path) -> None:
    messages = process_messages(tmp_path, "import subprocess\n", "plugins/modules/process.py")
    assert messages != []


def test_nested_plugin_directories_are_in_scope(tmp_path: Path) -> None:
    assert process_messages(tmp_path, "import subprocess\n", "plugins/a/b/c/mod.py") != []


@pytest.mark.parametrize(
    "name", ["tools/lint/helper.py", "tests/unit/plugins/test_x.py", "tests/plugins/x.py", "x.py"]
)
def test_code_outside_plugins_is_out_of_scope(tmp_path: Path, name: str) -> None:
    assert process_messages(tmp_path, "import subprocess\nimport os\nos.system('x')\n", name) == []


def test_path_outside_the_root_is_out_of_scope(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = plugin_file(tmp_path, "import subprocess\n", "plugins/x.py")
    assert rules.check_file(outside, root) == []


def test_unparsable_plugin_source_is_reported(tmp_path: Path) -> None:
    messages = process_messages(tmp_path, "def broken(:\n")
    assert any(message.startswith("cannot parse Python") for message in messages)


def test_null_bytes_in_plugin_source_are_reported(tmp_path: Path) -> None:
    target = plugin_file(tmp_path, "x = 1\n")
    target.write_bytes(b"x = 1\x00\n")
    messages = [violation.message for violation in rules.check_file(target, tmp_path)]
    assert any(message.startswith("cannot parse Python") for message in messages)


def test_check_paths_uses_the_given_root(tmp_path: Path) -> None:
    target = plugin_file(tmp_path, "import subprocess\n")
    assert len(rules.check_paths([target], tmp_path)) == 1
    assert rules.check_paths([target], tmp_path / "elsewhere") == []


def test_comment_and_process_violations_are_both_reported(tmp_path: Path) -> None:
    messages = process_messages(tmp_path, "import subprocess  # why\n")
    assert len(messages) == 2


def test_repository_plugins_pass_the_deny_by_default_rule() -> None:
    sources = sorted((rules.REPO_ROOT / "plugins").rglob("*.py"))
    assert rules.REPO_ROOT / rules.PROCESS_HELPER in sources
    assert rules.check_paths(sources) == []


def test_repository_helper_is_the_only_plugin_file_importing_subprocess() -> None:
    importers = [
        path.relative_to(rules.REPO_ROOT)
        for path in sorted((rules.REPO_ROOT / "plugins").rglob("*.py"))
        if "subprocess" in path.read_text(encoding="utf-8")
    ]
    assert importers == [rules.PROCESS_HELPER]


SANCTIONED_SANITY_IGNORE = (
    "plugins/module_utils/compliance/process.py pylint:ansible-bad-function\n"
)


@pytest.mark.parametrize("version", ["2.20", "2.21"])
def test_sanity_ignore_files_contain_exactly_the_one_sanctioned_entry(version: str) -> None:
    ignore = rules.REPO_ROOT / "tests" / "sanity" / f"ignore-{version}.txt"
    assert ignore.read_text(encoding="utf-8") == SANCTIONED_SANITY_IGNORE


def test_only_the_two_sanity_ignore_files_exist() -> None:
    names = sorted(path.name for path in (rules.REPO_ROOT / "tests" / "sanity").iterdir())
    assert names == ["ignore-2.20.txt", "ignore-2.21.txt"]


def test_ansible_lint_ignore_skips_only_the_two_sanity_ignore_files() -> None:
    lines = (rules.REPO_ROOT / ".ansible-lint-ignore").read_text(encoding="utf-8").splitlines()
    assert lines == [
        "tests/sanity/ignore-2.20.txt sanity[cannot-ignore] skip",
        "tests/sanity/ignore-2.21.txt sanity[cannot-ignore] skip",
    ]


def test_ansible_lint_ignore_is_not_published() -> None:
    galaxy = yaml.safe_load((rules.REPO_ROOT / "galaxy.yml").read_text(encoding="utf-8"))
    assert ".ansible-lint-ignore" in galaxy["build_ignore"]
