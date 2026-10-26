from __future__ import annotations

import ast
from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path

COMPLIANCE = "ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance"
XMLSAFE_IMPORT = f"from {COMPLIANCE} import xmlsafe\n"
CALLER_FILES = (
    "plugins/module_utils/compliance/openscap.py",
    "plugins/module_utils/compliance/catalog.py",
    "plugins/module_utils/compliance/audit.py",
    "plugins/modules/benchmark_info.py",
    "plugins/action/other.py",
)
MERGED_PRODUCTION_KEYWORDS = frozenset(
    {
        "accept",
        "check_mode",
        "create",
        "default",
        "dry_run",
        "final",
        "max_length",
        "multiline",
        "pattern",
        "replace",
        "reveal",
        "sensitive",
        "subject",
        "write",
    }
)
PR_18_KEYWORDS = frozenset(
    {
        "required",
        "max_scan_lag",
        "has_content",
        "breaks",
        "final_newline",
        "nested_sequence",
    }
)
PRODUCTION_KEYWORDS = MERGED_PRODUCTION_KEYWORDS | PR_18_KEYWORDS


def process_messages(root: Path, source: str, name: str = "plugins/modules/other.py") -> list[str]:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return [violation.message for violation in rules.check_file(target, root)]


REMOVED_IMPORTS = {
    "collections": ("import collections\n", "import of 'collections' is not allowed"),
    "collections-from-abc": (
        "from collections import abc\n",
        "import of 'collections' is not allowed",
    ),
    "collections-from-name": (
        "from collections import OrderedDict\n",
        "import of 'collections' is not allowed",
    ),
    "functools": ("import functools\n", "import of 'functools' is not allowed"),
    "functools-from": ("from functools import partial\n", "import of 'functools' is not allowed"),
    "itertools": ("import itertools\n", "import of 'itertools' is not allowed"),
    "itertools-from": ("from itertools import chain\n", "import of 'itertools' is not allowed"),
    "functools-through-typing": (
        "import typing\ntyping.functools.partial\n",
        "attribute 'functools' is not allowed",
    ),
    "functools-from-typing": (
        "from typing import functools\n",
        "import of module name 'functools' through another module is not allowed",
    ),
    "itertools-through-a-module": (
        "import re\nre.itertools\n",
        "attribute 'itertools' is not allowed",
    ),
}


@pytest.mark.parametrize(
    ("source", "message"), REMOVED_IMPORTS.values(), ids=REMOVED_IMPORTS.keys()
)
def test_removed_allow_list_imports_are_denied(tmp_path: Path, source: str, message: str) -> None:
    assert any(message in found for found in process_messages(tmp_path, source))


def test_the_import_allow_list_holds_only_used_names() -> None:
    assert frozenset(rules.ALLOWED_IMPORTS) == {
        "__future__",
        "collections.abc",
        "dataclasses",
        "datetime",
        "enum",
        "hashlib",
        "json",
        "os.path",
        "pathlib",
        "re",
        "stat",
        "types",
        "typing",
        "unicodedata",
    }


def test_collections_abc_stays_importable(tmp_path: Path) -> None:
    source = (
        "import collections.abc\nfrom collections.abc import Mapping\n"
        "def f(x):\n    return isinstance(x, collections.abc.Mapping)\n"
    )
    assert process_messages(tmp_path, source) == []


REMOVED_DUNDER_READS = ("__qualname__", "__doc__", "__module__")


@pytest.mark.parametrize("name", REMOVED_DUNDER_READS)
def test_removed_dunder_reads_are_denied(tmp_path: Path, name: str) -> None:
    expected = f"dunder attribute {name!r} is not allowed in plugins"
    assert process_messages(tmp_path, f"def f(x):\n    return x.{name}\n") == [expected]
    assert process_messages(tmp_path, f"def f(x):\n    return type(x).{name}\n") == [expected]
    assert process_messages(tmp_path, f"def f(x):\n    return getattr(x, {name!r})\n") == [expected]
    assert process_messages(tmp_path, f"def f(x):\n    return getattr(x, {name!r}, None)\n") == [
        expected
    ]


def test_only_the_name_dunder_may_be_read() -> None:
    assert frozenset({"__name__"}) == rules.DUNDER_READS


def test_reading_the_name_dunder_stays_allowed(tmp_path: Path) -> None:
    source = "def f(x):\n    return x.__name__, type(x).__name__, getattr(x, '__name__', None)\n"
    assert process_messages(tmp_path, source) == []


@pytest.mark.parametrize(
    "source",
    [
        "Auditor(registry=registry)\n",
        "audit.Auditor(owner_uid=0, registry=registry)\n",
        "functools_partial(Auditor, registry=scanner.BackendRegistry())\n",
        "x = Auditor(registry=None)\n",
    ],
)
@pytest.mark.parametrize("name", CALLER_FILES)
def test_the_registry_seam_is_a_banned_keyword(tmp_path: Path, source: str, name: str) -> None:
    messages = process_messages(tmp_path, source, name)
    assert "keyword 'registry' is not allowed in plugins" in messages


def test_a_registry_parameter_may_still_be_defined(tmp_path: Path) -> None:
    source = (
        "class Auditor:\n"
        "    def __init__(self, *, registry=None):\n"
        "        self._registry = registry\n"
    )
    assert process_messages(tmp_path, source, "plugins/module_utils/compliance/audit.py") == []


def test_the_banned_keywords_are_pinned() -> None:
    assert frozenset(rules.BANNED_KEYWORDS) == {
        "use_unsafe_shell",
        "owner_uid",
        "state_dir",
        "lock_timeout",
        "policies",
        "trusted_dirs",
        "runner",
        "clock",
        "limits",
        "registry",
    }


def _keyword_only_parameters(path: Path) -> set[str]:
    tree = ast.parse(path.read_bytes(), filename=str(path))
    return {
        argument.arg
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        for argument in node.args.kwonlyargs
    }


def test_every_keyword_only_plugin_parameter_is_classified() -> None:
    found: dict[str, set[str]] = {}
    for path in sorted((rules.REPO_ROOT / rules.PLUGINS_DIRECTORY).rglob("*.py")):
        for name in _keyword_only_parameters(path):
            found.setdefault(name, set()).add(path.name)
    unclassified = {
        name: sorted(files)
        for name, files in found.items()
        if name not in rules.BANNED_KEYWORDS | PRODUCTION_KEYWORDS
    }
    assert unclassified == {}
    assert PRODUCTION_KEYWORDS.isdisjoint(rules.BANNED_KEYWORDS)


def _positional_parameters(path: Path) -> set[str]:
    tree = ast.parse(path.read_bytes(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            arguments = node.args
            optional = (arguments.vararg, arguments.kwarg)
            names.update(argument.arg for argument in (*arguments.posonlyargs, *arguments.args))
            names.update(argument.arg for argument in optional if argument is not None)
    return names


def test_no_plugin_parameter_takes_a_seam_positionally() -> None:
    found: dict[str, set[str]] = {}
    for path in sorted((rules.REPO_ROOT / rules.PLUGINS_DIRECTORY).rglob("*.py")):
        for name in _positional_parameters(path) & rules.BANNED_KEYWORDS:
            found.setdefault(name, set()).add(path.name)
    assert found == {}


@pytest.mark.parametrize(
    "source",
    [
        "def f(path, owner_uid=0):\n    return path\n",
        "def f(owner_uid, /):\n    return owner_uid\n",
        "def f(*limits):\n    return limits\n",
        "def f(**registry):\n    return registry\n",
        "f = lambda clock: clock\n",
    ],
)
def test_the_classification_detects_a_positional_seam(tmp_path: Path, source: str) -> None:
    path = tmp_path / "plugin.py"
    path.write_text(source, encoding="utf-8")
    assert len(_positional_parameters(path) & rules.BANNED_KEYWORDS) == 1
    assert not _keyword_only_parameters(path) & rules.BANNED_KEYWORDS


def test_the_test_seams_of_the_plugins_are_banned_keywords() -> None:
    seams = {
        "plugins/module_utils/compliance/process.py": {"policies", "trusted_dirs", "owner_uid"},
        "plugins/module_utils/compliance/catalog.py": {"owner_uid"},
        "plugins/module_utils/compliance/fileio.py": {"owner_uid"},
        "plugins/module_utils/compliance/ledger.py": {"state_dir", "owner_uid", "lock_timeout"},
        "plugins/module_utils/compliance/openscap.py": {"runner", "clock", "limits"},
        "plugins/module_utils/compliance/audit.py": {"owner_uid", "registry", "clock"},
    }
    for name, expected in seams.items():
        parameters = _keyword_only_parameters(rules.REPO_ROOT / name)
        assert expected <= parameters
        assert expected <= rules.BANNED_KEYWORDS


OPEN_REGULAR_CALLS = {
    "attribute-call": XMLSAFE_IMPORT + "xmlsafe._open_regular('/x', 10)\n",
    "attribute-in-with": XMLSAFE_IMPORT + "with xmlsafe._open_regular('/x', 10) as h:\n    pass\n",
    "attribute-reference": XMLSAFE_IMPORT + "f = xmlsafe._open_regular\n",
    "from-import": f"from {COMPLIANCE}.xmlsafe import _open_regular\n",
    "relative-from-import": "from .xmlsafe import _open_regular\n",
    "getattr-literal": XMLSAFE_IMPORT + "getattr(xmlsafe, '_open_regular')('/x', 10)\n",
}


@pytest.mark.parametrize("source", OPEN_REGULAR_CALLS.values(), ids=OPEN_REGULAR_CALLS.keys())
@pytest.mark.parametrize("name", CALLER_FILES)
def test_only_xmlsafe_may_open_files_without_the_context_manager(
    tmp_path: Path, source: str, name: str
) -> None:
    assert any("_open_regular" in message for message in process_messages(tmp_path, source, name))


def test_callers_open_files_through_the_context_manager(tmp_path: Path) -> None:
    source = (
        XMLSAFE_IMPORT + "def read(path):\n"
        "    with xmlsafe.RegularFile(path, 10, subject='results') as handle:\n"
        "        return b''.join(xmlsafe.iter_handle_chunks(handle, 10))\n"
    )
    assert process_messages(tmp_path, source, "plugins/module_utils/compliance/catalog.py") == []


def test_xmlsafe_has_no_public_open_function() -> None:
    path = rules.REPO_ROOT / "plugins/module_utils/compliance/xmlsafe.py"
    tree = ast.parse(path.read_bytes())
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert "open_regular" not in functions
    assert "_open_regular" in functions


def test_no_plugin_file_names_the_private_open_function() -> None:
    plugins = rules.REPO_ROOT / rules.PLUGINS_DIRECTORY
    users = sorted(
        path.relative_to(rules.REPO_ROOT).as_posix()
        for path in plugins.rglob("*.py")
        if "open_regular" in path.read_text(encoding="utf-8")
    )
    assert users == ["plugins/module_utils/compliance/xmlsafe.py"]
