from __future__ import annotations

import importlib
import sys
import types
from typing import TYPE_CHECKING

import pytest

from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from pathlib import Path


def plugin_file(root: Path, source: str, name: str = "plugins/modules/other.py") -> Path:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return target


def process_messages(root: Path, source: str, name: str = "plugins/modules/other.py") -> list[str]:
    target = plugin_file(root, source, name)
    return [violation.message for violation in rules.check_file(target, root)]


REFLECTION_BYPASSES = {
    "reviewer-operator-attrgetter": (
        "import typing\nimport os.path\ntyping.operator.attrgetter('os')(os.path)\n"
    ),
    "reviewer-dataclasses-builtins-eval": "import dataclasses\ndataclasses.builtins.eval('1')\n",
    "reviewer-forwardref-evaluate": "import typing\ntyping.ForwardRef('x')._evaluate\n",
    "builtins-attribute-name": "import typing\ntyping.builtins\n",
    "operator-attribute-name": "import typing\ntyping.operator\n",
    "eval-attribute": "import typing\ntyping.x.eval('1')\n",
    "exec-attribute-call": "import typing\ntyping.x.exec('1')\n",
    "compile-attribute": "import re\nre.compile('x')\n",
    "attrgetter-attribute": "x.attrgetter\n",
    "methodcaller-attribute": "x.methodcaller\n",
    "evaluate-attribute": "x.y._evaluate\n",
    "evaluate-forward-ref-attribute": "x.evaluate_forward_ref(y)\n",
    "attrgetter-from-import": "from operator import attrgetter\n",
    "compile-from-import-alias": "from re import compile as c\n",
    "evaluate-forward-ref-from-import": "from typing import evaluate_forward_ref\n",
    "getattr-literal-builtins": "getattr(x, 'builtins')\n",
    "getattr-literal-methodcaller": "getattr(x, 'methodcaller')\n",
    "module-getattr-def": "def __getattr__(name):\n    return name\n",
    "module-getattr-async-def": "async def __getattr__(name):\n    return name\n",
    "module-getattr-in-if": "if True:\n    def __getattr__(name):\n        return name\n",
    "module-getattr-assignment": "__getattr__ = lambda name: name\n",
    "module-getattr-class": "class __getattr__:\n    pass\n",
    "module-getattr-import": "from helper import __getattr__\n",
}

INTERNALS_BYPASSES = {
    "kwdefaults-write": "f.__kwdefaults__ = {'remediate': True}\n",
    "kwdefaults-read": "x = f.__kwdefaults__\n",
    "defaults-write": "f.__defaults__ = (True,)\n",
    "code-read": "f.__code__\n",
    "closure-read": "f.__closure__\n",
    "globals-read": "f.__globals__\n",
    "kwdefaults-getattr": "getattr(f, '__kwdefaults__')\n",
    "defaults-setattr": "setattr(f, '__defaults__', ())\n",
    "closure-import": "from x import __closure__\n",
    "defaults-on-method": "class A:\n    def m(self):\n        self.m.__defaults__ = ()\n",
}

MODULE_ASSIGNMENT_BYPASSES = {
    "process-constant": (
        "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance"
        " import process\nprocess.POLICY = 1\n"
    ),
    "openscap-constant": "from . import openscap\nopenscap.LIMIT = 1\n",
    "plain-import": "import json\njson.dumps = print\n",
    "dotted-import-root": "import os.path\nos.path.join = print\n",
    "import-as": "import json as j\nj.dumps = print\n",
    "from-import-class": "from dataclasses import dataclass\ndataclass.attr = 1\n",
    "nested-attribute": "from . import process\nprocess.CONFIG.value = 1\n",
    "augmented": "from . import process\nprocess.COUNT += 1\n",
    "annotated": "from . import process\nprocess.COUNT: int = 1\n",
    "delete": "from . import process\ndel process.POLICY\n",
    "tuple-target": "from . import process\nprocess.A, process.B = 1, 2\n",
    "item-assignment": "from . import process\nprocess.POLICIES['oscap'] = ()\n",
    "item-delete": "from . import process\ndel process.POLICIES['oscap']\n",
    "setattr-module": "from . import process\nsetattr(process, 'POLICY', 1)\n",
    "delattr-module": "from . import process\ndelattr(process, 'POLICY')\n",
    "setattr-module-attribute": "from . import process\nsetattr(process.CONFIG, 'x', 1)\n",
    "object-setattr-module": "from . import process\nobject.__setattr__(process, 'POLICY', 1)\n",
    "object-delattr-module": "from . import process\nobject.__delattr__(process, 'POLICY')\n",
}

PRIVATE_ACCESS_BYPASSES = {
    "reviewer-expat-read": "from . import openscap\nopenscap._expat.ParserCreate()\n",
    "reviewer-backend-assign": "def f(backend):\n    backend._runner = print\n",
    "reviewer-parse-stream-call": "from . import openscap\nopenscap._parse_stream(a, b, limits)\n",
    "limits-assign": "def f(backend):\n    backend._limits = None\n",
    "private-read": "def f(backend):\n    return backend._clock\n",
    "private-call": "def f(backend):\n    backend._run()\n",
    "private-delete": "def f(backend):\n    del backend._runner\n",
    "private-augassign": "def f(backend):\n    backend._count += 1\n",
    "private-chained": "class A:\n    def m(self):\n        return self._settings._secret\n",
    "private-name-mangled": "def f(x):\n    return x.__secret\n",
    "single-underscore-name": "def f(x):\n    return x._\n",
    "dunder-assignment": "def f(x):\n    x.__class__ = int\n",
    "dunder-delete": "def f(x):\n    del x.__call__\n",
    "self-outside-class": "def f(self):\n    return self._x\n",
    "self-not-first-parameter": "class A:\n    def m(other, self):\n        return self._x\n",
    "self-not-a-parameter": "class A:\n    def m(x):\n        return self._x\n",
    "cls-outside-class": "def f(cls):\n    return cls._x\n",
    "async-self-wrong-name": "class A:\n    async def m(this):\n        return self._x\n",
    "from-import-private-name": "from . import _helper\n",
    "from-import-private-name-alias": "from .openscap import _expat as e\n",
    "from-import-private-module": "from ._helper import thing\n",
    "from-import-private-package": "from ansible.module_utils._text import to_text\n",
    "import-private-module": "import ansible.module_utils._text\n",
    "getattr-private-literal": "from . import openscap\ngetattr(openscap, '_expat')\n",
    "getattr-private-on-object": "def f(x):\n    return getattr(x, '_runner', None)\n",
    "setattr-private-on-object": "def f(x):\n    setattr(x, '_runner', print)\n",
    "getattr-in-class-body": "class A:\n    __getattr__ = None\n",
}

PRIVATE_ACCESS_ALLOWED = {
    "self-private-read": "class A:\n    def m(self):\n        return self._x\n",
    "self-private-assign": "class A:\n    def __init__(self):\n        self._x = 1\n",
    "self-private-call": "class A:\n    def m(self):\n        return self._helper()\n",
    "cls-private": "class A:\n    @classmethod\n    def m(cls):\n        return cls._x\n",
    "self-name-mangled": "class A:\n    def m(self):\n        self.__x = 1\n",
    "positional-only-self": "class A:\n    def m(self, /):\n        return self._x\n",
    "nested-function-in-method": (
        "class A:\n    def m(self):\n        def inner():\n            return self._x\n"
        "        return inner\n"
    ),
    "dunder-method-definition": (
        "class A:\n    def __getattr__(self, name):\n        return name\n"
        "    def __setattr__(self, name, value):\n        return None\n"
    ),
    "dunder-reads": "def f(x):\n    return x.__name__, type(x).__qualname__\n",
    "private-module-level-name": "_X = 1\n\n\ndef f():\n    return _X\n",
    "private-method-definition": "class A:\n    def _m(self):\n        return 1\n",
    "assign-attribute-of-local": "def f(x):\n    x.value = 1\n    x.items['a'] = 2\n",
    "setattr-on-local": "def f(x):\n    setattr(x, 'value', 1)\n    getattr(x, 'value')\n",
    "getattr-private-on-self": (
        "class A:\n    def m(self):\n        return getattr(self, '_x'), getattr(self, '_y')\n"
    ),
    "import-and-read-public": "from . import process\nprocess.run\nprocess.CONFIG['a']\n",
    "unbound-subscript": "def f(x):\n    x['a'] = 1\n    x[0].b = 2\n",
}

HARDENING_GROUPS = {
    "reflection": REFLECTION_BYPASSES,
    "internals": INTERNALS_BYPASSES,
    "module-assignment": MODULE_ASSIGNMENT_BYPASSES,
    "private-access": PRIVATE_ACCESS_BYPASSES,
}


@pytest.mark.parametrize("source", REFLECTION_BYPASSES.values(), ids=REFLECTION_BYPASSES.keys())
def test_guard_closes_string_based_reflection(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize("source", INTERNALS_BYPASSES.values(), ids=INTERNALS_BYPASSES.keys())
def test_guard_closes_function_internals(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize(
    "source", MODULE_ASSIGNMENT_BYPASSES.values(), ids=MODULE_ASSIGNMENT_BYPASSES.keys()
)
def test_guard_closes_assignment_to_imported_modules(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize(
    "source", PRIVATE_ACCESS_BYPASSES.values(), ids=PRIVATE_ACCESS_BYPASSES.keys()
)
def test_guard_closes_cross_module_private_access(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize(
    "source", PRIVATE_ACCESS_ALLOWED.values(), ids=PRIVATE_ACCESS_ALLOWED.keys()
)
def test_guard_keeps_own_private_access_and_dunders(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source) == []


@pytest.mark.parametrize("group", HARDENING_GROUPS)
def test_hardening_groups_are_exempt_in_the_process_helper(tmp_path: Path, group: str) -> None:
    name = "plugins/module_utils/compliance/process.py"
    for source in HARDENING_GROUPS[group].values():
        assert process_messages(tmp_path, source, name) == []


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (
            "import typing\ntyping.operator\n",
            "attribute 'operator' is not allowed in plugins",
        ),
        (
            "def __getattr__(n):\n    return n\n",
            "module-level __getattr__ is not allowed in plugins",
        ),
        (
            "from . import process\nprocess.X = 1\n",
            "assigning attribute 'X' of an imported module is not allowed in plugins",
        ),
        (
            "from . import process\nsetattr(process, 'X', 1)\n",
            "setattr on an imported module is not allowed in plugins",
        ),
        (
            "def f(b):\n    b._runner = 1\n",
            "underscore-prefixed attribute '_runner' of another object is not allowed",
        ),
        (
            "from . import _helper\n",
            "import of private name '_helper' is not allowed in plugins",
        ),
    ],
)
def test_hardening_messages(tmp_path: Path, source: str, message: str) -> None:
    assert message in process_messages(tmp_path, source)


def test_hardening_adds_regression_cases_for_every_route() -> None:
    assert {name: len(group) for name, group in HARDENING_GROUPS.items()} == {
        "reflection": 23,
        "internals": 10,
        "module-assignment": 18,
        "private-access": 27,
    }
    assert {"reviewer-operator-attrgetter", "reviewer-dataclasses-builtins-eval"} <= set(
        REFLECTION_BYPASSES
    )


@pytest.mark.parametrize(
    "name",
    [
        "model.py",
        "scanner.py",
        "openscap.py",
        "backends.py",
    ],
)
def test_merged_compliance_modules_have_no_false_positives(name: str) -> None:
    target = rules.REPO_ROOT / "plugins/module_utils/compliance" / name
    assert rules.check_file(target) == []


PROCESS = (
    "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance"
    " import process\n"
)
OPENSCAP = (
    "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance"
    " import openscap\n"
)
SCANNER = (
    "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance"
    " import scanner\n"
)

DUNDER_BYPASSES = {
    "getattribute-chain": (
        PROCESS + "process.__getattribute__('subprocess').__getattribute__('Popen')(['sh'])\n"
    ),
    "setattr-then-run": (
        PROCESS + "process.__setattr__('ALLOWED_EXECUTABLES', {})\nprocess.run(spec)\n"
    ),
    "builtin-self-getattribute": "len.__self__.__getattribute__('__imp' + 'ort__')('subprocess')\n",
    "dataclasses-inspect-frame": (
        "import dataclasses\n"
        "dataclasses.inspect.currentframe().f_builtins['__import__']('sub' + 'process')\n"
    ),
    "object-getattribute-private": OPENSCAP + "object.__getattribute__(openscap, '_expat')\n",
    "types-functiontype-codetype": (
        "import types\n"
        "types.FunctionType(types.CodeType(0, 0, 0, 0, 0, 0, b'', (), (), (), '', '', 0, b''), {})"
        "\n"
    ),
    "module-getattribute": OPENSCAP + "openscap.__getattribute__('_expat')\n",
    "module-delattr": PROCESS + "process.__delattr__('ALLOWED_EXECUTABLES')\n",
    "object-setattr-non-module": (
        "def f(backend):\n    object.__setattr__(backend, '_runner', print)\n"
    ),
    "dunder-class": "def f(x):\n    return x.__class__\n",
    "dunder-class-name-in-method": "class A:\n    def m(self):\n        return __class__\n",
    "dunder-dict": "def f(x):\n    return x.__dict__\n",
    "dunder-self-attribute": "class A:\n    def m(self):\n        return self.__class__\n",
    "dunder-call": "def f(x):\n    return x.__call__()\n",
    "dunder-init-subclass": "def f(x):\n    return x.__init_subclass__\n",
    "dunder-import-name": "from x import __getattribute__\n",
    "dunder-getattr-literal": "def f(x):\n    return getattr(x, '__class__')\n",
    "dunder-getattr-literal-on-self": (
        "class A:\n    def m(self):\n        return getattr(self, '__dict__')\n"
    ),
    "dunder-setattr-literal": "def f(x):\n    setattr(x, '__name__', 'y')\n",
    "dunder-name-write": "def f(x):\n    x.__name__ = 'y'\n",
    "dunder-loader-name": "__loader__\n",
    "dunder-spec-name": "__spec__\n",
    "setattr-in-other-method": (
        "class A:\n    def m(self):\n        object.__setattr__(self, 'x', 1)\n"
    ),
    "setattr-variable-field": (
        "class A:\n    def __post_init__(self):\n        object.__setattr__(self, name, 1)\n"
    ),
    "setattr-non-self-target": (
        "class A:\n    def __post_init__(self):\n        object.__setattr__(other, 'x', 1)\n"
    ),
    "setattr-cls-target": (
        "class A:\n    def __post_init__(cls):\n        object.__setattr__(cls, 'x', 1)\n"
    ),
    "setattr-dunder-field": (
        "class A:\n    def __post_init__(self):\n"
        "        object.__setattr__(self, '__class__', int)\n"
    ),
    "setattr-banned-field": (
        "class A:\n    def __post_init__(self):\n        object.__setattr__(self, 'eval', 1)\n"
    ),
    "setattr-non-literal-constant": (
        "class A:\n    def __post_init__(self):\n        object.__setattr__(self, 1, 1)\n"
    ),
    "setattr-keyword": (
        "class A:\n    def __post_init__(self):\n        object.__setattr__(self, 'x', value=1)\n"
    ),
    "setattr-extra-argument": (
        "class A:\n    def __post_init__(self):\n        object.__setattr__(self, 'x', 1, 2)\n"
    ),
    "setattr-not-object": (
        "class A:\n    def __post_init__(self):\n        other.__setattr__(self, 'x', 1)\n"
    ),
    "setattr-not-a-call": (
        "class A:\n    def __post_init__(self):\n        f = object.__setattr__\n"
    ),
    "setattr-not-the-callee": (
        "class A:\n    def __post_init__(self):\n        f(object.__setattr__)\n"
    ),
    "setattr-in-nested-function": (
        "class A:\n    def __post_init__(self):\n"
        "        def inner():\n            object.__setattr__(self, 'x', 1)\n"
    ),
    "setattr-after-rebinding-self": (
        "class A:\n    def __post_init__(self):\n        self = other\n"
        "        object.__setattr__(self, 'x', 1)\n"
    ),
    "setattr-in-module-function": (
        "def __post_init__(self):\n    object.__setattr__(self, 'x', 1)\n"
    ),
}

FRAME_BYPASSES = {
    f"frame-{name}": f"def f(x):\n    return x.{name}\n"
    for name in (
        "currentframe",
        "f_builtins",
        "f_globals",
        "f_locals",
        "f_back",
        "f_code",
        "gi_frame",
        "gi_code",
        "cr_frame",
        "cr_code",
        "ag_frame",
        "ag_code",
        "tb_frame",
        "tb_next",
        "co_code",
        "co_consts",
        "co_names",
        "CodeType",
        "FunctionType",
        "LambdaType",
        "MethodType",
    )
}

TYPES_BYPASSES = {
    "import-types": "import types\n",
    "import-types-as": "import types as t\n",
    "from-types-functiontype": "from types import FunctionType\n",
    "from-types-codetype": "from types import CodeType\n",
    "from-types-simplenamespace": "from types import SimpleNamespace\n",
    "from-types-two-names": "from types import MappingProxyType, ModuleType\n",
}

MODULE_ATTRIBUTE_BYPASSES = {
    "dataclasses-inspect": "import dataclasses\ndataclasses.inspect\n",
    "enum-sys": "import enum\nenum.sys\n",
    "pathlib-posixpath": "import pathlib\npathlib.posixpath\n",
    "json-decoder-codecs": "import json\njson.decoder.codecs\n",
    "attribute-types": "import dataclasses\ndataclasses.types\n",
    "pathlib-io": "import pathlib\npathlib.io\n",
    "chain-call": "import dataclasses\ndataclasses.inspect.getmodule(x)\n",
    "dotted-import-root": "import os.path\nos.path.copy\n",
    "collection-scanner-process": SCANNER + "scanner.process\n",
    "collection-from-import": OPENSCAP + "openscap.scanner\n",
    "attribute-subprocess": "x.subprocess\n",
    "attribute-importlib": "x.importlib.import_module\n",
    "enum-bltns": "import enum\nenum.bltns\n",
    "typing-stdlib-re": "import typing\ntyping.stdlib_re\n",
    "bare-bltns": "x.bltns\n",
    "bare-bltin": "x._bltin\n",
    "bare-stdlib-re": "x.stdlib_re\n",
    "bare-os-alias": "x.y._os\n",
    "bare-sys-alias": "x._sys\n",
    "getattr-module-literal": "import dataclasses\ngetattr(dataclasses.x, 'inspect')\n",
    "getattr-bltns-literal": "def f(x):\n    return getattr(x, 'bltns')\n",
    "from-import-stdlib-module": "from dataclasses import inspect\n",
    "from-import-stdlib-module-alias": "from typing import io as i\n",
}

ORDINARY_ATTRIBUTES_ALLOWED = {
    "dict-copy": "x = {}.copy()\n",
    "list-copy": "x = [].copy()\n",
    "object-time": "def f(obj):\n    return obj.time\n",
    "datetime-time": "from datetime import datetime\nx = datetime.now().time()\n",
    "other-scanner": "def f(other):\n    return other.scanner\n",
    "attribute-code": "def f(error):\n    return error.code\n",
    "attribute-inspect": "def f(x):\n    return x.inspect\n",
    "attribute-process": "def f(x):\n    return x.process\n",
    "attribute-openscap": "def f(x):\n    return x.openscap\n",
    "attribute-array": "def f(x):\n    return x.array('k')\n",
    "getattr-ordinary-literal": "def f(x):\n    return getattr(x, 'inspect', None)\n",
    "getattr-module-name-on-plain-object": "def f(x):\n    return getattr(x.y, 'copy')\n",
    "module-attribute-named-like-a-class": "import json\njson.decoder.JSONDecoder\njson.dumps\n",
    "field-named-like-a-module": (
        "class A:\n    def __post_init__(self):\n        object.__setattr__(self, 'inspect', 1)\n"
    ),
    "super-copy": "class C(dict):\n    def m(self):\n        return super().copy()\n",
}

SUPER_ALLOWED = {
    "init": "class C(dict):\n    def __init__(self):\n        super().__init__()\n",
    "init-with-arguments": (
        "class C(Exception):\n    def __init__(self, message):\n        super().__init__(message)\n"
    ),
    "post-init": "class C:\n    def __post_init__(self):\n        super().__post_init__()\n",
    "explicit-super": (
        "class C(dict):\n    def __init__(self):\n        super(C, self).__init__()\n"
    ),
    "classmethod-init": (
        "class C:\n    @classmethod\n    def make(cls):\n        return super(C, cls).__init__()\n"
    ),
}

SUPER_DENIED = {
    "least-privilege-new": ("class C:\n    def m(self):\n        return super().__new__(cls)\n"),
    "least-privilege-call": ("class C:\n    def m(self):\n        return super().__call__()\n"),
    "least-privilege-init-subclass": (
        "class C:\n    def m(self):\n        return super().__init_subclass__()\n"
    ),
    "least-privilege-reduce": ("class C:\n    def m(self):\n        return super().__reduce__()\n"),
    "least-privilege-reduce-ex": (
        "class C:\n    def m(self):\n        return super().__reduce_ex__(2)\n"
    ),
    "least-privilege-getattr": (
        "class C:\n    def m(self):\n        return super().__getattr__('x')\n"
    ),
    "least-privilege-get": (
        "class C:\n    def m(self):\n        return super().__get__(None, None)\n"
    ),
    "least-privilege-set-name": (
        "class C:\n    def m(self):\n        return super().__set_name__(None, 'x')\n"
    ),
    "least-privilege-repr": ("class C:\n    def m(self):\n        return super().__repr__()\n"),
    "least-privilege-format": (
        "class C:\n    def m(self):\n        return super().__format__('')\n"
    ),
    "least-privilege-setitem": (
        "class C:\n    def m(self):\n        return super().__setitem__(1, 2)\n"
    ),
    "least-privilege-enter": ("class C:\n    def m(self):\n        return super().__enter__()\n"),
    "least-privilege-exit": (
        "class C:\n    def m(self):\n        return super().__exit__(None, None, None)\n"
    ),
    "least-privilege-eq": ("class C:\n    def m(self):\n        return super().__eq__(1)\n"),
    "dict-attribute": "class C:\n    def m(self):\n        return super().__dict__\n",
    "getattribute-call": (
        "class C:\n    def m(self):\n        return super().__getattribute__('x')\n"
    ),
    "setattr-call": "class C:\n    def m(self):\n        super().__setattr__('x', 1)\n",
    "delattr-call": "class C:\n    def m(self):\n        super().__delattr__('x')\n",
    "class-attribute": "class C:\n    def m(self):\n        return super().__class__\n",
    "not-a-call": "class C:\n    def m(self):\n        return super().__init__\n",
    "passed-as-argument": "class C:\n    def m(self):\n        f(super().__init__)\n",
    "dunder-store": "class C:\n    def m(self):\n        super().__init__ = 1\n",
    "other-receiver": "class C:\n    def m(self):\n        other().__init__()\n",
    "other-function": "class C:\n    def m(self):\n        sup().__init__()\n",
    "super-keyword": "class C:\n    def m(self):\n        super(x=1).__init__()\n",
    "super-one-argument": "class C:\n    def m(self):\n        super(C).__init__()\n",
    "super-three-arguments": ("class C:\n    def m(self):\n        super(C, self, 1).__init__()\n"),
    "super-foreign-instance": (
        "class C:\n    def m(self, other):\n        super(C, other).__init__()\n"
    ),
    "super-expression-class": ("class C:\n    def m(self):\n        super(f(), self).__init__()\n"),
    "super-rebound-self": (
        "class C:\n    def m(self, other):\n        self = other\n"
        "        super(C, self).__init__()\n"
    ),
    "super-chained-receiver": (
        "class C:\n    def m(self):\n        super().__init__().__getattribute__('x')\n"
    ),
    "private-attribute-of-super": "class C:\n    def m(self):\n        return super()._x\n",
}

ALIAS_BYPASSES = {
    "assign-alias": PROCESS + "x = process\nx.A = 1\n",
    "default-value": PROCESS + "def f(m=process):\n    m.A = 1\n",
    "list-subscript": PROCESS + "[process][0].A = 1\n",
    "walrus": PROCESS + "(p := process).A = 1\n",
    "tuple-unpack": PROCESS + "a, b = process, 1\n",
    "starred-unpack": PROCESS + "*a, = (process,)\n",
    "class-attribute": PROCESS + "class K:\n    m = process\n",
    "closure": PROCESS
    + "def outer():\n    def inner():\n        return process\n    return inner\n",
    "for-target": PROCESS + "for m in (process,):\n    m.A = 1\n",
    "lambda-default": PROCESS + "f = lambda m=process: m\n",
    "dict-value": PROCESS + "{'m': process}['m'].A = 1\n",
    "comprehension": PROCESS + "[m for m in [process]]\n",
    "return": PROCESS + "def get():\n    return process\n",
    "decorator-argument": PROCESS + "@deco(process)\ndef f():\n    pass\n",
    "attribute-of-collection-module": SCANNER + "m = scanner.process\n",
    "call-argument": PROCESS + "f(process)\n",
    "keyword-argument": PROCESS + "f(m=process)\n",
    "yield": PROCESS + "def g():\n    yield process\n",
    "comparison": PROCESS + "process is None\n",
    "set-element": PROCESS + "{process}\n",
    "starred-argument": PROCESS + "f(*process)\n",
    "augmented-store": PROCESS + "process += 1\n",
    "rebinding": PROCESS + "process = 1\n",
    "delete": PROCESS + "del process\n",
    "global-declaration": PROCESS + "def f():\n    global process\n    process = 1\n",
    "nonlocal-declaration": (
        PROCESS + "def f():\n    def g():\n        nonlocal process\n    return g\n"
    ),
    "with-target": PROCESS + "with open('x') as process:\n    pass\n",
    "stdlib-module-alias": "import json\nx = json\n",
    "import-as-alias": "import json as j\nk = j\n",
    "stdlib-from-module": "from os import path\nx = path\n",
    "collections-abc": "from collections import abc\nx = abc\n",
    "dotted-import-root": "import os.path\nx = os\n",
    "ansible-module-from-import": "from ansible.module_utils import basic\nx = basic\n",
    "conditional-expression": PROCESS + "x = process if flag else None\n",
    "self-with-module": (
        PROCESS + "class C:\n    def f(self):\n        self.A = 1\n"
        "        return self._expat\nC.f(process)\n"
    ),
    "self-rebound-to-module": (
        OPENSCAP
        + "class C:\n    def f(self):\n        self = openscap\n        return self._expat\n"
    ),
}

SELF_BYPASSES = {
    "self-nonlocal": (
        "class C:\n    def f(self):\n        def g():\n            nonlocal self\n"
        "            self = 1\n        return self._x\n"
    ),
    "self-global": (
        "class C:\n    def f(self):\n        def g():\n            global self\n"
        "        return self._x\n"
    ),
    "self-assigned": (
        "class C:\n    def f(self, other):\n        self = other\n        return self._x\n"
    ),
    "self-augmented": "class C:\n    def f(self):\n        self += 1\n        return self._x\n",
    "self-deleted": "class C:\n    def f(self):\n        del self\n        return self._x\n",
    "self-walrus": "class C:\n    def f(self, o):\n        (self := o)\n        return self._x\n",
    "self-for-target": (
        "class C:\n    def f(self, items):\n        for self in items:\n            pass\n"
        "        return self._x\n"
    ),
    "self-with-target": (
        "class C:\n    def f(self, o):\n        with o as self:\n            pass\n"
        "        return self._x\n"
    ),
    "self-except-target": (
        "class C:\n    def f(self):\n        try:\n            pass\n"
        "        except ValueError as self:\n            pass\n        return self._x\n"
    ),
    "self-import-target": (
        "class C:\n    def f(self):\n        import json as self\n        return self._x\n"
    ),
    "self-import-from-target": (
        "class C:\n    def f(self):\n        from json import loads as self\n"
        "        return self._x\n"
    ),
    "self-import-plain": (
        "class C:\n    def f(self):\n        import self\n        return self._x\n"
    ),
    "self-nested-def-name": (
        "class C:\n    def f(self):\n        def self():\n            pass\n"
        "        return self._x\n"
    ),
    "self-nested-class-name": (
        "class C:\n    def f(self):\n        class self:\n            pass\n"
        "        return self._x\n"
    ),
    "self-nested-parameter": (
        "class C:\n    def f(self):\n        def g(self):\n            pass\n"
        "        return self._x\n"
    ),
    "self-lambda-parameter": (
        "class C:\n    def f(self):\n        g = lambda self: self\n        return self._x\n"
    ),
    "self-keyword-only": (
        "class C:\n    def f(self):\n        def g(*, self):\n            pass\n"
        "        return self._x\n"
    ),
    "self-vararg-shadow": (
        "class C:\n    def f(self):\n        def g(*self):\n            pass\n"
        "        return self._x\n"
    ),
    "self-match-capture": (
        "class C:\n    def f(self, v):\n        match v:\n            case self:\n"
        "                pass\n"
        "        return self._x\n"
    ),
    "self-match-as": (
        "class C:\n    def f(self, v):\n        match v:\n            case [1] as self:\n"
        "                pass\n        return self._x\n"
    ),
    "self-match-star": (
        "class C:\n    def f(self, v):\n        match v:\n            case [*self]:\n"
        "                pass\n"
        "        return self._x\n"
    ),
    "self-match-mapping-rest": (
        "class C:\n    def f(self, v):\n        match v:\n            case {'a': 1, **self}:\n"
        "                pass\n        return self._x\n"
    ),
    "self-staticmethod": (
        "class C:\n    @staticmethod\n    def f(self):\n        return self._x\n"
    ),
}

R_A_ALLOWED = {
    "global-of-a-plain-name": "def f():\n    global counter\n    counter = 1\n",
    "attribute-base": PROCESS + "process.run\nprocess.CONFIG['a']\nprocess.f(1)\n",
    "nested-attribute-base": PROCESS + "process.CONFIG.value\n",
    "stdlib-module-attribute": "import json\njson.dumps({})\n",
    "dotted-import-attribute": "import os.path\nos.path.join('a')\n",
    "from-import-class": "from datetime import datetime\nx = datetime\n",
    "from-import-function": "from dataclasses import replace\nx = replace\n",
    "ansible-class-import": (
        "from ansible.module_utils.basic import AnsibleModule\nx = AnsibleModule\n"
    ),
    "ansible-function-import": (
        "from ansible.module_utils.common.text.converters import to_text\nx = to_text\n"
    ),
    "types-mapping-proxy": "from types import MappingProxyType\nx = MappingProxyType({})\n",
    "post-init-store": (
        "class A:\n    def __post_init__(self):\n        object.__setattr__(self, 'x', 1)\n"
        "        object.__setattr__(self, '_y', 2)\n"
    ),
    "post-init-store-async-free-nested-lambda": (
        "class A:\n    def __post_init__(self):\n"
        "        object.__setattr__(self, 'x', sorted([1], key=lambda i: i))\n"
    ),
    "dunder-reads": "def f(x):\n    return x.__name__, x.__qualname__, x.__doc__, x.__module__\n",
    "getattr-dunder-read": "def f(x):\n    return getattr(x, '__name__', None)\n",
    "relative-lookalike-module": "from .helper import thing\nthing()\n",
    "self-method-and-cls": (
        "class C:\n    def f(self):\n        return self._x\n"
        "    @classmethod\n    def g(cls):\n        return cls._y\n"
    ),
    "async-method-self": "class C:\n    async def f(self):\n        return self._x\n",
    "local-named-like-method-name": (
        "class C:\n    def f(self):\n        return self._x\n    def g(self):\n        self = 1\n"
    ),
}

STUB_MODULE_ROOT = "plugins/module_utils/compliance"

HARDENING_GROUPS_2 = {
    "dunder": DUNDER_BYPASSES,
    "super-denied": SUPER_DENIED,
    "frame": FRAME_BYPASSES,
    "types": TYPES_BYPASSES,
    "module-attributes": MODULE_ATTRIBUTE_BYPASSES,
    "alias": ALIAS_BYPASSES,
    "self-rebinding": SELF_BYPASSES,
}


@pytest.mark.parametrize("source", DUNDER_BYPASSES.values(), ids=DUNDER_BYPASSES.keys())
def test_guard_denies_dunder_attributes_by_default(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize("source", FRAME_BYPASSES.values(), ids=FRAME_BYPASSES.keys())
def test_guard_bans_frame_and_code_attributes(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize("source", TYPES_BYPASSES.values(), ids=TYPES_BYPASSES.keys())
def test_guard_allows_only_mapping_proxy_type_from_types(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize(
    "source", MODULE_ATTRIBUTE_BYPASSES.values(), ids=MODULE_ATTRIBUTE_BYPASSES.keys()
)
def test_guard_bans_reaching_modules_through_attributes(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize("source", ALIAS_BYPASSES.values(), ids=ALIAS_BYPASSES.keys())
def test_guard_bans_every_use_of_a_module_name_but_attribute_access(
    tmp_path: Path, source: str
) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize("source", SELF_BYPASSES.values(), ids=SELF_BYPASSES.keys())
def test_guard_exempts_only_an_intact_self(tmp_path: Path, source: str) -> None:
    assert any("underscore-prefixed" in message for message in process_messages(tmp_path, source))


@pytest.mark.parametrize("source", R_A_ALLOWED.values(), ids=R_A_ALLOWED.keys())
def test_guard_keeps_attribute_access_on_modules_and_the_post_init_store(
    tmp_path: Path, source: str
) -> None:
    assert process_messages(tmp_path, source) == []


@pytest.mark.parametrize("group", HARDENING_GROUPS_2)
def test_second_round_groups_are_exempt_in_the_process_helper(tmp_path: Path, group: str) -> None:
    name = "plugins/module_utils/compliance/process.py"
    for source in HARDENING_GROUPS_2[group].values():
        assert process_messages(tmp_path, source, name) == []


def test_relative_module_imports_resolve_against_sibling_files(tmp_path: Path) -> None:
    base = "plugins/module_utils/compliance"
    plugin_file(tmp_path, "", f"{base}/process.py")
    plugin_file(tmp_path, "", f"{base}/pkg/__init__.py")
    plugin_file(tmp_path, "", f"{base}/pkg/inner.py")
    plugin_file(tmp_path, "", "plugins/module_utils/up.py")
    other = f"{base}/user.py"
    assert process_messages(tmp_path, "from . import process\nx = process\n", other)
    assert process_messages(tmp_path, "from . import pkg\nx = pkg\n", other)
    assert process_messages(tmp_path, "from .pkg import inner\nx = inner\n", other)
    assert process_messages(tmp_path, "from .. import up\nx = up\n", other)
    assert process_messages(tmp_path, "from . import missing\nx = missing\n", other) == []
    assert process_messages(tmp_path, "from . import process\nprocess.run\n", other) == []


@pytest.mark.parametrize(
    "source",
    ORDINARY_ATTRIBUTES_ALLOWED.values(),
    ids=ORDINARY_ATTRIBUTES_ALLOWED.keys(),
)
def test_ordinary_attributes_named_like_modules_are_allowed(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source) == []


@pytest.mark.parametrize("source", SUPER_ALLOWED.values(), ids=SUPER_ALLOWED.keys())
def test_super_dunder_method_calls_are_allowed(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source) == []


@pytest.mark.parametrize("source", SUPER_DENIED.values(), ids=SUPER_DENIED.keys())
def test_other_super_dunder_use_is_denied(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


def test_second_round_messages(tmp_path: Path) -> None:
    messages = process_messages(tmp_path, PROCESS + "x = process\n")
    assert "module name 'process' may only be used as process.attribute in plugins" in messages
    assert "dunder attribute '__getattribute__' is not allowed in plugins" in process_messages(
        tmp_path, "x.__getattribute__('y')\n"
    )
    assert "attribute 'currentframe' is not allowed in plugins" in process_messages(
        tmp_path, "x.currentframe()\n"
    )
    assert "attribute 'inspect' is not allowed in plugins" in process_messages(
        tmp_path, "import dataclasses\ndataclasses.inspect\n"
    )
    assert (
        "module name 'process' may not be declared global or nonlocal in plugins"
        in process_messages(tmp_path, PROCESS + "def f():\n    global process\n")
    )
    assert "import of 'types.FunctionType' is not allowed in plugins outside " + str(
        rules.PROCESS_HELPER
    ) in process_messages(tmp_path, "from types import FunctionType\n")


def test_second_round_counts() -> None:
    assert {name: len(group) for name, group in HARDENING_GROUPS_2.items()} == {
        "dunder": 37,
        "super-denied": 32,
        "frame": 21,
        "types": 6,
        "module-attributes": 23,
        "alias": 36,
        "self-rebinding": 23,
    }


def test_collection_module_names_are_derived_from_the_plugin_tree() -> None:
    assert {"process", "openscap", "scanner", "model", "backends"} <= (
        rules.COLLECTION_MODULE_ATTRIBUTES
    )
    assert "inspect" in rules.STDLIB_MODULE_ATTRIBUTES
    assert not {"re", "json", "typing", "dataclasses", "abc", "path"} & (
        rules.BANNED_MODULE_ATTRIBUTES
    )
    assert "types" in rules.STDLIB_MODULE_ATTRIBUTES


SUPER_REBINDING_BYPASSES = {
    "assignment": "super = 1\n",
    "augmented": "super += 1\n",
    "annotated": "super: int = 1\n",
    "walrus": "(super := 1)\n",
    "for-target": "for super in []:\n    pass\n",
    "with-target": "with open('x') as super:\n    pass\n",
    "except-target": "try:\n    pass\nexcept ValueError as super:\n    pass\n",
    "import-as": "import json as super\n",
    "from-import-as": "from json import loads as super\n",
    "from-import": "from helper import super\n",
    "function-definition": "def super():\n    pass\n",
    "async-function-definition": "async def super():\n    pass\n",
    "class-definition": "class super:\n    pass\n",
    "parameter": "def f(super):\n    pass\n",
    "keyword-only-parameter": "def f(*, super):\n    pass\n",
    "lambda-parameter": "f = lambda super: super\n",
    "global": "def f():\n    global super\n",
    "nonlocal": "def f():\n    super = 1\n    def g():\n        nonlocal super\n    return g\n",
    "delete": "del super\n",
    "match-capture": "match 1:\n    case super:\n        pass\n",
    "match-as": "match 1:\n    case 1 as super:\n        pass\n",
    "match-star": "match [1]:\n    case [*super]:\n        pass\n",
    "match-mapping-rest": "match {}:\n    case {**super}:\n        pass\n",
    "tuple-target": "super, other = 1, 2\n",
    "rebinding-then-call": (
        "class C:\n    def m(self, other):\n        super = other\n        super().__init__()\n"
    ),
    "object-assignment": "object = 1\n",
    "object-parameter": "def f(object):\n    pass\n",
    "object-import-as": "import json as object\n",
}

SUBMODULE_BYPASSES = {
    "os-path-assignment": "import os.path\nx = os.path\nx.join('a')\n",
    "os-path-store": "import os.path\nx = os.path\nx.join = print\n",
    "json-decoder-argument": "import json\nf(json.decoder)\n",
    "collections-abc-return": "import collections\ndef f():\n    return collections.abc\n",
    "expat-assignment": (
        "import xml.parsers.expat\n_expat = xml.parsers.expat\n_expat.ParserCreate()\n"
    ),
    "expat-package-assignment": "import xml.parsers.expat\nx = xml.parsers\n",
    "container": "import os.path\nx = [os.path]\n",
    "keyword-argument": "import json\nf(m=json.decoder)\n",
    "comparison": "import os.path\nos.path is None\n",
    "default-value": "import json\ndef f(m=json.decoder):\n    return m\n",
    "from-package-import-assignment": ("from xml.parsers import expat\nx = expat\n"),
}

SUBMODULE_ALLOWED = {
    "os-path-call": "import os.path\nos.path.join('a', 'b')\n",
    "json-decoder-attribute": "import json\njson.decoder.JSONDecodeError\n",
    "from-os-path": "from os import path\npath.join('a')\n",
    "dotted-expat-call": "import xml.parsers.expat\nxml.parsers.expat.ParserCreate()\n",
    "function-named-like-a-submodule": "import os.path\nx = os.path.join\n",
}

EXPAT_FILE = "plugins/module_utils/compliance/xmlsafe.py"


@pytest.mark.parametrize("name", SUPER_REBINDING_BYPASSES)
def test_protected_builtin_names_cannot_be_rebound(tmp_path: Path, name: str) -> None:
    messages = process_messages(tmp_path, SUPER_REBINDING_BYPASSES[name])
    assert any("may not be rebound" in message for message in messages)


@pytest.mark.parametrize("source", SUBMODULE_BYPASSES.values(), ids=SUBMODULE_BYPASSES.keys())
def test_submodules_reached_by_attribute_are_not_values(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)
    assert process_messages(tmp_path, source, EXPAT_FILE)


@pytest.mark.parametrize("source", SUBMODULE_ALLOWED.values(), ids=SUBMODULE_ALLOWED.keys())
def test_submodule_attribute_access_stays_allowed(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source, EXPAT_FILE) == []


def test_expat_package_import_form_is_limited_to_the_parser_file(tmp_path: Path) -> None:
    source = "from xml.parsers import expat\nexpat.ParserCreate()\n"
    assert process_messages(tmp_path, source, EXPAT_FILE) == []
    assert process_messages(tmp_path, source)
    assert process_messages(tmp_path, "from xml.parsers import expat, sax\n", EXPAT_FILE)
    assert process_messages(tmp_path, "from xml.parsers import sax\n", EXPAT_FILE)


def test_submodule_attributes_are_computed_from_the_allow_list() -> None:
    assert {"path", "abc", "expat", "parsers", "decoder", "sys"} <= rules.SUBMODULE_ATTRIBUTES
    assert "datetime" not in rules.SUBMODULE_ATTRIBUTES
    assert {"super", "object"} == rules.PROTECTED_NAMES


FROM_IMPORTED_SUBMODULES_DENIED = {
    "json-decoder-assignment": "from json import decoder\nx = decoder\n",
    "json-encoder-argument": "from json import encoder\nf(encoder)\n",
    "typing-functools-assignment": "from typing import functools\nx = functools\n",
    "aliased": "from json import decoder as d\nx = d\n",
    "aliased-return": "from json import decoder as d\ndef f():\n    return d\n",
    "module-named-attribute": "from json import decoder\ndecoder.codecs\n",
    "attribute-store": "from json import decoder\ndecoder.JSONDecoder = print\n",
}

FROM_IMPORTED_SUBMODULES_ALLOWED = {
    "attribute-access": "from json import decoder\ndecoder.JSONDecoder\n",
    "aliased-attribute-access": "from json import decoder as d\nd.JSONDecodeError\n",
}

VERSION_NAME_BYPASSES = {
    "forward-ref-evaluate": "import typing\ntyping.ForwardRef('x').evaluate()\n",
    "evaluate-attribute": "x.evaluate\n",
    "call-evaluate-function": "import annotationlib\nannotationlib.call_evaluate_function(f)\n",
    "call-evaluate-function-attribute": "x.call_evaluate_function(f)\n",
    "annotationlib-attribute": "import dataclasses\ndataclasses.annotationlib\n",
    "annotationlib-bare-attribute": "x.annotationlib\n",
    "annotationlib-import": "import annotationlib\n",
    "annotationlib-from-import": "from dataclasses import annotationlib\n",
    "evaluate-from-import": "from typing import evaluate\n",
    "evaluate-getattr": "def f(x):\n    return getattr(x, 'evaluate')\n",
}


@pytest.mark.parametrize(
    "source",
    FROM_IMPORTED_SUBMODULES_DENIED.values(),
    ids=FROM_IMPORTED_SUBMODULES_DENIED.keys(),
)
def test_from_imported_submodules_are_tracked_module_values(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    FROM_IMPORTED_SUBMODULES_ALLOWED.values(),
    ids=FROM_IMPORTED_SUBMODULES_ALLOWED.keys(),
)
def test_from_imported_submodules_stay_usable_as_attribute_bases(
    tmp_path: Path, source: str
) -> None:
    assert process_messages(tmp_path, source) == []


@pytest.mark.parametrize("source", VERSION_NAME_BYPASSES.values(), ids=VERSION_NAME_BYPASSES.keys())
def test_version_specific_evaluation_names_are_banned(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source)


def test_checked_in_name_sets_cover_the_running_interpreter() -> None:
    modules = sorted(rules.ALLOWED_IMPORTS.union(*rules.EXTRA_IMPORTS.values()))
    names = set(getattr(sys, "stdlib_module_names", ()))
    attributes = {
        attribute
        for name in modules
        for attribute, value in vars(importlib.import_module(name)).items()
        if isinstance(value, types.ModuleType)
    }
    assert names <= rules.STDLIB_MODULE_NAMES
    assert attributes <= rules.KNOWN_SUBMODULE_ATTRIBUTES
    assert {"annotationlib", "sre_compile", "errno"} <= rules.STDLIB_MODULE_NAMES
    assert {"annotationlib", "builtins", "bltns"} <= rules.KNOWN_SUBMODULE_ATTRIBUTES
    assert {"path", "expat", "parsers"} <= rules.SUBMODULE_ATTRIBUTES


FILE_IO_PARENT = (
    "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import"
    " ledger\n"
)
FILE_IO_PACKAGE = (
    "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils import compliance\n"
)
FILE_IO_REACH = {
    "through-the-ledger-module": FILE_IO_PARENT + "ledger.fileio.open_directory(path)\n",
    "getattr-on-the-ledger-module": FILE_IO_PARENT + "getattr(ledger, 'fileio')\n",
    "through-the-parent-package": FILE_IO_PACKAGE + "compliance.fileio\n",
    "plain-attribute": "def f(x):\n    return x.fileio\n",
    "plain-getattr-literal": "def f(x):\n    return getattr(x, 'fileio')\n",
    "attribute-store": "def f(x):\n    x.fileio = 1\n",
}
LEDGER_FILE = "plugins/module_utils/compliance/ledger.py"


@pytest.mark.parametrize("source", FILE_IO_REACH.values(), ids=FILE_IO_REACH.keys())
def test_fileio_is_not_reachable_by_attribute_outside_the_ledger(
    tmp_path: Path, source: str
) -> None:
    messages = process_messages(tmp_path, source)
    assert any("'fileio'" in message and "ledger.py" in message for message in messages)


def test_the_ledger_may_name_fileio_as_an_attribute(tmp_path: Path) -> None:
    source = "def f(x):\n    getattr(x, 'fileio')\n    return x.fileio\n"
    assert process_messages(tmp_path, source, LEDGER_FILE) == []
    assert process_messages(tmp_path, source, "plugins/module_utils/compliance/fileio.py")


XMLSAFE_IMPORT = (
    "from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import"
    " xmlsafe\n"
)
XMLSAFE_PACKAGE = "ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance"
EXPAT_REACH = {
    "attribute-call": ("expat", XMLSAFE_IMPORT + "xmlsafe.expat.ParserCreate()\n"),
    "getattr-on-the-module": ("expat", XMLSAFE_IMPORT + 'getattr(xmlsafe, "expat")\n'),
    "getattr-then-call": (
        "expat",
        XMLSAFE_IMPORT + 'getattr(xmlsafe, "expat").ParserCreate()\n',
    ),
    "assignment": ("expat", XMLSAFE_IMPORT + "x = xmlsafe.expat\n"),
    "parsers-chain-parsers": ("parsers", XMLSAFE_IMPORT + "xmlsafe.parsers.expat\n"),
    "parsers-chain-expat": ("expat", XMLSAFE_IMPORT + "xmlsafe.parsers.expat\n"),
    "plain-attribute": ("expat", "def f(x):\n    return x.expat.ParserCreate()\n"),
    "plain-parsers-attribute": ("parsers", "def f(x):\n    return x.parsers\n"),
    "getattr-on-a-value": ("expat", "def f(x):\n    return getattr(x, 'expat')\n"),
    "getattr-parsers": ("parsers", "def f(x):\n    return getattr(x, 'parsers')\n"),
    "getattr-default": ("expat", "def f(x):\n    return getattr(x, 'expat', None)\n"),
    "setattr": ("expat", "def f(x):\n    setattr(x, 'expat', None)\n"),
    "attribute-store": ("expat", "def f(x):\n    x.expat = None\n"),
    "match-class-keyword": (
        "expat",
        "def f(x):\n    match x:\n        case object(expat=e):\n            return e\n",
    ),
    "relative-from-import": ("expat", "from .xmlsafe import expat\nexpat.ParserCreate()\n"),
    "relative-from-import-alias": ("expat", "from .xmlsafe import expat as e\n"),
    "absolute-from-import": ("expat", "from " + XMLSAFE_PACKAGE + ".xmlsafe import expat\n"),
    "from-import-path": ("expat", "from .xmlsafe.expat import ParserCreate\n"),
    "from-import-parsers-path": ("parsers", "from " + XMLSAFE_PACKAGE + ".parsers import x\n"),
    "plain-import-path": ("expat", "import " + XMLSAFE_PACKAGE + ".xmlsafe.expat as e\n"),
}
EXPAT_REACH_FILES = [
    "plugins/module_utils/compliance/openscap.py",
    "plugins/module_utils/compliance/catalog.py",
    "plugins/module_utils/compliance/model.py",
    "plugins/module_utils/compliance/fileio.py",
    "plugins/module_utils/compliance/ledger.py",
    "plugins/module_utils/compliance/xmlsafe_other.py",
    "plugins/module_utils/other/xmlsafe.py",
    "plugins/modules/benchmark_info.py",
    "plugins/modules/profile_info.py",
    "plugins/modules/control_state.py",
    "plugins/modules/xmlsafe.py",
    "plugins/action/other.py",
]


@pytest.mark.parametrize("name", EXPAT_REACH_FILES)
@pytest.mark.parametrize("case", EXPAT_REACH.values(), ids=EXPAT_REACH.keys())
def test_raw_expat_is_not_reachable_outside_the_shared_parser(
    tmp_path: Path, name: str, case: tuple[str, str]
) -> None:
    attribute, source = case
    expected = f"{attribute!r} is restricted to {EXPAT_FILE}"
    messages = process_messages(tmp_path, source, name)
    assert any(message.endswith(expected) for message in messages), messages


EXPAT_OWNER_ALLOWED = {
    "package-import-call": "from xml.parsers import expat\nexpat.ParserCreate()\n",
    "package-import-constants": (
        "from xml.parsers import expat\nexpat.XML_PARAM_ENTITY_PARSING_NEVER\nexpat.ExpatError\n"
    ),
    "dotted-import-call": "import xml.parsers.expat\nxml.parsers.expat.ParserCreate()\n",
    "plain-attribute": "def f(x):\n    return x.expat\n",
    "plain-parsers-attribute": "def f(x):\n    return x.parsers\n",
    "getattr-on-a-value": "def f(x):\n    return getattr(x, 'expat')\n",
    "getattr-parsers": "def f(x):\n    return getattr(x, 'parsers')\n",
    "match-class-keyword": (
        "def f(x):\n    match x:\n        case object(expat=e):\n            return e\n"
    ),
}


@pytest.mark.parametrize("source", EXPAT_OWNER_ALLOWED.values(), ids=EXPAT_OWNER_ALLOWED.keys())
def test_the_shared_parser_may_use_its_reserved_names(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source, EXPAT_FILE) == []


def test_the_shared_parser_itself_passes_the_guard(tmp_path: Path) -> None:
    source = (rules.REPO_ROOT / EXPAT_FILE).read_text(encoding="utf-8")
    assert "expat.ParserCreate" in source
    assert process_messages(tmp_path, source, EXPAT_FILE) == []


def test_the_shared_parser_still_may_not_store_expat(tmp_path: Path) -> None:
    messages = process_messages(tmp_path, "from xml.parsers import expat\nx = expat\n", EXPAT_FILE)
    assert messages == ["module name 'expat' may only be used as expat.attribute in plugins"]


EXPAT_NEIGHBOURS_ALLOWED = {
    "other-xmlsafe-attribute": XMLSAFE_IMPORT + "xmlsafe.parse_chunks([b'<a/>'], events)\n",
    "other-xmlsafe-import": "from .xmlsafe import RegularFile, XmlSafetyError\n",
    "lookalike-attribute": "def f(x):\n    return x.expatriate, x.parsers_seen, x.expat_\n",
    "lookalike-getattr": "def f(x):\n    return getattr(x, 'expats')\n",
    "match-class-other-keyword": (
        "def f(x):\n    match x:\n        case object(real=e):\n            return e\n"
    ),
    "plain-import-other-path": "import " + XMLSAFE_PACKAGE + ".xmlsafe\n",
}


@pytest.mark.parametrize(
    "source", EXPAT_NEIGHBOURS_ALLOWED.values(), ids=EXPAT_NEIGHBOURS_ALLOWED.keys()
)
def test_other_names_near_the_reserved_ones_stay_allowed(tmp_path: Path, source: str) -> None:
    assert process_messages(tmp_path, source, "plugins/module_utils/compliance/openscap.py") == []


def test_the_reserved_names_are_derived_from_the_extra_imports_only() -> None:
    assert dict(rules.RESERVED_ATTRIBUTES) == {"expat": EXPAT_FILE, "parsers": EXPAT_FILE}
    assert not set(rules.RESERVED_ATTRIBUTES) & rules.SHARED_SUBMODULE_ATTRIBUTES
    assert {"path", "abc"} <= rules.SHARED_SUBMODULE_ATTRIBUTES
    expected = rules.SHARED_SUBMODULE_ATTRIBUTES | {"expat", "parsers"}
    assert expected == rules.SUBMODULE_ATTRIBUTES
