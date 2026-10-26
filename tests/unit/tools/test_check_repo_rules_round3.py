from __future__ import annotations

import inspect
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    audit,
    catalog,
    fileio,
    openscap,
    process,
)
from tools.lint import check_repo_rules as rules

if TYPE_CHECKING:
    from collections.abc import Callable

AUDIT = "plugins/module_utils/compliance/audit.py"
LEDGER = "plugins/module_utils/compliance/ledger.py"
OPENSCAP = "plugins/module_utils/compliance/openscap.py"
OTHER = "plugins/modules/other.py"
COMPLIANCE = "ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance"


def process_messages(root: Path, source: str, name: str = OTHER) -> list[str]:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return [violation.message for violation in rules.check_file(target, root)]


def findings(text: str) -> list[tuple[int, str]]:
    return sorted(
        (violation.line, violation.message)
        for violation in rules.check_banned_modules(Path("f.yml"), text)
    )


def play(task: str) -> str:
    return f"---\n- name: p\n  hosts: all\n  tasks:\n    - name: t\n      {task}\n"


def messages_of(text: str) -> list[str]:
    return [message for _, message in findings(text)]


POSITIONAL_SEAMS = {
    "positional": "def f(path, owner_uid=0):\n    return path\n",
    "positional-only": "def f(path, owner_uid=0, /):\n    return path\n",
    "after-a-default": "def f(path=None, limits=None):\n    return path\n",
    "method": "class C:\n    def f(self, registry):\n        return registry\n",
    "var-positional": "def f(*clock):\n    return clock\n",
    "var-keyword": "def f(**runner):\n    return runner\n",
    "lambda": "f = lambda owner_uid: owner_uid\n",
    "async": "async def f(policies):\n    return policies\n",
}


@pytest.mark.parametrize("source", POSITIONAL_SEAMS.values(), ids=POSITIONAL_SEAMS.keys())
@pytest.mark.parametrize("name", [OTHER, AUDIT, LEDGER, OPENSCAP])
def test_a_positional_seam_parameter_is_denied(tmp_path: Path, source: str, name: str) -> None:
    messages = process_messages(tmp_path, source, name)
    assert any(
        message.startswith("test seam ") and message.endswith(" must be a keyword-only parameter")
        for message in messages
    )


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (OTHER, "def f(*, owner_uid=0):\n    return owner_uid\n"),
        (OTHER, "f = lambda *, clock=None: clock\n"),
        (LEDGER, "def f(*, registry=None):\n    return registry\n"),
        (AUDIT, "def f(*, limits=None):\n    return limits\n"),
        (OPENSCAP, "def f(*, owner_uid=0):\n    return owner_uid\n"),
    ],
)
def test_a_seam_may_only_be_defined_by_its_owner(tmp_path: Path, name: str, source: str) -> None:
    assert any(
        message.endswith("may not be defined in this file")
        for message in process_messages(tmp_path, source, name)
    )


FORWARDS = {
    "parameter": (
        AUDIT,
        "def g(job, *, owner_uid=0):\n    return h(job, owner_uid=owner_uid)\n",
    ),
    "lambda-parameter": (AUDIT, "g = lambda *, clock=None: h(clock=clock)\n"),
    "attribute": (
        AUDIT,
        (
            "class A:\n"
            "    def __init__(self, *, registry=None):\n"
            "        self._registry = registry\n"
            "    def run(self, job):\n"
            "        return h(job, registry=self._registry)\n"
        ),
    ),
    "ledger-to-fileio": (
        LEDGER,
        (
            f"from {COMPLIANCE} import fileio\n"
            "class L:\n"
            "    def __init__(self, *, owner_uid=0):\n"
            "        self._owner_uid = owner_uid\n"
            "    def open(self, path):\n"
            "        return fileio.open_directory(path, owner_uid=self._owner_uid, create=False)\n"
        ),
    ),
    "openscap-limits": (
        OPENSCAP,
        "def parse(document, *, limits=None):\n    return bounds(limits=limits)\n",
    ),
}


@pytest.mark.parametrize(("name", "source"), FORWARDS.values(), ids=FORWARDS.keys())
def test_an_owner_may_forward_its_seam_unchanged(tmp_path: Path, name: str, source: str) -> None:
    assert process_messages(tmp_path, source, name) == []


REJECTED_FORWARDS = {
    "literal": (AUDIT, "def g(job):\n    return h(job, owner_uid=1000)\n"),
    "literal-in-a-seam-function": (
        AUDIT,
        "def g(job, *, owner_uid=0):\n    return h(job, owner_uid=1000)\n",
    ),
    "other-name": (
        AUDIT,
        "def g(job, *, owner_uid=0, uid=1):\n    return h(job, owner_uid=uid)\n",
    ),
    "expression": (
        AUDIT,
        "def g(job, *, owner_uid=0):\n    return h(job, owner_uid=owner_uid + 1)\n",
    ),
    "rebound": (
        AUDIT,
        (
            "def g(job, *, owner_uid=0):\n"
            "    owner_uid = 1000\n"
            "    return h(job, owner_uid=owner_uid)\n"
        ),
    ),
    "shadowed-by-a-loop": (
        AUDIT,
        (
            "def g(job, *, owner_uid=0):\n"
            "    for owner_uid in (1000,):\n"
            "        h(job, owner_uid=owner_uid)\n"
        ),
    ),
    "module-level": (AUDIT, "owner_uid = 1000\nh(owner_uid=owner_uid)\n"),
    "outer-function": (
        AUDIT,
        (
            "def g(*, owner_uid=0):\n"
            "    def inner(owner_uid):\n"
            "        return h(owner_uid=owner_uid)\n"
            "    return inner\n"
        ),
    ),
    "seam-of-another-file": (LEDGER, "def g(*, registry=None):\n    return h(registry=registry)\n"),
    "attribute-without-init-seam": (
        AUDIT,
        (
            "class A:\n"
            "    def __init__(self):\n"
            "        self._owner_uid = 1000\n"
            "    def run(self):\n"
            "        return h(owner_uid=self._owner_uid)\n"
        ),
    ),
    "attribute-without-init": (
        AUDIT,
        "class A:\n    def run(self):\n        return h(owner_uid=self._owner_uid)\n",
    ),
    "attribute-of-another-object": (
        AUDIT,
        (
            "class A:\n"
            "    def __init__(self, *, owner_uid=0):\n"
            "        self._owner_uid = owner_uid\n"
            "    def run(self, other):\n"
            "        return h(owner_uid=other._owner_uid)\n"
        ),
    ),
    "attribute-through-cls": (
        AUDIT,
        (
            "class A:\n"
            "    def __init__(self, *, owner_uid=0):\n"
            "        self._owner_uid = owner_uid\n"
            "    @classmethod\n"
            "    def run(cls):\n"
            "        return h(owner_uid=cls._owner_uid)\n"
        ),
    ),
    "attribute-of-another-seam": (
        AUDIT,
        (
            "class A:\n"
            "    def __init__(self, *, owner_uid=0, clock=None):\n"
            "        self._owner_uid = owner_uid\n"
            "    def run(self):\n"
            "        return h(owner_uid=self._clock)\n"
        ),
    ),
    "self-outside-a-class": (AUDIT, "def run(self):\n    return h(owner_uid=self._owner_uid)\n"),
    "non-owner": (OTHER, "def g(job):\n    return h(job, owner_uid=job)\n"),
}


@pytest.mark.parametrize(
    ("name", "source"), REJECTED_FORWARDS.values(), ids=REJECTED_FORWARDS.keys()
)
def test_anything_but_an_unchanged_forward_is_denied(
    tmp_path: Path, name: str, source: str
) -> None:
    messages = process_messages(tmp_path, source, name)
    assert any(re.fullmatch(r"keyword '\w+' is not allowed in plugins", m) for m in messages)


LATE = "the seam attribute '{}' may only be assigned to self in __init__"
RESERVED = "the seam attribute '{}' is reserved for the file that defines the seam"
CLASS_BODY = "the seam attribute '{}' may not be bound in a class body"
DYNAMIC = "the seam attribute '{}' may not be used with {}"
OWNER_IMPORT = f"from {COMPLIANCE} import audit\n"

SEAM_ATTRIBUTE_CHANGES = {
    "method-assignment": (
        (
            "class A:\n"
            "    def __init__(self, *, owner_uid=0):\n"
            "        self._owner_uid = owner_uid\n"
            "    def weaken(self):\n"
            "        self._owner_uid = 1000\n"
        ),
        LATE.format("_owner_uid"),
    ),
    "augmented": (
        "class A:\n    def weaken(self):\n        self._registry += 1\n",
        LATE.format("_registry"),
    ),
    "delete": (
        "class A:\n    def weaken(self):\n        del self._clock\n",
        LATE.format("_clock"),
    ),
    "module-level": ("class A:\n    pass\nA()._owner_uid = 1\n", LATE.format("_owner_uid")),
    "init-of-another-object": (
        (
            "class A:\n"
            "    def __init__(self, other, *, owner_uid=0):\n"
            "        type(self)._owner_uid = owner_uid\n"
        ),
        LATE.format("_owner_uid"),
    ),
    "nested-function-in-init": (
        (
            "class A:\n"
            "    def __init__(self, *, owner_uid=0):\n"
            "        def later():\n"
            "            self._owner_uid = 1000\n"
            "        self.later = later\n"
        ),
        LATE.format("_owner_uid"),
    ),
    "nested-async-function-in-init": (
        (
            "class A:\n"
            "    def __init__(self, *, clock=None):\n"
            "        async def later():\n"
            "            self._clock = None\n"
            "        self.later = later\n"
        ),
        LATE.format("_clock"),
    ),
    "deeply-nested-delete-in-init": (
        (
            "class A:\n"
            "    def __init__(self, *, registry=None):\n"
            "        def outer():\n"
            "            def inner():\n"
            "                del self._registry\n"
            "            return inner\n"
            "        self.outer = outer\n"
        ),
        LATE.format("_registry"),
    ),
    "setattr": (
        "class A:\n    def weaken(self):\n        setattr(self, '_owner_uid', 1000)\n",
        DYNAMIC.format("_owner_uid", "setattr"),
    ),
    "delattr": (
        "class A:\n    def weaken(self):\n        delattr(self, '_owner_uid')\n",
        DYNAMIC.format("_owner_uid", "delattr"),
    ),
    "object-setattr": (
        (
            "class A:\n"
            "    def __post_init__(self):\n"
            "        object.__setattr__(self, '_owner_uid', 1000)\n"
        ),
        "dunder attribute '__setattr__' is not allowed in plugins",
    ),
    "class-attribute": (
        "class A:\n    _owner_uid = 1000\n",
        CLASS_BODY.format("_owner_uid"),
    ),
    "annotated-class-attribute": (
        "class A:\n    _clock: object = None\n",
        CLASS_BODY.format("_clock"),
    ),
    "class-method-named-like-a-seam": (
        "class A:\n    def _registry(self):\n        return None\n",
        CLASS_BODY.format("_registry"),
    ),
}


@pytest.mark.parametrize(
    ("source", "message"), SEAM_ATTRIBUTE_CHANGES.values(), ids=SEAM_ATTRIBUTE_CHANGES.keys()
)
def test_a_seam_attribute_is_assigned_only_in_init(
    tmp_path: Path, source: str, message: str
) -> None:
    assert message in process_messages(tmp_path, source, AUDIT)


FOREIGN_SEAM_ATTRIBUTES = {
    "subclass-init": (
        OWNER_IMPORT + "class Mine(audit.Auditor):\n"
        "    def __init__(self):\n"
        "        super().__init__()\n"
        "        self._owner_uid = 1000\n",
        RESERVED.format("_owner_uid"),
    ),
    "subclass-class-attribute": (
        OWNER_IMPORT + "class Mine(audit.Auditor):\n    _owner_uid = 1000\n",
        CLASS_BODY.format("_owner_uid"),
    ),
    "method-called-on-an-owner-object": (
        OWNER_IMPORT + "class C:\n"
        "    def f(self):\n"
        "        self._owner_uid = 1000\n"
        "C.f(audit.Auditor())\n",
        RESERVED.format("_owner_uid"),
    ),
    "read": (
        "class C:\n    def f(self):\n        return self._registry\n",
        RESERVED.format("_registry"),
    ),
    "delete": ("class C:\n    def f(self):\n        del self._clock\n", RESERVED.format("_clock")),
    "setattr": (
        "class C:\n    def f(self):\n        setattr(self, '_owner_uid', 1000)\n",
        DYNAMIC.format("_owner_uid", "setattr"),
    ),
    "getattr": (
        "class C:\n    def f(self):\n        return getattr(self, '_limits', None)\n",
        DYNAMIC.format("_limits", "getattr"),
    ),
    "delattr": (
        "class C:\n    def f(self):\n        delattr(self, '_runner')\n",
        DYNAMIC.format("_runner", "delattr"),
    ),
    "object-setattr": (
        (
            "class C:\n"
            "    def __post_init__(self):\n"
            "        object.__setattr__(self, '_state_dir', '/tmp')\n"
        ),
        "dunder attribute '__setattr__' is not allowed in plugins",
    ),
    "match-pattern": (
        "def f(x):\n    match x:\n        case object(_lock_timeout=t):\n            return t\n",
        RESERVED.format("_lock_timeout"),
    ),
    "class-attribute-of-a-local-class": (
        "class C:\n    _policies = {}\n",
        CLASS_BODY.format("_policies"),
    ),
}


def _foreign_cases() -> list[tuple[str, str, str]]:
    cases: list[tuple[str, str, str]] = []
    for name in (OTHER, LEDGER, OPENSCAP):
        owned = rules.SEAM_OWNERS.get(Path(name), frozenset())
        for source, message in FOREIGN_SEAM_ATTRIBUTES.values():
            attribute = re.search(r"'_(\w+)'", message)
            if attribute is None or attribute.group(1) not in owned:
                cases.append((name, source, message))
    return cases


@pytest.mark.parametrize(("name", "source", "message"), _foreign_cases())
def test_a_seam_attribute_is_reserved_for_its_owner(
    tmp_path: Path, name: str, source: str, message: str
) -> None:
    assert message in process_messages(tmp_path, source, name)


def test_an_owner_stores_its_seam_directly_in_init(tmp_path: Path) -> None:
    source = (
        "class A:\n"
        "    def __init__(self, *, owner_uid=0, clock=None):\n"
        "        if clock is None:\n"
        "            self._clock = clock\n"
        "        with open('x') as handle:\n"
        "            self._owner_uid = owner_uid\n"
        "        self.items = [handle for _ in ()]\n"
    )
    assert process_messages(tmp_path, source, AUDIT) == []


def test_other_private_attributes_keep_their_rules(tmp_path: Path) -> None:
    source = (
        "class A:\n"
        "    def __init__(self, *, owner_uid=0):\n"
        "        self._owner_uid = owner_uid\n"
        "    def touch(self):\n"
        "        self._count = 1\n"
        "        setattr(self, '_count', 2)\n"
        "        return getattr(self, '_owner_uid'), self._owner_uid, [x for x in ()]\n"
    )
    assert process_messages(tmp_path, source, AUDIT) == []


def test_a_reserved_name_outside_a_class_body_is_not_an_attribute(tmp_path: Path) -> None:
    source = (
        "_owner_uid = 1000\ndef f(_clock):\n    return [_registry for _registry in (_clock,)]\n"
    )
    assert process_messages(tmp_path, source, OTHER) == []


def test_fileio_stays_restricted_to_the_ledger(tmp_path: Path) -> None:
    source = (
        f"from {COMPLIANCE} import fileio\n"
        "def g(path, *, owner_uid=0):\n"
        "    return fileio.open_directory(path, owner_uid=owner_uid)\n"
    )
    assert process_messages(tmp_path, source, AUDIT) == [
        "import of 'fileio' is restricted to ledger.py"
    ]
    assert sorted(process_messages(tmp_path, source, OTHER)) == [
        "import of 'fileio' is restricted to ledger.py",
        "keyword 'owner_uid' is not allowed in plugins",
        "test seam 'owner_uid' may not be defined in this file",
    ]


def test_the_seam_owners_are_pinned() -> None:
    assert dict(rules.SEAM_OWNERS) == {
        Path(AUDIT): {"owner_uid", "registry", "clock"},
        Path("plugins/module_utils/compliance/catalog.py"): {"owner_uid"},
        Path("plugins/module_utils/compliance/fileio.py"): {"owner_uid"},
        Path(LEDGER): {"state_dir", "owner_uid", "lock_timeout"},
        Path(OPENSCAP): {"runner", "clock", "limits"},
    }
    for seams in rules.SEAM_OWNERS.values():
        assert seams <= rules.BANNED_KEYWORDS


def _keyword_only(function: Callable[..., object], *names: str) -> bool:
    parameters = inspect.signature(function).parameters
    return all(parameters[name].kind is inspect.Parameter.KEYWORD_ONLY for name in names)


def test_the_seams_named_in_the_issue_are_keyword_only() -> None:
    assert _keyword_only(process.resolve_executable, "trusted_dirs", "owner_uid")
    assert _keyword_only(process.check_policy, "policies")
    assert _keyword_only(fileio.open_directory, "owner_uid")
    assert _keyword_only(fileio.SafeDirectory, "owner_uid")
    assert _keyword_only(audit.plan, "owner_uid")
    assert _keyword_only(audit.inspect_output_root, "owner_uid")
    assert _keyword_only(catalog.vetted_content_path, "owner_uid")
    assert _keyword_only(openscap.parse_results, "limits")
    assert _keyword_only(openscap.read_results, "limits")


def test_a_seam_cannot_be_passed_positionally() -> None:
    with pytest.raises(TypeError):
        inspect.signature(process.resolve_executable).bind("sh", ("/srv/tools",), 1000)
    with pytest.raises(TypeError):
        inspect.signature(fileio.open_directory).bind("/srv/state", 1000)
    with pytest.raises(TypeError):
        inspect.signature(audit.plan).bind(object(), 1000)
    with pytest.raises(TypeError):
        inspect.signature(openscap.parse_results).bind("<a/>", object())


def test_the_merged_plugins_satisfy_the_seam_rules() -> None:
    plugins = sorted((rules.REPO_ROOT / rules.PLUGINS_DIRECTORY).rglob("*.py"))
    assert any(path.name == "remediation_plan.py" for path in plugins)
    assert rules.check_paths(plugins) == []


DENIED_TARGETS = {
    "templated-name": ("include_tasks: '{{ f }}.yml'", "must not be templated"),
    "templated-file": (
        "ansible.builtin.include_tasks:\n        file: 'tasks/{{ f }}.yml'",
        "must not be templated",
    ),
    "templated-raw-params": (
        "ansible.builtin.import_tasks:\n        _raw_params: '{% if x %}a{% endif %}.yml'",
        "must not be templated",
    ),
    "templated-comment": ("include_tasks: 'a{# x #}.yml'", "must not be templated"),
    "playbook-dir": ("include_tasks: '{{ playbook_dir }}/x.yml'", "must not be templated"),
    "absolute": ("ansible.builtin.include_tasks: /etc/ansible/x.yml", "must be a relative path"),
    "absolute-with-space": ("include_tasks: ' /tmp/x.yml'", "must be a relative path"),
    "home": ("ansible.builtin.import_tasks: ~/x.yml", "must be a relative path"),
    "parent": ("ansible.builtin.include_tasks: ../x.yml", "must not contain '..'"),
    "inner-parent": ("include_tasks: tasks/../../../x.yml", "must not contain '..'"),
    "role-path-parent": (
        "include_tasks: '{{ role_path }}/tasks/../../x.yml'",
        "must not be templated",
    ),
    "role-path-dispatch-variable": (
        "include_tasks: '{{ role_path }}/tasks/{{ __linux_compliance_remediate_family.name }}.yml'",
        "must not be templated",
    ),
    "role-path-dispatch-variable-in-file": (
        (
            "include_tasks:\n        file: "
            "'{{role_path}}/tasks/{{__linux_compliance_remediate_family.name}}.yml'"
        ),
        "must not be templated",
    ),
    "role-path-other-variable": (
        "include_tasks: '{{ role_path }}/tasks/{{ family }}.yml'",
        "must not be templated",
    ),
    "role-path-filter": (
        (
            "include_tasks: '{{ role_path }}/tasks/{{ __linux_compliance_remediate_family.name"
            " | default(x) }}.yml'"
        ),
        "must not be templated",
    ),
    "role-path-outside-tasks": (
        "include_tasks: '{{ role_path }}/vars/x.yml'",
        "must not be templated",
    ),
    "role-path-two-variables": (
        (
            "include_tasks: '{{ role_path }}/tasks/{{ __linux_compliance_remediate_family.name }}"
            "{{ __linux_compliance_remediate_family.name }}.yml'"
        ),
        "must not be templated",
    ),
    "role-path-wrong-suffix": (
        "include_tasks: '{{ role_path }}/tasks/x.json'",
        "must not be templated",
    ),
}


@pytest.mark.parametrize(("task", "message"), DENIED_TARGETS.values(), ids=DENIED_TARGETS.keys())
def test_unsafe_include_targets_are_denied(task: str, message: str) -> None:
    messages = messages_of(play(task))
    assert len(messages) == 1
    assert message in messages[0]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("---\n- ansible.builtin.import_playbook: '{{ p }}.yml'\n", "must not be templated"),
        ("---\n- ansible.builtin.import_playbook: /srv/site.yml\n", "must be a relative path"),
        ("---\n- import_playbook: ../site.yml\n", "must not contain '..'"),
    ],
)
def test_unsafe_playbook_imports_are_denied(text: str, message: str) -> None:
    messages = messages_of(text)
    assert len(messages) == 1
    assert message in messages[0]


ALLOWED_TARGETS = (
    "include_tasks: '{{ role_path }}/tasks/file_permissions_apply.yml'",
    "include_tasks: '{{role_path}}/tasks/sub/check.yaml'",
    "include_tasks: tasks/a..b.yml",
    "import_tasks: ./other.yml",
)


@pytest.mark.parametrize("task", ALLOWED_TARGETS)
def test_role_path_and_relative_targets_are_allowed(task: str) -> None:
    assert findings(play(task)) == []


def test_the_remediate_dispatcher_passes_the_guard() -> None:
    tasks = rules.REPO_ROOT / "roles/remediate/tasks"
    for name in ("main.yml", "dispatch.yml"):
        text = (tasks / name).read_text(encoding="utf-8")
        assert "__linux_compliance_remediate_family.name }}.yml" not in text
        assert rules.check_banned_modules(tasks / name, text) == []
    assert "{{ role_path }}/tasks/file_permissions.yml" in (tasks / "dispatch.yml").read_text(
        encoding="utf-8"
    )


ROLE_NAME_TASKS = {
    "templated-name": (
        "ansible.builtin.include_role:\n        name: '{{ role }}'",
        "include_role role name must not be templated: '{{ role }}'",
    ),
    "templated-collection": (
        "ansible.builtin.import_role:\n        name: 'freesecdev.{{ c }}.audit'",
        "import_role role name must not be templated: 'freesecdev.{{ c }}.audit'",
    ),
    "absolute-role": (
        "ansible.builtin.include_role:\n        name: /srv/roles/x",
        "role name must be a plain or fully qualified role name: '/srv/roles/x'",
    ),
    "relative-role": (
        "ansible.builtin.include_role:\n        name: ../roles/x",
        "role name must be a plain or fully qualified role name: '../roles/x'",
    ),
    "sequence-role": (
        "ansible.builtin.include_role:\n        name: [x]",
        "role name must be a plain or fully qualified role name: 'sequence'",
    ),
    "free-form-templated": (
        "ansible.builtin.include_role: name={{ role }}",
        "ansible.builtin.include_role arguments must not be templated: 'name={{ role }}'",
    ),
    "free-form-path": (
        "include_role: name=../x tasks_from=main.yml",
        "include_role role name must be a plain or fully qualified role name: '../x'",
    ),
    "templated-tasks-from": (
        "ansible.builtin.include_role:\n        name: x\n        tasks_from: '{{ t }}.yml'",
        "tasks_from must not be templated, except {{ role_path }}/tasks/<file>: '{{ t }}.yml'",
    ),
    "role-path-tasks-from": (
        (
            "ansible.builtin.include_role:\n        name: x\n"
            "        tasks_from: '{{ role_path }}/tasks/a.yml'"
        ),
        "tasks_from must not be templated",
    ),
    "absolute-tasks-from": (
        "ansible.builtin.include_role:\n        name: x\n        tasks_from: /etc/x.yml",
        "tasks_from must be a relative path: '/etc/x.yml'",
    ),
    "parent-handlers-from": (
        "ansible.builtin.import_role:\n        name: x\n        handlers_from: ../../h.yml",
        "handlers_from must not contain '..': '../../h.yml'",
    ),
    "free-form-parent-tasks-from": (
        "include_role: name=x tasks_from=../t.yml",
        "include_role tasks_from must not contain '..': '../t.yml'",
    ),
}


@pytest.mark.parametrize(("task", "message"), ROLE_NAME_TASKS.values(), ids=ROLE_NAME_TASKS.keys())
def test_role_includes_need_a_static_role_and_entry_point(task: str, message: str) -> None:
    messages = messages_of(play(task))
    assert len(messages) == 1
    assert message in messages[0]


@pytest.mark.parametrize(
    "task",
    [
        "ansible.builtin.include_role:\n        name: freesecdev.linux_compliance.audit",
        "ansible.builtin.include_role:\n        name: my-role\n        tasks_from: sub/x.yml",
        "ansible.builtin.include_role: name=freesecdev.linux_compliance.audit",
        "ansible.builtin.include_role: name=x tasks_from=evaluate.yml apply",
        "ansible.builtin.include_role: name=x allow_duplicates=false",
        "ansible.builtin.include_role:\n        name: x\n        apply: {tags: [a]}",
    ],
)
def test_static_role_includes_are_allowed(task: str) -> None:
    assert findings(play(task)) == []


PLAY_ROLES = {
    "scalar": ("    - '{{ r }}'\n", "role name in roles must not be templated: '{{ r }}'"),
    "role-key": ("    - role: '{{ r }}'\n", "role name in roles must not be templated: '{{ r }}'"),
    "name-key": ("    - name: '{{ r }}'\n", "role name in roles must not be templated: '{{ r }}'"),
    "path": (
        "    - role: /srv/roles/x\n",
        "role name in roles must be a plain or fully qualified role name: '/srv/roles/x'",
    ),
    "parent": (
        "    - ../x\n",
        "role name in roles must be a plain or fully qualified role name: '../x'",
    ),
}


@pytest.mark.parametrize(("entry", "message"), PLAY_ROLES.values(), ids=PLAY_ROLES.keys())
def test_play_roles_need_static_names(entry: str, message: str) -> None:
    text = f"---\n- hosts: all\n  roles:\n{entry}"
    assert messages_of(text) == [message]


def test_static_play_roles_are_allowed() -> None:
    text = (
        "---\n- hosts: all\n  roles:\n"
        "    - freesecdev.linux_compliance.discover\n"
        "    - role: freesecdev.linux_compliance.audit\n"
        "      vars:\n        x: '{{ y }}'\n"
        "    - name: local_role\n"
    )
    assert findings(text) == []


def test_a_roles_value_that_is_not_a_list_is_left_to_ansible() -> None:
    assert findings("---\n- hosts: all\n  roles: x\n") == []


TEMPLATED_KEYS = {
    "module": ("---\n- name: t\n  '{{ m }}': id\n", 3),
    "statement": ("---\n- name: t\n  '{% if a %}x{% endif %}': id\n", 3),
    "in-a-play": ("---\n- hosts: all\n  tasks:\n    - '{{ m }}': id\n", 4),
    "in-a-block": ("---\n- block:\n    - name: t\n      '{{ m }}': cmd\n", 4),
    "merged": ("---\n- &t {'{{ m }}': id}\n- <<: *t\n  name: x\n", 2),
}


@pytest.mark.parametrize(("text", "line"), TEMPLATED_KEYS.values(), ids=TEMPLATED_KEYS.keys())
def test_templated_task_keys_are_denied(text: str, line: int) -> None:
    result = findings(text)
    assert result
    assert {found for found, _ in result} == {line}
    assert all(message.startswith("templated task key is not allowed") for _, message in result)


def test_templated_keys_in_module_parameters_and_data_are_not_task_keys() -> None:
    text = (
        "---\n- name: t\n"
        "  ansible.builtin.set_fact:\n    '{{ name }}': 1\n"
        "  vars:\n    '{{ k }}': v\n"
    )
    assert findings(text) == []


SKIPPED_DIRECTORIES = frozenset(
    {".git", ".venv", "build", "dist", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache"}
)
SKIPPED_PATHS = frozenset({".claude/worktrees"})
DIRECTORY_LINKS = {".claude/skills": ".agents/skills"}


def symlink_problems(root: Path) -> list[str]:
    """Return every symlink below ``root`` that leaves it or hides a directory from the guard."""
    problems: list[str] = []
    base = root.resolve()
    for directory, directories, files in os.walk(root):
        current = Path(directory)
        directories[:] = [
            name
            for name in directories
            if name not in SKIPPED_DIRECTORIES
            and (current / name).relative_to(root).as_posix() not in SKIPPED_PATHS
        ]
        for name in [*directories, *files]:
            link = current / name
            if not link.is_symlink():
                continue
            relative = link.relative_to(root).as_posix()
            target = link.resolve()
            if not target.is_relative_to(base):
                problems.append(f"{relative} points outside the repository")
            elif (
                target.is_dir()
                and DIRECTORY_LINKS.get(relative) != target.relative_to(base).as_posix()
            ):
                problems.append(f"{relative} is a symlinked directory the guard would not scan")
    return problems


def test_no_symlink_leaves_the_repository_or_hides_a_scanned_directory() -> None:
    assert symlink_problems(rules.REPO_ROOT) == []


def test_symlinked_task_directories_and_escapes_are_found(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "repo"
    (root / "roles" / "r").mkdir(parents=True)
    (root / "elsewhere").mkdir()
    (root / "roles" / "r" / "tasks").symlink_to(root / "elsewhere")
    (root / "roles" / "r" / "escape.yml").symlink_to(outside)
    (root / "fine.yml").write_text("---\n", encoding="utf-8")
    (root / "link.yml").symlink_to(root / "fine.yml")
    (root / "build").mkdir()
    (root / "build" / "ignored").symlink_to(outside)
    assert sorted(symlink_problems(root)) == [
        "roles/r/escape.yml points outside the repository",
        "roles/r/tasks is a symlinked directory the guard would not scan",
    ]
