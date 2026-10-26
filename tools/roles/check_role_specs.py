"""Check that each role's ``defaults/main.yml`` matches its ``meta/argument_specs.yml``.

Role variables are prefixed ``linux_compliance_<role>_``. The exceptions are the
collection-wide variables in :data:`SHARED_VARIABLES`, which several roles read with one
meaning, and the topic toggles of ADR 0011 in the roles of ``generate_toggles.TOGGLE_ROLES``.
Those toggles are checked exactly against the output of ``tools/roles/generate_toggles.py`` for
the rule catalogue ``roles/remediate/vars/rules.yml``: the set of toggle names, each default in
``defaults/main.yml`` (value and type) and each argument spec must equal the generated ones, so an
uncatalogued or misnamed toggle is a finding without relying on ``make lint-toggles``. Rule
toggles are never declared in a role (amendment of FREES-53 to ADR 0011): a declared one is a
finding. Toggles in any other role fail the prefix rule. An option that is not required may
default to null, which means "not set".
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml

from tools.roles import generate_toggles

if TYPE_CHECKING:
    from collections.abc import Sequence

ENTRY_POINT: Final[str] = "main"
SHARED_VARIABLES: Final[frozenset[str]] = frozenset({"linux_compliance_exceptions_file"})
NULLABLE_TYPES: Final[frozenset[str]] = frozenset({"str", "path"})
CATALOGUE: Final[Path] = Path("remediate") / "vars" / "rules.yml"
RULE_TOGGLE_PREFIX: Final[str] = "linux_compliance_rule_"
TYPE_CLASSES: Final[dict[str, type]] = {
    "str": str,
    "path": str,
    "bool": bool,
    "int": int,
    "float": float,
    "list": list,
    "dict": dict,
}


def load_mapping(path: Path) -> dict[str, object] | None:
    """Return the YAML mapping in ``path``, or ``None`` when it is missing or not a mapping."""
    if not path.is_file():
        return None
    loaded = cast("object", yaml.safe_load(path.read_text(encoding="utf-8")))
    if not isinstance(loaded, dict):
        return None
    return cast("dict[str, object]", loaded)


def matches_type(value: object, type_name: str, *, nullable: bool = False) -> bool:
    """Return whether ``value`` is acceptable for the argument spec type ``type_name``.

    ``None`` is acceptable only when ``nullable`` is true and the type is a string type.
    """
    if value is None:
        return nullable and type_name in NULLABLE_TYPES
    expected = TYPE_CLASSES[type_name]
    if isinstance(value, bool) and expected is not bool:
        return False
    return isinstance(value, expected)


def is_toggle(role: str, name: str) -> bool:
    """Return whether ``name`` is a generated control toggle that ``role`` may declare."""
    return role in generate_toggles.TOGGLE_ROLES and generate_toggles.is_generated(name)


def _same(first: object, second: object) -> bool:
    return json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def _undeclared(name: str) -> str:
    if name.startswith(RULE_TOGGLE_PREFIX):
        return (
            "is not a toggle generated from the rule catalogue: rule toggles are never declared "
            "in a role and follow their family toggle when unset (ADR 0011, FREES-53)"
        )
    return "is not a toggle generated from the rule catalogue"


def check_toggles(
    role_dir: Path, spec_options: dict[str, object], defaults: dict[str, object]
) -> list[str]:
    """Return findings for the control toggles of ``role_dir`` against the generated ones."""
    role = role_dir.name
    names = {name for name in {*spec_options, *defaults} if is_toggle(role, name)}
    if role not in generate_toggles.TOGGLE_ROLES:
        return []
    try:
        catalogue = generate_toggles.load_catalogue(role_dir.parent / CATALOGUE)
    except generate_toggles.GenerationError as error:
        return [f"{role}: the toggles cannot be checked: {error}"]
    expected_defaults = generate_toggles.toggle_defaults(catalogue)
    expected_specs = generate_toggles.toggle_specs(catalogue)
    findings = [
        f"{role}: {name}: {_undeclared(name)}" for name in sorted(names - set(expected_defaults))
    ]
    for name in expected_defaults:
        where = f"{role}: {name}"
        if name not in defaults or not _same(defaults[name], expected_defaults[name]):
            findings.append(f"{where}: defaults/main.yml differs from the generated default")
        if name not in spec_options or not _same(spec_options[name], expected_specs[name]):
            findings.append(f"{where}: the argument spec differs from the generated one")
    return findings


def check_option(role: str, name: str, spec: object, default: object) -> list[str]:
    """Return findings for one option, given its spec and the value from the defaults file."""
    where = f"{role}: {name}"
    if not isinstance(spec, dict):
        return [f"{where}: option spec must be a mapping"]
    option = cast("dict[str, object]", spec)
    if name not in SHARED_VARIABLES and not name.startswith(f"linux_compliance_{role}_"):
        return [f"{where}: variable must be prefixed linux_compliance_{role}_"]
    findings: list[str] = []
    type_name = option.get("type")
    if not isinstance(type_name, str) or type_name not in TYPE_CLASSES:
        return [f"{where}: type must be one of {', '.join(sorted(TYPE_CLASSES))}"]
    if not option.get("description"):
        findings.append(f"{where}: description is missing")
    if "default" not in option:
        findings.append(f"{where}: default is missing from the argument spec")
    elif option["default"] != default or type(option["default"]) is not type(default):
        findings.append(f"{where}: defaults/main.yml does not equal the argument spec default")
    nullable = option.get("required") is not True
    if not matches_type(default, type_name, nullable=nullable):
        findings.append(f"{where}: default does not have the declared type {type_name}")
    if type_name == "list" and not option.get("elements"):
        findings.append(f"{where}: list options must declare elements")
    return findings


def check_role(role_dir: Path) -> list[str]:
    """Return findings for the role in ``role_dir``."""
    role = role_dir.name
    specs = load_mapping(role_dir / "meta" / "argument_specs.yml")
    if specs is None:
        return [f"{role}: meta/argument_specs.yml is missing or not a mapping"]
    entry_points = specs.get("argument_specs")
    if not isinstance(entry_points, dict) or ENTRY_POINT not in entry_points:
        return [f"{role}: argument_specs must define the {ENTRY_POINT} entry point"]
    entry = cast("dict[str, object]", entry_points)[ENTRY_POINT]
    options = cast("dict[str, object]", entry).get("options") if isinstance(entry, dict) else None
    if not isinstance(options, dict):
        return [f"{role}: the {ENTRY_POINT} entry point must define options"]
    spec_options = cast("dict[str, object]", options)
    defaults = load_mapping(role_dir / "defaults" / "main.yml")
    if defaults is None:
        return [f"{role}: defaults/main.yml is missing or not a mapping"]
    findings = check_toggles(role_dir, spec_options, defaults)
    findings.extend(
        f"{role}: {name}: defined in defaults/main.yml but not in the argument spec"
        for name in sorted(set(defaults) - set(spec_options))
        if not is_toggle(role, name)
    )
    for name in sorted(spec_options):
        if is_toggle(role, name):
            continue
        if name not in defaults:
            findings.append(f"{role}: {name}: missing from defaults/main.yml")
        else:
            findings.extend(check_option(role, name, spec_options[name], defaults[name]))
    return findings + check_tasks(role_dir)


GUARD_TAG_PATTERN: Final[re.Pattern[str]] = re.compile(r"linux_compliance_[a-z0-9_]+_guard")
GUARD_MODULES: Final[frozenset[str]] = frozenset({"ansible.builtin.assert", "ansible.builtin.fail"})
SET_FACT: Final[str] = "ansible.builtin.set_fact"
NESTED_TASK_KEYS: Final[tuple[str, ...]] = ("block", "rescue", "always")


def guard_tag(role: str) -> str:
    """Return the tag of the tasks that detect a run with ``--skip-tags always``."""
    return f"linux_compliance_{role}_guard"


def dispatched_variable(role: str) -> str:
    """Return the only variable that a guard ``set_fact`` task may set."""
    return f"__linux_compliance_{role}_dispatched"


def _tags(task: object) -> object:
    return cast("dict[str, object]", task).get("tags") if isinstance(task, dict) else None


def is_guard_task(role: str, task: object) -> bool:
    """Return whether ``task`` is one of the guard tasks that may carry only the guard tag.

    A guard task is an ``ansible.builtin.assert`` or ``ansible.builtin.fail``, or the single
    ``ansible.builtin.set_fact`` that sets exactly the role's dispatched variable to ``false``.
    It has no keys besides ``name``, ``tags`` and its module, so it cannot loop, include or run
    anything else.
    """
    if not isinstance(task, dict):
        return False
    fields = cast("dict[str, object]", task)
    if fields.get("tags") != [guard_tag(role)]:
        return False
    modules = set(fields) - {"name", "tags"}
    if len(modules) != 1:
        return False
    module = modules.pop()
    if module in GUARD_MODULES:
        return True
    return module == SET_FACT and fields[module] == {dispatched_variable(role): False}


def _applied_tags(task: object) -> list[object]:
    if not isinstance(task, dict):
        return []
    applied: list[object] = []
    for value in cast("dict[str, object]", task).values():
        options = cast("dict[str, object]", value) if isinstance(value, dict) else {}
        apply = options.get("apply")
        tags = cast("dict[str, object]", apply).get("tags") if isinstance(apply, dict) else None
        if isinstance(tags, list):
            applied.extend(cast("list[object]", tags))
    return applied


def _guard_tags(task: object) -> list[str]:
    tags = _tags(task)
    own = cast("list[object]", tags) if isinstance(tags, list) else []
    return [str(tag) for tag in own + _applied_tags(task) if GUARD_TAG_PATTERN.fullmatch(str(tag))]


def _nested_tasks(task: object) -> list[object]:
    if not isinstance(task, dict):
        return []
    fields = cast("dict[str, object]", task)
    nested: list[object] = []
    for key in NESTED_TASK_KEYS:
        value = fields.get(key)
        if isinstance(value, list):
            nested.extend(cast("list[object]", value))
    return nested


def _walk(tasks: list[object]) -> list[object]:
    found: list[object] = []
    for task in tasks:
        found.append(task)
        found.extend(_walk(_nested_tasks(task)))
    return found


def _load_tasks(path: Path) -> list[object] | None:
    loaded = cast("object", yaml.safe_load(path.read_text(encoding="utf-8")))
    return cast("list[object]", loaded) if isinstance(loaded, list) else None


def check_guard_tags(role_dir: Path) -> list[str]:
    """Return findings for guard tags outside the guard tasks of the role's ``tasks/main.yml``."""
    role = role_dir.name
    findings: list[str] = []
    for path in sorted((role_dir / "tasks").glob("*.yml")):
        tasks = _load_tasks(path)
        top_level = tasks if path.name == "main.yml" and tasks is not None else []
        for task in _walk(tasks or []):
            if not _guard_tags(task):
                continue
            if any(task is guard for guard in top_level) and is_guard_task(role, task):
                continue
            findings.append(
                f"{role}: tasks/{path.name}: the guard tag {guard_tag(role)} is allowed only, and "
                f"alone, on a top-level assert, fail or the {dispatched_variable(role)}: false "
                f"set_fact of tasks/main.yml; found {_guard_tags(task)}"
            )
    return findings


def check_tasks(role_dir: Path) -> list[str]:
    """Return findings for tasks in ``tasks/main.yml`` that are not tagged ``always``.

    A guard task (see :func:`is_guard_task`) is allowed too: it carries only the role's guard tag,
    because it must run when ``always`` is skipped, so that the role can fail instead of silently
    doing nothing.
    """
    path = role_dir / "tasks" / "main.yml"
    if not path.is_file():
        return [f"{role_dir.name}: tasks/main.yml is missing"]
    tasks = _load_tasks(path)
    if tasks is None:
        return [f"{role_dir.name}: tasks/main.yml must be a list of tasks"]
    findings: list[str] = []
    for task in tasks:
        tags = _tags(task)
        if is_guard_task(role_dir.name, task):
            continue
        if not isinstance(tags, list) or "always" not in tags:
            findings.append(
                f"{role_dir.name}: every task in tasks/main.yml must be tagged always "
                f"(or be a guard task tagged only {guard_tag(role_dir.name)})"
            )
    return findings + check_guard_tags(role_dir)


def check_roles(roles_dir: Path) -> list[str]:
    """Return findings for every role directory below ``roles_dir``."""
    return [
        finding
        for role_dir in sorted(roles_dir.iterdir())
        if role_dir.is_dir()
        for finding in check_role(role_dir)
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roles_dir", nargs="?", type=Path, default=Path("roles"))
    arguments = parser.parse_args(argv)
    findings = check_roles(arguments.roles_dir)
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"{len(findings)} role specification problem(s)", file=sys.stderr)
        return 1
    print(f"role argument specs match defaults in {arguments.roles_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
