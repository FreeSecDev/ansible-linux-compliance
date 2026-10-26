"""Generate the family dispatch of the remediate role and the internal-variable guards.

Two kinds of task file are derived from the repository and checked for drift in CI
(FREES-137):

* ``roles/remediate/tasks/dispatch.yml``: one static ``include_tasks`` per family of the
  registry in ``roles/remediate/vars/rules.yml`` that has a rule with a native remediation
  (``generate_toggles.native_families``), in registry order; only such a family can have
  apply or cleanup work in the plan, a family whose rules are all ``audit_only`` is never
  included and needs no task file, and planned work of a family without an include fails the
  completeness check of the role. Each names the literal
  file ``{{ role_path }}/tasks/<family>.yml`` and runs for the plan entry of that family
  only, so no variable chooses which file is loaded.
* ``roles/<role>/tasks/internal_variables.yml`` for the audit, evidence, remediate and verify
  roles: the first tasks of every entry point. A role parameter, an include parameter and an
  extra variable outrank every fact that a role sets, so an internal
  ``__linux_compliance_<role>_*`` variable supplied from outside would replace the role's own
  value. The guard first refuses every internal fact, task variable and ``include_vars``
  constant that the ``varnames`` lookup sees but ``hostvars`` does not: such a name was passed
  as a role, include, block or play parameter, and it is refused whatever its value, because
  a template can imitate the sentinels below (FREES-157). The guard then sets every fact and
  registered variable of the role to a sentinel and asserts that each reads back as the
  sentinel; it gives every task and loop variable the sentinel as a task variable of the
  assertion and asserts the same; and it asserts that every constant of the role's variable
  files is either undefined or equal to the file. It then repeats the reset and the read-back
  with a second sentinel and resets the facts to the first one again: a fixed value supplied
  from outside that equals the first sentinel fails the second read-back (FREES-153). Any
  other value can only come from outside, and the role stops before it changes anything.

A run output (``RUN_OUTPUTS``) is an internal fact that the role sets for a later play of the
same run to read, such as the collection marker of the evidence role (FREES-154). Resetting it
to a sentinel at the start of an entry point would make a host whose collection failed look
like a host with a marker, so it is neither reset nor read back; it is checked where it is set
and read, and the play that starts the run refuses it when it is already set. Every run output
must be a fact that the role sets.

``playbooks/run_start.yml`` (``tools/roles/run_start.py``) is generated as well: the check that
every shipped playbook runs first, which refuses an internal name or a role output, every public
``linux_compliance_*`` fact that a role sets, that is already in ``hostvars`` when the run starts.

The variables are found in the role's task and variable files. A variable that the tool
cannot classify, or that is both a fact and a task variable, is an error, and so is a role
below ``roles/`` that names an internal variable of its own but is not in ``GUARDED_ROLES``,
so a new internal variable or role cannot be added without the guard. With ``--check``
nothing is written: the tool prints a unified diff of every file that differs and exits with
status 1.
"""

from __future__ import annotations

import argparse
import re
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml

from tools.roles import generate_toggles, run_start

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

GenerationError = generate_toggles.GenerationError
ROLES: Final[Path] = Path("roles")
DISPATCH: Final[Path] = Path("roles/remediate/tasks/dispatch.yml")
GUARD_FILE: Final[str] = "internal_variables.yml"
GUARDED_ROLES: Final[tuple[str, ...]] = ("audit", "evidence", "remediate", "verify")
RUN_OUTPUTS: Final[dict[str, frozenset[str]]] = {
    "evidence": frozenset({"__linux_compliance_evidence_run_bundle"}),
}
ROLE_TASK_FILES: Final[frozenset[str]] = frozenset({"main", "dispatch", "internal_variables"})
PUBLIC_PREFIX: Final[str] = "linux_compliance_"
SENTINEL: Final[str] = "__linux_compliance_unset__"
SECOND_SENTINEL: Final[str] = "__linux_compliance_unset_again__"
NESTED: Final[tuple[str, ...]] = ("block", "rescue", "always")
SET_FACT: Final[str] = "ansible.builtin.set_fact"
INCLUDE_VARS: Final[str] = "ansible.builtin.include_vars"
FACT_OPTIONS: Final[frozenset[str]] = frozenset({"cacheable"})
ROLE_PATH_FILE: Final[re.Pattern[str]] = re.compile(r"\{\{ role_path \}\}(/[A-Za-z0-9_./-]+)")
PLAIN_FILE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.yml")
ROLE_TITLES: Final[dict[str, str]] = {
    "audit": "Audit",
    "evidence": "Evidence",
    "remediate": "Remediate",
    "verify": "Verify",
}


@dataclass
class RoleVariables:
    """The internal variables of one role, by how the role defines them."""

    facts: set[str] = field(default_factory=set[str])
    locals: set[str] = field(default_factory=set[str])
    constants: dict[str, str] = field(default_factory=dict[str, str])
    outputs: set[str] = field(default_factory=set[str])
    cacheable: set[str] = field(default_factory=set[str])
    role_vars: set[str] = field(default_factory=set[str])


def prefix(role: str) -> str:
    """Return the prefix of the internal variables of ``role``."""
    return f"__linux_compliance_{role}_"


def _quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _file_value(source: str) -> str:
    lookup = f"lookup('ansible.builtin.file', role_path ~ {_quote(source)})"
    return f"({lookup} | ansible.builtin.from_yaml)"


def dispatch(families: Iterable[str], tasks_dir: Path) -> str:
    """Return the dispatch task file: one static include per family, in registry order."""
    lines = ["---"]
    for family in families:
        if family in ROLE_TASK_FILES:
            message = f"the family name {family} is the name of a task file of the role"
            raise GenerationError(message)
        if not (tasks_dir / f"{family}.yml").is_file():
            message = f"the family {family} has no task file roles/remediate/tasks/{family}.yml"
            raise GenerationError(message)
        if lines[-1] != "---":
            lines.append("")
        lines.extend(
            [
                f"- name: Remediate | Dispatch the {family} family when the plan gives it work",
                "  ansible.builtin.include_tasks:",
                f'    file: "{{{{ role_path }}}}/tasks/{family}.yml"',
                "    apply:",
                "      tags:",
                "        - always",
                '  loop: "{{ __linux_compliance_remediate_plan.families }}"',
                "  loop_control:",
                "    loop_var: __linux_compliance_remediate_family",
                '    label: "{{ __linux_compliance_remediate_family.name }}"',
                f"  when: __linux_compliance_remediate_family.name == {_quote(family)}",
                "  tags:",
                "    - always",
            ]
        )
    return "\n".join(lines) + "\n"


def _tasks(value: object) -> Iterable[dict[str, object]]:
    pending: list[object] = list(cast("list[object]", value)) if isinstance(value, list) else []
    while pending:
        task = pending.pop(0)
        if not isinstance(task, dict):
            continue
        mapping = cast("dict[str, object]", task)
        yield mapping
        for key in NESTED:
            nested = mapping.get(key)
            if isinstance(nested, list):
                pending.extend(cast("list[object]", nested))


def _keys(value: object) -> list[str]:
    return (
        [str(key) for key in cast("dict[object, object]", value)] if isinstance(value, dict) else []
    )


def _variables_file(role_dir: Path, source: str) -> dict[str, object]:
    path = role_dir / source.lstrip("/")
    loaded = (
        cast("object", yaml.safe_load(path.read_text(encoding="utf-8"))) if path.is_file() else None
    )
    if not isinstance(loaded, dict):
        message = f"{path} must exist and hold a mapping"
        raise GenerationError(message)
    return cast("dict[str, object]", loaded)


def _include_vars(task: dict[str, object], role_dir: Path, found: RoleVariables) -> None:
    options = task[INCLUDE_VARS]
    if not isinstance(options, dict):
        message = f"{role_dir.name}: include_vars must use the mapping form"
        raise GenerationError(message)
    settings = cast("dict[str, object]", options)
    target = str(settings.get("file", ""))
    match = ROLE_PATH_FILE.fullmatch(target)
    if match is not None:
        source = match.group(1)
    elif PLAIN_FILE.fullmatch(target):
        source = f"/vars/{target}"
    else:
        message = (
            f"{role_dir.name}: include_vars file {target!r} is neither a vars file "
            "nor below role_path"
        )
        raise GenerationError(message)
    name = settings.get("name")
    if name is not None:
        found.constants[str(name)] = _file_value(source)
        return
    for key in _variables_file(role_dir, source):
        found.constants[key] = f"{_file_value(source)}[{_quote(key)}]"


def _task_variables(task: dict[str, object], found: RoleVariables) -> None:
    options = task.get(SET_FACT)
    facts = [key for key in _keys(options) if key not in FACT_OPTIONS]
    found.facts.update(facts)
    if isinstance(options, dict) and cast("dict[str, object]", options).get("cacheable") is True:
        found.cacheable.update(facts)
    register = task.get("register")
    if isinstance(register, str):
        found.facts.add(register)
    found.locals.update(_keys(task.get("vars")))
    loop_control = task.get("loop_control")
    if isinstance(loop_control, dict):
        loop_var = cast("dict[str, object]", loop_control).get("loop_var")
        if isinstance(loop_var, str):
            found.locals.add(loop_var)


def role_variables(role_dir: Path, generated: dict[str, str]) -> RoleVariables:
    """Classify every internal variable that the tasks and variables of ``role_dir`` use.

    ``generated`` holds the generated content of task files by file name; it replaces the
    file on disk, and the guard file itself is never analysed.
    """
    role = role_dir.name
    found = RoleVariables()
    if (role_dir / "vars" / "main.yml").is_file():
        for key in _variables_file(role_dir, "/vars/main.yml"):
            found.constants[key] = f"{_file_value('/vars/main.yml')}[{_quote(key)}]"
            found.role_vars.add(key)
    texts = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((role_dir / "tasks").glob("*.yml"))
    }
    texts.update(generated)
    texts.pop(GUARD_FILE, None)
    referenced: set[str] = set()
    for text in texts.values():
        referenced.update(re.findall(re.escape(prefix(role)) + r"[a-z0-9_]+", text))
        for task in _tasks(yaml.safe_load(text)):
            if INCLUDE_VARS in task:
                _include_vars(task, role_dir, found)
            _task_variables(task, found)
    return _checked(role, found, referenced)


def _own(role: str, names: Iterable[str]) -> set[str]:
    return {name for name in names if name.startswith(prefix(role))}


def _checked(role: str, found: RoleVariables, referenced: set[str]) -> RoleVariables:
    owned = RoleVariables(
        _own(role, found.facts),
        _own(role, found.locals),
        {name: value for name, value in found.constants.items() if name.startswith(prefix(role))},
    )
    problems: list[str] = []
    both = owned.facts & owned.locals
    if both:
        problems.append(f"both a fact and a task variable: {', '.join(sorted(both))}")
    constant = set(owned.constants) & (owned.facts | owned.locals)
    if constant:
        problems.append(f"a constant that is also assigned: {', '.join(sorted(constant))}")
    unclassified = referenced - owned.facts - owned.locals - set(owned.constants)
    if unclassified:
        problems.append(f"used but never defined: {', '.join(sorted(unclassified))}")
    declared = RUN_OUTPUTS.get(role, frozenset())
    unset = declared - owned.facts
    if unset:
        problems.append(f"a run output that the role never sets: {', '.join(sorted(unset))}")
    if problems:
        message = f"{role}: internal variables " + "; ".join(problems)
        raise GenerationError(message)
    owned.outputs = owned.facts & declared
    owned.facts -= declared
    owned.cacheable = _own(role, found.cacheable)
    owned.role_vars = _own(role, found.role_vars)
    return owned


def _folded(text: str, indent: int) -> list[str]:
    """Return ``text`` split at spaces into lines of a folded scalar indented by ``indent``."""
    width = generate_toggles.MAX_LINE - indent
    return [" " * indent + line for line in textwrap.wrap(text, width, break_on_hyphens=False)]


def _that(item: str) -> list[str]:
    line = f"      - {item}"
    if len(line) <= generate_toggles.MAX_LINE:
        return [line]
    return ["      - >-", *_folded(item, 8)]


def _reset(title: str, facts: Sequence[str], sentinel: str, purpose: str) -> list[str]:
    """Return the task that sets every fact in ``facts`` to ``sentinel``."""
    lines = [f"- name: {title} | {purpose}", f"  {SET_FACT}:"]
    lines.extend(f"    {name}: {sentinel}" for name in facts)
    lines.extend(["  tags:", "    - always"])
    return lines


def _read_back(
    role: str, found: RoleVariables, sentinel: str, name: str, *, constants: bool
) -> list[str]:
    """Return the assertion that every fact and task variable reads back as ``sentinel``."""
    local = sorted(found.locals)
    lines = [f"- name: {name}", "  ansible.builtin.assert:", "    that:"]
    for variable in [*sorted(found.facts), *local]:
        lines.extend(_that(f"{variable} == {_quote(sentinel)}"))
    if constants:
        for variable, value in sorted(found.constants.items()):
            lines.extend(_that(f"{variable} is not defined or {variable} == {value}"))
    message = (
        f"An internal variable of the {role} role ({prefix(role)}*) is set from outside the role: "
        "by a role parameter, an include parameter (vars of include_role or include_tasks) or an "
        "extra variable (-e), which outrank every fact the role sets. The failed assertion "
        "names it. Remove it and pass only the documented linux_compliance_* variables. "
        "Nothing was scanned, changed or compared."
    )
    lines.extend(["    fail_msg: >-", *_folded(message, 6), "    quiet: true"])
    if local:
        lines.append("  vars:")
        lines.extend(f"    {variable}: {sentinel}" for variable in local)
    lines.extend(["  tags:", "    - always"])
    return lines


def _parameters(role: str, names: Sequence[str], name: str) -> list[str]:
    """Return the assertion that no name in ``names`` is a parameter of the role.

    A role parameter, an include parameter and a block or play variable are visible to the
    ``varnames`` lookup but not in ``hostvars``, so a name that the lookup finds and that is
    not a fact or an extra variable was passed as a parameter, whatever its value.
    """
    lines = [f"- name: {name}", "  ansible.builtin.assert:", "    that:"]
    for variable in names:
        lines.extend(
            _that(
                f"query('ansible.builtin.varnames', '^{variable}$') == [] "
                f"or '{variable}' in (hostvars[inventory_hostname] | list)"
            )
        )
    message = (
        f"An internal variable of the {role} role ({prefix(role)}*) is set from outside the role "
        "as a parameter: a role parameter, a variable of a roles entry, an include parameter "
        "(vars of include_role, import_role, include_tasks or import_tasks) or a block or play "
        "variable. "
        "It is refused by its name, whatever its value, because a template could evaluate to the "
        "value that a later check expects. The failed assertion names it. Remove it and pass only "
        "the documented linux_compliance_* variables. Nothing was scanned, changed or compared."
    )
    lines.extend(["    fail_msg: >-", *_folded(message, 6), "    quiet: true"])
    lines.extend(["  tags:", "    - always"])
    return lines


def guard(role: str, found: RoleVariables) -> str:
    """Return the internal-variable guard task file of ``role``.

    A fact, task variable or ``include_vars`` constant passed as a parameter is refused by its
    name first. The facts are reset to ``SENTINEL`` and read back with the task variables and the
    constants. When the role has facts or task variables, the reset and the read-back are
    repeated with ``SECOND_SENTINEL``, and the facts end as ``SENTINEL``: a value supplied
    from outside cannot equal both sentinels.
    """
    title = ROLE_TITLES[role]
    facts = sorted(found.facts)
    refuse = f"{title} | Refuse internal variables supplied from outside the role"
    tasks: list[list[str]] = []
    parameters = sorted(found.facts | found.locals | (set(found.constants) - found.role_vars))
    if parameters:
        tasks.append(_parameters(role, parameters, f"{refuse} as parameters"))
    if facts:
        tasks.append(_reset(title, facts, SENTINEL, "Reset the internal facts of the role"))
    tasks.append(_read_back(role, found, SENTINEL, refuse, constants=True))
    if facts or found.locals:
        if facts:
            purpose = "Reset the internal facts of the role to the second sentinel"
            tasks.append(_reset(title, facts, SECOND_SENTINEL, purpose))
        second = f"{refuse} as the first sentinel"
        tasks.append(_read_back(role, found, SECOND_SENTINEL, second, constants=False))
    if facts:
        purpose = "Reset the internal facts of the role to the first sentinel again"
        tasks.append(_reset(title, facts, SENTINEL, purpose))
    lines = ["---"]
    for index, task in enumerate(tasks):
        if index:
            lines.append("")
        lines.extend(task)
    return "\n".join(lines) + "\n"


def internal_variable_roles(roles_dir: Path) -> set[str]:
    """Return every role below ``roles_dir`` whose files name an internal variable of its own."""
    found: set[str] = set()
    for role_dir in sorted(path for path in roles_dir.iterdir() if path.is_dir()):
        pattern = re.compile(re.escape(prefix(role_dir.name)) + r"[a-z0-9_]")
        if any(
            pattern.search(path.read_text(encoding="utf-8", errors="replace"))
            for path in sorted(role_dir.rglob("*"))
            if path.is_file()
        ):
            found.add(role_dir.name)
    return found


def outputs(root: Path) -> dict[Path, str]:
    """Return the generated content of every output file below ``root``."""
    catalogue = generate_toggles.load_catalogue(root / generate_toggles.CATALOGUE)
    families = generate_toggles.native_families(catalogue)
    unguarded = internal_variable_roles(root / ROLES) - set(GUARDED_ROLES)
    if unguarded:
        message = (
            f"roles with internal variables but no guard: {', '.join(sorted(unguarded))}; "
            "add them to GUARDED_ROLES and import the guard at every entry point"
        )
        raise GenerationError(message)
    generated: dict[Path, str] = {DISPATCH: dispatch(families, root / DISPATCH.parent)}
    cacheable: set[str] = set()
    for role in GUARDED_ROLES:
        role_dir = root / ROLES / role
        own = {
            path.name: text
            for path, text in generated.items()
            if path.parent == ROLES / role / "tasks"
        }
        found = role_variables(role_dir, own)
        cacheable |= found.cacheable
        generated[ROLES / role / "tasks" / GUARD_FILE] = guard(role, found)
    generated[run_start.RUN_START] = run_start.play(role_outputs(root / ROLES), cacheable)
    return generated


def role_outputs(roles_dir: Path) -> set[str]:
    """Return every public ``linux_compliance_*`` fact that a role below ``roles_dir`` sets."""
    found: set[str] = set()
    for path in sorted(roles_dir.glob("*/tasks/*.yml")):
        for task in _tasks(yaml.safe_load(path.read_text(encoding="utf-8"))):
            found.update(key for key in _keys(task.get(SET_FACT)) if key.startswith(PUBLIC_PREFIX))
    return found


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path())
    parser.add_argument("--check", action="store_true", help="report drift instead of writing")
    arguments = parser.parse_args(argv)
    root = cast("Path", arguments.root)
    try:
        generated = outputs(root)
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if arguments.check:
        differences = generate_toggles.drift(root, generated)
        if differences:
            print("\n".join(differences), file=sys.stderr)
            print("error: the role guards are out of date; run make role-guards", file=sys.stderr)
            return 1
        print("role guards match the roles")
        return 0
    for relative, content in generated.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(content, encoding="utf-8")
    print(f"generated {', '.join(str(path) for path in generated)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
