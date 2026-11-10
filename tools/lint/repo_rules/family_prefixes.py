"""Give the task files of each remediation family a variable prefix of its own (FREES-208).

The remediate role names every internal variable ``__linux_compliance_remediate_<name>``, and
``tools/roles/generate_role_guards.py`` classifies each as a fact, a task variable or a constant
of the whole role: a name that one task file sets as a fact and another as a task variable makes
the generator refuse the role, and two families that set the same fact overwrite each other's
value when both run. Two pull requests (FREES-107 and the PAM configuration families) each chose
``__linux_compliance_remediate_sc_`` and only collided after both had merged. The convention of
the existing files makes such a collision impossible, and this rule group checks it:

* The task files of ``roles/remediate/tasks`` other than the role's own entry files
  (``main.yml``, ``dispatch.yml`` and the generated ``internal_variables.yml``) form groups: two
  files belong to one group when one includes the other as ``{{ role_path }}/tasks/<file>``, so
  a family file and its helpers are one group, and so are the families that share helpers
  (``sysctl``, ``ipv4_parameters`` and ``ipv6_parameters`` with ``sysctl_parameters.yml``,
  ``faillock`` and ``pwhistory`` with the ``pam_conf_*`` helpers).
* An internal variable that a task file defines (a ``set_fact`` key, a ``register``, a key of a
  task's ``vars`` or a ``loop_var``, in blocks at any depth, as the role-guard generator reads
  them) has the prefix ``__linux_compliance_remediate_<xx>_``, where ``<xx>`` is the first
  component of its name after the role's prefix; the name ``__linux_compliance_remediate_<xx>``
  itself has that prefix too.
* Every group uses exactly one such prefix, no other group uses it, and it is neither the first
  component of a constant of the role's variable files nor that of a name that the role shares
  between families.
* Shared names are exempt: the names that ``main.yml`` and ``dispatch.yml`` define, such as
  ``__linux_compliance_remediate_results``, to which every family adds its results, and
  ``__linux_compliance_remediate_rule``, the rule that a family file hands to its helpers
  (``SHARED_NAMES``, the family file contract of ``docs/remediation.md``).

A task file that cannot be parsed is left to the other rules. Violations are reported for the
file being checked, at the first line that names the variable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml

from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

ROLE: Final[Path] = Path("roles/remediate")
TASKS_DIRECTORY: Final[Path] = ROLE / "tasks"
VARIABLES_DIRECTORY: Final[Path] = ROLE / "vars"
ROLE_PREFIX: Final[str] = "__linux_compliance_remediate_"
ENTRY_FILES: Final[frozenset[str]] = frozenset(
    {"main.yml", "dispatch.yml", "internal_variables.yml"}
)
SHARED_SOURCES: Final[frozenset[str]] = frozenset({"main.yml", "dispatch.yml"})
SHARED_NAMES: Final[frozenset[str]] = frozenset({"__linux_compliance_remediate_rule"})
TASK_SUFFIXES: Final[frozenset[str]] = frozenset({".yml", ".yaml"})
NESTED: Final[tuple[str, ...]] = ("block", "rescue", "always")
SET_FACT: Final[str] = "ansible.builtin.set_fact"
FACT_OPTIONS: Final[frozenset[str]] = frozenset({"cacheable"})
INCLUDED_FILE: Final[re.Pattern[str]] = re.compile(
    r"\{\{ role_path \}\}/tasks/([A-Za-z0-9_][A-Za-z0-9_.-]*\.ya?ml)"
)
REFERENCE: Final[str] = "(FREES-208)"

Findings = dict[str, list[tuple[int, str]]]
Prefixes = dict[str, list[str]]


@dataclass(frozen=True, slots=True)
class TaskFile:
    """A task file of the role: its text, the variables it defines and the files it includes."""

    text: str
    defined: frozenset[str]
    includes: frozenset[str]


def prefix_of(name: str) -> str:
    """Return the first component of an internal variable name after the role's prefix."""
    return name.removeprefix(ROLE_PREFIX).split("_", 1)[0]


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


def _defined(task: dict[str, object]) -> set[str]:
    """Return every name that ``task`` defines, as the role-guard generator classifies them."""
    names = {key for key in _keys(task.get(SET_FACT)) if key not in FACT_OPTIONS}
    register = task.get("register")
    if isinstance(register, str):
        names.add(register)
    names.update(_keys(task.get("vars")))
    loop_control = task.get("loop_control")
    if isinstance(loop_control, dict):
        loop_var = cast("dict[str, object]", loop_control).get("loop_var")
        if isinstance(loop_var, str):
            names.add(loop_var)
    return {name for name in names if name.startswith(ROLE_PREFIX)}


def _task_file(text: str) -> TaskFile | None:
    """Return what a task file defines and includes, or ``None`` when it is not YAML."""
    try:
        document = cast("object", yaml.load(text, Loader=yaml.CSafeLoader))
    except yaml.YAMLError:
        return None
    defined: set[str] = set()
    for task in _tasks(document):
        defined.update(_defined(task))
    return TaskFile(text, frozenset(defined), frozenset(INCLUDED_FILE.findall(text)))


def _constant_prefixes(root: Path) -> set[str]:
    """Return the first components of the constants of the role's variable files."""
    found: set[str] = set()
    directory = root / VARIABLES_DIRECTORY
    if not directory.is_dir():
        return found
    for path in sorted(directory.iterdir()):
        if path.suffix not in TASK_SUFFIXES or not path.is_file():
            continue
        try:
            loaded = cast(
                "object", yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.CSafeLoader)
            )
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            continue
        found.update(prefix_of(name) for name in _keys(loaded) if name.startswith(ROLE_PREFIX))
    return found


def read_task_files(directory: Path) -> dict[str, TaskFile]:
    """Return the task files of ``directory`` that are regular YAML files, by file name."""
    files: dict[str, TaskFile] = {}
    for path in sorted(directory.iterdir()):
        if path.suffix not in TASK_SUFFIXES or not path.is_file() or path.is_symlink():
            continue
        try:
            parsed = _task_file(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if parsed is not None:
            files[path.name] = parsed
    return files


def groups(files: Mapping[str, TaskFile]) -> list[list[str]]:
    """Return the task files outside the entry files, grouped by the includes between them."""
    members = sorted(name for name in files if name not in ENTRY_FILES)
    parent = {name: name for name in members}

    def find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    for name in members:
        for included in files[name].includes:
            if included in parent:
                parent[find(included)] = find(name)
    groups: dict[str, list[str]] = {}
    for name in members:
        groups.setdefault(find(name), []).append(name)
    return sorted(groups.values())


def _line(text: str, name: str) -> int:
    match = re.search(re.escape(name) + r"(?![A-Za-z0-9_])", text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _listed(names: Iterable[str]) -> str:
    return ", ".join(sorted(names))


def _prefixes(group: list[str], files: Mapping[str, TaskFile], shared: set[str]) -> Prefixes:
    """Return the internal variables that the files of ``group`` define, by prefix."""
    by_prefix: Prefixes = {}
    for name in group:
        for variable in sorted(files[name].defined - shared):
            found = by_prefix.setdefault(prefix_of(variable), [])
            if variable not in found:
                found.append(variable)
    return by_prefix


def _shared_names(files: Mapping[str, TaskFile]) -> set[str]:
    """Return ``SHARED_NAMES`` and every name that ``main.yml`` and ``dispatch.yml`` define."""
    shared = set(SHARED_NAMES)
    for name in SHARED_SOURCES & files.keys():
        shared.update(files[name].defined)
    return shared


def analyse(root: Path) -> Findings:
    """Return the findings of every task file of the remediate role below ``root``, by file name."""
    directory = root / TASKS_DIRECTORY
    if not directory.is_dir():
        return {}
    files = read_task_files(directory)
    shared = _shared_names(files)
    reserved = _constant_prefixes(root) | {prefix_of(name) for name in shared}
    used = [(group, _prefixes(group, files, shared)) for group in groups(files)]
    owners: dict[str, list[list[str]]] = {}
    for group, by_prefix in used:
        for prefix in by_prefix:
            owners.setdefault(prefix, []).append(group)
    findings: Findings = {}
    for group, by_prefix in used:
        for prefix, variables in sorted(by_prefix.items()):
            messages = _messages(prefix, group, by_prefix, owners, reserved)
            if messages:
                _report(findings, files, group, variables, messages)
    return findings


def _report(
    findings: Findings,
    files: Mapping[str, TaskFile],
    group: list[str],
    variables: list[str],
    messages: list[str],
) -> None:
    """Add ``messages`` to every file of ``group`` that defines one of ``variables``."""
    for name in group:
        mine = [variable for variable in variables if variable in files[name].defined]
        if mine:
            line = _line(files[name].text, mine[0])
            findings.setdefault(name, []).extend((line, text) for text in messages)


def _messages(
    prefix: str,
    group: list[str],
    by_prefix: Prefixes,
    owners: Mapping[str, list[list[str]]],
    reserved: set[str],
) -> list[str]:
    full = f"{ROLE_PREFIX}{prefix}_"
    messages: list[str] = []
    if len(by_prefix) > 1:
        messages.append(
            f"the task files of one family ({_listed(group)}) define internal variables with "
            f"the prefixes {_listed(f'{ROLE_PREFIX}{other}_' for other in by_prefix)}; give "
            f"them the one prefix of the family {REFERENCE}"
        )
    others = [other for other in owners.get(prefix, []) if other is not group]
    if others:
        messages.append(
            f"the internal variable prefix {full} is also used by the task files of another "
            f"family ({'; '.join(_listed(other) for other in others)}); every family needs a "
            f"prefix of its own {REFERENCE}"
        )
    if prefix in reserved:
        messages.append(
            f"the internal variable prefix {full} is the first component of a constant of the "
            f"role or of a name that the role shares between families; choose another {REFERENCE}"
        )
    return messages


def family_prefix_findings(
    path: Path, relative: Path | None, root: Path, analysis: Findings | None = None
) -> list[Violation]:
    """Return the findings of ``path`` when it is a task file of the remediate role.

    ``analysis`` is the result of :func:`analyse` for ``root``, computed once by ``check_paths``;
    without it the role's task files are analysed for this path alone.
    """
    if relative is None or relative.parent != TASKS_DIRECTORY or relative.name in ENTRY_FILES:
        return []
    found = analyse(root) if analysis is None else analysis
    return [Violation(path, line, message) for line, message in found.get(relative.name, [])]
