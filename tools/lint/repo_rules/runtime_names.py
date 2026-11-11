"""Names of arguments and variables that Ansible learns only while the play runs (FREES-203).

The rules of FREES-159 read the literal keys of a task: :mod:`tools.lint.repo_rules.exec_modules`
refuses module parameters that run a command, and :mod:`tools.lint.repo_rules.exec_variables`
refuses variables that change what Ansible executes. Ansible also takes names from places that
those rules cannot read, and ansible-core 2.21.6 runs each of the following:

* ``set_fact`` templates its keys, so ``"{{ 'ansible_python' ~ '_interpreter' }}": /tmp/x`` sets the
  interpreter, ``ansible_connection`` or ``ansible_become_method``, and a key ``"{{ item }}"`` sets
  every variable that ``loop`` names.
* A module argument written as one template becomes the arguments at run time: the ``args``
  keyword given as a string (``_variable_params`` of ``ModuleArgsParser``), a free-form task value
  or ``action`` string such as ``"{{ d }}"`` (its ``_raw_params``) and a ``module_defaults`` entry
  given as a string. ``ansible.builtin.copy: "{{ d }}"`` runs the ``validate`` command that ``d``
  holds.
* ``loop_control`` ``loop_var`` and ``index_var`` name a variable that each loop item sets for the
  task, and Ansible templates ``loop_var``: ``loop_var: ansible_python_interpreter`` runs the module
  with the interpreter of the item. ``register`` and the ``name`` of ``include_vars`` and of a
  ``vars_prompt`` entry name a variable as well.

So in every task list of the repository (a YAML document whose root is a sequence, followed with
:func:`~tools.lint.repo_rules.ansible_tasks.task_mappings`):

* the arguments of ``set_fact`` are a mapping whose keys are literal strings. A templated key is
  accepted only below ``extensions/molecule/``, whose lifecycle harness switches the catalogue
  toggles of a family by name (``"{{ item }}": true``) in throwaway instances; the shipped roles and
  playbooks and the test playbooks have none;
* ``args``, every ``module_defaults`` entry and the mapping form of ``action`` and
  ``local_action`` are mappings with literal keys, and a free-form argument string (a task value or
  the rest of an ``action`` string) holds no template. The targets of ``include_tasks``,
  ``import_tasks``, ``import_playbook`` and the role includes are exempt, because
  :mod:`tools.lint.repo_rules.ansible_tasks` checks them as paths and role names;
* ``loop_var``, ``index_var``, ``register`` and the ``name`` of ``include_vars`` and of a
  ``vars_prompt`` entry are literal names that
  :func:`~tools.lint.repo_rules.exec_variables.is_exec_variable` does not match.

A key is a module name when it is not a keyword of a play, block, task or handler of ansible-core
(``PLAY_KEYWORDS`` and :data:`~tools.lint.repo_rules.remediate_modules.TASK_KEYWORDS`, both kept
equal to the installed ansible-core by unit tests).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.ansible_tasks import (
    ACTION_KEYS,
    MODULE_KEY,
    ROLE_INCLUDE_MODULES,
    TASK_INCLUDE_MODULES,
    TEMPLATE_MARKERS,
    module_name,
    scalar_items,
    task_mappings,
)
from tools.lint.repo_rules.common import Violation
from tools.lint.repo_rules.exec_variables import is_exec_variable
from tools.lint.repo_rules.remediate_modules import LOOP_PREFIX, TASK_KEYWORDS

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path

PLAY_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "fact_path",
        "force_handlers",
        "gather_facts",
        "gather_subset",
        "gather_timeout",
        "handlers",
        "hosts",
        "max_fail_percentage",
        "order",
        "post_tasks",
        "pre_tasks",
        "roles",
        "serial",
        "strategy",
        "tasks",
        "validate_argspec",
        "vars_files",
        "vars_prompt",
    }
)
SET_FACT: Final[str] = "set_fact"
INCLUDE_VARS: Final[str] = "include_vars"
ARGS_KEYWORD: Final[str] = "args"
DEFAULTS_KEYWORD: Final[str] = "module_defaults"
LOOP_CONTROL_KEYWORD: Final[str] = "loop_control"
REGISTER_KEYWORD: Final[str] = "register"
VARS_PROMPT_KEYWORD: Final[str] = "vars_prompt"
NAME_KEY: Final[str] = "name"
LOOP_VARIABLE_KEYS: Final[frozenset[str]] = frozenset({"loop_var", "index_var"})
PATH_ARGUMENT_MODULES: Final[frozenset[str]] = TASK_INCLUDE_MODULES | ROLE_INCLUDE_MODULES
HARNESS_DIRECTORY: Final[tuple[str, str]] = ("extensions", "molecule")
STRING_TAG: Final[str] = "tag:yaml.org,2002:str"

SET_FACT_KEY_MESSAGE: Final[str] = (
    "set_fact key {key!r} is not allowed: Ansible templates set_fact keys, so the variable it "
    "sets, which may change what Ansible executes, is known only at run time; use a literal "
    "variable name (ADR 0004)"
)
MAPPING_MESSAGE: Final[str] = (
    "{place} must be a mapping with literal keys: Ansible turns a template there into module "
    "arguments at run time, which the rules on module parameters and variables cannot read "
    "(ADR 0004)"
)
FREE_FORM_MESSAGE: Final[str] = (
    "free-form arguments {text!r} of {module!r} hold a template, which Ansible may turn into "
    "module arguments at run time; write the arguments as a mapping (ADR 0004)"
)
VARIABLE_NAME_MESSAGE: Final[str] = (
    "{place} {text!r} is not allowed: it names the variable that the task sets, which must be a "
    "literal name that does not change what Ansible executes (ADR 0004)"
)


def _is_templated(text: str) -> bool:
    return any(marker in text for marker in TEMPLATE_MARKERS)


def is_harness_file(relative: Path | None) -> bool:
    """Return whether ``relative`` is below ``extensions/molecule/``, compared case-folded."""
    if relative is None:
        return False
    return tuple(part.casefold() for part in relative.parts[: len(HARNESS_DIRECTORY)]) == (
        HARNESS_DIRECTORY
    )


def _is_module_key(name: str) -> bool:
    return not (name in TASK_KEYWORDS or name in PLAY_KEYWORDS or name.startswith(LOOP_PREFIX))


def _literal_key_problems(
    node: yaml.Node, place: str, *, set_fact: bool = False, harness: bool = False
) -> Iterator[tuple[yaml.Node, str]]:
    """Yield a problem unless ``node`` is a mapping whose keys are literal strings.

    The keys of ``set_fact`` arguments name variables; a templated one is accepted only in
    the harness.
    """
    if not isinstance(node, yaml.MappingNode):
        yield node, MAPPING_MESSAGE.format(place=place)
        return
    for key, _ in node.value:
        if not isinstance(key, yaml.ScalarNode):
            yield key, MAPPING_MESSAGE.format(place=place)
    for name, key, _ in scalar_items(node):
        if _is_templated(name) and not (set_fact and harness):
            message = (
                SET_FACT_KEY_MESSAGE.format(key=name)
                if set_fact
                else MAPPING_MESSAGE.format(place=place)
            )
            yield key, message


def _variable_name_problems(node: yaml.Node, place: str) -> Iterator[tuple[yaml.Node, str]]:
    """Yield a problem unless ``node`` is a literal variable name that changes no execution."""
    text = str(node.value) if isinstance(node, yaml.ScalarNode) else None
    if text is None or _is_templated(text) or is_exec_variable(text.strip()):
        shown = "a mapping or sequence" if text is None else text
        yield node, VARIABLE_NAME_MESSAGE.format(place=place, text=shown)


def _free_form_problems(module: str, node: yaml.Node) -> Iterator[tuple[yaml.Node, str]]:
    """Yield a problem for a free-form argument string of ``module`` that holds a template."""
    if (
        isinstance(node, yaml.ScalarNode)
        and node.tag == STRING_TAG
        and module_name(module.strip()) not in PATH_ARGUMENT_MODULES
        and _is_templated(str(node.value))
    ):
        yield node, FREE_FORM_MESSAGE.format(text=node.value, module=module)


def _free_form_name_problems(node: yaml.Node) -> Iterator[tuple[yaml.Node, str]]:
    """Yield a problem for every ``name=`` of a free-form ``include_vars`` string."""
    if not isinstance(node, yaml.ScalarNode):
        return
    for word in str(node.value).split():
        key, separator, value = word.partition("=")
        if separator and key == NAME_KEY:
            yield from _variable_name_problems(
                yaml.ScalarNode(STRING_TAG, value, node.start_mark, node.end_mark),
                "include_vars name",
            )


def _module_problems(
    name: str, value: yaml.Node, *, harness: bool
) -> Iterator[tuple[yaml.Node, str]]:
    """Yield the problems of the arguments ``value`` of the module key ``name``."""
    module = module_name(name.strip())
    if module == SET_FACT and isinstance(value, yaml.MappingNode):
        yield from _literal_key_problems(value, "set_fact", set_fact=True, harness=harness)
    elif module == INCLUDE_VARS and isinstance(value, yaml.MappingNode):
        for key, _, inner in scalar_items(value):
            if key == NAME_KEY:
                yield from _variable_name_problems(inner, "include_vars name")
    elif module == INCLUDE_VARS:
        yield from _free_form_name_problems(value)
    yield from _free_form_problems(name, value)


def _action_string_problems(node: yaml.Node) -> Iterator[tuple[yaml.Node, str]]:
    """Yield a problem when an action string, the module word and its arguments, is templated.

    A templated module word is refused by the module rules as well.
    """
    if isinstance(node, yaml.ScalarNode):
        words = str(node.value).split(maxsplit=1)
        yield from _free_form_problems(words[0] if words else "", node)


def _action_problems(keyword: str, value: yaml.Node) -> Iterator[tuple[yaml.Node, str]]:
    """Yield the problems of an ``action`` or ``local_action`` value.

    Its string form is checked after the module word like a free-form argument string; its
    mapping form must have literal keys, a mapping ``args`` and the same ``module`` string.
    """
    if isinstance(value, yaml.ScalarNode):
        yield from _action_string_problems(value)
        return
    yield from _literal_key_problems(value, keyword)
    if not isinstance(value, yaml.MappingNode):
        return
    for key, _, inner in scalar_items(value):
        if key == ARGS_KEYWORD:
            yield from _literal_key_problems(inner, f"{keyword} args")
        elif key == MODULE_KEY:
            yield from _action_string_problems(inner)


def _defaults_problems(value: yaml.Node) -> Iterator[tuple[yaml.Node, str]]:
    """Yield a problem for every ``module_defaults`` entry that is not a literal mapping."""
    entries = value.value if isinstance(value, yaml.SequenceNode) else [value]
    for entry in entries:
        if not isinstance(entry, yaml.MappingNode):
            yield entry, MAPPING_MESSAGE.format(place=DEFAULTS_KEYWORD)
            continue
        for module, _, arguments in scalar_items(entry):
            yield from _literal_key_problems(arguments, f"{DEFAULTS_KEYWORD} of {module}")


def _keyword_problems(name: str, value: yaml.Node) -> Iterator[tuple[yaml.Node, str]]:
    """Yield the problems of the task or play keyword ``name`` with ``value``."""
    if name == ARGS_KEYWORD:
        yield from _literal_key_problems(value, ARGS_KEYWORD)
    elif name == DEFAULTS_KEYWORD:
        yield from _defaults_problems(value)
    elif name == REGISTER_KEYWORD:
        yield from _variable_name_problems(value, REGISTER_KEYWORD)
    elif name == LOOP_CONTROL_KEYWORD:
        yield from _named_entry_problems([value], LOOP_VARIABLE_KEYS)
    elif name == VARS_PROMPT_KEYWORD and isinstance(value, yaml.SequenceNode):
        yield from _named_entry_problems(value.value, frozenset({NAME_KEY}), "vars_prompt name")


def _named_entry_problems(
    entries: Iterable[yaml.Node], keys: frozenset[str], place: str | None = None
) -> Iterator[tuple[yaml.Node, str]]:
    """Yield the problems of the variable names under ``keys`` of every mapping of ``entries``.

    ``place`` names the setting in the message; without it the key does.
    """
    for entry in entries:
        if isinstance(entry, yaml.MappingNode):
            for key, _, inner in scalar_items(entry):
                if key in keys:
                    yield from _variable_name_problems(inner, place or key)


def _task_problems(task: yaml.MappingNode, *, harness: bool) -> Iterator[tuple[yaml.Node, str]]:
    for name, _, value in scalar_items(task):
        if name in ACTION_KEYS:
            yield from _action_problems(name, value)
        elif _is_module_key(name):
            yield from _module_problems(name, value, harness=harness)
        else:
            yield from _keyword_problems(name, value)


def runtime_name_findings(
    path: Path, relative: Path | None, documents: Iterable[yaml.Node]
) -> list[Violation]:
    """Refuse arguments and variables of a task list whose names are known only at run time.

    ``relative`` is the repository path of ``path``; a templated ``set_fact`` key is accepted
    only below ``extensions/molecule/``.
    """
    harness = is_harness_file(relative)
    found: set[Violation] = set()
    for document in documents:
        if not isinstance(document, yaml.SequenceNode):
            continue
        for task in task_mappings(document):
            for node, message in _task_problems(task, harness=harness):
                found.add(Violation(path, node.start_mark.line + 1, message))
    return sorted(found)
