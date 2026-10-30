"""Parameters of ansible-core modules that run a command of the caller's choice (FREES-159).

Besides ``shell``, ``command``, ``raw``, ``script``, ``expect`` and ``cron``, several
ansible-core modules take a parameter that names a command, an executable or options of one
that they run: ``validate`` of the file modules, ``dpkg_options`` (``--pre-invoke``),
``extra_opts`` of ``unarchive`` (``tar --to-command``), ``ssh_opts`` of ``git``
(``ProxyCommand``), the ``reboot`` commands, ``fact_path`` (executable facts), the ``use``
backend of ``package`` and ``service`` (any module) and ``conf_file`` of ``dnf`` (a plugin
path). They are refused in every form in which a task can pass them (ADR 0004).

``ALLOWED_PARAMETERS`` lists the reviewed exceptions by file, module, parameter and exact literal
value. The only one is the ``visudo`` check of the sudo drop-ins (ADR 0022, FREES-175): sudo
stops reading its whole configuration at a syntax error, so a drop-in is moved into place only
after ``/usr/sbin/visudo -cf`` accepted the temporary file. A templated value, another value,
another module or another file is refused as before.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml

from tools.lint.repo_rules.ansible_tasks import module_name, scalar_items, task_mappings
from tools.lint.repo_rules.common import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

VALIDATE: Final[frozenset[str]] = frozenset({"validate"})
MODULE_PARAMETERS: Final[dict[str, frozenset[str]]] = {
    "apt": frozenset({"dpkg_options"}),
    "assemble": VALIDATE,
    "blockinfile": VALIDATE,
    "copy": VALIDATE,
    "dnf": frozenset({"conf_file"}),
    "dnf5": frozenset({"conf_file"}),
    "gather_facts": frozenset({"fact_path"}),
    "include_vars": frozenset({"extensions"}),
    "git": frozenset({"executable", "ssh_opts"}),
    "lineinfile": VALIDATE,
    "mount_facts": frozenset({"mount_binary"}),
    "package": frozenset({"use"}),
    "pip": frozenset({"executable", "extra_args", "virtualenv_command", "virtualenv_python"}),
    "reboot": frozenset({"boot_time_command", "reboot_command", "search_paths", "test_command"}),
    "replace": VALIDATE,
    "service": frozenset({"use"}),
    "setup": frozenset({"fact_path"}),
    "subversion": frozenset({"executable"}),
    "template": VALIDATE,
    "unarchive": frozenset({"extra_opts"}),
}
ALL_PARAMETERS: Final[frozenset[str]] = frozenset(
    parameter for parameters in MODULE_PARAMETERS.values() for parameter in parameters
)
ALLOWED_PARAMETERS: Final[frozenset[tuple[Path, str, str, str]]] = frozenset(
    {
        (
            Path("roles/remediate/tasks/sudo_dropin_apply.yml"),
            "copy",
            "validate",
            "/usr/sbin/visudo -cf %s",
        )
    }
)
PLAY_KEYWORDS: Final[frozenset[str]] = frozenset({"fact_path"})
ARGS_KEY: Final[str] = "args"
MODULE_KEY: Final[str] = "module"
ACTION_KEYS: Final[frozenset[str]] = frozenset({"action", "local_action"})
DEFAULTS_KEY: Final[str] = "module_defaults"
GROUP_PREFIX: Final[str] = "group/"


def _problem(module: str, parameter: str) -> str:
    return (
        f"parameter {parameter!r} of {module!r} is not allowed: the module runs the command, "
        "executable or options it names (ADR 0004)"
    )


def _free_form_names(text: str) -> Iterator[str]:
    for word in text.split():
        name, separator, _ = word.partition("=")
        if separator:
            yield name


def _parameter_nodes(value: yaml.Node) -> Iterator[tuple[yaml.Node, str, yaml.Node | None]]:
    if isinstance(value, yaml.MappingNode):
        for name, key, inner in scalar_items(value):
            yield key, name, inner
    elif isinstance(value, yaml.ScalarNode):
        yield from ((value, name, None) for name in _free_form_names(str(value.value)))


def _allowed(relative: Path | None, module: str, parameter: str, value: yaml.Node | None) -> bool:
    """Return whether the reviewed exception list allows ``parameter`` with this exact value.

    Only a plain scalar of the mapping form counts: a quoted, templated, free-form or
    non-scalar value is never allowed.
    """
    if relative is None or not isinstance(value, yaml.ScalarNode) or value.style is not None:
        return False
    return (relative, module_name(module), parameter, str(value.value)) in ALLOWED_PARAMETERS


def _action_module(value: yaml.Node) -> tuple[str, list[yaml.Node]] | None:
    if isinstance(value, yaml.ScalarNode):
        words = str(value.value).split(maxsplit=1)
        return (words[0], [value]) if words else None
    if isinstance(value, yaml.MappingNode):
        for name, _, inner in scalar_items(value):
            if name == MODULE_KEY and isinstance(inner, yaml.ScalarNode):
                words = str(inner.value).split(maxsplit=1)
                if words:
                    return words[0], [value, inner]
    return None


def _task_findings(
    task: yaml.MappingNode, relative: Path | None
) -> Iterator[tuple[yaml.Node, str]]:
    items = list(scalar_items(task))
    modules: list[tuple[str, list[yaml.Node]]] = []
    for name, key, value in items:
        if name in PLAY_KEYWORDS:
            yield key, f"keyword {name!r} is not allowed: Ansible runs executable facts there"
        elif module_name(name.strip()) in MODULE_PARAMETERS:
            modules.append((name.strip(), [value]))
        elif name in ACTION_KEYS:
            found = _action_module(value)
            if found is not None and module_name(found[0]) in MODULE_PARAMETERS:
                modules.append(found)
    arguments = [value for name, _, value in items if name == ARGS_KEY]
    for module, sources in modules:
        refused = MODULE_PARAMETERS[module_name(module)]
        for source in (*sources, *arguments):
            for node, parameter, given in _parameter_nodes(source):
                if parameter in refused and not (
                    any(source is item for item in sources)
                    and _allowed(relative, module, parameter, given)
                ):
                    yield node, _problem(module, parameter)


def _defaults_findings(value: yaml.Node) -> Iterator[tuple[yaml.Node, str]]:
    entries = value.value if isinstance(value, yaml.SequenceNode) else [value]
    for entry in entries:
        if not isinstance(entry, yaml.MappingNode):
            continue
        for module, _, parameters in scalar_items(entry):
            if module.startswith(GROUP_PREFIX):
                refused = ALL_PARAMETERS
            else:
                refused = MODULE_PARAMETERS.get(module_name(module.strip()), frozenset())
            for node, parameter, _ in _parameter_nodes(parameters):
                if parameter in refused:
                    yield node, _problem(module, parameter)


def _all_findings(
    documents: Iterable[yaml.Node], relative: Path | None
) -> Iterator[tuple[yaml.Node, str]]:
    for document in documents:
        if isinstance(document, yaml.SequenceNode):
            for task in task_mappings(document):
                yield from _task_findings(task, relative)
                for name, _, value in scalar_items(task):
                    if name == DEFAULTS_KEY:
                        yield from _defaults_findings(value)


def module_parameter_findings(
    path: Path, documents: Iterable[yaml.Node], relative: Path | None = None
) -> list[Violation]:
    """Reject module parameters that run a command, an executable or its options.

    ``relative`` is the path below the repository root; only there can an entry of
    :data:`ALLOWED_PARAMETERS` apply.
    """
    return sorted(
        {
            Violation(path, node.start_mark.line + 1, message)
            for node, message in _all_findings(documents, relative)
        }
    )
