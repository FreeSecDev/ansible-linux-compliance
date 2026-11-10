"""Remediation runs only reviewed modules (FREES-203, ADR 0032 §1).

ADR 0032 §1 widens ADR 0003 and ADR 0025 §1: a task of ``roles/remediate`` may use an
``ansible.builtin`` module, a module or action plugin of this collection, or a module of a community
collection that is on ``ALLOWED_COMMUNITY_MODULES``. The allow list starts empty, so a module such
as ``community.general.make`` or ``ansible.posix.at`` is refused because it is not listed, not
because of a deny entry. Adding a module to the list needs the security review that ADR 0032 §1
describes, in the same pull request.

The rule reads every YAML document below ``roles/remediate/`` whose root is a sequence, which is how
a task or handler file looks, and follows its tasks and blocks with
:func:`~tools.lint.repo_rules.ansible_tasks.task_mappings`, through aliases and merge keys. A key of
a task that is not a keyword of ``TASK_KEYWORDS`` and does not start with ``with_`` names the
module, and so do the first word of an ``action`` or ``local_action`` string and the ``module`` key
of their mapping form. Such a name must be the fully qualified name of a module of
``BUILTIN_MODULES``, of a ``freesecdev.linux_compliance`` module or of an allow-listed module: a
short name, an ``ansible.legacy`` name and a templated name are refused, because Ansible may resolve
them to any module. An ``action`` or ``local_action`` that is neither a string nor a mapping whose
every ``module`` key is a string is refused too: ansible-core's JSON loader reads a mapping such as
``{"__ansible_unsafe": "zz.evil.pwn"}`` there as the module name.

A fully qualified name is not proof of the code that runs, because a routing entry sends a name to
another plugin before Ansible looks for the file. ansible-core routes more than 3700
``ansible.builtin`` names to other collections (``ansible.builtin.make`` runs
``community.general.make``, ``ansible.builtin.sysctl`` runs ``ansible.posix.sysctl``), so only the
names of ``BUILTIN_MODULES`` are accepted: the module files of the pinned ansible-core that its
``plugin_routing`` neither redirects nor removes. A unit test keeps the list equal to the installed
ansible-core. A ``freesecdev.linux_compliance`` name is accepted only when ``plugins/modules`` or
``plugins/action`` holds its file and ``meta/runtime.yml`` has no routing entry for it other
than ``deprecation``; a ``meta/runtime.yml`` that cannot be read refuses every such name, and
:mod:`tools.lint.repo_rules.remediate_routing` refuses routing there that this rule does not read.

The allow list governs modules, so the role may not run another role's tasks: ``include_role`` and
``import_role`` are refused, and so is a dependency in ``meta/main.yml``. ``include_tasks`` and
``import_tasks`` are accepted only as a task key whose target is ``{{ role_path }}/tasks/`` followed
by a literal relative path. Ansible looks for a plain relative target in the role first, but falls
back to the playbook's directory, whose task files this rule never reads. A document with another
root, such as ``vars/rules.yml`` or ``meta/argument_specs.yml``, is not a task list and is not read.

Ansible also loads role files that are not YAML, or that PyYAML cannot read, as tasks, handlers
and metadata; :mod:`tools.lint.repo_rules.remediate_files` refuses every such file in the role, so
every task and handler file of the role is a document that this rule reads. ``delegate_to``,
``delegate_facts``, ``local_action`` and ``connection`` are refused on every task and block, so the
role never runs a task on the controller or on another host.

The rule guards against mistakes and unreviewed additions; it is not a sandbox against a
contributor who deliberately builds a bypass (ADR 0032, boundary of 2026-11-10). It does not read
Jinja filter, test and lookup plugins of other collections, files that tasks of the role plant
(``files/``, ``templates/``, a module written into one of Ansible's module paths), routing other
than that of modules, action plugins and ``module_utils``, play, inventory and configuration
settings outside the role, or a change to this rule and its tests. The independent review of every
pull request (ADR 0033) covers those.

``BUILTIN_MODULES`` equals the module files of the pinned ansible-core, without exception, so it
also holds ``async_wrapper``, which ansible-core runs on the host for an ``async`` task, and
``import_playbook``, which a role task cannot use. Both are code of ansible-core, so accepting them
lets no other collection's code run, and the drift test that keeps the list equal to ansible-core
fails if they are removed.

A name of ``BUILTIN_MODULES`` is still not proof of the module that runs when its action plugin
chooses that module while the play runs. ``gather_facts`` runs the fact modules that its
``network_os`` argument, ``ansible_network_os`` or ``ansible_facts_modules`` name (``cisco.ios.ios``
runs ``cisco.ios.ios_facts``), ``package`` runs the module that ``ansible_package_use`` or the
``pkg_mgr`` fact names, and ``service`` the one that the ``service_mgr`` fact names; a task can set
each of these, a fact also through a templated ``set_fact`` key. ``DISPATCHING_MODULES`` lists them,
and they are refused although they stay on ``BUILTIN_MODULES``. ``dnf`` also chooses its backend at
run time, but only among ``VALID_BACKENDS`` of ansible-core, ``dnf``, ``dnf5`` and ``yum``, which
ansible-core redirects to ``dnf``; ``BOUNDED_DISPATCHING_MODULES`` records that review. A unit
test reads every action plugin of the installed ansible-core and fails when one runs a module whose
name is not a literal and it is on neither list.

An allow-listed module is accepted only while its collection is pinned at one exact version
(``<major>.<minor>.<patch>``) in ``galaxy.yml`` ``dependencies``, in
``extensions/molecule/requirements.yml`` and in ``extensions/molecule/collections.pins``. Files
outside ``roles/remediate`` (Molecule scenarios, test playbooks and the other roles) are not in
scope; the banned modules of :mod:`tools.lint.repo_rules.ansible_tasks` apply to them as before.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml

from tools.lint.repo_rules.ansible_tasks import (
    ACTION_KEYS,
    INCLUDE_FILE_KEYS,
    MODULE_KEY,
    ROLE_PATH_TARGET,
    TEMPLATE_MARKERS,
    action_modules,
    scalar_items,
    task_mappings,
)
from tools.lint.repo_rules.common import REPO_ROOT, YAML_SUFFIXES, Violation
from tools.lint.repo_rules.remediate_routing import as_mapping, is_routed, read_yaml

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

ALLOWED_COMMUNITY_MODULES: Final[frozenset[str]] = frozenset()
BUILTIN_COLLECTION: Final[str] = "ansible.builtin"
OWN_COLLECTION: Final[str] = "freesecdev.linux_compliance"
BUILTIN_MODULES: Final[frozenset[str]] = frozenset(
    {
        "add_host",
        "apt",
        "apt_key",
        "apt_repository",
        "assemble",
        "assert",
        "async_status",
        "async_wrapper",
        "blockinfile",
        "command",
        "copy",
        "cron",
        "deb822_repository",
        "debconf",
        "debug",
        "dnf",
        "dnf5",
        "dpkg_selections",
        "expect",
        "fail",
        "fetch",
        "file",
        "find",
        "gather_facts",
        "get_url",
        "getent",
        "git",
        "group",
        "group_by",
        "hostname",
        "import_playbook",
        "import_role",
        "import_tasks",
        "include_role",
        "include_tasks",
        "include_vars",
        "iptables",
        "known_hosts",
        "lineinfile",
        "meta",
        "mount_facts",
        "package",
        "package_facts",
        "pause",
        "ping",
        "pip",
        "raw",
        "reboot",
        "replace",
        "rpm_key",
        "script",
        "service",
        "service_facts",
        "set_fact",
        "set_stats",
        "setup",
        "shell",
        "slurp",
        "stat",
        "subversion",
        "systemd",
        "systemd_service",
        "sysvinit",
        "tempfile",
        "template",
        "unarchive",
        "uri",
        "user",
        "validate_argument_spec",
        "wait_for",
        "wait_for_connection",
        "yum_repository",
    }
)
DISPATCHING_MODULES: Final[frozenset[str]] = frozenset({"gather_facts", "package", "service"})
BOUNDED_DISPATCHING_MODULES: Final[frozenset[str]] = frozenset({"dnf"})
REMEDIATE_ROLE: Final[tuple[str, str]] = ("roles", "remediate")
ROLE_METADATA: Final[frozenset[tuple[str, ...]]] = frozenset(
    {("roles", "remediate", "meta", "main.yml"), ("roles", "remediate", "meta", "main.yaml")}
)
TASK_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "action",
        "always",
        "any_errors_fatal",
        "args",
        "async",
        "async_val",
        "become",
        "become_exe",
        "become_flags",
        "become_method",
        "become_user",
        "block",
        "changed_when",
        "check_mode",
        "collections",
        "connection",
        "debugger",
        "delay",
        "delegate_facts",
        "delegate_to",
        "diff",
        "environment",
        "failed_when",
        "ignore_errors",
        "ignore_unreachable",
        "listen",
        "loop",
        "loop_control",
        "loop_with",
        "module_defaults",
        "name",
        "no_log",
        "notify",
        "poll",
        "port",
        "register",
        "remote_user",
        "rescue",
        "retries",
        "run_once",
        "tags",
        "throttle",
        "timeout",
        "until",
        "vars",
        "when",
    }
)
LOOP_PREFIX: Final[str] = "with_"
TASK_INCLUDE_MODULES: Final[frozenset[str]] = frozenset(
    {"ansible.builtin.include_tasks", "ansible.builtin.import_tasks"}
)
ROLE_INCLUDE_MODULES: Final[frozenset[str]] = frozenset(
    {"ansible.builtin.include_role", "ansible.builtin.import_role"}
)
QUALIFIED_NAME: Final[re.Pattern[str]] = re.compile(
    r"(?P<collection>[a-z0-9][a-z0-9_]*\.[a-z0-9][a-z0-9_]*)\.(?P<module>[a-z_][a-z0-9_]*)"
)
EXACT_VERSION: Final[re.Pattern[str]] = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
PIN_LINE: Final[re.Pattern[str]] = re.compile(
    r"collection (?P<name>\S+) (?P<version>\S+) [0-9a-f]{64} [0-9]+"
)
GALAXY_FILE: Final[Path] = Path("galaxy.yml")
REQUIREMENTS_FILE: Final[Path] = Path("extensions/molecule/requirements.yml")
PINS_FILE: Final[Path] = Path("extensions/molecule/collections.pins")
OWN_PLUGIN_DIRECTORIES: Final[tuple[Path, ...]] = (Path("plugins/modules"), Path("plugins/action"))
PLUGIN_SUFFIX: Final[str] = ".py"
DELEGATION_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"delegate_to", "delegate_facts", "local_action", "connection"}
)
DEPENDENCIES_KEY: Final[str] = "dependencies"
COLLECTIONS_KEY: Final[str] = "collections"
NAME_KEY: Final[str] = "name"
VERSION_KEY: Final[str] = "version"

MODULE_MESSAGE: Final[str] = (
    "module {name!r} is not allowed in roles/remediate: use an ansible.builtin or "
    "freesecdev.linux_compliance module by its fully qualified name, or a community module on the "
    "allow list (ADR 0032 §1)"
)
BUILTIN_MESSAGE: Final[str] = (
    "module {name!r} is not allowed in roles/remediate: it is not on BUILTIN_MODULES, the module "
    "files of the pinned ansible-core that its plugin_routing leaves in place, so it runs a module "
    "of another collection or none (ADR 0032 §1)"
)
DISPATCH_MESSAGE: Final[str] = (
    "module {name!r} is not allowed in roles/remediate: its action plugin chooses while the play "
    "runs, from an argument, a variable or a fact, which module to execute, and that module is "
    "never checked against the allow list (ADR 0032 §1)"
)
ACTION_SHAPE_MESSAGE: Final[str] = (
    "{keyword} must be a module string or a mapping whose every module key is a string in "
    "roles/remediate: Ansible reads a JSON load marker such as __ansible_unsafe there as the "
    "module name, which the rule cannot see (ADR 0032 §1)"
)
OWN_MISSING_MESSAGE: Final[str] = (
    "module {name!r} is not allowed in roles/remediate: plugins/modules and plugins/action hold "
    "no file {module}.py (ADR 0032 §1)"
)
OWN_ROUTED_MESSAGE: Final[str] = (
    "module {name!r} is not allowed in roles/remediate: meta/runtime.yml routes it with an entry "
    "other than deprecation (redirect, tombstone, action_plugin), or cannot be read "
    "(ADR 0032 §1)"
)
TEMPLATED_MESSAGE: Final[str] = (
    "templated module name {name!r} is not allowed in roles/remediate: the module must be known "
    "before the run (ADR 0032 §1)"
)
PIN_MESSAGE: Final[str] = (
    "allow-listed module {name!r} needs its collection {collection} pinned at one exact version "
    "in galaxy.yml dependencies, extensions/molecule/requirements.yml and "
    "extensions/molecule/collections.pins; found {versions} (ADR 0032 §1)"
)
ROLE_INCLUDE_MESSAGE: Final[str] = (
    "{name} is not allowed in roles/remediate: the tasks of another role are not checked against "
    "the allow list (ADR 0032 §1)"
)
INCLUDE_ACTION_MESSAGE: Final[str] = (
    "{name} in action or local_action is not allowed in roles/remediate: write it as a task key "
    "with a {{{{ role_path }}}}/tasks/ target (ADR 0032 §1)"
)
INCLUDE_TARGET_MESSAGE: Final[str] = (
    "{name} target {target!r} is not allowed in roles/remediate: use {{{{ role_path }}}}/tasks/ "
    "followed by a literal relative path, because Ansible looks for any other target in the "
    "playbook's directory too (ADR 0032 §1)"
)
DELEGATION_MESSAGE: Final[str] = (
    "{keyword} is not allowed in roles/remediate: the role runs its tasks on the managed host "
    "through the play's connection, so it never runs a task on the controller or another host "
    "(ADR 0032 §1)"
)
DEPENDENCY_MESSAGE: Final[str] = (
    "role dependencies are not allowed in roles/remediate/meta/main.yml: their tasks are not "
    "checked against the allow list; dependencies must be an empty list (ADR 0032 §1)"
)


def is_remediate_file(relative: Path | None) -> bool:
    """Return whether ``relative`` is a YAML file below ``roles/remediate/``.

    The directory names are compared case-folded, because macOS and Windows controllers ignore
    case.
    """
    if relative is None or relative.suffix.lower() not in YAML_SUFFIXES:
        return False
    return tuple(part.casefold() for part in relative.parts[:2]) == REMEDIATE_ROLE


def _is_role_metadata(relative: Path) -> bool:
    """Return whether ``relative`` is ``roles/remediate/meta/main.yml``, case-folded."""
    return tuple(part.casefold() for part in relative.parts) in ROLE_METADATA


def _is_keyword(name: str) -> bool:
    return name in TASK_KEYWORDS or name.startswith(LOOP_PREFIX)


def _module_names(task: yaml.MappingNode) -> Iterable[tuple[yaml.Node, str, yaml.Node | None]]:
    """Yield the node, text and arguments of every name that ``task`` may run as a module.

    That is every key that is not a keyword, with its value as the arguments, and the first word
    of an ``action`` or ``local_action`` string and every ``module`` key of their mapping form,
    without arguments.
    """
    for name, key, value in scalar_items(task):
        if name in ACTION_KEYS:
            for module in action_modules(value):
                words = str(module.value).split(maxsplit=1)
                yield module, words[0] if words else "", None
        elif not _is_keyword(name):
            yield key, name, value


def _action_shape_problems(task: yaml.MappingNode) -> Iterable[tuple[yaml.Node, str]]:
    """Yield every ``action`` or ``local_action`` value of ``task`` whose module is not plain.

    Ansible takes the module of these keywords from a string or from the ``module`` key of a
    mapping. ``DataLoader`` reads a task file as JSON first, and its ``AnsibleJSONDecoder`` turns a
    mapping that holds a load marker (``{"__ansible_unsafe": "zz.evil.pwn"}``, or
    ``__ansible_vault``) into a string, so such a mapping in the keyword or in its ``module`` key
    names a module that PyYAML shows as a mapping. A mapping without a ``module`` key, a ``module``
    value that is not a scalar and a value that is neither a scalar nor a mapping are refused.
    """
    for name, _, value in scalar_items(task):
        if name not in ACTION_KEYS or isinstance(value, yaml.ScalarNode):
            continue
        modules = (
            [inner for key, _, inner in scalar_items(value) if key == MODULE_KEY]
            if isinstance(value, yaml.MappingNode)
            else []
        )
        if not modules or not all(isinstance(module, yaml.ScalarNode) for module in modules):
            yield value, ACTION_SHAPE_MESSAGE.format(keyword=name)


def _load_mapping(path: Path) -> dict[object, object]:
    """Return the YAML mapping of ``path``, or an empty one when it cannot be read or parsed."""
    try:
        return as_mapping(read_yaml(path))
    except ValueError:
        return {}


def _galaxy_versions(root: Path, collection: str) -> list[object]:
    """Return the versions that ``galaxy.yml`` ``dependencies`` gives ``collection``."""
    dependencies = as_mapping(_load_mapping(root / GALAXY_FILE).get(DEPENDENCIES_KEY))
    return [dependencies[collection]] if collection in dependencies else []


def _requirements_versions(root: Path, collection: str) -> list[object]:
    """Return the version of every entry for ``collection`` in the Molecule requirements."""
    entries = _load_mapping(root / REQUIREMENTS_FILE).get(COLLECTIONS_KEY)
    if not isinstance(entries, list):
        return []
    mappings = [as_mapping(entry) for entry in cast("list[object]", entries)]
    return [entry.get(VERSION_KEY) for entry in mappings if entry.get(NAME_KEY) == collection]


def _pinned_versions(root: Path, collection: str) -> list[object]:
    """Return the version of every line for ``collection`` in the collection pins."""
    try:
        lines = (root / PINS_FILE).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    matches = (PIN_LINE.fullmatch(line) for line in lines)
    return [
        match.group(VERSION_KEY)
        for match in matches
        if match is not None and match.group(NAME_KEY) == collection
    ]


def pin_sources(collection: str, root: Path = REPO_ROOT) -> dict[str, list[object]]:
    """Return, for each of the three pin files, every version it gives ``collection``."""
    return {
        str(GALAXY_FILE): _galaxy_versions(root, collection),
        str(REQUIREMENTS_FILE): _requirements_versions(root, collection),
        str(PINS_FILE): _pinned_versions(root, collection),
    }


def pinned_version(sources: Mapping[str, Sequence[object]]) -> str | None:
    """Return the one exact version that every pin file of ``sources`` gives, or ``None``.

    Each file must name the collection once, with a ``<major>.<minor>.<patch>`` string, and the
    three versions must be equal.
    """
    if any(len(entries) != 1 for entries in sources.values()):
        return None
    versions = [entries[0] for entries in sources.values()]
    first = versions[0]
    if not isinstance(first, str) or EXACT_VERSION.fullmatch(first) is None:
        return None
    return first if all(version == first for version in versions) else None


def _own_module_problem(name: str, module: str, root: Path) -> str | None:
    """Return why the collection's ``module`` may not run, or ``None`` when it may."""
    if not any(
        (root / directory / f"{module}{PLUGIN_SUFFIX}").is_file()
        for directory in OWN_PLUGIN_DIRECTORIES
    ):
        return OWN_MISSING_MESSAGE.format(name=name, module=module)
    if is_routed(root, module):
        return OWN_ROUTED_MESSAGE.format(name=name)
    return None


def _community_module_problem(
    name: str, collection: str, allowed: frozenset[str], root: Path
) -> str | None:
    """Return why the community module ``name`` may not run, or ``None`` when it may."""
    if name not in allowed:
        return MODULE_MESSAGE.format(name=name)
    sources = pin_sources(collection, root)
    if pinned_version(sources) is None:
        return PIN_MESSAGE.format(name=name, collection=collection, versions=sources)
    return None


def _name_problem(name: str, allowed: frozenset[str], root: Path) -> str | None:
    """Return why ``name`` may not run in ``roles/remediate``, or ``None`` when it may."""
    if any(marker in name for marker in TEMPLATE_MARKERS):
        return TEMPLATED_MESSAGE.format(name=name)
    match = QUALIFIED_NAME.fullmatch(name)
    if match is None:
        return MODULE_MESSAGE.format(name=name)
    collection, module = match.group("collection", "module")
    if collection == BUILTIN_COLLECTION:
        if module in DISPATCHING_MODULES:
            return DISPATCH_MESSAGE.format(name=name)
        return None if module in BUILTIN_MODULES else BUILTIN_MESSAGE.format(name=name)
    if collection == OWN_COLLECTION:
        return _own_module_problem(name, module, root)
    return _community_module_problem(name, collection, allowed, root)


def _include_targets(arguments: yaml.Node) -> list[yaml.Node]:
    """Return the nodes that name the task file of an ``include_tasks`` or ``import_tasks``."""
    if isinstance(arguments, yaml.MappingNode):
        return [value for name, _, value in scalar_items(arguments) if name in INCLUDE_FILE_KEYS]
    return [arguments]


def _include_problems(
    node: yaml.Node, name: str, arguments: yaml.Node | None
) -> Iterable[tuple[yaml.Node, str]]:
    """Yield why an include of ``name`` may run tasks that the rule did not read.

    ``arguments`` is the value of the task key, or ``None`` for the module of an ``action``.
    """
    if name in ROLE_INCLUDE_MODULES:
        yield node, ROLE_INCLUDE_MESSAGE.format(name=name)
    elif name in TASK_INCLUDE_MODULES:
        if arguments is None:
            yield node, INCLUDE_ACTION_MESSAGE.format(name=name)
            return
        targets = _include_targets(arguments)
        if not targets:
            yield node, INCLUDE_TARGET_MESSAGE.format(name=name, target=None)
        for target in targets:
            text = str(target.value) if isinstance(target, yaml.ScalarNode) else None
            if text is None or ROLE_PATH_TARGET.fullmatch(text) is None:
                yield target, INCLUDE_TARGET_MESSAGE.format(name=name, target=text)


def _delegation_problems(task: yaml.MappingNode) -> Iterable[tuple[yaml.Node, str]]:
    """Yield every keyword of ``task`` that runs it on another host or through another connection.

    ``delegate_to``, ``delegate_facts``, ``local_action`` and ``connection`` let a task of the
    role write on the controller, for example into a module path of Ansible, from which
    ansible-core's own action plugins then load ``ansible.legacy`` modules.
    """
    for name, key, _ in scalar_items(task):
        if name in DELEGATION_KEYWORDS:
            yield key, DELEGATION_MESSAGE.format(keyword=name)


def _task_problems(
    document: yaml.SequenceNode, allowed: frozenset[str], root: Path
) -> Iterable[tuple[yaml.Node, str]]:
    """Yield every module, include and delegation of ``document`` that may not run."""
    for task in task_mappings(document):
        yield from _delegation_problems(task)
        yield from _action_shape_problems(task)
        for node, name, arguments in _module_names(task):
            problem = _name_problem(name, allowed, root)
            if problem is not None:
                yield node, problem
            else:
                yield from _include_problems(node, name, arguments)


def _dependency_problems(document: yaml.Node) -> Iterable[tuple[yaml.Node, str]]:
    """Yield every ``dependencies`` entry of a role metadata ``document`` that is not empty."""
    if not isinstance(document, yaml.MappingNode):
        return
    for name, key, value in scalar_items(document):
        if name != DEPENDENCIES_KEY:
            continue
        if not isinstance(value, yaml.SequenceNode) or value.value:
            yield key, DEPENDENCY_MESSAGE


def check_remediate_modules(
    path: Path,
    relative: Path | None,
    documents: Iterable[yaml.Node],
    *,
    allowed: frozenset[str] = ALLOWED_COMMUNITY_MODULES,
    root: Path = REPO_ROOT,
) -> list[Violation]:
    """Return a violation for every module a task of ``roles/remediate`` may not run.

    ``documents`` are the composed YAML documents of ``path``; ``relative`` is its repository
    path. ``allowed`` is the allow list and ``root`` the repository whose pin files, plugins and
    ``meta/runtime.yml`` are read. The role's ``meta/main.yml`` may not name a dependency.
    """
    if relative is None or not is_remediate_file(relative):
        return []
    metadata = _is_role_metadata(relative)
    violations: set[Violation] = set()
    for document in documents:
        if isinstance(document, yaml.SequenceNode):
            problems = _task_problems(document, allowed, root)
        elif metadata:
            problems = _dependency_problems(document)
        else:
            continue
        for node, problem in problems:
            violations.add(Violation(path, node.start_mark.line + 1, problem))
    return sorted(violations)
