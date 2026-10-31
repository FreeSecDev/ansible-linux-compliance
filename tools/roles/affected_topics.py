"""Plan only the lifecycle legs of the topics that a change affects (FREES-189).

``make molecule-matrix`` plans one CI leg per platform, native topic and toggle mode, and one per
regression group, so the matrix grows with every native topic. On a pull request and in the merge
queue, CI keeps only the legs of the topics that the change can affect; a push to ``main``, the
nightly schedule and a manual run always run the full matrix. This tool decides which topics those
are, from the base and the head revision of the repository and the paths that differ between them,
and filters the full matrices that ``make molecule-matrix`` printed for the head.

Nothing is listed by hand: every path is classified from the topic declarations, the catalogue and
the file names. A path that the mapping cannot confine to topics plans the full matrix (fail safe):

* **No lifecycle effect.** Documentation, changelog fragments, unit tests and fixtures, the
  check-mode playbooks, the reporting, lint, docs and IaC tools, and the configuration of
  linters and bots. None of them is read by a Molecule scenario.
* **Generated and checked for drift.** The role guards and the family dispatch
  (``make lint-role-guards``) are a function of files that are classified themselves, by
  generators below ``tools/roles``, which plan the full matrix when they change.
  ``content/catalogue.yml`` is only the input of ``roles/remediate/vars/rules.yml``
  (``generate_catalogue --check`` in the ``test-suites`` job), which is classified by its entries.
* **The catalogue.** ``roles/remediate/vars/rules.yml`` is compared entry by entry: a family's
  registry entry, its rules, its ``audit_only`` list and the subsystem tags affect that family,
  and the families of the rules that a tag gains or loses. A family that the registry gains or
  loses affects that family and its umbrella (FREES-195). A change to the order of the families
  that both revisions register, a family registered twice, a gained or lost family that heads an
  umbrella, a change to the order of entries of unchanged families or to any other key plans the
  full matrix.
* **Generated toggles.** The toggle defaults of the remediate and audit roles and their argument
  specs are compared per variable and per option (FREES-195). A topic toggle
  ``linux_compliance_<topic>_enabled`` of a family or an umbrella, with a boolean default and the
  generated specification, affects every family that it controls: the family, the families of
  the umbrella, and the families of the rules of a subsystem tag that it or its umbrella names.
  A family or umbrella that the choices of ``linux_compliance_remediate_allow_disruptive`` gain
  or lose affects the same families. A change that only rewrites descriptions has no lifecycle
  effect. Any other change plans the full matrix.
* **Role variables.** A changed key of ``roles/remediate/vars/main.yml`` affects the topics of
  the files that use it; a key that no file uses, or that a shared file uses, plans the full
  matrix.
* **Topic files.** A task file of ``roles/remediate/tasks`` named ``<family>.yml`` or
  ``<family>_*.yml``, a topic declaration ``extensions/molecule/shared/vars/topics/<topic>.yml``,
  and a file of ``extensions/molecule/shared/tasks`` that a topic's regression group names belong
  to that topic. Every file that includes such a file must belong to topics as well, and their
  topics are added; a file that a shared file includes plans the full matrix. A file that no
  topic owns belongs to the topics of the files that include it; one that nothing includes plans
  the full matrix. Only the generated family dispatch and the static regression dispatch, which
  ``make lint-lifecycle`` checks, may include topic files without adding topics. The regression
  dispatch itself is compared include by include.
* **Everything else**, including the shared harness, the images, ``module_utils`` and plugins,
  the other role files and defaults, the content pins, this tool and every file below
  ``tools/roles``, ``tools/molecule``, ``ci.yml``, the ``Makefile`` and the Python lock, plans the
  full matrix, as does any path that is not known.

CI runs the base revision's copy of this tool (``tools/molecule/plan-lifecycle.sh``), so a pull
request cannot shrink its own matrix by editing it. The tool prints one line of JSON: the scope
(``full`` or ``affected``), the topics, the reason for every path, and the filtered Docker and
libvirt matrices. Legs without a topic (the libvirt base scenarios and the self-test) are always
kept.
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final, NamedTuple, cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)
from tools.roles import check_lifecycle_topics, generate_toggles

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

GenerationError = generate_toggles.GenerationError
CATALOGUE: Final[str] = generate_toggles.CATALOGUE.as_posix()
ROLE_TASKS: Final[str] = "roles/remediate/tasks"
ROLE_VARIABLES: Final[str] = "roles/remediate/vars/main.yml"
MOLECULE_TASKS: Final[str] = check_lifecycle_topics.REGRESSION_DISPATCH.parent.as_posix()
REGRESSION_DISPATCH: Final[str] = check_lifecycle_topics.REGRESSION_DISPATCH.as_posix()
TOPICS: Final[str] = check_lifecycle_topics.TOPICS.as_posix()
ARGUMENT_SPECS: Final[frozenset[str]] = frozenset(
    {generate_toggles.SPECS.as_posix(), generate_toggles.AUDIT_SPECS.as_posix()}
)
TOGGLE_DEFAULTS: Final[frozenset[str]] = frozenset(
    {generate_toggles.DEFAULTS.as_posix(), generate_toggles.AUDIT_DEFAULTS.as_posix()}
)
TOPIC_TOGGLE: Final[re.Pattern[str]] = re.compile(r"linux_compliance_([a-z][a-z0-9_]*)_enabled")
TOGGLE_OPTION: Final[dict[str, object]] = {"type": "bool", "default": True}
ALLOW_LIST: Final[str] = generate_toggles.ALLOW_LIST
CHOICES_KEY: Final[str] = "choices"
UMBRELLA_KEY: Final[str] = toggles.UMBRELLA_KEY
GENERATED: Final[frozenset[str]] = frozenset(
    {
        "roles/remediate/tasks/dispatch.yml",
        "roles/audit/tasks/internal_variables.yml",
        "roles/evidence/tasks/internal_variables.yml",
        "roles/remediate/tasks/internal_variables.yml",
        "roles/verify/tasks/internal_variables.yml",
        "playbooks/run_start.yml",
        "content/catalogue.yml",
    }
)
NO_LIFECYCLE_PREFIXES: Final[tuple[str, ...]] = (
    "docs/",
    "changelogs/",
    "tests/unit/",
    "tests/fixtures/",
    "tests/browser/",
    "tests/system/",
    "tests/playbooks/",
    "tests/sanity/",
    "tools/reporting/",
    "tools/browser/",
    "tools/docs/",
    "tools/skills/",
    "tools/lint/",
    "tools/iac/",
    "infra/",
    "typings/",
    "extensions/ci/",
    ".agents/",
    ".claude/",
    ".github/ISSUE_TEMPLATE/",
    ".github/rulesets/",
)
NO_LIFECYCLE_FILES: Final[frozenset[str]] = frozenset(
    {
        ".ansible-lint",
        ".ansible-lint-ignore",
        ".checkov.yaml",
        ".markdownlint-cli2.yaml",
        ".pre-commit-config.yaml",
        ".renovaterc.json",
        ".yamllint.yaml",
        ".github/dependabot.yml",
        ".github/pull_request_template.md",
        ".github/release.yml",
        ".github/zizmor.yml",
        ".github/workflows/oidc-check.yml",
        ".github/workflows/scc-release-watch.yml",
        "AGENTS.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "NOTICE",
        "README.md",
        "SECURITY.md",
        "tests/conftest.py",
    }
)
ROLE_README: Final[re.Pattern[str]] = re.compile(r"roles/[a-z_]+/README\.md")
SAFE_PATH: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.@+-]+(/[A-Za-z0-9_.@+-]+)*")
REFERRER_ROOTS: Final[tuple[str, ...]] = ("roles", "extensions/molecule", "playbooks")
YAML_SUFFIXES: Final[frozenset[str]] = frozenset({".yml", ".yaml"})
FAMILIES_KEY: Final[str] = generate_toggles.FAMILIES_KEY
RULES_KEY: Final[str] = generate_toggles.RULES_KEY
AUDIT_ONLY_KEY: Final[str] = generate_toggles.AUDIT_ONLY_KEY
TAGS_KEY: Final[str] = generate_toggles.TAGS_KEY
DESCRIPTION_KEYS: Final[frozenset[str]] = frozenset({"description", "short_description"})
INCLUDE_TASKS: Final[str] = check_lifecycle_topics.INCLUDE_TASKS
INCLUDE_KEYS: Final[frozenset[str]] = check_lifecycle_topics.INCLUDE_KEYS
LEG_KEYS: Final[tuple[str, ...]] = ("platform", "scenario", "topic", "mode")
SCOPE_FULL: Final[str] = "full"
SCOPE_AFFECTED: Final[str] = "affected"


class FullMatrixError(Exception):
    """A change that the mapping cannot confine to topics, so the full matrix runs."""


class Decision(NamedTuple):
    """Whether the full matrix runs, the affected topics and the reason for every path."""

    full: bool
    topics: frozenset[str]
    reasons: tuple[str, ...]


class Catalogue(NamedTuple):
    """The parts of ``rules.yml`` that are compared per family."""

    families: list[tuple[str, object]]
    rules: list[tuple[str, object]]
    audit_only: dict[str, object]
    tags: dict[str, list[str]]
    rest: dict[str, object]
    family_of: dict[str, str]
    umbrellas: dict[str, str]


def _file_reference(name: str) -> re.Pattern[str]:
    """Match ``name`` as a file name below any directory, or its stem after ``tasks_from``."""
    stem = re.escape(PurePosixPath(name).stem)
    return re.compile(
        r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])"
        r"|\btasks_from:\s*['\"]?(?:[^\s'\"]*/)?" + stem + r"['\"]?\s*$",
        re.MULTILINE,
    )


class Tree:
    """One revision of the repository below ``root``, read as data only."""

    def __init__(self, root: Path) -> None:
        """Read the revision below ``root``."""
        self.root = root

    def text(self, relative: str) -> str | None:
        """Return the text of a file, or ``None`` when the revision has no such file.

        Raises:
            FullMatrixError: When the file exists but cannot be read as UTF-8 text.
        """
        path = self.root / relative
        if not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            message = f"{relative} cannot be read: {error}"
            raise FullMatrixError(message) from error

    def data(self, relative: str) -> object:
        """Return a YAML file as data, or ``None`` when the revision has no such file.

        Raises:
            FullMatrixError: When the file is not valid YAML.
        """
        text = self.text(relative)
        if text is None:
            return None
        try:
            return cast("object", yaml.load(text, Loader=yaml.CSafeLoader))
        except yaml.YAMLError as error:
            message = f"{relative} is not valid YAML"
            raise FullMatrixError(message) from error

    def is_link(self, relative: str) -> bool:
        """Return whether the path is a symbolic link in this revision."""
        return (self.root / relative).is_symlink()

    @functools.cached_property
    def sources(self) -> tuple[dict[str, str], frozenset[str]]:
        """Return the YAML files below the referrer roots and the targets of their links."""
        texts: dict[str, str] = {}
        targets: set[str] = set()
        for top in REFERRER_ROOTS:
            directory = self.root / top
            if not directory.is_dir():
                continue
            for path in sorted(directory.rglob("*")):
                relative = path.relative_to(self.root).as_posix()
                if path.is_symlink():
                    targets.add(_link_target(self.root, path))
                elif path.is_file() and path.suffix in YAML_SUFFIXES:
                    texts[relative] = cast("str", self.text(relative))
        return texts, frozenset(targets)


def _link_target(root: Path, link: Path) -> str:
    resolved = link.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _families(data: dict[str, object]) -> list[tuple[str, object]]:
    families: list[tuple[str, object]] = []
    for entry in toggles.as_sequence(data.get(FAMILIES_KEY)) or []:
        item = toggles.as_mapping(entry)
        name = item.get("name") if item is not None else None
        if not isinstance(name, str):
            message = f"{CATALOGUE}: a family entry has no name"
            raise FullMatrixError(message)
        families.append((name, entry))
    if not families:
        message = f"{CATALOGUE} has no family registry"
        raise FullMatrixError(message)
    return families


def _rules(data: dict[str, object], family_of: dict[str, str]) -> list[tuple[str, object]]:
    rules: list[tuple[str, object]] = []
    for entry in toggles.as_sequence(data.get(RULES_KEY)) or []:
        item = toggles.as_mapping(entry)
        family = item.get("family") if item is not None else None
        rule = item.get("rule_id") if item is not None else None
        if not isinstance(family, str) or not isinstance(rule, str):
            message = f"{CATALOGUE}: a rule has no family or identifier"
            raise FullMatrixError(message)
        rules.append((family, entry))
        family_of[rule] = family
    return rules


def _tags(data: dict[str, object]) -> dict[str, list[str]]:
    tags = toggles.as_mapping(data.get(TAGS_KEY, {}))
    if tags is None:
        message = f"{CATALOGUE}: {TAGS_KEY} must be a mapping"
        raise FullMatrixError(message)
    tagged: dict[str, list[str]] = {}
    for tag, listed in tags.items():
        items = toggles.as_sequence(listed)
        if items is None:
            message = f"{CATALOGUE}: the subsystem tag {tag} must list rules"
            raise FullMatrixError(message)
        tagged[tag] = [str(rule) for rule in items]
    return tagged


def _catalogue(tree: Tree) -> Catalogue:
    data = toggles.as_mapping(tree.data(CATALOGUE))
    if data is None:
        message = f"{CATALOGUE} is missing or not a mapping"
        raise FullMatrixError(message)
    family_of: dict[str, str] = {}
    families = _families(data)
    rules = _rules(data, family_of)
    audit_only = toggles.as_mapping(data.get(AUDIT_ONLY_KEY, {}))
    if audit_only is None:
        message = f"{CATALOGUE}: {AUDIT_ONLY_KEY} must be a mapping"
        raise FullMatrixError(message)
    for family, listed in audit_only.items():
        for rule in toggles.as_sequence(listed) or []:
            family_of.setdefault(str(rule), family)
    rest = {
        key: value
        for key, value in data.items()
        if key not in {FAMILIES_KEY, RULES_KEY, AUDIT_ONLY_KEY, TAGS_KEY}
    }
    return Catalogue(
        families, rules, audit_only, _tags(data), rest, family_of, _umbrellas(families)
    )


def _umbrellas(families: Sequence[tuple[str, object]]) -> dict[str, str]:
    """Return the umbrella of every family that names one as text."""
    found: dict[str, str] = {}
    for name, entry in families:
        umbrella = cast("dict[str, object]", entry).get(UMBRELLA_KEY)
        if isinstance(umbrella, str):
            found[name] = umbrella
    return found


def _umbrellas_of(*entries: object) -> set[str]:
    """Return the umbrellas that the registry entries name as text."""
    found: set[str] = set()
    for entry in entries:
        umbrella = (toggles.as_mapping(entry) or {}).get(UMBRELLA_KEY)
        if isinstance(umbrella, str):
            found.add(umbrella)
    return found


def _registry_topics(base: Catalogue, head: Catalogue) -> set[str]:
    """Return the families whose registry entry changed, was added or was removed, and umbrellas.

    Raises:
        FullMatrixError: When a family is registered twice, the families that both revisions
            register changed their order, or a gained or lost family heads an umbrella.
    """
    before, after = dict(base.families), dict(head.families)
    if len(before) != len(base.families) or len(after) != len(head.families):
        message = "the family registry lists a family twice"
        raise FullMatrixError(message)
    if [name for name, _ in base.families if name in after] != [
        name for name, _ in head.families if name in before
    ]:
        message = "the family registry reordered a family"
        raise FullMatrixError(message)
    heads = set(base.umbrellas.values()) | set(head.umbrellas.values())
    found: set[str] = set()
    for name in sorted(before.keys() | after.keys()):
        if name in before and name in after:
            if _same(before[name], after[name]):
                continue
        elif name in heads:
            message = f"the family registry gained or lost {name}, which heads an umbrella"
            raise FullMatrixError(message)
        found.add(name)
        found.update(_umbrellas_of(before.get(name), after.get(name)))
    return found


def _projected(
    base: Sequence[tuple[str | None, object]], head: Sequence[tuple[str | None, object]]
) -> set[str | None]:
    """Return the keys whose items differ; the items of the other keys must be in the same order.

    Raises:
        FullMatrixError: When only the order of the items of unchanged keys differs.
    """
    keys = {key for key, _ in base} | {key for key, _ in head}
    changed = {
        key
        for key in keys
        if [value for found, value in base if found == key]
        != [value for found, value in head if found == key]
    }
    if [item for item in base if item[0] not in changed] != [
        item for item in head if item[0] not in changed
    ]:
        message = "entries of unchanged topics moved"
        raise FullMatrixError(message)
    return changed


def _catalogue_topics(base: Catalogue, head: Catalogue) -> set[str]:
    found = _registry_topics(base, head)
    if base.rest != head.rest:
        message = "a key other than the families, rules, audit_only rules and tags changed"
        raise FullMatrixError(message)
    found.update(cast("set[str]", _projected(base.rules, head.rules)))
    found.update(
        family
        for family in base.audit_only.keys() | head.audit_only.keys()
        if base.audit_only.get(family) != head.audit_only.get(family)
    )
    names = {name for catalogue in (base, head) for name, _ in catalogue.families}
    for tag in base.tags.keys() | head.tags.keys():
        before, after = base.tags.get(tag, []), head.tags.get(tag, [])
        if before == after:
            continue
        if tag not in names:
            message = f"the subsystem tag {tag} changed and is not a family"
            raise FullMatrixError(message)
        found.add(tag)
        for rule in set(before) ^ set(after):
            families = {
                family
                for family in (base.family_of.get(rule), head.family_of.get(rule))
                if family is not None
            }
            if not families:
                message = f"the subsystem tag {tag} names {rule}, which no family catalogues"
                raise FullMatrixError(message)
            found.update(families)
    return found


def _same(before: object, after: object) -> bool:
    """Return whether two YAML values are equal in value and in type (``true`` is not ``1``).

    Values that cannot be compared this way, such as a mapping with keys of mixed types or a
    recursive structure built from YAML aliases, count as different.
    """
    try:
        return json.dumps(before, sort_keys=True, default=repr) == json.dumps(
            after, sort_keys=True, default=repr
        )
    except (TypeError, ValueError, RecursionError):
        return False


def _without(item: dict[str, object], name: str) -> dict[str, object]:
    return {key: value for key, value in item.items() if key != name}


def _differences(
    before: dict[str, object], after: dict[str, object]
) -> list[tuple[str, list[object]]]:
    """Return every key that only one side has or whose values differ, with its values."""
    return [
        (key, [data[key] for data in (before, after) if key in data])
        for key in sorted(before.keys() | after.keys())
        if key not in before or key not in after or not _same(before[key], after[key])
    ]


def _choices(value: object) -> tuple[dict[str, object], list[str]]:
    """Return an option of the allowed disruptive topics without its choices, and the choices.

    Raises:
        FullMatrixError: When the option is not a mapping with a list of text choices.
    """
    item = toggles.as_mapping(value)
    choices = toggles.as_sequence(item.get(CHOICES_KEY)) if item is not None else None
    if item is None or choices is None or not all(isinstance(choice, str) for choice in choices):
        message = f"{ALLOW_LIST} has no list of choices"
        raise FullMatrixError(message)
    return _without(item, CHOICES_KEY), [str(choice) for choice in choices]


def _without_descriptions(
    value: object, relative: str
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Return the keys beside ``argument_specs`` and every entry point without its descriptions.

    Raises:
        FullMatrixError: When the file has no mapping of entry points.
    """
    data = toggles.as_mapping(value)
    entries = toggles.as_mapping(data.get("argument_specs")) if data is not None else None
    if data is None or entries is None:
        message = f"{relative} has no argument_specs mapping"
        raise FullMatrixError(message)
    stripped: dict[str, dict[str, object]] = {}
    for name, entry in entries.items():
        item = toggles.as_mapping(entry)
        if item is None:
            message = f"{relative}: the entry point {name} is not a mapping"
            raise FullMatrixError(message)
        stripped[name] = {
            key: _options(found) if key == "options" else found
            for key, found in item.items()
            if key not in DESCRIPTION_KEYS
        }
    return _without(data, "argument_specs"), stripped


def _options(value: object) -> object:
    options = toggles.as_mapping(value)
    if options is None:
        return value
    result: dict[str, object] = {}
    for name, option in options.items():
        item = toggles.as_mapping(option)
        result[name] = (
            option
            if item is None
            else {
                key: _options(found) if key == "options" else found
                for key, found in item.items()
                if key != "description"
            }
        )
    return result


def _dispatch_key(task: object) -> str | None:
    """Return the file of an include that runs exactly for its own file, else ``None``."""
    item = toggles.as_mapping(task)
    if item is None or frozenset(item) != INCLUDE_KEYS:
        return None
    include = toggles.as_mapping(item[INCLUDE_TASKS])
    target = include.get("file") if include is not None else None
    if (
        include is None
        or frozenset(include) != frozenset({"file"})
        or not isinstance(target, str)
        or check_lifecycle_topics.REGRESSION_FILE.fullmatch(target) is None
        or item["when"] != f"'{target}' in lifecycle_regression.files"
    ):
        return None
    return target


def _dispatch_tasks(tree: Tree) -> list[tuple[str | None, object]]:
    data = tree.data(REGRESSION_DISPATCH)
    tasks = [] if data is None else toggles.as_sequence(data)
    if tasks is None:
        message = f"{REGRESSION_DISPATCH} is not a list of tasks"
        raise FullMatrixError(message)
    return [(_dispatch_key(task), task) for task in tasks]


class Context:
    """The two revisions and what the mapping derives from them."""

    def __init__(self, base: Tree, head: Tree) -> None:
        """Compare ``base`` with ``head``."""
        self.base = base
        self.head = head
        self.trees = (base, head)
        self._owners: dict[str, frozenset[str]] = {}
        self._matches: dict[str, frozenset[str]] = {}

    @functools.cached_property
    def catalogues(self) -> tuple[Catalogue, Catalogue]:
        """Return the catalogue of each revision."""
        return _catalogue(self.base), _catalogue(self.head)

    @functools.cached_property
    def families(self) -> frozenset[str]:
        """Return the families of either revision's registry."""
        return frozenset(name for catalogue in self.catalogues for name, _ in catalogue.families)

    def referrers(self, pattern: re.Pattern[str], exclude: Iterable[str]) -> set[str]:
        """Return the YAML files of either revision whose text matches ``pattern``."""
        if pattern.pattern not in self._matches:
            self._matches[pattern.pattern] = frozenset(
                relative
                for tree in self.trees
                for relative, text in tree.sources[0].items()
                if pattern.search(text) is not None
            )
        return set(self._matches[pattern.pattern]) - set(exclude)

    def owners(self, relative: str, trail: frozenset[str] = frozenset()) -> frozenset[str]:
        """Return the topics that a change of ``relative`` affects.

        Raises:
            FullMatrixError: When the file is shared or no topic owns it.
        """
        if relative in self._owners:
            return self._owners[relative]
        if relative in GENERATED or relative == REGRESSION_DISPATCH or relative in trail:
            return frozenset()
        path = PurePosixPath(relative)
        directory = path.parent.as_posix()
        if path.suffix != ".yml" or directory not in {ROLE_TASKS, MOLECULE_TASKS, TOPICS}:
            message = f"{relative} is shared"
            raise FullMatrixError(message)
        if any(relative in tree.sources[1] for tree in self.trees):
            message = f"a symbolic link points to {relative}"
            raise FullMatrixError(message)
        if directory == TOPICS:
            return frozenset({path.stem})
        found_set: set[str] = set()
        if directory == ROLE_TASKS:
            found_set.update(
                family
                for family in self.families
                if path.stem == family or path.stem.startswith(f"{family}_")
            )
        for referrer in sorted(self.referrers(_file_reference(path.name), {relative})):
            found_set.update(self.owners(referrer, trail | {relative}))
        if not found_set:
            message = f"{relative} belongs to no topic and no topic file includes it"
            raise FullMatrixError(message)
        found = frozenset(found_set)
        if not trail:
            self._owners[relative] = found
        return found

    def users(self, name: str, exclude: str) -> frozenset[str]:
        """Return the topics of the files that use the variable ``name``.

        Raises:
            FullMatrixError: When no file uses it or a shared file uses it.
        """
        pattern = re.compile(r"(?<![\w])" + re.escape(name) + r"(?![\w])")
        referrers = self.referrers(pattern, {exclude, *GENERATED})
        if not referrers:
            message = f"the variable {name} is used by no file that the mapping knows"
            raise FullMatrixError(message)
        found: set[str] = set()
        for referrer in sorted(referrers):
            found.update(self.owners(referrer))
        return frozenset(found)

    def classify(self, relative: str) -> tuple[frozenset[str], str]:
        """Return the topics that a change of ``relative`` affects and why.

        Raises:
            FullMatrixError: When the change must run the full matrix.
        """
        if SAFE_PATH.fullmatch(relative) is None or {".", ".."} & set(relative.split("/")):
            message = "the path is not a plain relative path"
            raise FullMatrixError(message)
        if any(tree.is_link(relative) for tree in self.trees):
            message = "the path is a symbolic link"
            raise FullMatrixError(message)
        if relative in GENERATED:
            return frozenset(), "generated from classified files and checked for drift"
        if (
            relative in NO_LIFECYCLE_FILES
            or relative.startswith(NO_LIFECYCLE_PREFIXES)
            or ROLE_README.fullmatch(relative) is not None
        ):
            return frozenset(), "not read by any Molecule scenario"
        return self._structured(relative)

    def _structured(self, relative: str) -> tuple[frozenset[str], str]:
        if relative == CATALOGUE:
            return frozenset(_catalogue_topics(*self.catalogues)), "catalogue entries"
        if relative == ROLE_VARIABLES:
            return self._variables(), "role variables"
        if relative in ARGUMENT_SPECS:
            return self._specs(relative), "toggle options of the argument specs"
        if relative in TOGGLE_DEFAULTS:
            return self._defaults(relative), "toggle defaults"
        if relative == REGRESSION_DISPATCH:
            return self._dispatch(), "includes of the regression dispatch"
        return self.owners(relative), "topic file"

    def controlled(self, topic: str) -> frozenset[str]:
        """Return the families whose rules the toggle of ``topic`` controls in either revision.

        These are the family named ``topic``, the families of the umbrella ``topic``, and the
        families of the rules of every subsystem tag that is ``topic`` or whose umbrella it is,
        as :func:`toggles.controlling_topics` resolves a rule's toggles.

        Raises:
            FullMatrixError: When ``topic`` is no family or umbrella of either revision, or a tag
                that it controls names a rule that no family catalogues.
        """
        if not toggles.is_topic_name(topic):
            message = f"{topic} cannot name a family or an umbrella"
            raise FullMatrixError(message)
        found: set[str] = set()
        for catalogue in self.catalogues:
            found.update(
                name
                for name, _ in catalogue.families
                if topic in (name, catalogue.umbrellas.get(name))
            )
            for tag, rules in sorted(catalogue.tags.items()):
                if topic not in (tag, catalogue.umbrellas.get(tag)):
                    continue
                for rule in rules:
                    if rule not in catalogue.family_of:
                        message = (
                            f"the subsystem tag {tag} names {rule}, which no family catalogues"
                        )
                        raise FullMatrixError(message)
                    found.add(catalogue.family_of[rule])
        if not found:
            message = f"{topic} is no family or umbrella of the family registry"
            raise FullMatrixError(message)
        return frozenset(found)

    def _toggle(self, name: str, *, generated: bool) -> frozenset[str]:
        """Return the families that a changed topic toggle controls.

        Raises:
            FullMatrixError: When ``name`` is no topic toggle or a value is not the generated one.
        """
        match = TOPIC_TOGGLE.fullmatch(name)
        if match is None or not generated:
            message = f"{name} is not a generated topic toggle"
            raise FullMatrixError(message)
        return self.controlled(match.group(1))

    def _defaults(self, relative: str) -> frozenset[str]:
        before, after = (toggles.as_mapping(tree.data(relative)) for tree in self.trees)
        if before is None or after is None:
            message = f"{relative} is missing or not a mapping"
            raise FullMatrixError(message)
        found: set[str] = set()
        for key, values in _differences(before, after):
            found.update(
                self._toggle(key, generated=all(isinstance(value, bool) for value in values))
            )
        return frozenset(found)

    def _specs(self, relative: str) -> frozenset[str]:
        (before_rest, before), (after_rest, after) = (
            _without_descriptions(tree.data(relative), relative) for tree in self.trees
        )
        if not _same(before_rest, after_rest) or before.keys() != after.keys():
            message = "the argument specs gained, lost or changed an entry point or a key"
            raise FullMatrixError(message)
        found: set[str] = set()
        for entry in sorted(before):
            old, new = (
                toggles.as_mapping(item.get("options", {}))
                for item in (before[entry], after[entry])
            )
            if (
                old is None
                or new is None
                or not _same(_without(before[entry], "options"), _without(after[entry], "options"))
            ):
                message = f"the entry point {entry} changed beyond its options and descriptions"
                raise FullMatrixError(message)
            for option, values in _differences(old, new):
                if option == ALLOW_LIST and len(values) == len(self.trees):
                    found.update(self._allowed(old[option], new[option]))
                    continue
                found.update(
                    self._toggle(
                        option, generated=all(_same(value, TOGGLE_OPTION) for value in values)
                    )
                )
        return frozenset(found)

    def _allowed(self, before: object, after: object) -> frozenset[str]:
        """Return the families of the choices that the list of allowed disruptive topics changed.

        Raises:
            FullMatrixError: When anything but the gained or lost choices changed.
        """
        (old_rest, old), (new_rest, new) = _choices(before), _choices(after)
        if not _same(old_rest, new_rest) or [choice for choice in old if choice in new] != [
            choice for choice in new if choice in old
        ]:
            message = f"{ALLOW_LIST} changed beyond the choices that it gained or lost"
            raise FullMatrixError(message)
        found: set[str] = set()
        for choice in sorted(set(old) ^ set(new)):
            found.update(self.controlled(choice))
        return frozenset(found)

    def _variables(self) -> frozenset[str]:
        before, after = (toggles.as_mapping(tree.data(ROLE_VARIABLES) or {}) for tree in self.trees)
        if before is None or after is None:
            message = f"{ROLE_VARIABLES} is not a mapping"
            raise FullMatrixError(message)
        changed = {
            key
            for key in before.keys() | after.keys()
            if key not in before or key not in after or before[key] != after[key]
        }
        found: set[str] = set()
        for key in sorted(changed):
            pattern = re.compile(r"(?<![\w])" + re.escape(key) + r"(?![\w])")
            if any(
                pattern.search(json.dumps(value)) is not None
                for values in (before, after)
                for other, value in values.items()
                if other != key
            ):
                message = f"another role variable uses {key}"
                raise FullMatrixError(message)
            found.update(self.users(key, ROLE_VARIABLES))
        return frozenset(found)

    def _dispatch(self) -> frozenset[str]:
        changed = _projected(_dispatch_tasks(self.base), _dispatch_tasks(self.head))
        if None in changed:
            message = "a task of the regression dispatch other than an exact include changed"
            raise FullMatrixError(message)
        found: set[str] = set()
        for file in sorted(cast("set[str]", changed)):
            found.update(self.owners(f"{MOLECULE_TASKS}/{file}"))
        return frozenset(found)


def decide(base: Path, head: Path, changed: Sequence[str]) -> Decision:
    """Return which topics the change from ``base`` to ``head`` affects, or the full matrix."""
    context = Context(Tree(base), Tree(head))
    topics: set[str] = set()
    reasons: list[str] = []
    full = False
    for relative in changed:
        try:
            found, why = context.classify(relative)
        except FullMatrixError as error:
            full = True
            reasons.append(f"{relative}: {error}: full matrix")
            continue
        topics.update(found)
        named = ", ".join(sorted(found)) if found else "no topic"
        reasons.append(f"{relative}: {why}: {named}")
    return Decision(full, frozenset(topics), tuple(reasons))


def legs_of(matrix: object, where: str) -> list[dict[str, str]]:
    """Return the legs of a matrix printed by ``make molecule-matrix``.

    Raises:
        GenerationError: When the matrix is not one.
    """
    data = toggles.as_mapping(matrix)
    entries = toggles.as_sequence(data.get("include")) if data is not None else None
    if entries is None:
        message = f"{where} is not a matrix with an include list"
        raise GenerationError(message)
    found: list[dict[str, str]] = []
    for entry in entries:
        item = toggles.as_mapping(entry)
        if (
            item is None
            or set(item) != set(LEG_KEYS)
            or not all(isinstance(value, str) for value in item.values())
        ):
            message = f"{where}: every leg must have exactly the string keys {', '.join(LEG_KEYS)}"
            raise GenerationError(message)
        found.append({key: str(value) for key, value in item.items()})
    return found


def select(decision: Decision, legs: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Return the legs that the decision runs: all, or those without a topic or of its topics."""
    if decision.full:
        return list(legs)
    return [leg for leg in legs if leg["topic"] == "" or leg["topic"] in decision.topics]


def plan(decision: Decision, docker: object, libvirt: object) -> dict[str, object]:
    """Return the plan for CI: the scope, the topics, the reasons and the filtered matrices."""
    docker_legs = select(decision, legs_of(docker, "the Docker matrix"))
    libvirt_legs = select(decision, legs_of(libvirt, "the libvirt matrix"))
    return {
        "scope": SCOPE_FULL if decision.full else SCOPE_AFFECTED,
        "topics": sorted(decision.topics),
        "reasons": list(decision.reasons),
        "lifecycle_legs": len(docker_legs),
        "docker": {"include": docker_legs},
        "libvirt": {"include": libvirt_legs},
    }


def _read_json(path: Path) -> object:
    try:
        return cast("object", json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        message = f"{path} cannot be read as JSON: {error}"
        raise GenerationError(message) from error


def _read_changed(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        message = f"{path} cannot be read: {error}"
        raise GenerationError(message) from error
    return [item for item in text.split("\0") if item]


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-root", type=Path, default=Path())
    parser.add_argument("--head-root", type=Path, required=True)
    parser.add_argument("--changed", type=Path, required=True)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--libvirt", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        changed = _read_changed(cast("Path", arguments.changed))
        decision = decide(
            cast("Path", arguments.base_root), cast("Path", arguments.head_root), changed
        )
        found = plan(
            decision,
            _read_json(cast("Path", arguments.docker)),
            _read_json(cast("Path", arguments.libvirt)),
        )
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(found, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
