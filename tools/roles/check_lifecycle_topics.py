"""Check that every native topic has a valid toggle lifecycle declaration (FREES-60).

The Molecule toggle lifecycle harness (``extensions/molecule/shared/lifecycle.yml``) applies
every topic that has a rule with a native remediation, checks idempotence and check mode,
switches the topic off with its topic toggle and with its rule toggles, and asserts that the
declared state before the topic is restored exactly. What it inspects for a topic comes from
one declaration, ``extensions/molecule/shared/vars/topics/<topic>.yml``.

The topics are derived from the catalogue ``roles/remediate/vars/rules.yml`` with
``generate_toggles.native_families``, the predicate that the remediation dispatch uses. This
check fails when a native topic has no declaration, when a declaration names a topic without
a native rule, and when a declaration does not follow the format of ``docs/molecule.md``:
unknown keys, a family or disruptive flag that disagrees with the file name or the registry,
a disruptive topic without a containment note, a declaration without an ``applied``
expectation, an expectation or a pre-state for an item that is not declared, an unknown
attribute or platform, a malformed mode, a ``rewritten`` flag that is not a boolean, a
pre-state that leaves a rule ``unchanged`` that is not a native rule of the topic or with a
status other than ``compliant``, ``notapplicable`` or ``overridden``, a pre-state file whose
``content`` is not a non-empty text or that also sets an owner or group, a pre-state ``applied``
override that the top-level ``applied`` would refuse, or ``unselected_platforms`` that name
every platform, which would let the topic run nowhere. A topic therefore cannot gain a native rule
without its lifecycle test, and the harness cannot silently skip a declared expectation or a
topic. The harness repeats the coverage check at run time and fails on a platform that skips
a topic without the declaration saying so.

Each cycle runs with one set of Molecule drivers, the prefixes of the scenario directories
(FREES-61): a pre-state runs with the drivers it ``requires``, else with those its topic
``requires``, else in the Docker scenarios only, because the libvirt scenarios run only what a
container cannot prove (an ownership change, a kernel parameter, a service). This check fails
when no lifecycle scenario of such a driver (one whose ``side_effect`` is the harness) runs a
platform that the topic does not list under ``unselected_platforms``, so every declared cycle is
exercised by some driver. ``cycle_platforms`` returns the same map for ``make molecule-matrix``,
which plans one CI leg per topic, toggle mode, driver and platform that runs a cycle.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple, cast

import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)
from tools.roles import generate_toggles

if TYPE_CHECKING:
    from collections.abc import Sequence

GenerationError = generate_toggles.GenerationError
TOPICS: Final[Path] = Path("extensions/molecule/shared/vars/topics")
VERSIONS: Final[Path] = Path("extensions/molecule/shared/vars/versions.yml")
MOLECULE: Final[Path] = Path("extensions/molecule")
DRIVERS: Final[tuple[str, ...]] = ("docker", "libvirt")
UNRESTRICTED_DRIVERS: Final[frozenset[str]] = frozenset({"docker"})
REQUIRES_KEY: Final[str] = "requires"
IMAGES_KEY: Final[str] = "molecule_images"
LIFECYCLE_PLAYBOOK: Final[str] = "../shared/lifecycle.yml"
TOP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "family",
        "disruptive",
        "containment",
        "audit",
        "state",
        "applied",
        "pre_states",
        "unselected_platforms",
        "requires",
    }
)
REQUIRED_KEYS: Final[tuple[str, ...]] = ("family", "disruptive", "state", "applied")
CATEGORY_KEYS: Final[dict[str, str]] = {
    "files": "path",
    "packages": "name",
    "services": "name",
    "sysctl": "name",
    "users": "name",
    "groups": "name",
}
ATTRIBUTES: Final[dict[str, frozenset[str]]] = {
    "files": frozenset(
        {
            "exists",
            "type",
            "mode",
            "owner",
            "group",
            "uid",
            "gid",
            "inode",
            "mtime",
            "attributes",
            "checksum",
            "link_target",
        }
    ),
    "packages": frozenset({"installed", "versions"}),
    "services": frozenset({"exists", "state", "status"}),
    "sysctl": frozenset({"value"}),
    "users": frozenset({"exists", "entry"}),
    "groups": frozenset({"exists", "entry"}),
}
AUDIT_KEYS: Final[frozenset[str]] = frozenset({"applied_outcomes", "reason"})
EXTRA_AUDIT_OUTCOMES: Final[frozenset[str]] = frozenset({"notapplicable"})
PRE_STATE_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "audit", "files", "unchanged", "applied", "requires"}
)
UNCHANGED_KEYS: Final[frozenset[str]] = frozenset({"rule", "status", "platforms"})
UNCHANGED_STATUSES: Final[frozenset[str]] = frozenset({"compliant", "notapplicable", "overridden"})
REWRITTEN_KEY: Final[str] = "rewritten"
PRE_STATE_FILE_KEYS: Final[frozenset[str]] = frozenset(
    {"path", "mode", "owner", "group", "content"}
)
MAX_CONTENT: Final[int] = 4096
UNSELECTED_KEYS: Final[frozenset[str]] = frozenset({"platform", "reason"})
PLATFORMS_KEY: Final[str] = "platforms"
CHANGES_KEY: Final[str] = "changes"
MODE: Final[re.Pattern[str]] = re.compile(r"[0-7]{4}")
NAME: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.@+-]+")
PATH: Final[re.Pattern[str]] = re.compile(r"/[A-Za-z0-9_.@+/-]*")


def _load(path: Path) -> object:
    try:
        return cast("object", yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as error:
        message = f"{path}: cannot be read as YAML: {error}"
        raise GenerationError(message) from error


def _text(value: object) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _strings(value: object) -> list[str] | None:
    items = toggles.as_sequence(value)
    if items is None or not items or not all(_text(item) for item in items):
        return None
    return [str(item) for item in items]


class Context(NamedTuple):
    """What a declaration is checked against besides the platforms.

    ``coverage`` maps each driver to the platforms of its lifecycle scenarios (``None``: every
    driver runs every platform); ``rules`` holds the short identifiers of the topic's native rules.
    """

    coverage: dict[str, frozenset[str]] | None = None
    rules: frozenset[str] = frozenset()


class Declaration:
    """The validation of one topic declaration; ``errors`` collects every finding."""

    def __init__(
        self,
        where: str,
        platforms: frozenset[str],
        coverage: dict[str, frozenset[str]] | None = None,
        rules: frozenset[str] = frozenset(),
    ) -> None:
        """Start the validation of ``where`` for the platforms, driver coverage and native rules.

        ``coverage`` maps each driver to the platforms that its lifecycle scenarios run; without it
        every driver counts as running every platform. ``rules`` holds the short identifiers of the
        native rules of the topic, which a pre-state may declare ``unchanged``.
        """
        self.where = where
        self.platforms = platforms
        self.coverage: dict[str, frozenset[str]] = (
            coverage if coverage is not None else dict.fromkeys(DRIVERS, platforms)
        )
        self.rules = rules
        self.errors: list[str] = []
        self.items: dict[str, set[str]] = {category: set() for category in CATEGORY_KEYS}
        self.drivers: frozenset[str] = frozenset(DRIVERS)
        self.skipped_platforms: set[str] = set()
        self.topic_drivers: frozenset[str] | None = None
        self.pre_state_drivers: list[frozenset[str] | None] = [None]

    def error(self, message: str) -> None:
        """Record a finding about this declaration."""
        self.errors.append(f"{self.where}: {message}")

    def mapping(self, value: object, what: str) -> dict[str, object] | None:
        """Return ``value`` as a mapping, or record that ``what`` must be one."""
        mapping = toggles.as_mapping(value)
        if mapping is None:
            self.error(f"{what} must be a mapping")
        return mapping

    def sequence(self, value: object, what: str) -> list[object]:
        """Return ``value`` as a list, or record that ``what`` must be one and return none."""
        items = toggles.as_sequence(value)
        if items is None:
            self.error(f"{what} must be a list")
            return []
        return items

    def keys(self, mapping: dict[str, object], allowed: frozenset[str], what: str) -> None:
        """Record every key of ``mapping`` that ``allowed`` does not contain."""
        for key in sorted(set(mapping) - allowed):
            self.error(f"{what} has the unknown key {key!r}")

    def platform_list(self, item: dict[str, object], what: str) -> None:
        """Check the optional platform restriction of an item."""
        if PLATFORMS_KEY not in item:
            return
        platforms = _strings(item[PLATFORMS_KEY])
        if platforms is None:
            self.error(f"{what} needs a non-empty list of platforms")
            return
        for platform in platforms:
            if platform not in self.platforms:
                self.error(f"{what} names the unknown platform {platform!r}")

    def key_value(self, category: str, item: dict[str, object], what: str) -> str | None:
        """Return the identifying value of an item, or record why it is missing or malformed."""
        key = CATEGORY_KEYS[category]
        value = item.get(key)
        pattern = PATH if key == "path" else NAME
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            self.error(f"{what} needs a valid {key}")
            return None
        return value

    def state_item_keys(self, category: str, item: dict[str, object], what: str) -> frozenset[str]:
        """Return the keys that a state item of ``category`` may have; check a file's flag."""
        if category != "files":
            return frozenset({CATEGORY_KEYS[category], PLATFORMS_KEY})
        if not isinstance(item.get(REWRITTEN_KEY, False), bool):
            self.error(f"{what}.{REWRITTEN_KEY} must be a boolean")
        return frozenset({CATEGORY_KEYS[category], PLATFORMS_KEY, REWRITTEN_KEY})

    def state(self, value: object) -> None:
        """Check the items whose state the harness records."""
        state = self.mapping(value, "state")
        if state is None:
            return
        self.keys(state, frozenset(CATEGORY_KEYS), "state")
        for category in CATEGORY_KEYS:
            if category not in state:
                continue
            for index, entry in enumerate(self.sequence(state[category], f"state.{category}")):
                what = f"state.{category}[{index}]"
                item = self.mapping(entry, what)
                if item is None:
                    continue
                self.keys(item, self.state_item_keys(category, item, what), what)
                self.platform_list(item, what)
                key = self.key_value(category, item, what)
                if key is None:
                    continue
                if key in self.items[category]:
                    self.error(f"{what} declares {key} twice")
                self.items[category].add(key)
        if not any(self.items.values()):
            self.error("state declares no item")

    def expectation(self, category: str, item: dict[str, object], what: str) -> None:
        """Check the attributes that an expectation sets or requires to change."""
        attributes = ATTRIBUTES[category]
        allowed = attributes | {CATEGORY_KEYS[category], PLATFORMS_KEY, CHANGES_KEY}
        self.keys(item, frozenset(allowed), what)
        changes: list[str] = []
        if CHANGES_KEY in item:
            found = _strings(item[CHANGES_KEY])
            if found is None:
                self.error(f"{what} needs a non-empty list of changes")
            else:
                changes = found
        for attribute in changes:
            if attribute not in attributes:
                self.error(f"{what} cannot require a change of {attribute!r}")
            elif attribute in item:
                self.error(f"{what} both sets and requires a change of {attribute!r}")
        if not changes and not attributes & set(item):
            self.error(f"{what} expects nothing")
        mode = item.get("mode")
        if "mode" in item and (not isinstance(mode, str) or MODE.fullmatch(mode) is None):
            self.error(f"{what} needs a four-digit octal mode string")

    def applied(self, value: object) -> None:
        """Check the expectations after the topic is applied."""
        if self.expectations(value, "applied") == 0:
            self.error(
                "applied declares no expectation; the state after apply is the evidence that the "
                "remediation works when a container audit cannot show it"
            )

    def expectations(self, value: object, where: str) -> int:
        """Check the expectations in ``value`` and return how many there are."""
        applied = self.mapping(value, where)
        if applied is None:
            return -1
        self.keys(applied, frozenset(CATEGORY_KEYS), where)
        expectations = 0
        for category in CATEGORY_KEYS:
            if category not in applied:
                continue
            seen: dict[str, set[str]] = {}
            for index, entry in enumerate(self.sequence(applied[category], f"{where}.{category}")):
                what = f"{where}.{category}[{index}]"
                item = self.mapping(entry, what)
                if item is None:
                    continue
                self.platform_list(item, what)
                self.expectation(category, item, what)
                key = self.key_value(category, item, what)
                if key is None:
                    continue
                if key not in self.items[category]:
                    self.error(f"{what} expects {key}, which state.{category} does not declare")
                covered = set(_strings(item.get(PLATFORMS_KEY)) or self.platforms)
                if seen.get(key, set()) & covered:
                    self.error(f"{what} expects {key} twice for a platform")
                seen.setdefault(key, set()).update(covered)
                expectations += 1
        return expectations

    def unselected(self, value: object) -> None:
        """Check the platforms whose profile selects no native rule of the topic."""
        seen: set[str] = set()
        for index, entry in enumerate(self.sequence(value, "unselected_platforms")):
            what = f"unselected_platforms[{index}]"
            item = self.mapping(entry, what)
            if item is None:
                continue
            self.keys(item, UNSELECTED_KEYS, what)
            platform = item.get("platform")
            if not isinstance(platform, str) or platform not in self.platforms:
                self.error(f"{what} needs a known platform")
            elif platform in seen:
                self.error(f"{what} lists {platform} twice")
            else:
                seen.add(platform)
                self.skipped_platforms.add(platform)
            if not _text(item.get("reason")):
                self.error(f"{what} needs a reason")
        if seen and seen >= self.platforms:
            self.error(
                "unselected_platforms lists every platform, so the lifecycle of the topic "
                "would run nowhere"
            )

    def audit(self, value: object) -> None:
        """Check the additional audit outcomes that the container platform allows."""
        audit = self.mapping(value, "audit")
        if audit is None:
            return
        self.keys(audit, AUDIT_KEYS, "audit")
        outcomes = _strings(audit.get("applied_outcomes"))
        if outcomes is None:
            self.error("audit.applied_outcomes must be a non-empty list")
        else:
            for outcome in outcomes:
                if outcome not in EXTRA_AUDIT_OUTCOMES:
                    self.error(f"audit.applied_outcomes cannot add {outcome!r}")
        if not _text(audit.get("reason")):
            self.error("audit.reason must explain why the audit cannot show pass or fixed")

    def pre_state_files(self, value: object, what: str) -> None:
        """Check the file modes and owners that a pre-state sets before a cycle."""
        for index, entry in enumerate(self.sequence(value, f"{what}.files")):
            where = f"{what}.files[{index}]"
            item = self.mapping(entry, where)
            if item is None:
                continue
            self.keys(item, PRE_STATE_FILE_KEYS, where)
            key = self.key_value("files", item, where)
            if key is not None and key not in self.items["files"]:
                self.error(f"{where} sets {key}, which state.files does not declare")
            if "content" in item:
                self.pre_state_content(item, where)
            elif len(set(item) & {"mode", "owner", "group"}) == 0:
                self.error(f"{where} sets no mode, owner or group")
            mode = item.get("mode")
            if "mode" in item and (not isinstance(mode, str) or MODE.fullmatch(mode) is None):
                self.error(f"{where} needs a four-digit octal mode string")
            for owner in ("owner", "group"):
                if owner in item and not (
                    isinstance(item[owner], str) and NAME.fullmatch(str(item[owner]))
                ):
                    self.error(f"{where} needs a valid {owner}")

    def pre_state_content(self, item: dict[str, object], where: str) -> None:
        """Check a file that the pre-state writes, as root, before a cycle and removes after it."""
        content = item["content"]
        if not _text(content) or len(str(content)) > MAX_CONTENT:
            self.error(f"{where} needs a non-empty content of at most {MAX_CONTENT} characters")
        for owner in ("owner", "group"):
            if owner in item:
                self.error(f"{where} writes its content as root and cannot set the {owner}")

    def driver_list(self, value: object, what: str) -> frozenset[str] | None:
        """Return the drivers that ``what`` requires, or record why the list is invalid."""
        drivers = _strings(value)
        if drivers is None:
            self.error(f"{what} needs a non-empty list of drivers")
            return None
        if len(set(drivers)) != len(drivers):
            self.error(f"{what} names a driver twice")
        unknown = [driver for driver in drivers if driver not in DRIVERS]
        for driver in unknown:
            self.error(
                f"{what} names the unknown driver {driver!r}; known are {', '.join(DRIVERS)}"
            )
        return None if unknown else frozenset(drivers)

    def requires(self, value: object) -> None:
        """Check the drivers that the topic needs."""
        drivers = self.driver_list(value, REQUIRES_KEY)
        if drivers is not None:
            self.drivers = drivers
            self.topic_drivers = drivers

    def cycle_drivers(self) -> frozenset[str]:
        """Return the drivers whose scenarios run a cycle of the topic.

        A pre-state runs with the drivers it requires, else with those the topic requires, else
        in the Docker scenarios only; the libvirt scenarios run only what containers cannot.
        """
        default = self.topic_drivers or UNRESTRICTED_DRIVERS
        return frozenset[str]().union(*(drivers or default for drivers in self.pre_state_drivers))

    def cycle_platforms(self) -> dict[str, frozenset[str]]:
        """Return, per driver of a cycle, the platforms on which the topic runs."""
        running = frozenset(self.platforms - self.skipped_platforms)
        return dict.fromkeys(sorted(self.cycle_drivers()), running)

    def covered(self) -> None:
        """Check that each driver of a cycle has a lifecycle scenario on every running platform."""
        running = self.platforms - self.skipped_platforms
        for driver in sorted(self.cycle_drivers()):
            for platform in sorted(running - self.coverage.get(driver, frozenset())):
                self.error(
                    f"the declaration requires {driver}, but no {driver} scenario in {MOLECULE} "
                    f"runs the platform {platform}, which unselected_platforms does not list"
                )

    def pre_state_unchanged(self, value: object, what: str) -> None:
        """Check the rules that a pre-state already satisfies, so that they change nothing."""
        seen: set[str] = set()
        for index, entry in enumerate(self.sequence(value, f"{what}.unchanged")):
            where = f"{what}.unchanged[{index}]"
            item = self.mapping(entry, where)
            if item is None:
                continue
            self.keys(item, UNCHANGED_KEYS, where)
            self.platform_list(item, where)
            rule = item.get("rule")
            if not isinstance(rule, str) or rule not in self.rules:
                self.error(f"{where} needs the short identifier of a native rule of the topic")
            elif rule in seen:
                self.error(f"{where} lists {rule} twice")
            else:
                seen.add(rule)
            if item.get("status") not in UNCHANGED_STATUSES:
                self.error(f"{where} needs the status compliant, notapplicable or overridden")

    def _pre_state_requires(self, item: dict[str, object], what: str) -> None:
        """Record the drivers of a pre-state, which must be drivers of its topic."""
        if REQUIRES_KEY not in item:
            self.pre_state_drivers.append(None)
            return
        drivers = self.driver_list(item[REQUIRES_KEY], f"{what}.requires") or frozenset()
        for driver in sorted(drivers - self.drivers):
            self.error(f"{what} requires {driver}, which the topic does not require")
        self.pre_state_drivers.append(drivers & self.drivers or None)

    def pre_states(self, value: object) -> None:
        """Check the states from which the harness runs the cycles."""
        entries = self.sequence(value, "pre_states")
        self.pre_state_drivers = []
        if not entries:
            self.error("pre_states must not be empty; leave it out for the as-built state")
        names: set[str] = set()
        for index, entry in enumerate(entries):
            what = f"pre_states[{index}]"
            item = self.mapping(entry, what)
            if item is None:
                continue
            self.keys(item, PRE_STATE_KEYS, what)
            name = item.get("name")
            if not _text(name):
                self.error(f"{what} needs a name")
            elif str(name) in names:
                self.error(f"{what} repeats the name {name!r}")
            else:
                names.add(str(name))
            if "audit" in item and not isinstance(item["audit"], bool):
                self.error(f"{what}.audit must be a boolean")
            if "files" in item:
                self.pre_state_files(item["files"], what)
            self._pre_state_requires(item, what)
            if "unchanged" in item:
                self.pre_state_unchanged(item["unchanged"], what)
            if "applied" in item and self.expectations(item["applied"], f"{what}.applied") == 0:
                self.error(f"{what}.applied declares no expectation; leave it out instead")


def _identity(
    declaration: Declaration, data: dict[str, object], family: str, *, disruptive: bool
) -> None:
    declaration.keys(data, TOP_KEYS, "the declaration")
    for key in REQUIRED_KEYS:
        if key not in data:
            declaration.error(f"the declaration needs {key!r}")
    if data.get("family") != family:
        declaration.error(f"family must be {family!r}, the name of the file")
    if data.get("disruptive") is not disruptive:
        declaration.error(f"disruptive must be {str(disruptive).lower()}, as in the registry")
    if disruptive and not _text(data.get("containment")):
        declaration.error("a disruptive topic must describe its containment")
    if not disruptive and "containment" in data:
        declaration.error("containment is only for a disruptive topic")


def check_declaration(
    path: Path,
    family: str,
    platforms: frozenset[str],
    *,
    disruptive: bool,
    context: Context | None = None,
) -> list[str]:
    """Return the findings for the declaration of ``family`` in ``path``.

    ``context`` holds the driver coverage of the scenarios and the short identifiers of the
    native rules of ``family``.
    """
    return _declaration(path, family, platforms, disruptive=disruptive, context=context).errors


def _declaration(
    path: Path, family: str, platforms: frozenset[str], *, disruptive: bool, context: Context | None
) -> Declaration:
    found = context if context is not None else Context()
    declaration = Declaration(str(path), platforms, found.coverage, found.rules)
    data = declaration.mapping(_load(path), "the declaration")
    if data is None:
        return declaration
    _identity(declaration, data, family, disruptive=disruptive)
    if REQUIRES_KEY in data:
        declaration.requires(data[REQUIRES_KEY])
    if "state" in data:
        declaration.state(data["state"])
    if "applied" in data:
        declaration.applied(data["applied"])
    if "audit" in data:
        declaration.audit(data["audit"])
    if "pre_states" in data:
        declaration.pre_states(data["pre_states"])
    if "unselected_platforms" in data:
        declaration.unselected(data["unselected_platforms"])
    declaration.covered()
    return declaration


def platforms(root: Path) -> frozenset[str]:
    """Return the image keys of the Molecule platforms, which declarations may name."""
    data = toggles.as_mapping(_load(root / VERSIONS))
    images = toggles.as_mapping(data.get(IMAGES_KEY)) if data is not None else None
    if not images:
        message = f"{root / VERSIONS} has no {IMAGES_KEY} mapping"
        raise GenerationError(message)
    return frozenset(images)


def scenarios(root: Path, platforms: frozenset[str]) -> dict[str, frozenset[str]]:
    """Return, per driver, the platforms that the lifecycle scenarios below ``root`` run.

    A scenario is a directory of ``extensions/molecule`` with a ``molecule.yml``; its name
    starts with its driver. Every platform must name a key of ``versions.yml``. Only a scenario
    whose ``side_effect`` playbook is the harness counts as running its platforms.
    """
    covered: dict[str, set[str]] = {driver: set() for driver in DRIVERS}
    for config in sorted((root / MOLECULE).glob("*/molecule.yml")):
        driver = config.parent.name.split("-", 1)[0]
        if driver not in covered:
            message = f"{config}: a scenario name must start with one of {', '.join(DRIVERS)}"
            raise GenerationError(message)
        data = toggles.as_mapping(_load(config))
        entries = toggles.as_sequence(data.get("platforms")) if data is not None else None
        if not entries:
            message = f"{config}: the scenario has no platforms"
            raise GenerationError(message)
        for entry in entries:
            item = toggles.as_mapping(entry)
            image = item.get("image") if item is not None else None
            if not isinstance(image, str) or image not in platforms:
                message = f"{config}: every platform needs an image key of {VERSIONS}"
                raise GenerationError(message)
            if _runs_lifecycle(data):
                covered[driver].add(image)
    return {driver: frozenset(images) for driver, images in covered.items()}


def _runs_lifecycle(data: dict[str, object] | None) -> bool:
    ansible = toggles.as_mapping(data.get("ansible")) if data is not None else None
    playbooks = toggles.as_mapping(ansible.get("playbooks")) if ansible is not None else None
    return playbooks is not None and playbooks.get("side_effect") == LIFECYCLE_PLAYBOOK


def native_rules(catalogue: toggles.Catalogue, family: str) -> frozenset[str]:
    """Return the short identifiers of the native rules of ``family``."""
    return frozenset(
        toggles.rule_short_id(str(rule["rule_id"]))
        for rule in catalogue.rules
        if rule["family"] == family and toggles.is_native(rule)
    )


def check(root: Path) -> tuple[list[str], list[str]]:
    """Return the native topics and every finding about their declarations below ``root``."""
    catalogue = generate_toggles.load_catalogue(root / generate_toggles.CATALOGUE)
    native = generate_toggles.native_families(catalogue)
    known = platforms(root)
    coverage = scenarios(root, known)
    directory = root / TOPICS
    declared = sorted(path.stem for path in directory.glob("*.yml")) if directory.is_dir() else []
    errors = [
        f"{TOPICS / (family + '.yml')}: the native topic {family} has no lifecycle declaration"
        for family in native
        if family not in declared
    ]
    errors.extend(
        f"{TOPICS / (family + '.yml')}: {family} has no native rule in "
        f"{generate_toggles.CATALOGUE}, so it must not have a lifecycle declaration"
        for family in declared
        if family not in native
    )
    for family in native:
        if family in declared:
            errors.extend(
                check_declaration(
                    directory / f"{family}.yml",
                    family,
                    known,
                    disruptive=catalogue.families[family],
                    context=Context(coverage, native_rules(catalogue, family)),
                )
            )
    return native, errors


def cycle_platforms(root: Path) -> dict[str, dict[str, frozenset[str]]]:
    """Return, per native topic and driver of a cycle, the platforms on which the topic runs.

    The map is the one that ``make lint-lifecycle`` checks; a finding stops it, so that no CI
    leg is planned from an invalid declaration.
    """
    native, errors = check(root)
    if errors:
        message = "; ".join(errors)
        raise GenerationError(message)
    catalogue = generate_toggles.load_catalogue(root / generate_toggles.CATALOGUE)
    known = platforms(root)
    return {
        family: _declaration(
            root / TOPICS / f"{family}.yml",
            family,
            known,
            disruptive=catalogue.families[family],
            context=Context(None, native_rules(catalogue, family)),
        ).cycle_platforms()
        for family in native
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path())
    arguments = parser.parse_args(argv)
    root = cast("Path", arguments.root)
    try:
        native, errors = check(root)
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if errors:
        print("\n".join(errors), file=sys.stderr)
        print(
            "error: every native topic needs a valid lifecycle declaration; see docs/molecule.md",
            file=sys.stderr,
        )
        return 1
    print(f"lifecycle declarations cover every native topic: {', '.join(native)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
