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
``content`` is not a non-empty text or that also sets an owner or group, pre-state ``lines``
(``regexp`` and ``line`` on one line each) of a file that ``state.files`` does not declare
``rewritten`` or of an entry that also sets ``content`` (FREES-185), a pre-state ``applied``
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

A topic may declare ``regressions`` (FREES-175): named groups of task files of
``extensions/molecule/shared/tasks`` that test what the cycles cannot (a change of method, a change
by hand, a refusal), each optionally limited to ``platforms``. Every file must be one that the
static dispatch ``lifecycle_regressions.yml`` includes, so no variable chooses a file to include.
Each include must run exactly when its own file is in the selected group (no other condition, no
tags), every dispatched file must be named by some group, and every dispatched file must end by
recording that it ran, which the harness checks for every file of the group of a leg (FREES-175).
``regression_platforms`` returns, per topic and group, the platforms whose Docker lifecycle scenario
runs it; ``make molecule-matrix`` plans one leg per group and platform, with the mode
``regressions-<group>``, so that the regressions do not lengthen the cycle legs.

A topic may declare ``profiles`` (FREES-190): per platform, the profile of that platform's pinned
datastream that its cycles and regressions run with instead of the platform's own, with a reason,
for a topic whose rules the platform's own profile does not select. The profile must be one that
``content/manifest.yml`` lists for the datastream of the platform, and a platform that
``unselected_platforms`` lists cannot have one.
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
REGRESSIONS_KEY: Final[str] = "regressions"
REGRESSION_KEYS: Final[frozenset[str]] = frozenset({"name", "files", "platforms"})
REGRESSION_DRIVER: Final[str] = "docker"
REGRESSION_DISPATCH: Final[Path] = Path(
    "extensions/molecule/shared/tasks/lifecycle_regressions.yml"
)
INCLUDE_TASKS: Final[str] = "ansible.builtin.include_tasks"
SET_FACT: Final[str] = "ansible.builtin.set_fact"
INCLUDE_KEYS: Final[frozenset[str]] = frozenset({"name", INCLUDE_TASKS, "when"})
RECORD_KEYS: Final[frozenset[str]] = frozenset({"name", SET_FACT})
RECORD_FACT: Final[str] = "lifecycle_regression_files_run"
REGRESSION_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]{0,31}")
REGRESSION_FILE: Final[re.Pattern[str]] = re.compile(r"lifecycle_[a-z0-9_]{1,64}\.yml")
MANIFEST: Final[Path] = Path("content/manifest.yml")
PROFILE_PREFIX: Final[str] = "xccdf_org.ssgproject.content_profile_"
PROFILE_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9_]{0,127}")
PROFILES_KEY: Final[str] = "profiles"
PROFILE_KEYS: Final[frozenset[str]] = frozenset({"platform", "profile", "reason"})
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
        "regressions",
        PROFILES_KEY,
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
    "audit_rules": "line",
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
    "audit_rules": frozenset({"loaded"}),
}
DRIVERS_KEY: Final[str] = "drivers"
KERNEL_CATEGORIES: Final[frozenset[str]] = frozenset({"audit_rules"})
AUDIT_KEYS: Final[frozenset[str]] = frozenset({"applied_outcomes", "reason"})
EXTRA_AUDIT_OUTCOMES: Final[frozenset[str]] = frozenset({"notapplicable"})
PRE_STATE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "name",
        "audit",
        "modes",
        "files",
        "unchanged",
        "applied",
        "requires",
        "loads_audit_rules",
        "reasons",
    }
)
REASON_KEYS: Final[frozenset[str]] = frozenset({"step", "reason", "rules", "platforms"})
REASON_STEPS: Final[frozenset[str]] = frozenset({"apply", "cleanup"})
NO_REASON: Final[str] = "none"
REASON: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z_]{0,39}")
TOGGLE_MODES: Final[frozenset[str]] = frozenset({"topic", "rule"})
UNCHANGED_KEYS: Final[frozenset[str]] = frozenset({"rule", "status", "platforms"})
UNCHANGED_STATUSES: Final[frozenset[str]] = frozenset({"compliant", "notapplicable", "overridden"})
REWRITTEN_KEY: Final[str] = "rewritten"
PRE_STATE_FILE_KEYS: Final[frozenset[str]] = frozenset(
    {"path", "mode", "owner", "group", "content", "lines"}
)
PRE_STATE_LINE_KEYS: Final[frozenset[str]] = frozenset({"regexp", "line"})
MAX_CONTENT: Final[int] = 4096
UNSELECTED_KEYS: Final[frozenset[str]] = frozenset({"platform", "reason"})
PLATFORMS_KEY: Final[str] = "platforms"
CHANGES_KEY: Final[str] = "changes"
MODE: Final[re.Pattern[str]] = re.compile(r"[0-7]{4}")
NAME: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.@+-]+")
PATH: Final[re.Pattern[str]] = re.compile(r"/[A-Za-z0-9_.@+/-]*")
LINE: Final[re.Pattern[str]] = re.compile(r"-[A-Za-z0-9 ,=!<>/._+-]{1,511}")


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
    driver runs every platform); ``rules`` holds the short identifiers of the topic's native rules;
    ``profiles`` maps each platform to the profiles of its pinned datastream (``None``: any
    well-formed profile).
    """

    coverage: dict[str, frozenset[str]] | None = None
    rules: frozenset[str] = frozenset()
    dispatched: frozenset[str] | None = None
    profiles: dict[str, frozenset[str]] | None = None


class Declaration:
    """The validation of one topic declaration; ``errors`` collects every finding."""

    def __init__(self, where: str, platforms: frozenset[str], context: Context) -> None:
        """Start the validation of ``where`` for the platforms and the ``context`` of the check.

        ``context.coverage`` maps each driver to the platforms that its lifecycle scenarios run;
        without it every driver counts as running every platform. ``context.rules`` holds the short
        identifiers of the native rules of the topic, which a pre-state may declare ``unchanged``.
        ``context.dispatched`` holds the regression files that the static dispatch includes
        (``None``: any file), and ``context.profiles`` the profiles of each platform's datastream.
        """
        self.where = where
        self.platforms = platforms
        self.coverage: dict[str, frozenset[str]] = (
            context.coverage if context.coverage is not None else dict.fromkeys(DRIVERS, platforms)
        )
        self.rules = context.rules
        self.dispatched = context.dispatched
        self.known_profiles = context.profiles
        self.regressions: dict[str, frozenset[str]] = {}
        self.regression_files: set[str] = set()
        self.errors: list[str] = []
        self.items: dict[str, set[str]] = {category: set() for category in CATEGORY_KEYS}
        self.drivers: frozenset[str] = frozenset(DRIVERS)
        self.skipped_platforms: set[str] = set()
        self.rewritten: set[str] = set()
        self.topic_drivers: frozenset[str] | None = None
        self.pre_state_drivers: list[frozenset[str] | None] = [None]
        self.pre_state_modes: list[frozenset[str]] = [TOGGLE_MODES]

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
        pattern = PATH if key == "path" else LINE if key == "line" else NAME
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            self.error(f"{what} needs a valid {key}")
            return None
        return value

    def state_item_keys(self, category: str, item: dict[str, object], what: str) -> frozenset[str]:
        """Return the keys that a state item of ``category`` may have; check a file's flag."""
        if category in KERNEL_CATEGORIES:
            _kernel_drivers(self, item, what)
            return frozenset({CATEGORY_KEYS[category], PLATFORMS_KEY, DRIVERS_KEY})
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
                if category == "files" and item.get(REWRITTEN_KEY) is True:
                    self.rewritten.add(key)
        if not any(self.items.values()):
            self.error("state declares no item")

    def expectation(self, category: str, item: dict[str, object], what: str) -> None:
        """Check the attributes that an expectation sets or requires to change."""
        attributes = ATTRIBUTES[category]
        allowed = attributes | {CATEGORY_KEYS[category], PLATFORMS_KEY, CHANGES_KEY}
        if category in KERNEL_CATEGORIES:
            allowed |= {DRIVERS_KEY}
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
        if self._expectations(value, "applied") == 0:
            self.error(
                "applied declares no expectation; the state after apply is the evidence that the "
                "remediation works when a container audit cannot show it"
            )

    def _expectations(self, value: object, where: str) -> int:
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
                self._pre_state_content(item, where)
            elif len(set(item) & {"mode", "owner", "group", "lines"}) == 0:
                self.error(f"{where} sets no mode, owner or group")
            if "lines" in item:
                _pre_state_file_lines(self, item, where, key)
            mode = item.get("mode")
            if "mode" in item and (not isinstance(mode, str) or MODE.fullmatch(mode) is None):
                self.error(f"{where} needs a four-digit octal mode string")
            for owner in ("owner", "group"):
                if owner in item and not (
                    isinstance(item[owner], str) and NAME.fullmatch(str(item[owner]))
                ):
                    self.error(f"{where} needs a valid {owner}")

    def _audit_platforms(self, value: object, what: str) -> None:
        """Check the platforms on which a pre-state runs its scans, when it names them."""
        platforms = _strings(value)
        if platforms is None or any(platform not in self.platforms for platform in platforms):
            self.error(f"{what}.audit must be a boolean or a non-empty list of known platforms")

    def _pre_state_runs(self, item: dict[str, object], what: str) -> None:
        """Check where a pre-state scans and in which toggle modes it runs, when it names them."""
        if "audit" in item and not isinstance(item["audit"], bool):
            self._audit_platforms(item["audit"], what)
        if "modes" not in item:
            self.pre_state_modes.append(TOGGLE_MODES)
            return
        modes = _strings(item["modes"])
        if modes is None or len(set(modes)) != len(modes) or not set(modes) <= TOGGLE_MODES:
            self.error(
                f"{what}.modes must be a non-empty list of distinct toggle modes: topic, rule"
            )
            self.pre_state_modes.append(TOGGLE_MODES)
            return
        self.pre_state_modes.append(frozenset(modes))

    def _pre_state_content(self, item: dict[str, object], where: str) -> None:
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
        """Check that each driver of a cycle has a lifecycle scenario on every running platform.

        Each driver must also run a pre-state in both toggle modes: the matrix plans a leg per
        mode, and a leg whose mode no pre-state runs would prove nothing about that toggle.
        """
        running = self.platforms - self.skipped_platforms
        default = self.topic_drivers or UNRESTRICTED_DRIVERS
        for driver in sorted(self.cycle_drivers()):
            modes = frozenset[str]().union(
                *(
                    modes
                    for drivers, modes in zip(
                        self.pre_state_drivers, self.pre_state_modes, strict=True
                    )
                    if driver in (drivers or default)
                )
            )
            for mode in sorted(TOGGLE_MODES - modes):
                self.error(
                    f"no pre-state runs with {driver} in the {mode} mode, so the {mode} leg of "
                    f"{driver} would run no cycle; give a pre-state of {driver} the {mode} mode"
                )
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

    def _pre_state_parts(self, item: dict[str, object], what: str) -> None:
        """Check the optional parts of a pre-state."""
        if "unchanged" in item:
            self.pre_state_unchanged(item["unchanged"], what)
        if "loads_audit_rules" in item:
            self._pre_state_loads(item, what)
        if "reasons" in item:
            self.pre_state_reasons(item["reasons"], what)
        if "applied" in item and self._expectations(item["applied"], f"{what}.applied") == 0:
            self.error(f"{what}.applied declares no expectation; leave it out instead")

    def _pre_state_loads(self, item: dict[str, object], what: str) -> None:
        """Check that a pre-state loads its audit rule files only where a kernel can load them."""
        loads = item["loads_audit_rules"]
        if not isinstance(loads, bool):
            self.error(f"{what}.loads_audit_rules must be a boolean")
            return
        drivers = _strings(item.get(REQUIRES_KEY))
        if loads and (not drivers or set(drivers) & UNRESTRICTED_DRIVERS):
            self.error(f"{what} loads audit rules, so it must require drivers other than docker")

    def pre_state_reasons(self, value: object, what: str) -> None:
        """Check the reasons that the results of the rules of a pre-state's cycles must carry."""
        for index, entry in enumerate(self.sequence(value, f"{what}.reasons")):
            where = f"{what}.reasons[{index}]"
            item = self.mapping(entry, where)
            if item is None:
                continue
            self.keys(item, REASON_KEYS, where)
            self.platform_list(item, where)
            if item.get("step") not in REASON_STEPS:
                self.error(f"{where} needs the step apply or cleanup")
            reason = item.get("reason")
            if not isinstance(reason, str) or REASON.fullmatch(reason) is None:
                self.error(f"{where} needs a machine-readable reason, or {NO_REASON}")
            if "rules" in item:
                rules = _strings(item["rules"])
                if rules is None or not set(rules) <= self.rules:
                    self.error(f"{where}.rules needs short identifiers of the topic's native rules")

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
        self.pre_state_modes = []
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
            self._pre_state_runs(item, what)
            if "files" in item:
                self.pre_state_files(item["files"], what)
            self._pre_state_requires(item, what)
            self._pre_state_parts(item, what)


def _kernel_drivers(declaration: Declaration, item: dict[str, object], what: str) -> None:
    """Check the drivers of an item that only a real kernel can show, such as a loaded rule.

    The containers cannot read the kernel's audit rules, so such an item must name the
    drivers that record it, and Docker is not one of them.
    """
    drivers = declaration.driver_list(item.get(DRIVERS_KEY), f"{what}.{DRIVERS_KEY}")
    if drivers is not None and drivers & UNRESTRICTED_DRIVERS:
        declaration.error(f"{what} cannot be recorded with docker, whose containers cannot read it")


def check_profiles(declaration: Declaration, value: object) -> None:
    """Check the profiles that the topic runs with instead of the profiles of the platforms."""
    seen: set[str] = set()
    for index, entry in enumerate(declaration.sequence(value, PROFILES_KEY)):
        what = f"{PROFILES_KEY}[{index}]"
        item = declaration.mapping(entry, what)
        if item is None:
            continue
        declaration.keys(item, PROFILE_KEYS, what)
        platform = item.get("platform")
        if not isinstance(platform, str) or platform not in declaration.platforms:
            declaration.error(f"{what} needs a known platform")
            platform = None
        elif platform in seen:
            declaration.error(f"{what} names {platform} twice")
        elif platform in declaration.skipped_platforms:
            declaration.error(f"{what} names {platform}, which unselected_platforms lists")
        seen.add(str(platform))
        profile = item.get("profile")
        if not isinstance(profile, str) or PROFILE_NAME.fullmatch(profile) is None:
            declaration.error(f"{what} needs the short identifier of a profile")
        elif (
            platform is not None
            and declaration.known_profiles is not None
            and profile not in declaration.known_profiles.get(platform, frozenset())
        ):
            declaration.error(f"{what} names {profile}, which the datastream of {platform} lacks")
        if not _text(item.get("reason")):
            declaration.error(f"{what} needs a reason")


def _pre_state_file_lines(
    declaration: Declaration, item: dict[str, object], where: str, key: str | None
) -> None:
    """Check the lines of a pre-state file entry, which edit a declared, rewritten file."""
    if "content" in item:
        declaration.error(
            f"{where} sets both content and lines: content writes a file that does not "
            "exist, lines edit one that does"
        )
    _pre_state_lines(declaration, item["lines"], where)
    if key is not None and key not in declaration.rewritten:
        declaration.error(
            f"{where} sets lines of {key}, which state.files must declare rewritten: "
            "the harness puts its content back with a new inode after the cycle"
        )


def _pre_state_lines(declaration: Declaration, value: object, what: str) -> None:
    """Check the lines that a pre-state sets in a declared file, as an administrator would."""
    entries = declaration.sequence(value, f"{what}.lines")
    if not entries:
        declaration.error(f"{what}.lines must not be empty")
    for index, entry in enumerate(entries):
        where = f"{what}.lines[{index}]"
        item = declaration.mapping(entry, where)
        if item is None:
            continue
        declaration.keys(item, PRE_STATE_LINE_KEYS, where)
        for key in sorted(PRE_STATE_LINE_KEYS):
            text = item.get(key)
            if not _text(text) or "\n" in str(text):
                declaration.error(f"{where} needs a {key} on one line")


def _regression_groups(declaration: Declaration, value: object) -> None:
    """Check the named groups of regression files of the topic."""
    entries = declaration.sequence(value, REGRESSIONS_KEY)
    if not entries:
        declaration.error(f"{REGRESSIONS_KEY} must not be empty; leave it out without regressions")
    for index, entry in enumerate(entries):
        what = f"{REGRESSIONS_KEY}[{index}]"
        item = declaration.mapping(entry, what)
        if item is None:
            continue
        declaration.keys(item, REGRESSION_KEYS, what)
        declaration.platform_list(item, what)
        name = item.get("name")
        if not isinstance(name, str) or REGRESSION_NAME.fullmatch(name) is None:
            declaration.error(f"{what} needs a name of lower-case letters, digits and underscores")
            continue
        if name in declaration.regressions:
            declaration.error(f"{what} repeats the name {name!r}")
            continue
        files = _strings(item.get("files"))
        if files is None:
            declaration.error(f"{what} needs a non-empty list of files")
            continue
        declaration.regression_files.update(files)
        for file in files:
            if REGRESSION_FILE.fullmatch(file) is None:
                declaration.error(f"{what} names the file {file!r}, not a lifecycle task file")
            elif declaration.dispatched is not None and file not in declaration.dispatched:
                declaration.error(
                    f"{what} names {file}, which {REGRESSION_DISPATCH} does not include"
                )
        chosen = _strings(item.get(PLATFORMS_KEY)) or sorted(declaration.platforms)
        declaration.regressions[name] = frozenset(chosen) & declaration.platforms


def _regression_platforms(declaration: Declaration) -> dict[str, frozenset[str]]:
    """Return, per regression group, the platforms whose Docker scenario runs it."""
    running = (declaration.platforms - declaration.skipped_platforms) & declaration.coverage.get(
        REGRESSION_DRIVER, frozenset()
    )
    return {name: chosen & running for name, chosen in sorted(declaration.regressions.items())}


def _regressions_run(declaration: Declaration) -> None:
    """Check that every regression group runs on at least one platform."""
    for name, chosen in _regression_platforms(declaration).items():
        if not chosen:
            declaration.error(
                f"{REGRESSIONS_KEY} {name} runs on no platform with a {REGRESSION_DRIVER} "
                "lifecycle scenario that unselected_platforms does not list"
            )


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
    declaration = Declaration(str(path), platforms, found)
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
    if PROFILES_KEY in data:
        check_profiles(declaration, data[PROFILES_KEY])
    if REGRESSIONS_KEY in data:
        _regression_groups(declaration, data[REGRESSIONS_KEY])
    declaration.covered()
    _regressions_run(declaration)
    return declaration


def platforms(root: Path) -> frozenset[str]:
    """Return the image keys of the Molecule platforms, which declarations may name."""
    data = toggles.as_mapping(_load(root / VERSIONS))
    images = toggles.as_mapping(data.get(IMAGES_KEY)) if data is not None else None
    if not images:
        message = f"{root / VERSIONS} has no {IMAGES_KEY} mapping"
        raise GenerationError(message)
    return frozenset(images)


def datastream_profiles(root: Path) -> dict[str, frozenset[str]]:
    """Return, per Molecule platform, the short identifiers of the profiles of its datastream."""
    versions = toggles.as_mapping(_load(root / VERSIONS)) or {}
    images = toggles.as_mapping(versions.get(IMAGES_KEY)) or {}
    manifest = toggles.as_mapping(_load(root / MANIFEST)) or {}
    streams: dict[str, frozenset[str]] = {}
    for entry in toggles.as_sequence(manifest.get("datastreams")) or []:
        stream = toggles.as_mapping(entry) or {}
        streams[str(stream.get("name"))] = frozenset(
            str((toggles.as_mapping(profile) or {}).get("id", "")).removeprefix(PROFILE_PREFIX)
            for profile in toggles.as_sequence(stream.get("profiles")) or []
        )
    return {
        str(platform): streams.get(
            str((toggles.as_mapping(image) or {}).get("datastream")), frozenset()
        )
        for platform, image in images.items()
    }


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


def _dispatch_error(root: Path, problem: str) -> GenerationError:
    return GenerationError(f"{root / REGRESSION_DISPATCH}: {problem}")


def _record_value(file: str) -> str:
    return "{{ " + RECORD_FACT + " + ['" + file + "'] }}"


def _dispatched_file(root: Path, item: dict[str, object]) -> str:
    """Return the file of one dispatch include, which must run exactly for its own file."""
    if frozenset(item) != INCLUDE_KEYS:
        message = f"an include must have exactly the keys {sorted(INCLUDE_KEYS)}, no tags"
        raise _dispatch_error(root, message)
    include = toggles.as_mapping(item[INCLUDE_TASKS])
    target = include.get("file") if include is not None else None
    if (
        include is None
        or frozenset(include) != frozenset({"file"})
        or not isinstance(target, str)
        or REGRESSION_FILE.fullmatch(target) is None
    ):
        message = "every include must name one literal file and nothing else"
        raise _dispatch_error(root, message)
    if item["when"] != f"'{target}' in lifecycle_regression.files":
        message = f"the include of {target} must run when '{target}' in lifecycle_regression.files"
        raise _dispatch_error(root, message)
    return target


def _records_its_run(root: Path, file: str) -> bool:
    """Return whether the regression file ends by recording that it ran."""
    tasks = toggles.as_sequence(_load(root / REGRESSION_DISPATCH.parent / file))
    last = toggles.as_mapping(tasks[-1]) if tasks else None
    if last is None or frozenset(last) != RECORD_KEYS:
        return False
    facts = toggles.as_mapping(last[SET_FACT])
    return facts is not None and facts == {RECORD_FACT: _record_value(file)}


def dispatched_regressions(root: Path) -> frozenset[str]:
    """Return the regression files that the static dispatch includes, by file name.

    Every include must run exactly when its own file is in the selected group, without tags or
    another condition, and every included file must end by recording that it ran. Tasks other
    than includes, such as the one that records the group that ran, are allowed.

    Raises:
        GenerationError: When the dispatch or an included file breaks these rules.
    """
    tasks = toggles.as_sequence(_load(root / REGRESSION_DISPATCH))
    if tasks is None:
        message = "must be a list of tasks"
        raise _dispatch_error(root, message)
    found: set[str] = set()
    for task in tasks:
        item = toggles.as_mapping(task)
        if item is None:
            message = "every task must be a mapping"
            raise _dispatch_error(root, message)
        if INCLUDE_TASKS not in item:
            continue
        target = _dispatched_file(root, item)
        if not _records_its_run(root, target):
            message = (
                f"{target} must end with a set_fact that adds '{target}' to {RECORD_FACT}, "
                "so the harness can tell that it ran"
            )
            raise _dispatch_error(root, message)
        found.add(target)
    return frozenset(found)


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
    dispatched = dispatched_regressions(root)
    profiles = datastream_profiles(root)
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
    named: set[str] = set()
    for family in native:
        if family in declared:
            declaration = _declaration(
                directory / f"{family}.yml",
                family,
                known,
                disruptive=catalogue.families[family],
                context=Context(coverage, native_rules(catalogue, family), dispatched, profiles),
            )
            errors.extend(declaration.errors)
            named.update(declaration.regression_files)
    errors.extend(
        f"{REGRESSION_DISPATCH}: {file} is included, but no regression group of a topic names it"
        for file in sorted(dispatched - named)
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


def regression_platforms(root: Path) -> dict[str, dict[str, frozenset[str]]]:
    """Return, per native topic and regression group, the platforms of its Docker legs.

    Raises:
        GenerationError: When ``make lint-lifecycle`` would report a finding.
    """
    native, errors = check(root)
    if errors:
        message = "; ".join(errors)
        raise GenerationError(message)
    catalogue = generate_toggles.load_catalogue(root / generate_toggles.CATALOGUE)
    known = platforms(root)
    coverage = scenarios(root, known)
    return {
        family: _regression_platforms(
            _declaration(
                root / TOPICS / f"{family}.yml",
                family,
                known,
                disruptive=catalogue.families[family],
                context=Context(coverage, native_rules(catalogue, family)),
            )
        )
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
