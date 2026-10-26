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
attribute or platform, a malformed mode, or ``unselected_platforms`` that name every
platform, which would let the topic run nowhere. A topic therefore cannot gain a native rule
without its lifecycle test, and the harness cannot silently skip a declared expectation or a
topic. The harness repeats the coverage check at run time and fails on a platform that skips
a topic without the declaration saying so.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

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
IMAGES_KEY: Final[str] = "molecule_images"
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
PRE_STATE_KEYS: Final[frozenset[str]] = frozenset({"name", "audit", "files"})
PRE_STATE_FILE_KEYS: Final[frozenset[str]] = frozenset({"path", "mode", "owner", "group"})
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


class Declaration:
    """The validation of one topic declaration; ``errors`` collects every finding."""

    def __init__(self, where: str, platforms: frozenset[str]) -> None:
        """Start the validation of the declaration in ``where`` for the known ``platforms``."""
        self.where = where
        self.platforms = platforms
        self.errors: list[str] = []
        self.items: dict[str, set[str]] = {category: set() for category in CATEGORY_KEYS}

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

    def state(self, value: object) -> None:
        """Check the items whose state the harness records."""
        state = self.mapping(value, "state")
        if state is None:
            return
        self.keys(state, frozenset(CATEGORY_KEYS), "state")
        for category, key_field in CATEGORY_KEYS.items():
            if category not in state:
                continue
            for index, entry in enumerate(self.sequence(state[category], f"state.{category}")):
                what = f"state.{category}[{index}]"
                item = self.mapping(entry, what)
                if item is None:
                    continue
                self.keys(item, frozenset({key_field, PLATFORMS_KEY}), what)
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
        applied = self.mapping(value, "applied")
        if applied is None:
            return
        self.keys(applied, frozenset(CATEGORY_KEYS), "applied")
        expectations = 0
        for category in CATEGORY_KEYS:
            if category not in applied:
                continue
            seen: set[str] = set()
            for index, entry in enumerate(self.sequence(applied[category], f"applied.{category}")):
                what = f"applied.{category}[{index}]"
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
                if key in seen:
                    self.error(f"{what} expects {key} twice")
                seen.add(key)
                expectations += 1
        if expectations == 0:
            self.error(
                "applied declares no expectation; the state after apply is the evidence that the "
                "remediation works when a container audit cannot show it"
            )

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
            if len(set(item) & {"mode", "owner", "group"}) == 0:
                self.error(f"{where} sets no mode, owner or group")
            mode = item.get("mode")
            if "mode" in item and (not isinstance(mode, str) or MODE.fullmatch(mode) is None):
                self.error(f"{where} needs a four-digit octal mode string")
            for owner in ("owner", "group"):
                if owner in item and not (
                    isinstance(item[owner], str) and NAME.fullmatch(str(item[owner]))
                ):
                    self.error(f"{where} needs a valid {owner}")

    def pre_states(self, value: object) -> None:
        """Check the states from which the harness runs the cycles."""
        entries = self.sequence(value, "pre_states")
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
    path: Path, family: str, platforms: frozenset[str], *, disruptive: bool
) -> list[str]:
    """Return the findings for the declaration of ``family`` in ``path``."""
    declaration = Declaration(str(path), platforms)
    data = declaration.mapping(_load(path), "the declaration")
    if data is None:
        return declaration.errors
    _identity(declaration, data, family, disruptive=disruptive)
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
    return declaration.errors


def platforms(root: Path) -> frozenset[str]:
    """Return the image keys of the Molecule platforms, which declarations may name."""
    data = toggles.as_mapping(_load(root / VERSIONS))
    images = toggles.as_mapping(data.get(IMAGES_KEY)) if data is not None else None
    if not images:
        message = f"{root / VERSIONS} has no {IMAGES_KEY} mapping"
        raise GenerationError(message)
    return frozenset(images)


def check(root: Path) -> tuple[list[str], list[str]]:
    """Return the native topics and every finding about their declarations below ``root``."""
    catalogue = generate_toggles.load_catalogue(root / generate_toggles.CATALOGUE)
    native = generate_toggles.native_families(catalogue)
    known = platforms(root)
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
                )
            )
    return native, errors


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
