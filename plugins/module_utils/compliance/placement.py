"""The control placement of a finding among the collection's control families (FREES-170).

A finding of a benchmark whose rules are not ComplianceAsCode rules, such as a DISA STIG rule of
SCC, is placed through the ComplianceAsCode rules that check the same STIG ID (ADR 0019,
amendment of FREES-170; ADR 0013, schema 1.2). :class:`ControlPlacement` is the placement that
:class:`model.Finding` carries as ``control``. Every field is an identifier with an anchored ASCII
pattern, so the checks here are the pattern, the length and the item counts; :mod:`model` turns a
:class:`PlacementError` into a ``ModelError`` when it reads a document.

The module uses only the standard library and syntax that runs on Python 3.9.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, NoReturn, cast

CONTROL_KEY: Final[str] = "control"
UNMAPPED_FAMILY: Final[str] = "unmapped"
MAX_MAPPED_RULES: Final[int] = 64
MAX_CONTROL_TAGS: Final[int] = 64
MAX_FAMILY_LENGTH: Final[int] = 64
MAX_ID_LENGTH: Final[int] = 256
MAX_VARIABLES: Final[int] = 4096
FAMILY_PATTERN: Final[str] = r"[a-z][a-z0-9_]{0,63}"
STIG_ID_PATTERN: Final[str] = r"[A-Z][A-Z0-9]{1,15}-[0-9]{2}-[0-9]{6}"
VARIABLE_PATTERN: Final[str] = r"[a-z][a-z0-9_]*"
RULE_PATTERN: Final[str] = r"xccdf_[A-Za-z0-9_.-]+?_rule_[A-Za-z0-9_.+-]+"
KEYS: Final[tuple[str, ...]] = (
    "family",
    "topic",
    "tags",
    "stig_id",
    "mapped_rules",
    "partially_disabled_by",
)
MAX_ECHO_LENGTH: Final[int] = 64


class PlacementError(ValueError):
    """Raised when a control placement is invalid."""


def _fail(message: str) -> NoReturn:
    raise PlacementError(message)


def _text(value: object, name: str, pattern: str, max_length: int) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    if not value:
        _fail(f"{name} must not be empty")
    if len(value) > max_length:
        _fail(f"{name} exceeds {max_length} characters")
    if re.fullmatch(pattern, value) is None:
        _fail(f"{name} has an invalid format")
    return value


def _texts(value: object, name: str, pattern: str, max_items: int) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        _fail(f"{name} must be a tuple")
    items = cast("tuple[object, ...]", value)
    if len(items) > max_items:
        _fail(f"{name} exceeds {max_items} items")
    texts = tuple(_text(item, f"{name} item", pattern, MAX_ID_LENGTH) for item in items)
    if len(set(texts)) != len(texts):
        _fail(f"{name} contains duplicates")
    return tuple(sorted(texts))


def _strings(data: dict[str, object], key: str) -> tuple[str, ...]:
    value = data[key]
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in cast("list[object]", value)
    ):
        _fail(f"{CONTROL_KEY}.{key} must be an array of strings")
    return tuple(cast("list[str]", value))


@dataclass(frozen=True)
class ControlPlacement:
    """Where a finding belongs among the collection's control families.

    ``mapped_rules`` are the ComplianceAsCode rules that check the finding's STIG ID. ``family`` is
    their primary family and ``topic`` the umbrella of that family, or the family itself when it
    has no umbrella. ``tags`` holds the other families of the mapped rules and their subsystem
    tags. A finding with no catalogued mapped rule has the family and topic
    :data:`UNMAPPED_FAMILY` and no tags. ``partially_disabled_by`` names the toggle variables that
    switch off some, but not all, of the mapped rules, so the rule stays enabled.
    """

    family: str
    topic: str
    tags: tuple[str, ...]
    stig_id: str | None
    mapped_rules: tuple[str, ...]
    partially_disabled_by: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate and canonically order the placement."""
        _text(self.family, "control.family", FAMILY_PATTERN, MAX_FAMILY_LENGTH)
        _text(self.topic, "control.topic", FAMILY_PATTERN, MAX_FAMILY_LENGTH)
        tags = _texts(self.tags, "control.tags", FAMILY_PATTERN, MAX_CONTROL_TAGS)
        if self.stig_id is not None:
            _text(self.stig_id, "control.stig_id", STIG_ID_PATTERN, MAX_FAMILY_LENGTH)
        rules = _texts(self.mapped_rules, "control.mapped_rules", RULE_PATTERN, MAX_MAPPED_RULES)
        partial = _texts(
            self.partially_disabled_by,
            "control.partially_disabled_by",
            VARIABLE_PATTERN,
            MAX_VARIABLES,
        )
        if self.family in tags:
            _fail("control.tags must not repeat control.family")
        unmapped = self.family == UNMAPPED_FAMILY
        if unmapped != (self.topic == UNMAPPED_FAMILY) or (unmapped and tags):
            _fail("an unmapped control has the topic unmapped and no tags, and only it has them")
        if partial and not rules:
            _fail("control.partially_disabled_by requires control.mapped_rules")
        object.__setattr__(self, "tags", tags)
        object.__setattr__(self, "mapped_rules", rules)
        object.__setattr__(self, "partially_disabled_by", partial)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible mapping."""
        return {
            "family": self.family,
            "mapped_rules": list(self.mapped_rules),
            "partially_disabled_by": list(self.partially_disabled_by),
            "stig_id": self.stig_id,
            "tags": list(self.tags),
            "topic": self.topic,
        }

    @classmethod
    def from_dict(cls, data: object) -> ControlPlacement:
        """Build a placement from a mapping with exactly the keys of :data:`KEYS`."""
        if not isinstance(data, dict):
            _fail(f"{CONTROL_KEY} must be an object")
        fields = cast("dict[str, object]", data)
        unknown = sorted(repr(str(key)[:MAX_ECHO_LENGTH]) for key in fields if key not in KEYS)
        if unknown:
            _fail(f"{CONTROL_KEY} has unknown keys: {', '.join(unknown[:5])}")
        missing = [key for key in KEYS if key not in fields]
        if missing:
            _fail(f"{CONTROL_KEY} is missing keys: {', '.join(missing)}")
        stig_id = fields["stig_id"]
        if stig_id is not None and not isinstance(stig_id, str):
            _fail(f"{CONTROL_KEY}.stig_id must be a string or null")
        return cls(
            family=cast("str", fields["family"]),
            topic=cast("str", fields["topic"]),
            tags=_strings(fields, "tags"),
            stig_id=stig_id,
            mapped_rules=_strings(fields, "mapped_rules"),
            partially_disabled_by=_strings(fields, "partially_disabled_by"),
        )
