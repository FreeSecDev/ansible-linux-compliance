"""Filter that resolves the operator's value overrides of the remediate role (ADR 0032 §2)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
    values,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: value_overrides
short_description: Validate the value overrides of the remediate role and resolve each rule's target
version_added: "0.1.0"
description:
  - Validates C(linux_compliance_remediate_value_overrides), which maps the short identifier of an
    XCCDF C(Value) to the value that the operator wants as the target of every native rule with that
    value (ADR 0032 §2), and resolves the profile value and the target of every rule that the plan
    applies.
  - A key is refused when it is not the value of a native rule of the catalogue, when it is a value
    of the C(banners) family, whose text is chosen with C(linux_compliance_remediate_banner_text),
    when a rule with that value names no C(value_comparison) yet (its family is not wired for
    overrides), when the rules of the value name different comparisons, and when the value is not
    one that the comparison takes (C(validate) of C(plugins/module_utils/compliance/values.py)),
    which takes only a YAML integer that is not a boolean, or a string, in the form that the
    family's reader reads as written. A list, a mapping, a boolean and null are refused. Keys are
    validated whether or not remediation is enabled, so a typo fails the role before anything is
    read or changed.
  - A valid key that no rule of the plan applies is not refused, because one inventory may serve
    several profiles. It is listed in C(unused_overrides) with the reason of the plan for the first
    of its rules by identifier (C(not_in_profile), C(disabled_by_toggle),
    C(disruptive_not_allowed) or C(remediation_disabled)), or with C(no_profile_value_for_content)
    when a rule with that value is applied but the catalogue holds no value of the profile for the
    discovered content. An override never stands in for a missing profile value, because the
    classification of the value in force needs it; the family then fails closed as without the
    override.
  - The profile value is resolved as the families resolve it in Jinja, from the rule's
    C(profile_values) entry whose C(content_sha256) is the discovered content and whose
    C(profiles) contain the profile, its C(value) parts joined.
  - Returns data and never raises for operator input. Every problem is returned in C(errors),
    which the role turns into a failed task before any family runs.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, options
options:
  _input:
    description:
      - The rules with a native remediation, C(__linux_compliance_remediate_rules) of
        C(roles/remediate/vars/rules.yml), a list of mappings.
    type: list
    elements: dict
    required: true
  options:
    description:
      - A mapping with exactly the keys below. A missing or unknown key is an error.
      - C(overrides) is C(linux_compliance_remediate_value_overrides), a mapping of value
        identifiers to values.
      - C(plan) is the plan of the filter C(remediation_plan); its C(rules) give the action and
        the reason of every rule.
      - C(content_sha256) is the SHA-256 digest of the discovered content, or C(none) when
        remediation is disabled.
      - C(profile) is the profile short identifier C(linux_compliance_remediate_profile).
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Resolve the value overrides
  ansible.builtin.set_fact:
    resolved: >-
      {{ catalogue | freesecdev.linux_compliance.value_overrides({
           'overrides': {'var_password_pam_minlen': 16}, 'plan': plan,
           'content_sha256': discovered.content_sha256, 'profile': 'cis_level1_server'}) }}
"""

RETURN = r"""
_value:
  description: The resolved values.
  type: dict
  contains:
    errors:
      description: Validation errors. C(rules) and C(unused_overrides) are empty unless it is empty.
      type: list
      elements: str
    rules:
      description:
        - Every rule with a value that the plan applies, by rule identifier, with C(value_id),
          C(value_source) (C(override) when an override of its value is used, also when it equals
          the profile value, else C(profile)), C(profile_value) (C(none) when the catalogue holds
          none for the content and profile), C(target) (the override's canonical text, else the
          profile value) and C(comparison) (the rule's C(value_comparison), or C(none)).
      type: dict
    unused_overrides:
      description: The keys that no applied rule uses, sorted, each with C(value_id) and C(reason).
      type: list
      elements: dict
    notices:
      description: One operator message per unused key.
      type: list
      elements: str
"""

OPTION_KEYS: Final[frozenset[str]] = frozenset({"content_sha256", "overrides", "plan", "profile"})
PROFILE_PATTERN: Final[str] = r"[a-z0-9][a-z0-9_]{0,127}"
SHA256_PATTERN: Final[str] = r"[0-9a-fA-F]{64}"
VALUE_PREFIX: Final[str] = "xccdf_org.ssgproject.content_value_"
OVERRIDES_VARIABLE: Final[str] = "linux_compliance_remediate_value_overrides"
BANNER_VARIABLE: Final[str] = "linux_compliance_remediate_banner_text"
UNCOMPARED_FAMILIES: Final[frozenset[str]] = frozenset({"banners"})
COMPARISON_KEY: Final[str] = "value_comparison"
APPLY: Final[str] = "apply"
OVERRIDE: Final[str] = "override"
PROFILE: Final[str] = "profile"
NO_PROFILE_VALUE: Final[str] = "no_profile_value_for_content"
PLAN_REASONS: Final[frozenset[str]] = frozenset(
    {"disabled_by_toggle", "disruptive_not_allowed", "not_in_profile", "remediation_disabled"}
)
UNUSED_REASONS: Final[frozenset[str]] = PLAN_REASONS | {NO_PROFILE_VALUE}
MAX_OVERRIDES: Final[int] = 1024


class CatalogueError(ValueError):
    """A catalogue or plan entry that the filter cannot read; the role fails closed on it."""


@dataclass(frozen=True)
class ValueRule:
    """A native rule of the catalogue with a profile value."""

    rule_id: str
    family: str
    value_id: str
    comparison: str | None
    profile_values: tuple[Mapping[str, object], ...]


@dataclass(frozen=True)
class Planned:
    """The action and the reason that the plan gives a rule."""

    action: str
    reason: str


def _is_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _text(value: object, what: str) -> str:
    if not isinstance(value, str):
        message = f"{what} must be a string, got {values.shown(value)}"
        raise CatalogueError(message)
    return value


def _value_rule(raw: object) -> ValueRule | None:
    """Return the value rule of a catalogue entry, ``None`` for a rule without a value, or raise."""
    if not isinstance(raw, Mapping):
        message = f"every catalogue rule must be a mapping, got {values.shown(raw)}"
        raise CatalogueError(message)
    entry = cast("Mapping[str, object]", raw)
    rule_id = _text(entry.get("rule_id"), "the rule_id of a catalogue rule")
    parameters = entry.get("parameters")
    if not isinstance(parameters, Mapping) or "value_id" not in parameters:
        return None
    fields = cast("Mapping[str, object]", parameters)
    comparison = fields.get(COMPARISON_KEY)
    profile_values = fields.get("profile_values", [])
    if comparison is not None:
        _text(comparison, f"{rule_id}: value_comparison")
    if not _is_sequence(profile_values) or not all(
        isinstance(item, Mapping) for item in cast("Sequence[object]", profile_values)
    ):
        message = f"{rule_id}: profile_values must be a list of mappings"
        raise CatalogueError(message)
    return ValueRule(
        rule_id=rule_id,
        family=_text(entry.get("family"), f"{rule_id}: family"),
        value_id=_text(fields["value_id"], f"{rule_id}: value_id"),
        comparison=cast("str | None", comparison),
        profile_values=tuple(cast("Sequence[Mapping[str, object]]", profile_values)),
    )


def value_rules(catalogue: object) -> dict[str, list[ValueRule]]:
    """Return the rules with a profile value, grouped by value identifier, or raise."""
    if not _is_sequence(catalogue):
        message = "the rule catalogue must be a list"
        raise CatalogueError(message)
    grouped: dict[str, list[ValueRule]] = {}
    for raw in cast("Sequence[object]", catalogue):
        found = _value_rule(raw)
        if found is not None:
            grouped.setdefault(found.value_id, []).append(found)
    return grouped


def planned_rules(plan: object) -> dict[str, Planned]:
    """Return the action and the reason of every rule of the plan, or raise."""
    rules = cast("Mapping[str, object]", plan).get("rules") if isinstance(plan, Mapping) else None
    if not _is_sequence(rules):
        message = "the plan must be a mapping with a list of rules"
        raise CatalogueError(message)
    planned: dict[str, Planned] = {}
    for raw in cast("Sequence[object]", rules):
        if not isinstance(raw, Mapping):
            message = "every rule of the plan must be a mapping"
            raise CatalogueError(message)
        entry = cast("Mapping[str, object]", raw)
        rule_id = _text(entry.get("rule_id"), "the rule_id of a planned rule")
        planned[rule_id] = Planned(
            action=_text(entry.get("action"), f"{rule_id}: the planned action"),
            reason=_text(entry.get("reason"), f"{rule_id}: the planned reason"),
        )
    return planned


def profile_value(rule: ValueRule, content_sha256: str | None, profile: str) -> str | None:
    """Return the value of ``profile`` in the content ``content_sha256`` for ``rule``, or ``None``.

    This is the lookup of the family files: the first entry of ``profile_values`` whose digest is
    the content's and whose profiles contain the profile, its value parts joined.
    """
    if content_sha256 is None:
        return None
    for entry in rule.profile_values:
        profiles = entry.get("profiles")
        if entry.get("content_sha256") != content_sha256 or not _is_sequence(profiles):
            continue
        if profile not in cast("Sequence[object]", profiles):
            continue
        parts = entry.get("value")
        if not _is_sequence(parts) or not all(
            isinstance(part, str) for part in cast("Sequence[object]", parts)
        ):
            message = f"{rule.rule_id}: a profile value must be a list of strings"
            raise CatalogueError(message)
        return "".join(cast("Sequence[str]", parts))
    return None


def _unknown_key(key: str) -> str:
    shown = values.shown(key)
    if key.startswith(VALUE_PREFIX):
        return (
            f"{OVERRIDES_VARIABLE}: {shown} is a full XCCDF value identifier; use the short "
            f"identifier without {VALUE_PREFIX!r}, such as {values.shown(key[len(VALUE_PREFIX) :])}"
        )
    return (
        f"{OVERRIDES_VARIABLE}: {shown} is not the value of a native rule of the catalogue; "
        "the keys are the short identifiers of XCCDF values, such as var_password_pam_minlen, "
        "listed in docs/remediation-variables.md"
    )


def _comparison(key: str, rules: Sequence[ValueRule]) -> tuple[str | None, str | None]:
    """Return the comparison of a value and ``None``, or ``None`` and the reason it is refused."""
    if any(rule.family in UNCOMPARED_FAMILIES for rule in rules):
        return None, (
            f"{OVERRIDES_VARIABLE}: {key} is a banner value, which is a pattern to match and not a "
            f"value to write; choose the banner text with {BANNER_VARIABLE} (ADR 0021)"
        )
    names = {rule.comparison for rule in rules}
    if None in names:
        unwired = sorted(rule.rule_id for rule in rules if rule.comparison is None)
        return None, (
            f"{OVERRIDES_VARIABLE}: {key} cannot be overridden yet: {', '.join(unwired)} "
            "names no value_comparison, because its family is not wired for overrides "
            "(ADR 0032 §3)"
        )
    if len(names) > 1:
        return None, (
            f"{OVERRIDES_VARIABLE}: the rules of {key} name different comparisons "
            f"({', '.join(sorted(cast('set[str]', names)))}), so the catalogue is invalid"
        )
    return cast("str", next(iter(names))), None


def check_override(
    key: object, raw: object, grouped: Mapping[str, Sequence[ValueRule]], errors: toggles.Errors
) -> str | None:
    """Return the canonical text of one override, or record why it is refused and return None."""
    if not isinstance(key, str) or key not in grouped:
        errors.add(
            _unknown_key(key)
            if isinstance(key, str)
            else (f"{OVERRIDES_VARIABLE}: the key {values.shown(key)} must be a string")
        )
        return None
    name, refusal = _comparison(key, grouped[key])
    if refusal is not None:
        errors.add(refusal)
        return None
    try:
        return str(values.comparator(cast("str", name)).validate(raw))
    except values.ValueOverrideError as error:
        errors.add(f"{OVERRIDES_VARIABLE}: {key} ({name}) {error}")
        return None


def check_overrides(
    raw: object, grouped: Mapping[str, Sequence[ValueRule]], errors: toggles.Errors
) -> dict[str, str]:
    """Return the canonical text of every valid override, recording every refusal."""
    if not isinstance(raw, Mapping):
        errors.add(
            f"{OVERRIDES_VARIABLE} must be a mapping of XCCDF value identifiers to values, "
            f"got {values.shown(raw)}"
        )
        return {}
    given = cast("Mapping[object, object]", raw)
    if len(given) > MAX_OVERRIDES:
        errors.add(f"{OVERRIDES_VARIABLE} has {len(given)} keys, more than {MAX_OVERRIDES}")
        return {}
    accepted: dict[str, str] = {}
    for key in sorted(given, key=repr):
        canonical = check_override(key, given[key], grouped, errors)
        if canonical is not None:
            accepted[cast("str", key)] = canonical
    return accepted


def _reason(rules: Sequence[ValueRule], planned: Mapping[str, Planned]) -> str:
    """Return why a value that no applied rule uses is unused, or raise."""
    first = min(rules, key=lambda rule: rule.rule_id)
    reason = planned[first.rule_id].reason
    if reason not in PLAN_REASONS:
        message = f"{first.rule_id}: the plan gives the unknown reason {values.shown(reason)}"
        raise CatalogueError(message)
    return reason


@dataclass(frozen=True)
class Context:
    """The validated inputs that the resolution of every rule depends on."""

    grouped: Mapping[str, Sequence[ValueRule]]
    planned: Mapping[str, Planned]
    content_sha256: str | None
    profile: str


def resolve(context: Context, accepted: Mapping[str, str]) -> dict[str, object]:
    """Return the values of the applied rules, the unused overrides and their notices, or raise."""
    rules: dict[str, object] = {}
    used: set[str] = set()
    without_profile_value: set[str] = set()
    for value_id, members in sorted(context.grouped.items()):
        for rule in members:
            if rule.rule_id not in context.planned:
                message = f"{rule.rule_id}: the catalogue rule is missing from the plan"
                raise CatalogueError(message)
            if context.planned[rule.rule_id].action != APPLY:
                continue
            found = profile_value(rule, context.content_sha256, context.profile)
            override = accepted.get(value_id) if found is not None else None
            if value_id in accepted:
                (used if found is not None else without_profile_value).add(value_id)
            rules[rule.rule_id] = {
                "value_id": value_id,
                "value_source": PROFILE if override is None else OVERRIDE,
                "profile_value": found,
                "target": found if override is None else override,
                "comparison": rule.comparison,
            }
    unused = [
        {
            "value_id": value_id,
            "reason": (
                NO_PROFILE_VALUE
                if value_id in without_profile_value
                else _reason(context.grouped[value_id], context.planned)
            ),
        }
        for value_id in sorted(accepted)
        if value_id not in used
    ]
    return {
        "errors": [],
        "rules": rules,
        "unused_overrides": unused,
        "notices": [
            f"{item['value_id']}: the value override is not used in this run ({item['reason']}); "
            "nothing was changed for it"
            for item in unused
        ],
    }


def _failed(errors: Sequence[str]) -> dict[str, object]:
    return {"errors": list(errors), "rules": {}, "unused_overrides": [], "notices": []}


def _settings(given: Mapping[str, object], errors: toggles.Errors) -> tuple[str | None, str]:
    content_sha256 = given["content_sha256"]
    profile = given["profile"]
    if content_sha256 is not None and not toggles.is_text(content_sha256, SHA256_PATTERN):
        errors.add(
            f"content_sha256 must be none or a SHA-256 digest, got {toggles.show(content_sha256)}"
        )
    if not toggles.is_text(profile, PROFILE_PATTERN):
        errors.add(f"profile must be a profile short identifier, got {toggles.show(profile)}")
    return cast("str | None", content_sha256), cast("str", profile)


def value_overrides(catalogue: object, options: object) -> dict[str, object]:
    """Validate the value overrides and resolve every applied rule's target; see DOCUMENTATION."""
    errors = toggles.Errors()
    if (
        not isinstance(options, Mapping)
        or frozenset(cast("Mapping[object, object]", options)) != OPTION_KEYS
    ):
        return _failed([f"options must be a mapping with exactly {sorted(OPTION_KEYS)}"])
    given = cast("Mapping[str, object]", options)
    content_sha256, profile = _settings(given, errors)
    try:
        grouped = value_rules(catalogue)
        planned = planned_rules(given["plan"])
    except CatalogueError as error:
        return _failed([*errors.items, str(error)])
    accepted = check_overrides(given["overrides"], grouped, errors)
    if errors.items:
        return _failed(errors.items)
    try:
        return resolve(Context(grouped, planned, content_sha256, profile), accepted)
    except CatalogueError as error:
        return _failed([str(error)])


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object, object], dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"value_overrides": value_overrides}
