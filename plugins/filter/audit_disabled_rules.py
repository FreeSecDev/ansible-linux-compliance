"""Filter that resolves the rules the audit role excludes because a toggle disables them."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    toggles,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: audit_disabled_rules
short_description: Resolve the rules that the audit excludes and reports as disabled
version_added: "0.1.0"
description:
  - Resolves, for every rule of the remediate role's catalogue that the discovered profile
    selects, with or without a native remediation, its toggle state from its rule toggle and its
    family toggle, exactly as the C(remediation_plan) filter does (ADR 0011). Both filters use
    the same module_utils code, so a rule or topic switched off once is cleaned up by remediation
    and reported as C(disabled) by the audit with the same controlling variable.
  - Adds the explicit entries of C(linux_compliance_audit_disabled_rules), which are for rules
    that the catalogue does not contain. A catalogued rule in that list is an error, because the
    audit would then skip a rule that remediation still applies; its toggle must be used instead.
  - The global remediation opt-in plays no part; the audit honours the toggles whether or not
    remediation runs.
  - Returns data and never raises for operator input; problems are returned in C(errors), which
    the role turns into a failed task before any scan.
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
      - C(audit_only) maps each family to the full identifiers of its rules without a native
        remediation, C(__linux_compliance_remediate_audit_only) of the same file. They are
        toggled and disabled exactly like the native rules.
      - C(families) is the family registry of C(roles/remediate/vars/rules.yml).
      - C(toggles) maps every variable whose name matches C(^linux_compliance_.+_enabled$) to its
        value, validated as for C(remediation_plan).
      - C(profile_rule_ids) lists the full rule identifiers that the discovered profile selects;
        only those rules can be disabled in the scan.
      - C(disabled_rules) is C(linux_compliance_audit_disabled_rules), a list of mappings with a
        C(rule_id) and an optional C(disabled_by); the module validates the rest.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Resolve the rules that the toggles disable
  ansible.builtin.set_fact:
    disabled: >-
      {{ catalogue | freesecdev.linux_compliance.audit_disabled_rules({
           'audit_only': audit_only, 'families': registry,
           'toggles': {'linux_compliance_auditd_enabled': false},
           'profile_rule_ids': discovered_rule_ids, 'disabled_rules': []}) }}
"""

RETURN = r"""
_value:
  description: The resolution.
  type: dict
  contains:
    errors:
      description: Validation errors. C(disabled_rules) is empty unless this list is empty.
      type: list
      elements: str
    disabled_rules:
      description:
        - The explicit entries followed by the rules that a toggle switches off, each with
          C(rule_id) and C(disabled_by), sorted by rule identifier, in the format of the
          C(disabled_rules) option of C(freesecdev.linux_compliance.compliance_scan).
      type: list
      elements: dict
    warnings:
      description:
        - One C(WARNING:) message per topic toggle that is false while no catalogued rule of its
          family is selected by the profile, so that it excludes nothing.
      type: list
      elements: str
"""

OPTION_KEYS: Final[frozenset[str]] = frozenset(
    {"audit_only", "disabled_rules", "families", "profile_rule_ids", "toggles"}
)


def _result(
    errors: list[str], disabled: list[dict[str, object]], warnings: list[str]
) -> dict[str, object]:
    if errors:
        return {"errors": errors, "disabled_rules": [], "warnings": []}
    return {"errors": [], "disabled_rules": disabled, "warnings": warnings}


def _profile(raw: object, errors: toggles.Errors) -> frozenset[str]:
    items = toggles.as_sequence(raw)
    if items is None or not all(isinstance(item, str) for item in items):
        errors.add("profile_rule_ids must list the rule identifiers of the discovered profile")
        return frozenset()
    return frozenset(str(item) for item in items)


def _explicit(
    raw: object, catalogue: toggles.Catalogue, errors: toggles.Errors
) -> list[dict[str, object]]:
    items = toggles.as_sequence(raw)
    if items is None:
        errors.add("linux_compliance_audit_disabled_rules must be a list")
        return []
    catalogued = {str(rule["rule_id"]): str(rule["toggle"]) for rule in catalogue.rules}
    entries: list[dict[str, object]] = []
    for item in items:
        entry = toggles.as_mapping(item)
        rule_id = None if entry is None else entry.get("rule_id")
        if entry is None or not isinstance(rule_id, str):
            errors.add("every linux_compliance_audit_disabled_rules item needs a rule_id string")
        elif rule_id in catalogued:
            errors.add(
                f"{rule_id} is in the rule catalogue; switch it off with "
                f"{catalogued[rule_id]} or its family toggle, not with "
                f"linux_compliance_audit_disabled_rules, so that the audit and remediation agree"
            )
        else:
            entries.append(entry)
    return entries


def audit_disabled_rules(catalogue: object, options: object) -> dict[str, object]:
    """Resolve the disabled rules of the audit; see the DOCUMENTATION block for the contract."""
    errors = toggles.Errors()
    given = toggles.as_mapping(options)
    if given is None or frozenset(given) != OPTION_KEYS:
        keys = [] if given is None else sorted(given)[:10]
        errors.add(f"options must be a mapping with exactly {sorted(OPTION_KEYS)}, got {keys}")
        return _result(errors.items, [], [])
    loaded = toggles.load_catalogue(
        catalogue, given["audit_only"], given["families"], given["toggles"], errors
    )
    profile = _profile(given["profile_rule_ids"], errors)
    explicit = _explicit(given["disabled_rules"], loaded, errors)
    switched_off = toggles.disabled_rules(loaded.rules, loaded.toggles, profile)
    combined = sorted(explicit + switched_off, key=lambda entry: str(entry["rule_id"]))
    return _result(errors.items, combined, toggles.topic_warnings(loaded, profile))


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object, object], dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"audit_disabled_rules": audit_disabled_rules}
