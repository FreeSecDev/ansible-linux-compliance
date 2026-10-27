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
    selects, with or without a native remediation, its toggle state from its rule toggle, its
    family toggle and the toggle of the umbrella that groups the family, exactly as the
    C(remediation_plan) filter does (ADR 0011). Both filters use
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
      - C(families) is the family registry of C(roles/remediate/vars/rules.yml), with the
        umbrella of each family that belongs to one.
      - C(toggles) maps every variable whose name matches C(^linux_compliance_.+_enabled$) to its
        value, validated as for C(remediation_plan).
      - C(tags) maps a family to the catalogued rules of other families that carry it as a
        subsystem tag, C(__linux_compliance_remediate_tags) of the same file (FREES-165). A rule
        is disabled when its family, the umbrella of its family, one of its tags or the umbrella
        of a tag is switched off, and C(disabled_by) follows the precedence of C(remediation_plan).
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
           'audit_only': audit_only, 'families': registry, 'tags': tags,
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
        - One C(WARNING:) message per topic or umbrella toggle that is false while no catalogued
          rule of the families that it governs is selected by the profile, so that it excludes
          nothing.
      type: list
      elements: str
"""

OPTION_KEYS: Final[frozenset[str]] = frozenset(
    {"audit_only", "disabled_rules", "families", "profile_rule_ids", "tags", "toggles"}
)


def _result(
    errors: list[str], disabled: list[dict[str, object]], warnings: list[str]
) -> dict[str, object]:
    if errors:
        return {"errors": errors, "disabled_rules": [], "warnings": []}
    return {"errors": [], "disabled_rules": disabled, "warnings": warnings}


def audit_disabled_rules(catalogue: object, options: object) -> dict[str, object]:
    """Resolve the disabled rules of the audit; see the DOCUMENTATION block for the contract."""
    errors = toggles.Errors()
    given = toggles.as_mapping(options)
    if given is None or frozenset(given) != OPTION_KEYS:
        keys = [] if given is None else sorted(given)[:10]
        errors.add(f"options must be a mapping with exactly {sorted(OPTION_KEYS)}, got {keys}")
        return _result(errors.items, [], [])
    profile = toggles.profile_rule_set(given["profile_rule_ids"], errors)
    resolution = toggles.resolve_audit(catalogue, given, profile, errors)
    return _result(errors.items, resolution.disabled, resolution.warnings)


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object, object], dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"audit_disabled_rules": audit_disabled_rules}
