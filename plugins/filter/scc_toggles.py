"""Filter that maps the collection's toggles and control families to the DISA rules of SCC."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    placement,
    stig,
    toggles,
)

if TYPE_CHECKING:
    from collections.abc import Callable

DOCUMENTATION = r"""
---
name: scc_toggles
short_description: Map the toggles and control families to the DISA STIG rules that SCC scans
version_added: "0.1.0"
description:
  - Resolves the toggles of ADR 0011 for the ComplianceAsCode rules of the STIG mapping
    C(content/stig-mapping.json) exactly as the C(audit_disabled_rules) filter does for an
    OpenSCAP scan, with the same module_utils code, and then maps them to the DISA rules of the SCC
    profile through their STIG IDs (ADR 0019, amendment of FREES-170).
  - A DISA rule is disabled only when every ComplianceAsCode rule mapped to its STIG ID is
    disabled; its C(disabled_by) is the variable that disables most of them, the alphabetically
    first on a tie. When only some are disabled, the rule stays enabled and is listed in
    C(partially_disabled), and its placement names the variables.
  - A DISA rule whose STIG ID maps to no ComplianceAsCode rule is never disabled by a toggle. Only
    an explicit C(linux_compliance_audit_disabled_rules) entry, which names the DISA rule and its
    C(disabled_by), disables it.
  - Every DISA rule gets a control placement. Its family is the family that most of its
    catalogued mapped rules belong to, the alphabetically first on a tie; the other families and
    the subsystem tags of the mapped rules are its tags; its topic is the umbrella of the family,
    or the family. A rule without a catalogued mapped rule has the family and topic C(unmapped).
  - The mapping must implement the DISA release of the SCC benchmark version, otherwise the
    result is an error and nothing is scanned.
  - Returns data and never raises for operator input; problems are returned in C(errors), which
    the role turns into a failed task before any scan.
author:
  - FreeSecDev (@FreeSecDev)
positional: _input, options
options:
  _input:
    description:
      - The rules with a native remediation, C(__linux_compliance_remediate_rules) of
        C(roles/remediate/vars/rules.yml).
    type: list
    elements: dict
    required: true
  options:
    description:
      - A mapping with exactly the keys below. A missing or unknown key is an error.
      - C(audit_only), C(families), C(tags), C(toggles) and C(disabled_rules) as for
        C(audit_disabled_rules). An explicit entry names either a DISA rule of the SCC profile,
        with a C(disabled_by), or a ComplianceAsCode rule that the catalogue does not contain.
      - C(mapping) is the text of C(content/stig-mapping.json).
      - C(benchmark_id) and C(benchmark_version) are the SCC benchmark that C(profile_info) read
        on the managed host, and C(rules) the C(rules) it returned, each with C(rule_id) and
        C(version), the STIG ID.
    type: dict
    required: true
"""

EXAMPLES = r"""
- name: Map the toggles to the DISA rules of the SCC profile
  ansible.builtin.set_fact:
    scc: >-
      {{ catalogue | freesecdev.linux_compliance.scc_toggles({
           'audit_only': audit_only, 'families': registry, 'tags': tags,
           'toggles': {'linux_compliance_ssh_enabled': false}, 'disabled_rules': [],
           'mapping': lookup('ansible.builtin.file', 'content/stig-mapping.json'),
           'benchmark_id': scc_profile.benchmark_id,
           'benchmark_version': scc_profile.benchmark_version,
           'rules': scc_profile.rules}) }}
"""

RETURN = r"""
_value:
  description: The resolution.
  type: dict
  contains:
    errors:
      description: Validation errors. Every other list is empty unless this list is empty.
      type: list
      elements: str
    disabled_rules:
      description:
        - The DISA rules to report as C(disabled), each with C(rule_id) and C(disabled_by), sorted
          by rule identifier, in the format of the C(disabled_rules) option of
          C(freesecdev.linux_compliance.compliance_scan).
      type: list
      elements: dict
    control_placement:
      description:
        - One placement per rule of the SCC profile, in the format of the C(control_placement)
          option of C(freesecdev.linux_compliance.compliance_scan).
      type: list
      elements: dict
    partially_disabled:
      description:
        - The DISA rules whose mapped rules are disabled only in part, each with C(rule_id),
          C(stig_id), C(disabled_by), C(disabled_rules), C(enabled_rules) and C(note), the text
          C(partially disabled by) and the variables.
      type: list
      elements: dict
    summary:
      description:
        - Counts of the profile's rules, those mapped to a ComplianceAsCode rule, the unmapped
          ones, the disabled ones and the partially disabled ones, the C(stig_release) and
          C(pairs_checked), the number of reported rules that were checked against a pinned DISA
          rule to STIG ID pair. It is zero for a profile that pins none, such as Ubuntu 24.04.
      type: dict
    warnings:
      description: The topic warnings of C(audit_disabled_rules), for the mapped rules.
      type: list
      elements: str
"""

OPTION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "audit_only",
        "benchmark_id",
        "benchmark_version",
        "disabled_rules",
        "families",
        "mapping",
        "rules",
        "tags",
        "toggles",
    }
)


def _empty(errors: list[str]) -> dict[str, object]:
    return {
        "errors": errors,
        "disabled_rules": [],
        "control_placement": [],
        "partially_disabled": [],
        "summary": {},
        "warnings": [],
    }


def _split(
    entries: list[dict[str, object]],
    scc_ids: frozenset[str],
    catalogued: frozenset[str],
    errors: toggles.Errors,
) -> tuple[dict[str, str], dict[str, str]]:
    explicit: dict[str, str] = {}
    disabled: dict[str, str] = {}
    for entry in entries:
        rule_id = str(entry["rule_id"])
        variable = entry.get("disabled_by")
        if rule_id in scc_ids:
            if not isinstance(variable, str) or not variable:
                errors.add(
                    f"the SCC rule {rule_id} in linux_compliance_audit_disabled_rules needs a "
                    "disabled_by"
                )
            else:
                explicit[rule_id] = variable
        elif rule_id in catalogued or rule_id.startswith(toggles.RULE_PREFIX):
            given = variable if isinstance(variable, str) and variable else None
            disabled[rule_id] = given or toggles.rule_toggle_name(rule_id)
        else:
            errors.add(
                f"{rule_id} in linux_compliance_audit_disabled_rules is neither a rule of the SCC "
                "profile nor a ComplianceAsCode rule"
            )
    return explicit, disabled


def _text(value: object, name: str, errors: toggles.Errors) -> str:
    if not isinstance(value, str) or not value:
        errors.add(f"{name} must be a non-empty string")
        return ""
    return value


def _inputs(
    given: dict[str, object], errors: toggles.Errors
) -> tuple[tuple[stig.SccRule, ...], stig.StigProfile, int] | None:
    benchmark_id = _text(given["benchmark_id"], "benchmark_id", errors)
    benchmark_version = _text(given["benchmark_version"], "benchmark_version", errors)
    try:
        rules = stig.scc_rules(given["rules"])
        profile = stig.mapping_for(given["mapping"], benchmark_id, benchmark_version)
        checked = stig.check_reported(rules, profile)
    except stig.MappingError as error:
        errors.add(str(error))
        return None
    return rules, profile, checked


def scc_toggles(catalogue: object, options: object) -> dict[str, object]:
    """Map the toggles to the SCC profile; see the DOCUMENTATION block for the contract."""
    errors = toggles.Errors()
    given = toggles.as_mapping(options)
    if given is None or frozenset(given) != OPTION_KEYS:
        keys = [] if given is None else sorted(given)[:10]
        errors.add(f"options must be a mapping with exactly {sorted(OPTION_KEYS)}, got {keys}")
        return _empty(errors.items)
    inputs = _inputs(given, errors)
    if inputs is None:
        return _empty(errors.items)
    rules, profile, checked = inputs
    resolution = toggles.resolve_audit(catalogue, given, profile.mapped_rules(), errors)
    loaded = resolution.catalogue
    if placement.UNMAPPED_FAMILY in loaded.families:
        errors.add(
            f"the family name {placement.UNMAPPED_FAMILY} is reserved for unmapped SCC rules"
        )
    family_of = {str(rule["rule_id"]): str(rule["family"]) for rule in loaded.rules}
    explicit, disabled = _split(
        resolution.disabled,
        frozenset(rule.rule_id for rule in rules),
        frozenset(family_of),
        errors,
    )
    if errors.items:
        return _empty(errors.items)
    families = stig.Families(family_of, loaded.umbrellas, loaded.tags)
    return _resolved(
        stig.resolve(rules, profile, disabled, families, explicit),
        len(rules),
        (profile.stig_release, checked),
        resolution.warnings,
    )


def _resolved(
    result: stig.Resolution, count: int, release: tuple[str, int], warnings: list[str]
) -> dict[str, object]:
    unmapped = sum(1 for item in result.placements if not item["mapped_rules"])
    return {
        "errors": [],
        "disabled_rules": result.disabled,
        "control_placement": result.placements,
        "partially_disabled": result.partial,
        "summary": {
            "rules": count,
            "mapped": count - unmapped,
            "unmapped": unmapped,
            "disabled": len(result.disabled),
            "partially_disabled": len(result.partial),
            "stig_release": release[0],
            "pairs_checked": release[1],
        },
        "warnings": warnings,
    }


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[[object, object], dict[str, object]]]:
        """Return the filters of this plugin."""
        return {"scc_toggles": scc_toggles}
