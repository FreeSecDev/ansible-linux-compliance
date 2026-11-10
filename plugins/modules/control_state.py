#!/usr/bin/python
"""Ansible module that maintains the on-host ledger of applied remediations (ADR 0011)."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: control_state
short_description: Read and maintain the on-host ledger of applied remediations
version_added: "0.1.0"
description:
  - Maintains the state ledger C(/var/lib/freesecdev/linux_compliance/state.json), which records for
    every remediated rule what is needed to revert it when the rule is disabled.
  - Each entry holds the rule identifier, control family, revert strategy, prior values, collection
    version and the time the rule was applied, and optionally where the value the rule wrote came
    from (the profile or an operator override, ADR 0032).
  - The ledger also holds the deviation register, which lists the rules whose value in force is
    looser than the selected profile's. A deviation is recorded whether or not the rule wrote
    anything, and is kept apart from the entries, which say what to revert.
  - The ledger is written as schema version 1 while no entry records a value and the register is
    empty, so an existing ledger keeps its bytes, and as version 2 otherwise. An older collection
    version refuses a version 2 ledger (C(unsupported_schema)).
  - The ledger is owned by root with mode C(0600) in a C(0700) directory, is written atomically and
    is serialised between concurrent runs with a lock. The module needs C(become).
  - A corrupt, oversized or unsafe ledger (symbolic link, wrong owner, group or world permission
    bits) is an error. The module never repairs or resets it.
  - The location of the ledger cannot be changed through module arguments.
author:
  - FreeSecDev (@FreeSecDev)
options:
  action:
    description:
      - C(get) returns the entry of a rule, C(record) adds or replaces it, C(remove) deletes it and
        C(list) returns all entries and deviations.
      - C(record_deviation) adds or replaces the deviation of a rule and C(remove_deviation)
        deletes it.
    type: str
    required: true
    choices: [get, record, remove, list, record_deviation, remove_deviation]
  rule_id:
    description:
      - Full XCCDF rule identifier, for example
        C(xccdf_org.ssgproject.content_rule_sshd_disable_root_login).
      - Required for C(get), C(record), C(remove), C(record_deviation) and C(remove_deviation).
    type: str
  family:
    description:
      - Control family (a lower-case slug such as C(ssh) or C(auditd)). Required for C(record).
      - Filters the result for C(list).
    type: str
  revert_strategy:
    description:
      - How the rule is reverted (ADR 0011). Required for C(record).
      - C(recorded_value) and C(recorded_state) need at least one prior value. C(owned_dropin) and
        C(irreversible) take none.
    type: str
    choices: [owned_dropin, recorded_value, recorded_state, irreversible]
  prior_values:
    description:
      - Non-sensitive prior values to restore on revert.
    type: list
    elements: dict
    default: []
    suboptions:
      name:
        description: Name of the setting, package or service.
        type: str
        required: true
      value:
        description: Prior value. Omit it to record that the setting did not exist.
        type: str
  sensitive_prior_values:
    description:
      - Prior values that must not appear in logs. Their values are masked in Ansible output and are
        redacted in every return value and diff unless O(reveal_sensitive) is set.
    type: list
    elements: dict
    default: []
    suboptions:
      name:
        description: Name of the setting.
        type: str
        required: true
      value:
        description: Prior value. Omit it to record that the setting did not exist.
        type: str
  collection_version:
    description:
      - Version of the collection that applied the rule or recorded the deviation (for example
        C(0.1.0)). Required for C(record) and C(record_deviation).
    type: str
  applied_at:
    description:
      - Time the rule was applied, as UTC C(YYYY-MM-DDTHH:MM:SSZ). Defaults to the current time.
      - An existing identical entry keeps its original time.
    type: str
  value:
    description:
      - Where the value that the rule wrote came from, for C(record) (ADR 0032).
      - Omit it for a rule that writes no value from an XCCDF C(Value); such an entry reads as
        C(value_source=profile).
      - An existing entry whose O(value) differs is replaced only with O(replace).
    type: dict
    suboptions:
      value_id:
        description: Short identifier of the XCCDF value, for example C(var_password_pam_minlen).
        type: str
        required: true
      value_source:
        description:
          - C(profile) when the target is the profile's value, C(override) when the operator chose
            it.
        type: str
        required: true
        choices: [profile, override]
      profile_value:
        description: The selected profile's value.
        type: str
        required: true
      target:
        description: The value that the rule aimed at.
        type: str
        required: true
  deviation:
    description:
      - The deviation to record, for C(record_deviation). Required for it.
      - An existing record of the rule with the same content keeps its time; a different one is
        replaced.
    type: dict
    suboptions:
      value_id:
        description: Short identifier of the XCCDF value.
        type: str
        required: true
      profile_value:
        description: The selected profile's value.
        type: str
        required: true
      effective_value:
        description:
          - The value in force on the host after the run, which is looser than
            O(deviation.profile_value).
        type: str
        required: true
  recorded_at:
    description:
      - Time the deviation was recorded, as UTC C(YYYY-MM-DDTHH:MM:SSZ), for C(record_deviation).
        Defaults to the current time.
    type: str
  replace:
    description:
      - Replace an existing entry that differs. Without it, a differing entry is an error
        (C(conflict)), so the original prior values cannot be overwritten by accident.
    type: bool
    default: false
  reveal_sensitive:
    description:
      - Return sensitive prior values in clear text for C(get) and C(list).
      - Set C(no_log) on the task when you use it.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Reports what would change, creates and writes nothing.
  diff_mode:
    support: full
    description: Shows the entry or the deviation before and after, with sensitive values redacted.
notes:
  - Requires root. The ledger directory and file must be owned by uid 0.
  - Sensitive values are stored in the root-only ledger, because reverting needs them.
seealso:
  - ref: ADR 0011
    description: Per-rule and per-topic control toggles with cleanup on disable.
"""

EXAMPLES = r"""
- name: Record that a drop-in was applied
  freesecdev.linux_compliance.control_state:
    action: record
    rule_id: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_ip_forward
    family: sysctl
    revert_strategy: owned_dropin
    collection_version: "0.1.0"
  become: true

- name: Record the prior value of an in-place edit
  freesecdev.linux_compliance.control_state:
    action: record
    rule_id: xccdf_org.ssgproject.content_rule_sshd_disable_root_login
    family: ssh
    revert_strategy: recorded_value
    prior_values:
      - name: PermitRootLogin
        value: "yes"
    collection_version: "0.1.0"
  become: true

- name: Read an entry
  freesecdev.linux_compliance.control_state:
    action: get
    rule_id: xccdf_org.ssgproject.content_rule_sshd_disable_root_login
  become: true
  register: ledger_entry

- name: Forget a rule after a successful cleanup
  freesecdev.linux_compliance.control_state:
    action: remove
    rule_id: xccdf_org.ssgproject.content_rule_sshd_disable_root_login
  become: true

- name: List the applied rules of one family
  freesecdev.linux_compliance.control_state:
    action: list
    family: ssh
  become: true
  register: applied_ssh_rules

- name: Record a drop-in that writes an operator's value
  freesecdev.linux_compliance.control_state:
    action: record
    rule_id: xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen
    family: pwquality
    revert_strategy: owned_dropin
    value:
      value_id: var_password_pam_minlen
      value_source: override
      profile_value: "14"
      target: "8"
    collection_version: "0.1.0"
  become: true

- name: Record that the value in force is looser than the profile
  freesecdev.linux_compliance.control_state:
    action: record_deviation
    rule_id: xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen
    deviation:
      value_id: var_password_pam_minlen
      profile_value: "14"
      effective_value: "8"
    collection_version: "0.1.0"
  become: true

- name: Forget the deviation once the value meets the profile again
  freesecdev.linux_compliance.control_state:
    action: remove_deviation
    rule_id: xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen
  become: true
"""

RETURN = r"""
ledger_path:
  description: Path of the ledger file.
  type: str
  returned: always
  sample: /var/lib/freesecdev/linux_compliance/state.json
action:
  description: The action that ran.
  type: str
  returned: always
  sample: get
found:
  description:
    - Whether an entry exists for O(rule_id), or for O(action=remove_deviation) whether a deviation
      existed.
  type: bool
  returned: when O(action=get), O(action=remove) or O(action=remove_deviation)
  sample: true
entry:
  description:
    - The entry. Sensitive prior values are redacted (C(value) is null, C(redacted) is true) unless
      O(reveal_sensitive) is set.
  type: dict
  returned: when O(action=get) and found, or O(action=record)
  contains:
    rule_id:
      description: Full XCCDF rule identifier.
      type: str
      sample: xccdf_org.ssgproject.content_rule_sshd_disable_root_login
    family:
      description: Control family.
      type: str
      sample: ssh
    revert_strategy:
      description: Revert strategy.
      type: str
      sample: recorded_value
    prior_values:
      description: Recorded prior values sorted by name.
      type: list
      elements: dict
      sample: [{"name": "PermitRootLogin", "redacted": false, "sensitive": false, "value": "yes"}]
    collection_version:
      description: Collection version that applied the rule.
      type: str
      sample: 0.1.0
    applied_at:
      description: UTC time the rule was applied.
      type: str
      sample: "2026-10-25T12:00:00Z"
    value:
      description:
        - The value record (C(value_id), C(value_source), C(profile_value), C(target)), or null when
          the entry records none.
      type: dict
      sample: null
    value_source:
      description: C(override) or C(profile); an entry without a value record reads as C(profile).
      type: str
      sample: profile
entries:
  description: All entries sorted by rule identifier, redacted like C(entry).
  type: list
  elements: dict
  returned: when O(action=list)
  sample: []
deviation:
  description: The deviation record.
  type: dict
  returned: when O(action=record_deviation)
  contains:
    rule_id:
      description: Full XCCDF rule identifier.
      type: str
      sample: xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen
    value_id:
      description: Short identifier of the XCCDF value.
      type: str
      sample: var_password_pam_minlen
    profile_value:
      description: The selected profile's value.
      type: str
      sample: "14"
    effective_value:
      description: The value in force on the host.
      type: str
      sample: "8"
    recorded_at:
      description: UTC time the deviation was first recorded with this content.
      type: str
      sample: "2026-11-10T12:00:00Z"
    collection_version:
      description: Collection version that recorded the deviation.
      type: str
      sample: 0.1.0
deviations:
  description:
    - Every deviation of the register sorted by rule identifier, like C(deviation). O(family)
      does not filter it.
  type: list
  elements: dict
  returned: when O(action=list)
  sample: []
count:
  description: Number of entries returned.
  type: int
  returned: when O(action=list)
  sample: 0
error_type:
  description:
    - Stable identifier of the failure, for example C(corrupt), C(symlink), C(wrong_owner),
      C(unsafe_mode), C(too_large), C(lock_timeout), C(conflict), C(invalid_entry) or
      C(unsupported_platform).
  type: str
  returned: on failure
  sample: corrupt
path:
  description: Path of the ledger file that the failed action used.
  type: str
  returned: on failure
  sample: /var/lib/freesecdev/linux_compliance/state.json
"""

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final, cast

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance.ledger import (
    VALUE_SOURCES,
    DeviationRecord,
    Ledger,
    LedgerEntry,
    LedgerError,
    PriorValue,
    ValueRecord,
    check_family,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance.model import (
    TIMESTAMP_FORMAT,
    RevertStrategy,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

ACTIONS: Final[tuple[str, ...]] = (
    "get",
    "record",
    "remove",
    "list",
    "record_deviation",
    "remove_deviation",
)
STRATEGIES: Final[tuple[str, ...]] = tuple(strategy.value for strategy in RevertStrategy)
SOURCES: Final[tuple[str, ...]] = tuple(sorted(VALUE_SOURCES, reverse=True))
REQUIRED_IF: Final[list[tuple[str, str, tuple[str, ...]]]] = [
    ("action", "get", ("rule_id",)),
    ("action", "remove", ("rule_id",)),
    ("action", "record", ("rule_id", "family", "revert_strategy", "collection_version")),
    ("action", "record_deviation", ("rule_id", "deviation", "collection_version")),
    ("action", "remove_deviation", ("rule_id",)),
]


def _prior_value_spec(*, sensitive: bool) -> dict[str, object]:
    return {
        "type": "list",
        "elements": "dict",
        "default": [],
        "options": {
            "name": {"type": "str", "required": True},
            "value": {"type": "str", "no_log": sensitive},
        },
    }


def _required_text() -> dict[str, object]:
    return {"type": "str", "required": True}


def argument_spec() -> dict[str, object]:
    """Return the Ansible argument specification."""
    return {
        "action": {"type": "str", "required": True, "choices": list(ACTIONS)},
        "rule_id": {"type": "str"},
        "family": {"type": "str"},
        "revert_strategy": {"type": "str", "choices": list(STRATEGIES)},
        "prior_values": _prior_value_spec(sensitive=False),
        "sensitive_prior_values": _prior_value_spec(sensitive=True),
        "collection_version": {"type": "str"},
        "applied_at": {"type": "str"},
        "value": {
            "type": "dict",
            "options": {
                "value_id": _required_text(),
                "value_source": {"type": "str", "required": True, "choices": list(SOURCES)},
                "profile_value": _required_text(),
                "target": _required_text(),
            },
        },
        "deviation": {
            "type": "dict",
            "options": {
                "value_id": _required_text(),
                "profile_value": _required_text(),
                "effective_value": _required_text(),
            },
        },
        "recorded_at": {"type": "str"},
        "replace": {"type": "bool", "default": False},
        "reveal_sensitive": {"type": "bool", "default": False},
    }


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _prior_values(raw: object, *, sensitive: bool) -> list[PriorValue]:
    items = cast("list[dict[str, object]]", raw)
    return [
        PriorValue(_text(item["name"]), _optional_text(item["value"]), sensitive) for item in items
    ]


def _now_or(value: object) -> str:
    if value is None:
        return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)
    return _text(value)


def _value_from(raw: object) -> ValueRecord | None:
    if raw is None:
        return None
    fields = cast("dict[str, object]", raw)
    return ValueRecord(
        _text(fields["value_id"]),
        _text(fields["value_source"]),
        _text(fields["profile_value"]),
        _text(fields["target"]),
    )


def _entry_from(params: Mapping[str, object]) -> LedgerEntry:
    values = _prior_values(params["prior_values"], sensitive=False) + _prior_values(
        params["sensitive_prior_values"], sensitive=True
    )
    return LedgerEntry(
        _text(params["rule_id"]),
        _text(params["family"]),
        RevertStrategy(params["revert_strategy"]),
        tuple(values),
        _text(params["collection_version"]),
        _now_or(params["applied_at"]),
        _value_from(params["value"]),
    )


def _deviation_from(params: Mapping[str, object]) -> DeviationRecord:
    fields = cast("dict[str, object]", params["deviation"])
    return DeviationRecord(
        _text(params["rule_id"]),
        _text(fields["value_id"]),
        _text(fields["profile_value"]),
        _text(fields["effective_value"]),
        _now_or(params["recorded_at"]),
        _text(params["collection_version"]),
    )


def _render(item: LedgerEntry | DeviationRecord | None) -> str:
    if item is None:
        return ""
    view = item.view() if isinstance(item, LedgerEntry) else item.to_dict()
    return json.dumps(view, indent=2, sort_keys=True) + "\n"


def _diff(
    before: LedgerEntry | DeviationRecord | None, after: LedgerEntry | DeviationRecord | None
) -> dict[str, str]:
    return {"before": _render(before), "after": _render(after)}


def _get(module: AnsibleModule, ledger: Ledger) -> None:
    params = module.params
    entry = ledger.get(_text(params["rule_id"]))
    if entry is None:
        module.exit_json(changed=False, action="get", ledger_path=ledger.path, found=False)
    else:
        module.exit_json(
            changed=False,
            action="get",
            ledger_path=ledger.path,
            found=True,
            entry=entry.view(reveal=bool(params["reveal_sensitive"])),
        )


def _record(module: AnsibleModule, ledger: Ledger) -> None:
    params = module.params
    outcome = ledger.record(
        _entry_from(params), replace=bool(params["replace"]), dry_run=module.check_mode
    )
    module.exit_json(
        changed=outcome.changed,
        action="record",
        ledger_path=ledger.path,
        entry=outcome.entry.view(),
        diff=_diff(outcome.previous, outcome.entry),
    )


def _remove(module: AnsibleModule, ledger: Ledger) -> None:
    outcome = ledger.remove(_text(module.params["rule_id"]), dry_run=module.check_mode)
    module.exit_json(
        changed=outcome.changed,
        action="remove",
        ledger_path=ledger.path,
        found=outcome.previous is not None,
        diff=_diff(outcome.previous, None),
    )


def _list(module: AnsibleModule, ledger: Ledger) -> None:
    params = module.params
    family = params["family"]
    if family is not None:
        check_family(family)
    reveal = bool(params["reveal_sensitive"])
    document = ledger.document()
    entries = [
        entry.view(reveal=reveal)
        for entry in document.entries
        if family is None or entry.family == family
    ]
    module.exit_json(
        changed=False,
        action="list",
        ledger_path=ledger.path,
        entries=entries,
        count=len(entries),
        deviations=[item.to_dict() for item in document.deviations],
    )


def _record_deviation(module: AnsibleModule, ledger: Ledger) -> None:
    outcome = ledger.record_deviation(_deviation_from(module.params), dry_run=module.check_mode)
    module.exit_json(
        changed=outcome.changed,
        action="record_deviation",
        ledger_path=ledger.path,
        deviation=outcome.record.to_dict(),
        diff=_diff(outcome.previous, outcome.record),
    )


def _remove_deviation(module: AnsibleModule, ledger: Ledger) -> None:
    outcome = ledger.remove_deviation(_text(module.params["rule_id"]), dry_run=module.check_mode)
    module.exit_json(
        changed=outcome.changed,
        action="remove_deviation",
        ledger_path=ledger.path,
        found=outcome.previous is not None,
        diff=_diff(outcome.previous, None),
    )


def run(module: AnsibleModule, ledger: Ledger) -> None:
    """Run the requested action against ``ledger`` and exit through ``module``."""
    action = module.params["action"]
    try:
        if action == "get":
            _get(module, ledger)
        elif action == "record":
            _record(module, ledger)
        elif action == "remove":
            _remove(module, ledger)
        elif action == "record_deviation":
            _record_deviation(module, ledger)
        elif action == "remove_deviation":
            _remove_deviation(module, ledger)
        else:
            _list(module, ledger)
    except LedgerError as error:
        module.fail_json(msg=str(error), error_type=error.error_type, path=ledger.path)


def main() -> None:
    """Module entry point."""
    module = AnsibleModule(
        argument_spec=argument_spec(), required_if=REQUIRED_IF, supports_check_mode=True
    )
    run(module, Ledger())


if __name__ == "__main__":
    main()
