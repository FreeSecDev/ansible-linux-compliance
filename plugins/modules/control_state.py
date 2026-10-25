#!/usr/bin/python
"""Ansible module that maintains the on-host ledger of applied remediations (ADR 0011)."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: control_state
short_description: Read and maintain the on-host ledger of applied remediations
version_added: "0.1.0"
description:
  - Maintains the state ledger C(/var/lib/freesecdev/linux_compliance/state.json), which records
    for every
    remediated rule what is needed to revert it when the rule is disabled.
  - Each entry holds the rule identifier, control family, revert strategy, prior values, collection
    version
    and the time the rule was applied.
  - The ledger is owned by root with mode C(0600) in a C(0700) directory, is written atomically and
    is
    serialised between concurrent runs with a lock. The module needs C(become).
  - A corrupt, oversized or unsafe ledger (symbolic link, wrong owner, group or world permission
    bits) is an
    error. The module never repairs or resets it.
  - The location of the ledger cannot be changed through module arguments.
author:
  - FreeSecDev (@FreeSecDev)
options:
  action:
    description:
      - C(get) returns the entry of a rule, C(record) adds or replaces it, C(remove) deletes it and
        C(list)
        returns all entries.
    type: str
    required: true
    choices: [get, record, remove, list]
  rule_id:
    description:
      - Full XCCDF rule identifier, for example
        C(xccdf_org.ssgproject.content_rule_sshd_disable_root_login).
      - Required for C(get), C(record) and C(remove).
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
      - Version of the collection that applied the rule (for example C(0.1.0)). Required for
        C(record).
    type: str
  applied_at:
    description:
      - Time the rule was applied, as UTC C(YYYY-MM-DDTHH:MM:SSZ). Defaults to the current time.
      - An existing identical entry keeps its original time.
    type: str
  replace:
    description:
      - Replace an existing entry that differs. Without it, a differing entry is an error
        (C(conflict)),
        so the original prior values cannot be overwritten by accident.
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
    description: Shows the entry before and after, with sensitive values redacted.
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
  description: Whether an entry exists for O(rule_id).
  type: bool
  returned: when O(action=get) or O(action=remove)
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
entries:
  description: All entries sorted by rule identifier, redacted like C(entry).
  type: list
  elements: dict
  returned: when O(action=list)
  sample: []
count:
  description: Number of entries returned.
  type: int
  returned: when O(action=list)
  sample: 0
"""

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final, cast

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance.ledger import (
    Ledger,
    LedgerEntry,
    LedgerError,
    PriorValue,
    check_family,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance.model import (
    TIMESTAMP_FORMAT,
    RevertStrategy,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

ACTIONS: Final[tuple[str, ...]] = ("get", "record", "remove", "list")
STRATEGIES: Final[tuple[str, ...]] = tuple(strategy.value for strategy in RevertStrategy)
REQUIRED_IF: Final[list[tuple[str, str, tuple[str, ...]]]] = [
    ("action", "get", ("rule_id",)),
    ("action", "remove", ("rule_id",)),
    ("action", "record", ("rule_id", "family", "revert_strategy", "collection_version")),
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


def _entry_from(params: Mapping[str, object]) -> LedgerEntry:
    applied_at = params["applied_at"]
    if applied_at is None:
        applied_at = datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)
    values = _prior_values(params["prior_values"], sensitive=False) + _prior_values(
        params["sensitive_prior_values"], sensitive=True
    )
    return LedgerEntry(
        _text(params["rule_id"]),
        _text(params["family"]),
        RevertStrategy(params["revert_strategy"]),
        tuple(values),
        _text(params["collection_version"]),
        _text(applied_at),
    )


def _render(entry: LedgerEntry | None) -> str:
    if entry is None:
        return ""
    return json.dumps(entry.view(), indent=2, sort_keys=True) + "\n"


def _diff(before: LedgerEntry | None, after: LedgerEntry | None) -> dict[str, str]:
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
    entries = [
        entry.view(reveal=reveal)
        for entry in ledger.entries()
        if family is None or entry.family == family
    ]
    module.exit_json(
        changed=False,
        action="list",
        ledger_path=ledger.path,
        entries=entries,
        count=len(entries),
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
