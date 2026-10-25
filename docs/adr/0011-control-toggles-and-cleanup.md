# 0011. Per-rule and per-topic control toggles with cleanup on disable

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** project owner, lead architect
- **Jira:** pending (remediation epic)
- **Pull requests:** pending

## Context

The project owner requires that every security rule can be switched on or off through variables, individually or
per topic. For example, it must be possible to disable everything related to auditd. When a control that was
previously enabled and applied is disabled, the collection must clean up what it applied, not merely stop managing it.

Ansible variable precedence replaces dictionaries rather than merging them, so nested toggle dictionaries would be
overwritten wholesale by any inventory layer that sets one key.

## Decision

### Variables

- One topic toggle per control family: `linux_compliance_<family>_enabled`, for example
  `linux_compliance_auditd_enabled`, `linux_compliance_ssh_enabled`, `linux_compliance_sysctl_enabled`.
- One toggle per rule: `linux_compliance_rule_<rule_short_id>_enabled`, for example
  `linux_compliance_rule_sshd_disable_root_login_enabled`. Its default is the value of the rule's family toggle.
- All toggles are flat booleans, so any inventory layer can override a single rule or topic.
- A rule is **effective** when the global `linux_compliance_remediate_enabled` is true, its rule toggle is true, the
  rule belongs to the selected profile, and disruptive families are allow-listed.
- The rule catalogue (`roles/remediate/vars/rules.yml`) lists every implemented rule with its family, ComplianceAsCode
  identifier, disruptive flag and reversibility. Defaults and argument specs are generated from it and checked in CI,
  so no rule can exist without a toggle.

### Apply and revert

Every implemented rule has both an apply path and a revert path. The revert strategy is fixed per rule:

| Strategy | Used when | Revert action |
|---|---|---|
| Owned drop-in | The service supports drop-in directories (`/etc/sysctl.d`, `/etc/audit/rules.d`, `/etc/ssh/sshd_config.d`, `/etc/modprobe.d`, `/etc/security/*.d`) | Remove the collection-owned drop-in file and reload |
| Recorded value | A shared file or setting must be edited in place | Restore the prior value recorded in the state ledger |
| Recorded package or service state | A package is installed or removed, or a service is enabled, disabled or masked | Restore the recorded prior state |
| Irreversible | Partitioning, mount layout or similar | Never reverted automatically; cleanup reports a manual action and links the runbook |

Owned drop-ins are preferred, because cleanup then needs no history and remains correct even if the ledger is lost.

### State ledger

A typed module `freesecdev.linux_compliance.control_state` maintains
`/var/lib/freesecdev/linux_compliance/state.json`. The file is owned by root with mode `0600` and is written atomically.
For each applied rule it records the rule identifier, family, revert strategy, prior values, collection version and the
time it was applied. A rule is cleaned up when it is not effective but the ledger records it as applied. Successful
cleanup removes the ledger entry. If the ledger is missing or a prior value is unknown, cleanup removes owned drop-ins
and reports `cleanup incomplete` for the rest. It never guesses a previous value.

### Cleanup safety

- Cleanup runs in the remediate role and honours check mode and diff mode.
- Cleanup of a disruptive family requires the same allow-list entry as applying it, because reverting SSH, PAM or
  firewall settings can also lock operators out.
- Cleanup is idempotent: a second run with the same toggles reports zero changes.
- Package removal during cleanup happens only when the ledger shows the collection installed the package.

### Audit and reporting

Disabled rules are excluded from the scan through a generated XCCDF tailoring file. They are reported as
`disabled`, a distinct outcome that names the controlling variable. They are never reported as `pass` or silently
dropped. The exceptions report lists disabled rules that have no matching exception record, so governance can require
justification without blocking operators.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Nested toggle dictionaries | Replaced wholesale by Ansible variable precedence; one override silently drops the rest |
| Toggle only; no cleanup | Leaves previously applied hardening behind, contrary to the requirement |
| Infer prior state from distribution defaults | Guessing; wrong on customised hosts |
| Ansible tags for selection | Tags are run-time selection, not persistent configuration, and cannot drive cleanup |

## Benefits

Operators can turn off any rule or topic, and the host returns to its pre-collection state for that control.

## Trade-offs

Every rule needs a tested revert path, roughly doubling the remediation test surface. The ledger is new on-host state.

## Security implications

The ledger reveals which controls are applied, so it is root-only. Disabling a control reduces protection, so disabled
rules are always visible in reports. Cleanup of disruptive families is gated like their application.

## Operational consequences

Molecule gains a toggle-and-cleanup scenario for every family. It applies the family, disables it, asserts the
pre-collection state is restored, and asserts a further run changes nothing. The support matrix records reversibility
per rule.
