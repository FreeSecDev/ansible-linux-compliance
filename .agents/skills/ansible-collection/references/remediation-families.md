# Remediation families

Each family is one file, `roles/remediate/tasks/<family>.yml`, covering a narrow area such as `sysctl`, `ssh`,
`auditd`, `file_permissions`, `services` or `mounts`. Toggles and cleanup follow
[ADR 0011](../../../../docs/adr/0011-control-toggles-and-cleanup.md).

## Checklist for a control

1. Identify the stable ComplianceAsCode rule ID (short form `sshd_disable_root_login`; full XCCDF ID in findings).
2. Add it to `roles/remediate/vars/rules.yml` with family, disruptive flag and revert strategy
   (`owned_dropin`, `recorded_value`, `recorded_state` or `irreversible`).
3. Choose a native module (`ansible.posix.sysctl`, `ansible.builtin.lineinfile`, `ansible.builtin.file`,
   `ansible.builtin.service`, `community.general.*`). If none exists, stop and request a project module.
4. Prefer a collection-owned drop-in file named `50-freesecdev-linux-compliance-<family>.<ext>` over in-place edits.
5. For in-place edits and package or service changes, record the prior state with
   `freesecdev.linux_compliance.control_state` before changing anything.
6. Implement the apply block, guarded by the effective toggle, and the revert block, guarded by
   "not effective and recorded as applied".
7. For disruptive families, guard both blocks with the allow-list.
8. Tag tasks with the rule ID and family.
9. Use `validate:` where the module supports it, and a handler for reloads.
10. Prove check mode reports `changed` correctly, a second run reports zero changes, and toggling off restores the
    prior state with a further run reporting zero changes.

## Toggle variables

| Variable | Default |
|---|---|
| `linux_compliance_remediate_enabled` | `false` |
| `linux_compliance_<family>_enabled` | `true` for families in the selected profile |
| `linux_compliance_rule_<rule_short_id>_enabled` | `{{ linux_compliance_<family>_enabled }}` |
| `linux_compliance_remediate_allow_disruptive` | `[]` |

## Disruptive families

SSH, PAM, sudo, firewall, network, bootloader, mounts and crypto policy. They are applied and cleaned up only when
listed in `linux_compliance_remediate_allow_disruptive`.

## Dispatch pattern

`tasks/main.yml` validates inputs, loads the ledger, includes each family file with `ansible.builtin.include_tasks`
and writes the ledger. It has no rule logic of its own.

## Not allowed

- Importing or copying ComplianceAsCode generated remediation playbooks.
- `ansible.builtin.shell`, `command`, `raw`, `script` or aliases in any form.
- One large file for unrelated controls.
- Nested toggle dictionaries, or a rule without a toggle.
- A rule without a revert path, unless it is catalogued as `irreversible` with a runbook.
