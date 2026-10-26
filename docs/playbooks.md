# Playbooks

Scope: the orchestration playbooks shipped in `playbooks/`. Audience: operators and playbook authors.
Jira: FREES-41, FREES-52. The playbooks contain no component logic; they only reference roles and other playbooks by
FQCN. The `discover`, `audit` ([audit guide](audit.md)) and `remediate` ([remediation guide](remediation.md)) roles are
implemented. The `verify` and `evidence` roles are skeletons (FREES-40) that fail with a "not implemented yet" message
naming their tracking issue.

| Playbook | Plays and roles in order | `become` |
|---|---|---|
| `playbooks/audit.yml` | `discover`, `audit`; then the `audit` role's `stale` entry point in a second play on `localhost` | `audit` only |
| `playbooks/remediate.yml` | `audit.yml` (`discover`, `audit`), then `remediate`, then `verify.yml` (`verify`) | `audit`, `remediate`, `verify` |
| `playbooks/verify.yml` | `verify` | `verify` |

`remediate.yml` imports `freesecdev.linux_compliance.audit` first, so every remediation starts from a verified profile
and a recorded baseline audit, and the `remediate` role gets the `linux_compliance_discovered` fact it requires. A host
whose baseline audit fails is removed from the later plays and is not remediated; keep
`linux_compliance_audit_fail_on_noncompliant` at its default `false` with this playbook, or every non-compliant host is
skipped. The playbook ends with `freesecdev.linux_compliance.verify`, which is still a skeleton (FREES-54): until it is
implemented, `remediate.yml` exits with the verify role's "not implemented yet" failure after the remediation has run,
and `linux_compliance_remediated` holds what the remediation did. That exit status is not a remediation failure.

`discover`, `audit` and `verify` never change the host; `audit` writes evidence files below
`linux_compliance_audit_output_dir` and reports them separately from `changed`. `remediate` changes a host only after
the opt-in below. `become` is set on the role entry, never on the whole play, and the audit role also sets it on its
scan task only. The `evidence` role is not part of a playbook yet.

`playbooks/audit.yml` has two plays. The first audits the target hosts. The second runs on the controller after every
host and every `serial` batch of the first, and reports the exceptions that no audited host needed
([audit guide](audit.md#stale-exceptions-once-for-all-hosts)); without an exceptions file it does nothing visible. When
every host of the first play fails, Ansible ends the playbook and the second play does not run.

## Selecting hosts

The play target is `linux_compliance_target_hosts`, which defaults to the inventory group `linux_compliance`. No
playbook targets `all`. Override it on the command line:

```text
ansible-playbook -i inventory.yml freesecdev.linux_compliance.audit -e linux_compliance_target_hosts=web01
```

Only `-e` can set it. Play `hosts:` is evaluated before inventory variables apply, so a value in `group_vars` or
`host_vars` is ignored.

## Variables

Role variables are documented in each role `README.md` and in `meta/argument_specs.yml`; see
[collection design](collection-design.md) for the summary table. Common ones:

| Variable | Default | Used by |
|---|---|---|
| `linux_compliance_target_hosts` | group `linux_compliance` | all playbooks |
| `linux_compliance_<role>_profile` | `cis_level1_server` | `discover`, `audit`, `remediate`, `verify` |
| `linux_compliance_discover_content_path`, `linux_compliance_discover_content_sha256` | empty, required | `discover` |
| `linux_compliance_audit_fail_on_noncompliant` | `false` | `audit` |
| `linux_compliance_audit_fail_on_noncompliant_after_waivers` | `false` | `audit` |
| `linux_compliance_exceptions_file` | `null` | `audit` (and `verify` once implemented) |
| `linux_compliance_audit_output_dir` | `/var/lib/freesecdev/linux_compliance/evidence` | `audit` |
| `linux_compliance_audit_scan_timeout` | `1800` | `audit` |
| `linux_compliance_audit_disabled_rules` | `[]` | `audit` |
| `linux_compliance_remediate_enabled` | `false` | `remediate` |
| `linux_compliance_remediate_allow_disruptive` | `[]` | `remediate` |
| `linux_compliance_<family>_enabled`, `linux_compliance_rule_<rule_short_id>_enabled` | not set (on) | `remediate` |
| `linux_compliance_verify_fail_on_regression` | `true` | `verify` |

## Remediation opt-in

Remediation is off by default (`linux_compliance_remediate_enabled: false`,
[ADR 0011](adr/0011-control-toggles-and-cleanup.md)). Enable it explicitly, as a JSON boolean:

```text
ansible-playbook -i inventory.yml freesecdev.linux_compliance.remediate \
  -e linux_compliance_target_hosts=web01 \
  -e '{"linux_compliance_remediate_enabled": true}'
```

Disruptive families (auditd, services, network, firewall, SSH, PAM, sudo, crypto policy, mounts and bootloader)
additionally need to be named in `linux_compliance_remediate_allow_disruptive`, for example
`-e '{"linux_compliance_remediate_allow_disruptive": ["ssh"]}'`. Passing `linux_compliance_remediate_enabled=true`
without JSON passes a string and fails the input validation; this is intentional and fails closed.

Every rule can also be switched off on its own or per topic, with flat booleans such as
`linux_compliance_file_permissions_enabled` or `linux_compliance_rule_file_permissions_crontab_enabled`. Switching off
a rule that was applied before cleans it up on the next run with the opt-in. Unknown toggle names fail the role. See the
[remediation guide](remediation.md) for the effective-state rules and the disruptive families. FREES-55 generates the
defaults of the toggles from the rule catalogue.

## Tags

Every validation and stop task in the roles is tagged `always` (in the `audit` and `remediate` roles every task is,
including the family files that `remediate` includes), so `--tags` cannot bypass them: for example, `--tags nothing`
still validates inputs and stops with the role's tracking key. Toggles, not tags, select remediation rules
([ADR 0011](adr/0011-control-toggles-and-cleanup.md)): `remediate` fails when a rule planned for apply or cleanup has no
result, and it fails with `--skip-tags always` through its guard tasks (tag `linux_compliance_remediate_guard`).

`--skip-tags always` is unsupported. Except in the `remediate` role, which fails, it skips input validation, the
not-implemented stop and fact gathering, so the play runs nothing and exits 0. That exit status must not be read as success. A role cannot prevent this, because any
guard it adds is itself tagged `always`.
