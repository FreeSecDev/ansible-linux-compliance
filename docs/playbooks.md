# Playbooks

Scope: the orchestration playbooks shipped in `playbooks/`. Audience: operators and playbook authors.
Jira: FREES-41, FREES-52, FREES-54, FREES-51. The playbooks contain no component logic; they only reference roles and
other playbooks by FQCN. The `discover`, `audit` ([audit guide](audit.md)), `remediate`
([remediation guide](remediation.md)), `verify` ([verify guide](verify.md)) and `evidence`
([evidence bundles](evidence.md)) roles are implemented.

| Playbook | Plays and roles in order | `become` |
|---|---|---|
| `playbooks/audit.yml` | `discover`, `audit`; then the `audit` role's `stale` entry point in a second play on `localhost` | `audit` only |
| `playbooks/remediate.yml` | the `verify` role's `preflight.yml` entry point; `audit.yml` (`discover`, `audit`, then the read-only stale-exceptions report on `localhost`); the `verify` role's `baseline.yml` entry point; `remediate`; then `verify.yml` | `audit`, `remediate` |
| `playbooks/verify.yml` | the `verify` role's `preflight.yml` entry point, `audit.yml` again (`discover`, `audit`, stale-exceptions report), then `verify` | `audit` |
| `playbooks/evidence.yml` | `audit.yml` with the result gates deferred, then `evidence` on every target host (with the stale result of the run), the `evidence` role's `summary.yml` on `localhost`, then the `audit` role's `gate.yml` | `audit`; the `evidence` role's host `stat` and fetch only |

`remediate.yml` imports `audit.yml` first, by relative path so that the repository guard can scan the imported
playbook. Every remediation therefore starts from a verified profile and a recorded baseline audit, and the
`remediate` role gets the `linux_compliance_discovered` fact it requires. The full play sequence is:

1. Preflight: the `verify` role's `preflight.yml` entry point fails every host whose
   `linux_compliance_audit_fail_on_noncompliant` is not unset or `false`, before anything is audited. That gate would
   skip every non-compliant host after the first audit and fail every host with a failing rule in the second audit
   before the comparison could report its regressions.
2. `audit.yml`: `discover` and `audit` on the target hosts, then the stale-exceptions report on `localhost`.
3. Record the baseline: the `verify` role's `baseline.yml` entry point copies `linux_compliance_audited` to
   `linux_compliance_baseline` on each host and marks it as recorded in the facts of the host. It fails if a marker
   exists already or an extra variable would keep another baseline.
4. `remediate` on the target hosts (only with the opt-in).
5. `verify.yml`: the preflight again, `audit.yml` again, which replaces `linux_compliance_audited` with a fresh audit
   and prints the stale-exceptions report of that audit, then the `verify` role, which compares it with the recorded
   baseline and publishes `linux_compliance_verified`.

The playbook exits 0 when both audits completed, no rule regressed and no rule started to fail, also when remediation
is off and nothing changed. A regression fails the host unless `linux_compliance_verify_fail_on_regression` is
`false`, a new failure unless `linux_compliance_verify_fail_on_new_failures` is `false`; an incomplete scan or a
refused comparison always fails it ([verify guide](verify.md)). A host whose baseline audit fails is removed from the
later plays and is not remediated. `linux_compliance_remediated` holds what the remediation did.

`playbooks/verify.yml` on its own needs a baseline that `baseline.yml` recorded earlier in the same run; a
`linux_compliance_baseline` from inventory or play variables is refused. Without one it audits and then
fails with a message that says how to record the baseline; facts do not survive between runs.

`discover`, `audit` and `verify` never change the host; `audit` writes evidence files below
`linux_compliance_audit_output_dir` and reports them separately from `changed`. `verify` only reads facts on the
controller and runs without `become`. `remediate` changes a host only after the opt-in below. `become` is set on the
role entry, never on the whole play, and the audit role also sets it on its scan task only. The `evidence` role
writes only on the controller; `playbooks/evidence.yml` runs it after `audit.yml`.

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
| `linux_compliance_audit_fail_on_noncompliant` | `false` | `audit`; refused by `remediate.yml` and `verify.yml` |
| `linux_compliance_audit_fail_on_noncompliant_after_waivers` | `false` | `audit` |
| `linux_compliance_exceptions_file` | `null` | `audit`, `verify` |
| `linux_compliance_audit_output_dir` | `/var/lib/freesecdev/linux_compliance/evidence` | `audit` |
| `linux_compliance_audit_scan_timeout` | `1800` | `audit` |
| `linux_compliance_audit_disabled_rules` | `[]` | `audit` |
| `linux_compliance_remediate_enabled` | `false` | `remediate` |
| `linux_compliance_remediate_allow_disruptive` | `[]` | `remediate` |
| `linux_compliance_<family>_enabled` | `true` | `remediate`, `audit` |
| `linux_compliance_rule_<rule_short_id>_enabled` | the family toggle | `remediate`, `audit` |
| `linux_compliance_verify_fail_on_regression` | `true` | `verify` |
| `linux_compliance_verify_fail_on_new_failures` | `true` | `verify` |
| `linux_compliance_verify_mode` | `raw` | `verify` |

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
a rule that was applied before cleans it up on the next run with the opt-in, and the audit reports it as `disabled`,
naming the controlling variable. Unknown toggle names fail both roles. See the
[remediation guide](remediation.md) for the effective-state rules and the disruptive families, and the
[variable reference](remediation-variables.md), generated from the rule catalogue, for every toggle.

## Tags

Every validation and stop task in the roles is tagged `always` (in the `audit`, `remediate` and `verify` roles every
task is, including the family files that `remediate` includes), so `--tags` cannot bypass them: for example, `--tags nothing`
still validates inputs and stops with the role's tracking key. Toggles, not tags, select remediation rules
([ADR 0011](adr/0011-control-toggles-and-cleanup.md)): `remediate` fails when a rule planned for apply or cleanup has no
result, and it fails with `--skip-tags always` through its guard tasks (tag `linux_compliance_remediate_guard`). The
`verify` role fails the same way (tag `linux_compliance_verify_guard`), so a skipped regression check never looks like a
passed one.

`--skip-tags always` is unsupported. Except in the `remediate` and `verify` roles, which fail, it skips input validation, the
not-implemented stop and fact gathering, so the play runs nothing and exits 0. That exit status must not be read as success. A role cannot prevent this, because any
guard it adds is itself tagged `always`.
