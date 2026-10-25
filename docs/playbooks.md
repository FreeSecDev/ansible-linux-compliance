# Playbooks

Scope: the orchestration playbooks shipped in `playbooks/`. Audience: operators and playbook authors.
Jira: FREES-41. The playbooks contain no component logic; they only reference roles by FQCN. The `discover` and
`audit` roles are implemented ([audit guide](audit.md)). The other roles are skeletons (FREES-40) that fail with a "not
implemented yet" message naming their tracking issue, so `remediate.yml` and `verify.yml` stop at their first role
until that role is implemented.

| Playbook | Roles in order | `become` |
|---|---|---|
| `playbooks/audit.yml` | `discover`, `audit` | `audit` only |
| `playbooks/remediate.yml` | `remediate` | `remediate` |
| `playbooks/verify.yml` | `verify` | `verify` |

`discover`, `audit` and `verify` never change the host; `audit` writes evidence files below
`linux_compliance_audit_output_dir` and reports them separately from `changed`. `remediate` changes a host only after
the opt-in below. `become` is set on the role entry, never on the whole play, and the audit role also sets it on its
scan task only. The `evidence` role is not part of a playbook yet.

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
| `linux_compliance_audit_output_dir` | `/var/lib/freesecdev/linux_compliance/evidence` | `audit` |
| `linux_compliance_audit_scan_timeout` | `1800` | `audit` |
| `linux_compliance_audit_disabled_rules` | `[]` | `audit` |
| `linux_compliance_verify_fail_on_regression` | `true` | `verify` |

## Remediation opt-in

Remediation is off by default (`linux_compliance_remediate_enabled: false`,
[ADR 0011](adr/0011-control-toggles-and-cleanup.md)). Enable it explicitly, as a JSON boolean:

```text
ansible-playbook -i inventory.yml freesecdev.linux_compliance.remediate \
  -e linux_compliance_target_hosts=web01 \
  -e '{"linux_compliance_remediate_enabled": true}'
```

Disruptive families (SSH, PAM, sudo, firewall, network, bootloader, mounts, crypto policy) additionally need to be named
in `linux_compliance_remediate_allow_disruptive`, for example
`-e '{"linux_compliance_remediate_allow_disruptive": ["ssh"]}'`. Passing `linux_compliance_remediate_enabled=true`
without JSON passes a string and fails the input validation; this is intentional and fails closed.

Per-rule and per-family toggles do not exist yet (FREES-55).

## Tags

Every validation and stop task in the roles is tagged `always` (in the `audit` role every task is), so `--tags` cannot bypass them: for example,
`--tags nothing` still validates inputs and stops with the role's tracking key.

`--skip-tags always` is unsupported. It skips input validation, the not-implemented stop and fact gathering, so the
play runs nothing and exits 0. That exit status must not be read as success. A role cannot prevent this, because any
guard it adds is itself tagged `always`.
