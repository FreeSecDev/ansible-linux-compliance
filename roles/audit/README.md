# audit

Scope: role `freesecdev.linux_compliance.audit`. Audience: playbook authors and contributors.

Scans the host against the selected profile and produces normalized findings.

## Status

Skeleton only. The role validates its inputs and then fails with "not implemented yet". Implementation is
tracked in FREES-49. The intended platforms in `meta/main.yml` (Ubuntu 24.04 and RHEL 9 compatible, per
[ADR 0010](../../docs/adr/0010-initial-os-and-benchmark-scope.md)) are intentions, not tested support.

## Safety

The `audit` role never changes the managed host.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_audit_profile` | `str` | `"cis_level1_server"` | ComplianceAsCode profile short identifier, without the XCCDF prefix. The initial implementation scope is the CIS Level 1 Server profile on Ubuntu 24.04 (ADR 0010). A profile is never substituted silently for another benchmark. |
| `linux_compliance_audit_fail_on_noncompliant` | `bool` | `false` | Fail the play when the audit reports at least one failed rule. The audit never changes the host either way. |

## Running

Select hosts with `-e linux_compliance_target_hosts=<group or host>`. Only `-e` works: play `hosts:` is evaluated
before inventory variables apply, so setting it in `group_vars` has no effect. Pass booleans as JSON, for example
`-e '{"linux_compliance_remediate_enabled": true}'`; `-e linux_compliance_remediate_enabled=true` passes a string and
the input validation fails closed.
