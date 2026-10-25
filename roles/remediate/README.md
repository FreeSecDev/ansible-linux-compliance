# remediate

Scope: role `freesecdev.linux_compliance.remediate`. Audience: playbook authors and contributors.

Applies the selected profile with native Ansible modules, only after explicit opt-in.

## Status

Skeleton only. The role validates its inputs and then fails with "not implemented yet". Implementation is
tracked in FREES-52. The intended platforms in `meta/main.yml` (Ubuntu 24.04 and RHEL 9 compatible, per
[ADR 0010](../../docs/adr/0010-initial-os-and-benchmark-scope.md)) are intentions, not tested support.

## Safety

The `remediate` role changes a host only when `linux_compliance_remediate_enabled` is `true`, and applies disruptive families only when they are listed in `linux_compliance_remediate_allow_disruptive`.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_remediate_enabled` | `bool` | `false` | Global opt-in for remediation. When false the role must not change the host (ADR 0011). |
| `linux_compliance_remediate_allow_disruptive` | `list` | `[]` | Disruptive control families that may be applied or cleaned up. A disruptive family runs only when it is named here, because it can lock operators out. |
| `linux_compliance_remediate_profile` | `str` | `"cis_level1_server"` | ComplianceAsCode profile short identifier, without the XCCDF prefix. The initial implementation scope is the CIS Level 1 Server profile on Ubuntu 24.04 (ADR 0010). A profile is never substituted silently for another benchmark. |

Per-rule and per-family toggles (`linux_compliance_<family>_enabled`,
`linux_compliance_rule_<rule_short_id>_enabled`) are generated from the rule catalogue by FREES-55 and do not exist
yet ([ADR 0011](../../docs/adr/0011-control-toggles-and-cleanup.md)).

## Running

Select hosts with `-e linux_compliance_target_hosts=<group or host>`. Only `-e` works: play `hosts:` is evaluated
before inventory variables apply, so setting it in `group_vars` has no effect. Pass booleans as JSON, for example
`-e '{"linux_compliance_remediate_enabled": true}'`; `-e linux_compliance_remediate_enabled=true` passes a string and
the input validation fails closed.
