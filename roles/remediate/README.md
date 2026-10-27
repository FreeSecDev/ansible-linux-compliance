# remediate

Scope: role `freesecdev.linux_compliance.remediate`. Audience: playbook authors and contributors.

Dispatches the rules of the catalogue `vars/rules.yml` to their control family task files, applies effective rules with
native modules and cleans up rules that were applied before and are now disabled. It does nothing without the explicit
opt-in. The full guide, including the family file contract, is [docs/remediation.md](../../docs/remediation.md).

## Status

Dispatcher and safety model implemented (FREES-52), with one reference rule with a native remediation:
`xccdf_org.ssgproject.content_rule_file_permissions_crontab` in the `file_permissions` family. The catalogue
`vars/rules.yml` holds every rule of the 25 pinned profiles, 1203 rules in 21 families, generated from the pinned
content (FREES-53, [control families](../../docs/control-families.md)); every rule without a native remediation has
the strategy `audit_only` and is reported as `not_implemented`, never as remediated. The topic toggles are generated
from the catalogue (FREES-55). The native remediations of the other families follow. The intended platforms in
`meta/main.yml` (Ubuntu 24.04 and RHEL
9 compatible, per [ADR 0010](../../docs/adr/0010-initial-os-and-benchmark-scope.md)) are intentions, not tested
support: the reference rule runs in the Docker Molecule scenarios on Ubuntu 24.04 and Rocky Linux 9, whose toggle
lifecycle step applies and cleans up every topic with a native rule (FREES-60, `docs/molecule.md`).

## Safety

- Nothing is read or changed unless `linux_compliance_remediate_enabled` is `true`; every rule is then reported as
  skipped.
- Disruptive families (auditd, services, packages, desktop, network, kernel_modules, firewall, ssh, pam, accounts,
  sudo, mandatory_access_control, crypto_policy, mounts, bootloader) are applied and cleaned up only when they are
  named in `linux_compliance_remediate_allow_disruptive`; otherwise their native rules are skipped with the reason
  `disruptive_not_allowed`.
- Rules without a native remediation (`audit_only`) are never dispatched; each one the profile selects gets a result
  with the status `not_implemented` and `changed: false`.
- With the opt-in the role needs `linux_compliance_discovered` from the `discover` role for the same profile and applies
  only rules that this profile selects.
- Unknown rule or family toggles, non-boolean toggles and allow-list entries that are not disruptive families fail the
  role before anything changes.
- Check mode changes nothing, including the state ledger; diff mode shows file and ledger diffs.
- Tags do not select rules: every task is tagged `always`, the role fails when a planned rule has no result, and
  `--skip-tags always` fails the role through its guard tasks (`linux_compliance_remediate_guard`).
- A cleanup that cannot restore the prior state keeps the ledger entry and reports `cleanup_incomplete`.
- The state ledger (`freesecdev.linux_compliance.control_state`) needs root, so run the role with `become`.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree. The topic toggles and the allow-list
choices in both files are generated from `vars/rules.yml` with `make toggles`; `make lint-toggles` fails on drift.
`vars/rules.yml` itself is generated from the pinned content with `make catalogue`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_remediate_enabled` | `bool` | `false` | Global opt-in. When false the role neither reads nor changes the host, cleanup included (ADR 0011). |
| `linux_compliance_remediate_allow_disruptive` | `list` | `[]` | Disruptive families that may be applied or cleaned up; only the disruptive families of the registry are accepted. |
| `linux_compliance_remediate_profile` | `str` | `"cis_level1_server"` | ComplianceAsCode profile short identifier, without the XCCDF prefix. With the opt-in it must equal the profile the `discover` role verified. A profile is never substituted silently. |

Toggles ([ADR 0011](../../docs/adr/0011-control-toggles-and-cleanup.md)) are flat booleans:
`linux_compliance_<family>_enabled` for a whole topic, default `true`, and `linux_compliance_rule_<rule_short_id>_enabled`
for one rule, which is not declared and follows its family toggle until it is set; then it wins over its family
toggle. Every toggle is listed in the [remediation variable reference](../../docs/remediation-variables.md). The `audit` role
reads the same toggles with the same resolution, so a rule or topic switched off once is cleaned up here and reported as
`disabled` by the audit, naming the controlling variable.

## Result

The fact `linux_compliance_remediated` holds `enabled`, `check_mode`, `profile`, `allow_disruptive`, `summary` (rules
per action), `rules` (action, reason and controlling variable per rule), `results` (one per applied or cleaned-up
rule and one with the status `not_implemented` per `audit_only` rule that would be applied), `disabled_rules`,
`orphaned` and `notices`.

## Running

Use the playbook `freesecdev.linux_compliance.remediate`, which runs `discover` and `audit` first. Select hosts with
`-e linux_compliance_target_hosts=<group or host>`. Only `-e` works: play `hosts:` is evaluated before inventory
variables apply, so setting it in `group_vars` has no effect. Pass booleans as JSON, for example
`-e '{"linux_compliance_remediate_enabled": true}'`; `-e linux_compliance_remediate_enabled=true` passes a string and
the input validation fails closed.
