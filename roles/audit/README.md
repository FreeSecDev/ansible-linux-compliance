# audit

Scope: role `freesecdev.linux_compliance.audit`. Audience: playbook authors and contributors.

Scans the host against the profile that the `discover` role verified, with the
`freesecdev.linux_compliance.compliance_scan` module, and publishes normalized findings, provenance and evidence paths
as the fact `linux_compliance_audited`. The full guide is [docs/audit.md](../../docs/audit.md).

## Status

Implemented (FREES-49). The intended platforms in `meta/main.yml` (Ubuntu 24.04 and RHEL 9 compatible, per
[ADR 0010](../../docs/adr/0010-initial-os-and-benchmark-scope.md)) are intentions, not tested support: no Molecule
scenario runs a real scan yet.

## Safety

The `audit` role never changes the configuration of the managed host. It writes evidence files (mode `0600`) into a new
run directory (mode `0700`) below `linux_compliance_audit_output_dir`; the module reports that as `evidence_written`, not
as `changed`. Only the scan task uses `become`. The scanner reads a private, digest-verified copy of the datastream in
the run directory, never the file at the discovered content path; the copy is removed after the scan. In check mode the scan runs for real into a temporary directory below
an existing output directory that is removed before the task returns, so the findings are real and nothing is kept;
when the output directory does not exist, check mode does not create it and the result is `not_run`.

## Order

1. Validate the inputs.
2. Check that `linux_compliance_discovered` exists and names the same profile (`discover` must run first).
3. Check that host facts were gathered.
4. Run `compliance_scan` with `fail_on_incomplete: false`, so the result is always registered.
5. Set the fact `linux_compliance_audited`.
6. Fail when the scan did not complete (`run_status` `failed` or `timed_out`).
7. Fail on failed or errored rules when `linux_compliance_audit_fail_on_noncompliant` is true.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_audit_profile` | `str` | `"cis_level1_server"` | ComplianceAsCode profile short identifier, without the XCCDF prefix. Must equal the profile the `discover` role verified. A profile is never substituted silently. |
| `linux_compliance_audit_fail_on_noncompliant` | `bool` | `false` | Fail the play when at least one rule is `fail` or `error`. A scan that did not complete always fails. |
| `linux_compliance_audit_backend` | `str` | `"openscap"` | Scanner backend; `openscap` is the only one. |
| `linux_compliance_audit_output_dir` | `str` | `"/var/lib/freesecdev/linux_compliance/evidence"` | Root-owned directory without group or other permissions below which each run gets its own directory. Missing components are created with mode `0700`; symlinks are refused. |
| `linux_compliance_audit_scan_timeout` | `int` | `1800` | Scan time limit in seconds, 1 to 3600. |
| `linux_compliance_audit_disabled_rules` | `list` of `dict` | `[]` | Rules disabled by operator toggles (ADR 0011): `rule_id` (full XCCDF identifier) and optional `disabled_by` (variable name, default `linux_compliance_rule_<short id>_enabled`). Reported as `disabled`, never as passing. |

## Result

`linux_compliance_audited` holds `run_id`, `run_status` (`completed`, `failed`, `timed_out`, or `not_run` in check
mode without an existing output directory), `summary` (counts per outcome), `scan_run` (the normalized findings document of ADR 0013), `evidence`
(`directory` and `files` with path, kind, SHA-256 and size), `evidence_written`, `disabled_rules` and `planned`.

## Running

Select hosts with `-e linux_compliance_target_hosts=<group or host>`. Only `-e` works: play `hosts:` is evaluated
before inventory variables apply, so setting it in `group_vars` has no effect. Pass booleans as JSON, for example
`-e '{"linux_compliance_audit_fail_on_noncompliant": true}'`; `-e linux_compliance_audit_fail_on_noncompliant=true`
passes a string and the input validation fails closed.
