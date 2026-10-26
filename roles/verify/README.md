# verify

Scope: role `freesecdev.linux_compliance.verify`. Audience: playbook authors and contributors.

Compares the audit of a host after remediation with the baseline audit recorded before it and reports, per rule,
whether it improved, regressed or stayed the same. The full guide is [docs/verify.md](../../docs/verify.md).

## Status

Implemented (FREES-54). The comparison runs on the controller with the
`freesecdev.linux_compliance.compare_scans` filter; `playbooks/remediate.yml` records the baseline, remediates, audits
again and runs this role. The intended platforms in `meta/main.yml` (Ubuntu 24.04 and RHEL 9 compatible, per
[ADR 0010](../../docs/adr/0010-initial-os-and-benchmark-scope.md)) are intentions, not tested support: the role was
tested with synthetic audit results (`make test-verify`), and the Molecule scenario with two real scans is a FREES-60
follow-up.

## Safety

- The role never changes the managed host and never connects to it; it only reads facts and needs no `become`.
- It compares only a baseline that its `baseline.yml` entry point recorded in this run, marked in the facts of the
  host, and each recorded baseline only once; a `linux_compliance_baseline` from inventory or play variables is refused.
- It refuses to compare audits of another host, benchmark, content version or digest, profile or scanner, the same run
  twice, and a later scan that started before the baseline finished.
- Raw results are compared with raw results, waived with waived, and waived only when both audits applied the same
  exceptions file (same SHA-256). Classification uses the evaluated outcome, so a waiver, a disabled rule or a check that
  stopped erroring is never an improvement.
- Regressions, new failures (rules that were not applicable or missing and fail afterwards) and passing rules that
  are no longer applicable are always published and printed.
- An incomplete comparison (a scan that did not complete) has no figures and always fails the host. `--skip-tags always` fails the role through its guard tasks
  (`linux_compliance_verify_guard`).
- The result is evidence about two scans of one host, never a claim of compliance.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_verify_profile` | `str` | `"cis_level1_server"` | ComplianceAsCode profile short identifier, without the XCCDF prefix. Both audits must report this profile; a profile is never substituted silently. |
| `linux_compliance_verify_fail_on_regression` | `bool` | `true` | Fail the host when a rule that passed in the baseline no longer passes. Regressions are reported either way; an incomplete comparison always fails. |
| `linux_compliance_verify_fail_on_new_failures` | `bool` | `true` | Fail the host when a rule that was not applicable or missing in the baseline fails afterwards. New failures are reported either way. |
| `linux_compliance_verify_mode` | `str` | `"raw"` | `raw` compares `linux_compliance_audited.scan_run`; `waived` compares `exceptions.evaluation.scan_run` and needs `linux_compliance_exceptions_file`. |
| `linux_compliance_exceptions_file` | `str` | `null` | Shared with the audit role. Required in waived mode; both audits must have applied this path with the same SHA-256. |

## Entry points

| Entry point | Use |
|---|---|
| `main` | Compare `linux_compliance_audited` with `linux_compliance_baseline` and publish `linux_compliance_verified` |
| `baseline.yml` | Record `linux_compliance_audited` as `linux_compliance_baseline` before remediation, and mark it as recorded |
| `preflight.yml` | Refuse `linux_compliance_audit_fail_on_noncompliant`, which would hide regressions, before anything is audited |

## Result

The fact `linux_compliance_verified` holds `status`, `complete`, `incomplete_reasons`, `mode`, `exceptions_sha256`,
`identity`, `baseline` and `post` (run identifiers, times and summaries), `counts` per category, `regressions`,
`new_failures`, `passed_now_not_applicable`, `rules`, `regression_detected`, `new_failure_detected`, `message` and
`gate` (`fail_on_regression`, `fail_on_new_failures`, `failed`).

## Running

Use the playbook `freesecdev.linux_compliance.remediate`. Select hosts with
`-e linux_compliance_target_hosts=<group or host>`. Only `-e` works: play `hosts:` is evaluated before inventory
variables apply, so setting it in `group_vars` has no effect. Pass booleans as JSON, for example
`-e '{"linux_compliance_verify_fail_on_regression": false}'`; `-e linux_compliance_verify_fail_on_regression=false`
passes a string and the input validation fails closed.
