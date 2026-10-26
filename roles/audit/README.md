# audit

Scope: role `freesecdev.linux_compliance.audit`. Audience: playbook authors and contributors.

Scans the host against the profile that the `discover` role verified, with the
`freesecdev.linux_compliance.compliance_scan` module, and publishes normalized findings, provenance and evidence paths
as the fact `linux_compliance_audited`. With `linux_compliance_exceptions_file` set it applies the exceptions file
([docs/exceptions.md](../../docs/exceptions.md)) and publishes the waived result next to the raw one. The full guide
is [docs/audit.md](../../docs/audit.md).

## Status

Implemented (FREES-49; exceptions FREES-136). The intended platforms in `meta/main.yml` (Ubuntu 24.04 and RHEL 9 compatible, per
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
2. When `linux_compliance_exceptions_file` is set, read and validate it once on the controller (`run_once`); an invalid
   file fails the play before any scan. Warn about exceptions that set a framework but no profiles.
3. Check that `linux_compliance_discovered` exists and names the same profile (`discover` must run first).
4. Resolve the disabled rules from the control toggles and `linux_compliance_audit_disabled_rules` (`toggles.yml`);
   invalid toggles fail the host before any scan.
5. Check that host facts were gathered.
6. Run `compliance_scan` with `fail_on_incomplete: false`, so the result is always registered.
7. Set the fact `linux_compliance_audited` with the raw result.
8. Apply the exceptions file to a completed scan run and add `linux_compliance_audited.exceptions`; in check mode
   without a scan, report that waivers were not applied. A scan start in the future fails the host.
9. Fail when the scan did not complete (`run_status` `failed` or `timed_out`).
10. Record `linux_compliance_audited.gate` and fail on failed or errored rules when
    `linux_compliance_audit_fail_on_noncompliant` is true, counting the raw result unless
    `linux_compliance_audit_fail_on_noncompliant_after_waivers` is true. `error` always counts.

`tasks/main.yml` imports `scan.yml` (which imports `exceptions_file.yml`, `toggles.yml` and `exceptions_apply.yml`) and
`gate.yml`. More entry points exist,
named with their suffix because `tasks_from` must end in `.yml`:

- `evaluate.yml` runs steps 2, 8, 9 and 10 on an existing `linux_compliance_audited` fact without scanning.
- `deferred.yml` runs `main` without its result gates and `evaluate_deferred.yml` runs `evaluate.yml` without them;
  both record `linux_compliance_audited.gate` as `{deferred: true, enforced: false}`.
- `enforce.yml` enforces the gates that one of them deferred: it records the decision with `deferred: true` and
  `enforced: true`, then fails the host as `main` would. `playbooks/evidence.yml` uses this pair so that the evidence
  of every audited host is collected; no variable defers a gate.
- `stale.yml` aggregates stale exceptions once over the target hosts in `linux_compliance_audit_stale_hosts` (the
  final play of `playbooks/audit.yml`).

With an exceptions file, only the linear strategy is supported (with or without `serial`). Under the `free` strategy
at least one host of every batch with two or more hosts fails, so the play fails. A host that finishes has applied
the validated file ([audit guide](../../docs/audit.md#reading-and-validating-the-file)). Every host of the play,
across all `serial` batches, must resolve the variable to the same path.

## Variables

Defined in `meta/argument_specs.yml` and `defaults/main.yml`, which must agree.

| Variable | Type | Default | Description |
|---|---|---|---|
| `linux_compliance_audit_profile` | `str` | `"cis_level1_server"` | ComplianceAsCode profile short identifier, without the XCCDF prefix. Must equal the profile the `discover` role verified. A profile is never substituted silently. |
| `linux_compliance_audit_fail_on_noncompliant` | `bool` | `false` | Fail the play when at least one rule is `fail` or `error`, counted on the raw result by default, so a waiver never passes it. A scan that did not complete always fails. |
| `linux_compliance_audit_fail_on_noncompliant_after_waivers` | `bool` | `false` | Count the waived result instead of the raw result in that gate. `error` always counts. Without applied waivers the raw result is counted. |
| `linux_compliance_exceptions_file` | `str` | `null` | Absolute path, on the controller, of the exceptions file. `null` applies no exceptions. The same for every host of the play. Shared with the `verify` role, so it has no role prefix. |
| `linux_compliance_audit_backend` | `str` | `"openscap"` | Scanner backend; `openscap` is the only one. |
| `linux_compliance_audit_output_dir` | `str` | `"/var/lib/freesecdev/linux_compliance/evidence"` | Root-owned directory without group or other permissions below which each run gets its own directory. Missing components are created with mode `0700`; symlinks are refused. |
| `linux_compliance_audit_scan_timeout` | `int` | `1800` | Scan time limit in seconds, 1 to 3600. |
| `linux_compliance_audit_disabled_rules` | `list` of `dict` | `[]` | Rules outside the rule catalogue to disable (ADR 0011): `rule_id` (full XCCDF identifier) and optional `disabled_by` (variable name, default `linux_compliance_rule_<short id>_enabled`). Reported as `disabled`, never as passing. A catalogued rule here fails the role; switch it off with its toggle. |

The control toggles of ADR 0011 (`linux_compliance_<family>_enabled`, default `true`, and
`linux_compliance_rule_<rule_short_id>_enabled`, which follows its family toggle until it is set, listed in the
[remediation variable reference](../../docs/remediation-variables.md)) are read by this role. The topic toggles are
defined in its defaults and argument specification too, generated with `make toggles` exactly as in the remediate role;
rule toggles are declared in neither role, so set them as inventory, play or task vars or with `-e`, not as role
parameters, which the argument validation rejects. The catalogue holds every rule of the pinned profiles, so
`linux_compliance_auditd_enabled: false` excludes every auditd rule of the profile. Before the scan the role
resolves the toggles for the catalogued rules that the profile selects, with the same code as the remediate role, and adds the
rules they switch off to the disabled rules, with the controlling variable as `disabled_by`. Unknown or non-boolean
toggles fail the role before any scan, and a topic toggle that excludes nothing prints a `WARNING:`. See [docs/audit.md](../../docs/audit.md#disabled-rules-adr-0011).

## Result

`linux_compliance_audited` holds `run_id`, `run_status` (`completed`, `failed`, `timed_out`, or `not_run` in check
mode without an existing output directory), `summary` (counts per outcome), `scan_run` (the normalized findings document of ADR 0013), `evidence`
(`directory` and `files` with path, kind, SHA-256 and size), `evidence_written`, `disabled_rules` and `planned`.
`scan_run` and `summary` are the raw result and are never changed. `exceptions` holds `file`, `status`
(`not_requested`, `applied`, `not_run` or `not_completed`), `applied`, `message`, `source_sha256`,
`framework_without_profiles`, `evaluation` (the `apply_exceptions` evaluation document; its `scan_run` is the waived
scan run) and `summary` (the count per outcome of the waived run). `gate` holds `enabled`, `after_waivers`, `basis`
(`raw` or `waived`), `counted` and the `fail`, `error` and `waived` counts used.

The `stale.yml` entry point publishes `linux_compliance_audit_stale_exceptions` with these keys:

- `computed`;
- `complete`, true only when every target host was evaluated;
- `unmatched`, the identifiers unmatched on every evaluated host;
- `stale`, equal to `unmatched` when `complete` is true and null otherwise;
- `source_sha256`;
- `target_hosts`, `audited_hosts` and `evaluated_hosts`;
- `not_evaluated_hosts`: every target host without an evaluation, including hosts limited out, unreachable or failed.

Only complete coverage produces the advice to remove an exception.

## Running

Select hosts with `-e linux_compliance_target_hosts=<group or host>`. Only `-e` works: play `hosts:` is evaluated
before inventory variables apply, so setting it in `group_vars` has no effect. Pass booleans as JSON, for example
`-e '{"linux_compliance_audit_fail_on_noncompliant": true}'`; `-e linux_compliance_audit_fail_on_noncompliant=true`
passes a string and the input validation fails closed. Set `linux_compliance_exceptions_file` in play variables or with
`-e`, never per host.
