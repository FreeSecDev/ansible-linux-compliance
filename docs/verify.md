# Verify

Scope: the `freesecdev.linux_compliance.verify` role and the `freesecdev.linux_compliance.compare_scans` filter.
Audience: operators, playbook authors and reviewers. Jira: FREES-54, with the rules recorded on FREES-136. Decisions:
[ADR 0013](adr/0013-normalized-findings-model.md) (findings model, including the FREES-54 note).

Verification compares the audit of a host before remediation (the baseline) with an audit of the same host after it.
It reports, rule by rule, what improved, what regressed, what started to fail and what stayed the same. It never changes the host and never
connects to it: the comparison runs on the controller, on facts that the [audit role](audit.md) published. A comparison
is evidence about two scans of one host. It is not a certification and never a claim of compliance with CIS, STIG,
NIST, PCI DSS, ISO 27001 or NIS2, and "no regression" does not mean "compliant".

## Running it

`playbooks/remediate.yml` records the baseline, remediates, audits again and verifies
([playbooks](playbooks.md)):

```text
ansible-playbook -i inventory.yml freesecdev.linux_compliance.remediate \
  -e linux_compliance_target_hosts=web01 \
  -e linux_compliance_discover_content_path=/opt/freesecdev/content/ssg-ubuntu2404-ds.xml \
  -e linux_compliance_discover_content_sha256=<sha256 from content/manifest.yml> \
  -e '{"linux_compliance_remediate_enabled": true}'
```

The playbook exits 0 when every host was audited twice with complete scans, no rule regressed and no rule started to
fail. A regression, a new failure, an incomplete scan or a refused comparison fails that host and the playbook exits
non-zero.

| Order | Play | Entry point | What it does |
|---|---|---|---|
| 1 | Refuse settings that would hide regressions before any host is audited | `verify` `preflight.yml` | Fails unless `linux_compliance_audit_fail_on_noncompliant` is unset or `false` |
| 2 | Audit hosts against a compliance profile (`audit.yml`) | `discover`, `audit` | Baseline audit; publishes `linux_compliance_audited` |
| 3 | Report exceptions that no audited host needed (`audit.yml`) | `audit` `stale.yml` on `localhost` | Stale-exceptions report of the baseline |
| 4 | Record the audit before remediation as the baseline | `verify` `baseline.yml` | Copies `linux_compliance_audited` to `linux_compliance_baseline` and marks it as recorded |
| 5 | Remediate hosts against a compliance profile | `remediate` | Remediation, only with the opt-in |
| 6 | Refuse settings that would hide regressions (`verify.yml`) | `verify` `preflight.yml` | The same check again, because `verify.yml` also runs on its own |
| 7 | Audit hosts against a compliance profile (`verify.yml` imports `audit.yml`) | `discover`, `audit` | Fresh audit; replaces `linux_compliance_audited` |
| 8 | Report exceptions that no audited host needed (`audit.yml`) | `audit` `stale.yml` on `localhost` | Stale-exceptions report of the later audit |
| 9 | Compare the audit after remediation with the baseline (`verify.yml`) | `verify` `main` | Compares, publishes `linux_compliance_verified`, enforces the gates |

The second audit is the unchanged `audit.yml`, imported by `playbooks/verify.yml`, so there is exactly one audit
implementation. A host that fails the baseline audit is removed from the later plays and is never remediated; a host
whose second audit fails (for example a scan that did not complete) never reaches the comparison and fails the run.

`playbooks/verify.yml` on its own audits the hosts and then compares, so it needs a baseline that `baseline.yml`
recorded in an earlier play of the same run. Without one, the verify role fails after the audit with a message that
says how to record it. Facts do not survive between `ansible-playbook` runs, and the role does not read a baseline
from disk yet.

### The audit failure gate is refused

With `linux_compliance_audit_fail_on_noncompliant: true` the audit after remediation would fail every host that still
has a failing rule, before the verify role could report its regressions and new failures; the run would be non-zero,
but the regressions would never be printed. The `preflight.yml` entry point therefore fails every host whose value is
not unset or the boolean `false` (a string fails too), before anything is audited or remediated. The gate of the run
is the verify role. `remediate.yml` and `verify.yml` both run it first.

## Recording the baseline

The `baseline.yml` entry point records the current `linux_compliance_audited` fact as `linux_compliance_baseline`
on each host, in a play of its own between the first audit and the remediation:

1. It fails when a baseline marker already exists (see below): an earlier `baseline.yml` of this run that no
   comparison consumed, a persistent fact cache that kept one from an earlier run, or an extra variable
   `-e ansible_facts=...`.
2. It copies the fact with `set_fact` and checks that the copy has the run identifier of the audit that just ran. An
   extra variable or a role parameter named `linux_compliance_baseline` takes precedence over `set_fact` and would
   silently keep a stale baseline; the check turns that into a failure before anything is remediated.
3. It records the marker `__linux_compliance_verify_baseline_recorded` (the `run_id` and the SHA-256 of the recorded
   baseline as sorted JSON) with `set_fact` and `cacheable: true`, so that it lands in the facts of the host
   (`hostvars[host]['ansible_facts']`). Inventory, `host_vars`, `group_vars`, play variables and role variables cannot
   set a host's facts; the role reads the marker only from there. It checks that the marker it reads is the one it
   wrote.

The `main` entry point accepts a baseline only when that marker exists and matches its `run_id` and SHA-256, and then
clears the marker, so every recorded baseline is compared **once**. A `linux_compliance_baseline` from inventory,
`host_vars`, `group_vars` or play variables, a baseline that changed after it was recorded, and a second comparison of
the same baseline are refused before anything is compared. To compare again (for example in waived mode after raw
mode), record the baseline again after a new first audit.

## The comparison

The `main` entry point validates its inputs, requires `linux_compliance_baseline` and `linux_compliance_audited`,
checks and clears the baseline marker, and runs `freesecdev.linux_compliance.compare_scans` with the selected mode and the full profile identifier
`xccdf_org.ssgproject.content_profile_<linux_compliance_verify_profile>`.

### Only like is compared with like

The filter refuses, and the role fails the host, unless both audits:

- are two different runs (different `run_id`), and the later scan started at or after the baseline scan finished,
  which also catches swapped arguments. Both times come from the clock of the host, so a remediation that steps the
  clock back (for example a time synchronisation rule correcting a clock that ran ahead) can make the comparison
  refuse; that fails closed, and the host needs a fresh baseline and audit with the corrected clock;
- report the same host identity (`hostname`, distribution, version, architecture and machine identifier);
- report the same benchmark, the same content version **and** datastream SHA-256, and the same profile, which must be
  the profile of `linux_compliance_verify_profile`;
- were produced by the same scanner name and version, because a scanner change can change results without any change
  on the host.

Each audit result is validated with the findings model before use. Its `run_status` and `run_id` must match its scan
run, `scan_run` must be null exactly when no scan ran (check mode, `not_run`), and the raw `scan_run` must not carry
exception data.

### Raw and waived mode

| Mode | Compares | Requirement |
|---|---|---|
| `raw` (default) | `linux_compliance_audited.scan_run` of both audits | The raw scan runs carry no waiver |
| `waived` | `linux_compliance_audited.exceptions.evaluation.scan_run` of both audits | `linux_compliance_exceptions_file` is set, both audits applied that path, and both recorded the same `exceptions.source_sha256` |

Raw is never compared with waived. In waived mode the filter also checks that each waived scan run belongs to its raw
run (same `run_id`, same evaluated outcome for every rule) and that the evaluation was made from the recorded file.
A file that was edited between the two audits has another SHA-256, so the comparison is refused even though the path is
the same. The verify role does not read the exceptions file itself; the digests recorded by the audit role are the
binding check.

### Categories

Every rule of either run gets exactly one category. The category is decided on the **evaluated** outcome of each
finding, which is what the scanner reported; a waived finding's evaluated outcome is `fail`. The rules are applied in
this order and the first match wins:

| Order | Condition (evaluated outcomes) | Category |
|---|---|---|
| 1 | `pass` before, missing after | `regressed` |
| 2 | Missing or `notapplicable` before, `fail` after | `newly_failing` |
| 3 | Any other rule missing from one of the runs | `error` |
| 4 | `pass` before, anything except `pass` and `notapplicable` after (`fail`, `error`, `notchecked`, `disabled`) | `regressed` |
| 5 | `error` on either side | `error` |
| 6 | The same outcome on both sides, including `notchecked` and `disabled` | `unchanged` |
| 7 | `fail` before, `pass` after | `improved` |
| 8 | `notapplicable` after | `newly_not_applicable` |
| 9 | `notapplicable` before, `pass` after | `newly_applicable` |
| 10 | Every other transition, all from or to `notchecked` or `disabled` | `not_comparable` |

Consequences:

- **Only `fail` to `pass` is an improvement.** `error` to `pass` is `error`: a check that was broken and works now
  proves nothing about the host. `notchecked` or `disabled` to `pass` is `not_comparable`.
- **A waiver is never an improvement.** `fail` to `waived` is `unchanged` in both modes, because the rule still fails.
  `waived` to `pass` is `improved`, because the evaluated outcome went from `fail` to `pass`: the improvement is the
  pass, not the waiver.
- **`disabled` is never an improvement.** A rule that passed and is disabled afterwards is a regression, because it is
  no longer shown to pass; one that failed and is disabled afterwards is `not_comparable`. In `remediate.yml` both
  audits use the same `linux_compliance_audit_disabled_rules`, so disabled transitions only appear when the toggles
  change between the audits.
- **A rule that passed and errors or disappears afterwards is `regressed`**, not `error`, so the regression gate
  catches it. The real audit reports every expected rule, so a missing rule only appears in edited or synthetic facts.
- **Remediation changes applicability, and that is shown.** A rule that was not applicable (or missing) and fails
  afterwards is `newly_failing`: a failure that the remediated state introduced. It is named in the message, printed
  as `WARNING: NEW FAILURE`, and fails the host unless `linux_compliance_verify_fail_on_new_failures` is `false`. A rule
  that passed and is `notapplicable` afterwards is `newly_not_applicable`, not a regression (the check no longer
  applies, so nothing is shown to be violated), but it is listed in `passed_now_not_applicable` and printed as a
  `WARNING:` with every rule, because a remediation that removes what a rule checks deserves a look. A rule that
  failed and is `notapplicable` afterwards is not an improvement either.

### Incomplete comparisons

When either scan did not complete (`failed`, `timed_out`, or `not_run` in check mode without a scan), the comparison
is `incomplete`. `counts`, `rules`, `regressions`, `regression_detected`, `new_failures`, `new_failure_detected` and
`passed_now_not_applicable` are null, `incomplete_reasons` names the
side and its status, and the message says that no improvement and no regression is reported and that the absence of
regressions is not established. The role then fails the host, whatever `linux_compliance_verify_fail_on_regression`
and `linux_compliance_verify_fail_on_new_failures` say. Through `remediate.yml` this path is rarely reached, because the audit role already fails a host whose scan did
not complete.

## What the role publishes

`linux_compliance_verified` on each host:

| Key | Content |
|---|---|
| `status`, `complete`, `incomplete_reasons` | `complete` or `incomplete`, and why |
| `mode`, `exceptions_sha256` | The mode, and in waived mode the SHA-256 of the exceptions file both audits applied |
| `identity` | Host, benchmark, profile, content version and digest, and scanner shared by both runs; null when a scan is missing |
| `baseline`, `post` | `run_id`, `run_status`, `started_at`, `finished_at` and `summary` (count per outcome of the compared scan run) |
| `counts` | One count per category |
| `regressions` | The regressed rules, each with `rule_id`, `category`, and `baseline` and `post` (`outcome`, `evaluated_outcome`) |
| `rules` | Every rule in the same shape |
| `regression_detected` | Whether at least one rule regressed |
| `new_failures`, `new_failure_detected` | The newly failing rules, and whether there is at least one |
| `passed_now_not_applicable` | The rules that passed in the baseline and are `notapplicable` afterwards |
| `message` | A summary that starts with `REGRESSION:` and/or `NEW FAILURE:`, with `No regression and no new failure:` only when there is neither, or with `Verification incomplete:`; it never claims compliance |
| `gate` | `fail_on_regression`, `fail_on_new_failures` and `failed`, the decision of the role |

## Regressions and new failures are always reported

Regressions and new failures are reported whether or not they fail the host. The role prints the message, then:

- `WARNING: REGRESSION on <host>: N rule(s) passed in the baseline and no longer pass.` with one line per rule and its
  new outcome;
- `WARNING: NEW FAILURE on <host>: N rule(s) were not applicable or missing in the baseline and fail now.` with every
  rule;
- `WARNING: N rule(s) on <host> passed in the baseline and are not applicable now; ...` with every rule;
- a warning that lists the rules in the `error` category.

With the defaults `linux_compliance_verify_fail_on_regression: true` and
`linux_compliance_verify_fail_on_new_failures: true` the host then fails. With `false` it passes, and the rules stay
in `linux_compliance_verified.regressions` and `new_failures`.

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `linux_compliance_verify_profile` | `cis_level1_server` | Profile short identifier that both audits must report |
| `linux_compliance_verify_fail_on_regression` | `true` | Fail the host on regressions; they are reported either way |
| `linux_compliance_verify_fail_on_new_failures` | `true` | Fail the host on new failures; they are reported either way |
| `linux_compliance_verify_mode` | `raw` | `raw` or `waived`, see above |
| `linux_compliance_exceptions_file` | `null` | Shared with the audit role; required in waived mode, where both audits must have applied this path |

Pass booleans as JSON (`-e '{"linux_compliance_verify_fail_on_regression": false}'`); a string fails the input
validation. Every task of `main` is tagged `always`, and guard tasks tagged `linux_compliance_verify_guard` fail the
role under `--skip-tags always`, so a skipped verification can never look like a passed one.

## Entry points

| Entry point | Use |
|---|---|
| `main` | Compare `linux_compliance_audited` with `linux_compliance_baseline`, publish `linux_compliance_verified`, enforce the gates |
| `baseline.yml` | Record `linux_compliance_audited` as `linux_compliance_baseline` and mark it, between the first audit and the remediation |
| `preflight.yml` | Refuse `linux_compliance_audit_fail_on_noncompliant` before anything is audited |

## Trust

Both scan runs come from the scanned host, so a host that is already compromised can report whatever it likes in both
audits; the comparison cannot detect that, exactly like a single audit cannot
([threat model](security/threat-model.md)). What the comparison does guarantee is that it does not mix two different
kinds of scan, that a waiver, a disabled rule or a repaired check never counts as an improvement, that an
incomplete scan never yields figures, and that the baseline is one that `baseline.yml` recorded in this run.

The baseline marker is not a secret. Residual risk: an operator who passes `-e ansible_facts=...` with a forged
marker to `verify.yml` on its own, or a custom playbook that sets a forged baseline and marker with its own
`set_fact` tasks, can still make the role compare against it. Both are deliberate acts by someone who already
controls the playbook run and its trusted configuration; the role does not defend against them. `baseline.yml`
refuses an extra variable that sets the marker, so `remediate.yml` is not affected.

## Tests

- `tests/unit/plugins/filter/test_compare_scans.py` covers every category transition and every pair of scanner
  outcomes, rules missing from either run (a passing rule that disappears is `regressed`, a failing rule that appears
  is `newly_failing`), the three applicability changes of the review (pass and fail to `notapplicable`,
  `notapplicable` to fail) with their lists and message, a mismatched host, benchmark, profile, content version, content digest and scanner, the same run twice, a
  later scan that started before the baseline finished, a scan that did not complete on either side and check mode
  without a scan, an `error` that becomes `pass` (not an improvement), waived mode with the same file and with a
  different file, waived results that do not belong to their raw run, and malformed audit results. The filter has 100%
  line and branch coverage.
- `make test-verify` (part of `make ci` and of the CI job `test`) runs the role without `oscap` on the local inventory
  host `web01`, with synthetic `linux_compliance_audited` facts and the audit role's `evaluate.yml` entry point for
  the waived results, and the per-checkout `ANSIBLE_HOME`. `tests/playbooks/verify.yml` checks an
  improvement without regressions, a regression that fails the host by default and is published and printed without
  failing it when the gate is off, an incomplete scan that fails the host even with the gate off, a refused benchmark
  and profile mismatch and the same run twice, a waiver applied only after remediation that is `unchanged` in raw mode
  and refused in waived mode, a waived comparison with the same file, and a file edited between the audits that is
  refused by its digest. It also checks that a baseline is compared only once, and that the three applicability
  changes fail the host by default through the new-failure gate and pass with it off. The Makefile requires the
  `WARNING: REGRESSION`, `WARNING: NEW FAILURE` and not-applicable warning lines in the output.
- `tests/playbooks/verify-forged.yml` (inventory `tests/playbooks/inventory/verify-forged.yml`) passes an all-`fail`
  baseline against an all-`pass` audit, without `baseline.yml`, as a host variable, a group variable and a play
  variable, once with a matching marker planted as a host variable, an inventory `ansible_facts` and a play variable
  `ansible_facts`, and once with no baseline at all. Every case must fail before anything is compared.
- `tests/playbooks/verify-baseline-override.yml` runs twice, with an extra variable `linux_compliance_baseline` and with
  an extra variable `ansible_facts` that sets the marker, and requires that `baseline.yml` refuses both.
- `tests/playbooks/verify-preflight.yml` requires that `preflight.yml` refuses
  `linux_compliance_audit_fail_on_noncompliant` as `true` and as the string `"false"`, and accepts it unset and `false`.
- `tests/playbooks/verify-skip-always.yml` requires that the guard fails the role under `--skip-tags always`.

Not covered yet: `playbooks/remediate.yml` end to end with a real scan, remediation and second scan on a managed host.
That needs the Docker Molecule framework (FREES-59, pull request 14), which had not merged when this was written, so
the scenario is a follow-up for FREES-60.
