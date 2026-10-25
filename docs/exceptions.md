# Exceptions and waivers

Scope: the policy for accepted risks, the exceptions file format and how the collection applies it. Audience:
operators who write exceptions, the people who approve them, and role and report authors. Jira: FREES-50. Decision:
[ADR 0013, amendment of FREES-50](adr/0013-normalized-findings-model.md#amendment-2026-10-25-exceptions-file-and-waivers-frees-50).

An exception (waiver) records that a specific rule may fail on specific hosts for a limited time, why, who owns that
decision and who approved it. Exceptions live in a YAML file in Git, next to the inventory, so every change is
reviewed in a pull request and the history shows who accepted which risk and when. A waived finding is still a
finding: reports show it as `waived` with the exception that covers it, and a waiver never counts as a pass. A scan
provides evidence, not certification; an exception does not make a host compliant with any framework.

Code: `plugins/module_utils/compliance/exceptions.py` (validation and matching),
`plugins/module_utils/compliance/yamlsubset.py` (strict loader), and the controller filters
`freesecdev.linux_compliance.apply_exceptions` and `freesecdev.linux_compliance.stale_exceptions` in
`plugins/filter/`.

## Policy

1. **Every field is required.** An exception without an identifier, rule, framework, scope, justification, owner,
   approval (approver and date), creation date, expiry date or risk is rejected. No field may be null or empty.
2. **Exceptions expire.** The maximum validity is **365 days** from `created` to `expires`. There are no permanent
   exceptions. To renew, add a new entry with a new `id`, a new approval and new dates, and remove or keep the old
   one; Git keeps the history either way.
3. **Separation of duties.** Owner and approver are each an email address or a handle (see
   [Owner and approver](#owner-and-approver)), and the approver must not be the owner. The names are compared after
   NFKC normalisation, trimming and case folding, and a handle counts as the same person as an email address with
   that local part (`alice` and `alice@example.com`). The file records the names; the authority to approve comes from
   the review of the pull request that changes the file, so protect the file with the same branch rules as the
   inventory.
4. **No back-dating into the future.** `created` must not be after today, `approval.date` lies between `created` and
   today, and `approval.date` is before `expires`. "Today" is the current UTC date on the controller.
5. **Fail closed on bad input.** One invalid entry, a duplicate identifier or a malformed file rejects the whole file
   and fails the task. Nothing is applied from an invalid file, and no entry is silently skipped.
6. **Only failures are waived.** An `error` is never waived, nor is anything from a scan that did not complete. A
   broken check must be fixed, not accepted. `pass`, `notapplicable`, `notchecked` and `disabled` stay as they are.
7. **Waivers are never silent.** Every waived finding carries the exception identifier, its expiry and a reason that
   contains the justification, risk, framework, owner, approver and dates. Every exception gets a status for every
   scan run it is applied to, including expired, superseded and unused ones.
8. **Expired exceptions stop suppressing failures.** From the expiry date on, the finding is `fail` again. The
   evaluation lists the exception as `expired`. If the exception had already expired when the scan started, the
   finding also names it (state `expired`).
9. **The scanned host's clock cannot extend a waiver.** Expiry is judged at the later of the scan start and the
   controller's clock, and a scan that claims to start in the future is refused; see
   [Time and clocks](#time-and-clocks).

## File format

The file is a single YAML document. Its JSON Schema is
[`schemas/exceptions-v1.schema.json`](schemas/exceptions-v1.schema.json) (JSON Schema 2020-12) and a complete example
is [`examples/exceptions.yml`](examples/exceptions.yml).

```yaml
---
schema_version: "1.0"
exceptions:
  - id: EXC-2026-001
    rule: xccdf_org.ssgproject.content_rule_sshd_disable_root_login
    framework: cis
    scope:
      hosts:
        - bastion01
    justification: >-
      The legacy deployment tool on bastion01 can only log in as root. Access is limited to the
      management VLAN and every session is recorded. The tool is replaced in OPS-1234.
    owner: platform-team@example.com
    approval:
      approver: security-lead@example.com
      date: 2026-10-02
    created: 2026-10-01
    expires: 2027-03-31
    risk: medium
```

| Field | Contract |
|---|---|
| `schema_version` | `"1.0"`, quoted |
| `exceptions` | A list of at most 1000 entries; an empty list is valid |
| `id` | `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 64 characters, unique in the file ignoring case |
| `rule` | Full XCCDF rule identifier, checked with the findings model's rule-ID rule; short IDs are rejected |
| `framework` | `cis`, `stig`, `nist_800_53`, `nist_800_171`, `pci_dss` or `anssi` (the model's framework IDs) |
| `scope` | At least one of `hosts`, `groups`, `profiles` and `benchmark`; `benchmark` requires `profiles`; see [Scope](#scope) |
| `justification` | Free text, at most 4096 characters including surrounding whitespace (as in the schema); the stored value is trimmed |
| `owner` | The accountable person or team: an email address or a handle, see [Owner and approver](#owner-and-approver) |
| `approval.approver` | Who approved: an email address or a handle, not the owner |
| `approval.date` | `YYYY-MM-DD`; the exception takes effect at 00:00:00 UTC on this date |
| `created` | `YYYY-MM-DD`, not in the future |
| `expires` | `YYYY-MM-DD`, after `created` by at most 365 days; the exception stops at 00:00:00 UTC on this date |
| `risk` | `low`, `medium`, `high` or `critical` |

All dates are UTC calendar dates. The exception is in effect from `approval.date` 00:00:00 UTC up to, but not
including, `expires` 00:00:00 UTC, so the last day it applies is the day before `expires`. An exception whose
`expires` is today is already expired.

### Owner and approver

Each must be, after NFKC normalisation, trimming and case folding, one of:

- a handle matching `^[a-z0-9][a-z0-9._-]{0,63}$`, for example `platform-team` or `sec.lead`;
- an email address: a local part of up to 64 characters from `[a-z0-9._%+-]`, starting with a letter or digit, then
  `@` and a domain of at least two dot-separated labels (`alice@example.com`). A trailing dot is rejected.

Only ASCII is accepted after normalisation, so a Cyrillic `а` in `аlice@example.com` is rejected. Fullwidth forms such
as `ａlice@example.com` normalise to `alice@example.com`. The collection stores and reports the canonical form. The
JSON Schema accepts only the canonical lowercase form; write the names that way.

### YAML subset

Code on the managed side of the collection may only use the Python standard library, which has no YAML parser, so the
file is read by a strict loader for a subset of YAML (`yamlsubset.py`). Files written like the example above work.
The loader:

- requires the first line to be exactly `---` and allows one document, with block mappings, block sequences,
  one-line plain and quoted scalars, one-line flow sequences such as `[web01, web02]` and `|` or `>` block scalars;
- allows comment lines and comments after a value;
- rejects duplicate keys, anchors and aliases, tags, flow mappings, merge keys (and a plain `<<` value),
  multi-line plain or quoted scalars, tabs, carriage returns, control, separator and bidi characters, files over
  1 MiB, nesting deeper than 8 levels and sequences, block or flow, of more than 10000 items;
- treats a block scalar at the end of a file without a final newline as PyYAML does (no line break is added);
- reads every scalar as a string, so unquoted dates such as `2026-10-01` stay text, and rejects unquoted values that
  other YAML loaders would read as something else (`yes`, `on`, `true` and similar, numbers such as `1.0` or `1234`)
  so the file means the same to every tool. Quote such values.

Errors name the line. The JSON Schema describes the document as this loader reads it. A generic YAML 1.1 loader turns
unquoted dates into date objects; quote the dates if you validate the file with such a tool, or call
`exceptions.parse_document` on the loaded data to get the full validation (the caller then has to reject duplicate
keys itself). The schema cannot express the rules that compare fields (dates, the validity cap, owner and approver,
unique identifiers); the module enforces them.

`tests/unit/tools/test_yamlsubset_differential.py` generates a seeded corpus of 3000 documents on every CI run and
requires that every document the loader accepts loads to the same value with PyYAML (dates compared as text).

## Scope

| Key | Matches |
|---|---|
| `hosts` | The inventory host name (`inventory_hostname`), exactly |
| `groups` | Any of the inventory groups of the host (`group_names`), exactly; `all` and `ungrouped` are rejected because `group_names` never contains them |
| `profiles` | The full XCCDF profile identifier of the scan run (`profile_id`), exactly |
| `benchmark.id`, `benchmark.version` | The `benchmark_id` and the content version (`content.content_version`) of the scan run; both must be equal. Requires `profiles` |

Every key that is present must match (AND); within a list one entry is enough (OR). There are no wildcards or
patterns. Host scopes are matched against the controller's inventory name, never against the host name the scanned
host reports about itself, because a compromised host could claim another host's name.

`framework` records which framework's control the exception is granted against and appears in reports, but it does
not restrict matching by itself. Rules are deduplicated by rule ID across frameworks (ADR 0013), and in
ComplianceAsCode the CIS and STIG profiles of a distribution share one benchmark identifier, so neither `framework`
nor `benchmark` can tell a CIS scan from a STIG scan. **To limit an exception to one framework, list its profiles in
`profiles`.** Because a benchmark scope alone would silently cover every profile of the benchmark, a scope with
`benchmark` must also name `profiles` (fail closed). A scope without `profiles` (only `hosts` or `groups`) applies to
every profile scanned on those hosts; that is deliberate and visible in the scope, but name the profiles whenever the
approval was for one framework.

## How exceptions are applied

Each exception gets exactly one status per scan run:

| Status | When | Effect on the finding |
|---|---|---|
| `waived` | The rule failed in a completed run, the scope matches, the exception was approved before the scan started and has not expired at the evaluation time | `fail` becomes `waived`; `evaluated_outcome` stays `fail`; the exception is `active` with identifier, reason and expiry |
| `expired` | As above, but the evaluation time is on or after `expires` | Stays `fail`; carries the exception with state `expired` when it had expired by the scan start, otherwise no exception is attached (the findings model only allows `expired` at or before the scan start) |
| `not_yet_effective` | As above, but the scan started before `approval.date` | Stays `fail`; no exception attached |
| `not_failing` | The scope matches but the finding is not `fail`, or the run did not complete | Unchanged (`error` stays `error`) |
| `superseded` | Another exception for the same failing finding was chosen | None; `superseded_by` names the chosen one |
| `unmatched` | The rule is not in the run or the scope does not match this host | None |

When several exceptions match one failing finding, an exception in effect wins over an expired one, which wins over
one not yet in effect; among equals the earliest `expires` wins (the waiver that lapses first), then the lowest `id`.
The result also carries `expired: true` for every exception whose expiry is at or before the evaluation time, whatever
its status.

### Time and clocks

`started_at` comes from the scanned host, so it is untrusted: a host whose clock runs behind would otherwise keep a
lapsed waiver alive. The filter therefore takes the controller's current UTC time and:

- refuses (fails the task) a scan whose `started_at` is more than **5 minutes** after the controller time;
- judges expiry at the **later** of `started_at` and the controller time (`evaluated_at`), so a host can only make a
  waiver lapse sooner, never later;
- judges whether an exception was already approved at `started_at`, so a scan from before the approval is never
  waived;
- flags the evaluation with `scan_lag_exceeded: true` when the scan started more than `max_scan_lag_hours` (default
  **24**) before the controller time, and still evaluates it. A large lag means either an old scan run that is being
  re-applied or a host clock that is behind; both deserve a look.

Applying the current exceptions file to an old scan run therefore uses today's validity: a waiver that has expired
since the scan no longer applies. Reports built from scan runs that were already marked are unaffected, because they
read the marked findings.

**Stale exceptions** are exceptions that matched no finding at all. One host cannot tell, so
`freesecdev.linux_compliance.stale_exceptions` takes the evaluations of all hosts and returns the identifiers that are
`unmatched` on every one. The answer covers only the hosts that were evaluated; an exception for a host outside the
play is reported as stale. An exception that is `not_failing` everywhere is not stale but is a candidate for removal,
because the rule now passes.

### Evaluation document

`apply_exceptions` returns:

| Key | Content |
|---|---|
| `schema_version` | `"1.0"` |
| `scan_run` | The scan run in the findings-model format, with waived and expired findings marked |
| `exceptions` | One entry per exception, sorted by `id`: the record as in the file plus `expires_at`, `status`, `outcome` (the evaluated outcome of the matched finding or `null`), `expired` and `superseded_by` |
| `summary` | The number of exceptions per status |
| `source_sha256` | SHA-256 of the exceptions text; `stale_exceptions` refuses evaluations of different files |
| `scan_started_at`, `controller_time` | The scan start reported by the host and the controller's time, UTC |
| `evaluated_at` | The later of the two: the instant at which expiry was judged |
| `scan_lag_seconds`, `max_scan_lag_seconds`, `scan_lag_exceeded` | How long before the controller time the scan started (negative within the 5-minute tolerance), the limit, and whether it was exceeded |
| `max_validity_days` | `365` |
| `target` | The inventory host and sorted groups used for matching |

A scan run whose findings already carry exception data is rejected, so a waiver cannot be applied twice.

## Using the filters from a role

The filters run on the controller. The exceptions file is read with `ansible.builtin.file`, which reads it on the
controller as well, so the file never has to be copied to a managed host.

The `audit` role (FREES-49) is implemented and publishes the scan run as `linux_compliance_audited.scan_run`, but it
does not apply exceptions yet: its `linux_compliance_audit_fail_on_noncompliant` check counts the failures the scan
reported, before any waiver. The `verify` role (FREES-54) is still a skeleton. Wiring the filters into these roles is a
separate follow-up. Until then a play can apply them after the `audit` role, for example:

```yaml
---
- name: Apply the exceptions file to the scan run
  ansible.builtin.set_fact:
    linux_compliance_audit_evaluation: >-
      {{ linux_compliance_audited.scan_run
         | freesecdev.linux_compliance.apply_exceptions(
             lookup('ansible.builtin.file', linux_compliance_audit_exceptions_file),
             inventory_hostname, group_names) }}
  when: linux_compliance_audit_exceptions_file | length > 0

- name: Report exceptions that no host of this play needs
  ansible.builtin.debug:
    msg: >-
      {{ ansible_play_hosts
         | map('extract', hostvars, 'linux_compliance_audit_evaluation')
         | list
         | freesecdev.linux_compliance.stale_exceptions }}
  run_once: true
  when: linux_compliance_audit_exceptions_file | length > 0
```

The filter accepts the scan run as a mapping or as its JSON text. `linux_compliance_audit_exceptions_file` and
`linux_compliance_audit_evaluation` are illustrative names in the play, not role variables; the roles will define
their own when they wire the filters in. An invalid file fails the task with a message that names the entry or line.

## Reporting

Write the `scan_run` of an evaluation document to a JSON file and pass it to `tools/reporting` (FREES-75) with
`--scan-run`. The report then shows:

- waived findings as their own `waived` count, which never counts as a pass and stays in the denominator;
- the exception identifier, state, reason and expiry of every finding, in the embedded scan run;
- `expired_waivers`, the number of failures whose exception expired.

`tests/unit/tools/reporting/test_exceptions_report.py` runs a scan run through `exceptions.evaluate_run` and then
through the report, and checks all three against the report schema.

**Known gap:** the report does not read the evaluation document itself, so it has no view of the per-exception
statuses and does not list stale exceptions. Until it does, use the `stale_exceptions` filter or
`exceptions.stale_exception_ids` on the evaluation documents. Closing the gap changes the report schema, so it needs
its own `schema_version` decision under [ADR 0016](adr/0016-report-schema-and-summary-semantics.md).

## Security notes

- The exceptions file is configuration from Git and is trusted only after review, but it is still parsed
  defensively: no anchors or aliases (so no alias expansion attacks), no tags, no duplicate keys, bounded size, depth
  and list lengths, and every field is validated before anything is applied.
- The owner and approver fields are names, not authenticated identities. Accountability comes from the reviewed Git
  history of the file.
- A waiver changes only `fail` to `waived` and never hides an `error` or a scan that did not complete, so a broken
  scanner cannot be waived into a clean-looking report.
- Anyone who can merge changes to the exceptions file can waive failures until the expiry. Protect it like the
  inventory and keep expiries short.

## Limits

| Item | Limit |
|---|---|
| File size | 1 MiB |
| Nesting depth | 8 |
| Entries | 1000 |
| Items in any one YAML sequence, block or flow | 10000 |
| Hosts, groups or profiles per scope | 256 |
| Validity | 365 days |
| `id` | 64 characters |
| `justification` | 4096 characters |
| `owner`, `approver` | 254 characters (a handle at most 64) |
| Scan start after the controller time | 5 minutes |
| Scan lag before the evaluation is flagged | 24 hours by default, 1 to 8760 |
