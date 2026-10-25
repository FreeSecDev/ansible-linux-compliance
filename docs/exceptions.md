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
3. **Separation of duties.** The approver must not be the owner (compared ignoring case). The file records the
   names; the authority to approve comes from the review of the pull request that changes the file, so protect the
   file with the same branch rules as the inventory.
4. **No back-dating into the future.** `created` must not be after today, `approval.date` lies between `created` and
   today, and `approval.date` is before `expires`. "Today" is the current UTC date on the controller.
5. **Fail closed on bad input.** One invalid entry, a duplicate identifier or a malformed file rejects the whole file
   and fails the task. Nothing is applied from an invalid file, and no entry is silently skipped.
6. **Only failures are waived.** An `error` is never waived, nor is anything from a scan that did not complete. A
   broken check must be fixed, not accepted. `pass`, `notapplicable`, `notchecked` and `disabled` stay as they are.
7. **Waivers are never silent.** Every waived finding carries the exception identifier, its expiry and a reason that
   contains the justification, risk, framework, owner, approver and dates. Every exception gets a status for every
   scan run it is applied to, including expired, superseded and unused ones.
8. **Expired exceptions stop suppressing failures.** From the expiry date on, the finding is `fail` again. It still
   names the expired exception (state `expired`) so the lapse is visible.

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
| `scope` | At least one of `hosts`, `groups` and `benchmark`; see [Scope](#scope) |
| `justification` | Free text, at most 4096 characters; surrounding whitespace is trimmed |
| `owner` | The accountable person or team, at most 256 characters |
| `approval.approver` | Who approved, at most 256 characters, not the owner |
| `approval.date` | `YYYY-MM-DD`; the exception takes effect at 00:00:00 UTC on this date |
| `created` | `YYYY-MM-DD`, not in the future |
| `expires` | `YYYY-MM-DD`, after `created` by at most 365 days; the exception stops at 00:00:00 UTC on this date |
| `risk` | `low`, `medium`, `high` or `critical` |

All dates are UTC calendar dates. The exception is in effect from `approval.date` 00:00:00 UTC up to, but not
including, `expires` 00:00:00 UTC, so the last day it applies is the day before `expires`. An exception whose
`expires` is today is already expired.

### YAML subset

Code on the managed side of the collection may only use the Python standard library, which has no YAML parser, so the
file is read by a strict loader for a subset of YAML (`yamlsubset.py`). Files written like the example above work.
The loader:

- requires the first line to be exactly `---` and allows one document, with block mappings, block sequences,
  one-line plain and quoted scalars, one-line flow sequences such as `[web01, web02]` and `|` or `>` block scalars;
- allows comment lines and comments after a value;
- rejects duplicate keys, anchors and aliases, tags, flow mappings, merge keys, multi-line plain or quoted scalars,
  tabs, carriage returns, control, separator and bidi characters, files over 1 MiB and nesting deeper than 8 levels;
- reads every scalar as a string, so unquoted dates such as `2026-10-01` stay text, and rejects unquoted values that
  other YAML loaders would read as something else (`yes`, `on`, `true` and similar, numbers such as `1.0` or `1234`)
  so the file means the same to every tool. Quote such values.

Errors name the line. The JSON Schema describes the document as this loader reads it. A generic YAML 1.1 loader turns
unquoted dates into date objects; quote the dates if you validate the file with such a tool, or call
`exceptions.parse_document` on the loaded data to get the full validation (the caller then has to reject duplicate
keys itself). The schema cannot express the rules that compare fields (dates, the validity cap, owner and approver,
unique identifiers); the module enforces them.

## Scope

| Key | Matches |
|---|---|
| `hosts` | The inventory host name (`inventory_hostname`), exactly |
| `groups` | Any of the inventory groups of the host (`group_names`), exactly; `all` and `ungrouped` are rejected because `group_names` never contains them |
| `benchmark.id`, `benchmark.version` | The `benchmark_id` and the content version (`content.content_version`) of the scan run; both must be equal |

Every key that is present must match (AND); within a list one entry is enough (OR). There are no wildcards or
patterns. A scope with only `benchmark` applies to every host scanned with that benchmark version, so use it
sparingly. Host scopes are matched against the controller's inventory name, never against the host name the scanned
host reports about itself, because a compromised host could claim another host's name.

`framework` records which framework's control the exception is granted against and appears in reports. It does not
restrict matching: rules are deduplicated by rule ID across frameworks (ADR 0013), so a rule is waived or not,
whichever framework references it. Use `benchmark` to restrict an exception to one benchmark.

## How exceptions are applied

Exceptions are evaluated at the scan start time (`started_at` of the scan run), not when a report is built, so
re-reporting an old scan gives the same result. Each exception gets exactly one status per scan run:

| Status | When | Effect on the finding |
|---|---|---|
| `waived` | The rule failed in a completed run, the scope matches and the exception is in effect | `fail` becomes `waived`; `evaluated_outcome` stays `fail`; the exception is `active` with identifier, reason and expiry |
| `expired` | As above, but the scan started on or after `expires` | Stays `fail`; carries the exception with state `expired` |
| `not_yet_effective` | As above, but the scan started before `approval.date` | Stays `fail`; no exception attached |
| `not_failing` | The scope matches but the finding is not `fail`, or the run did not complete | Unchanged (`error` stays `error`) |
| `superseded` | Another exception for the same failing finding was chosen | None; `superseded_by` names the chosen one |
| `unmatched` | The rule is not in the run or the scope does not match this host | None |

When several exceptions match one failing finding, an exception in effect wins over an expired one, which wins over
one not yet in effect; among equals the earliest `expires` wins (the waiver that lapses first), then the lowest `id`.
The result also carries `expired: true` for every exception whose expiry is at or before the scan start, whatever its
status.

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
| `evaluated_at` | The scan start time used for expiry |
| `max_validity_days` | `365` |
| `target` | The inventory host and sorted groups used for matching |

A scan run whose findings already carry exception data is rejected, so a waiver cannot be applied twice.

## Using the filters from a role

The filters run on the controller. The exceptions file is read with `ansible.builtin.file`, which reads it on the
controller as well, so the file never has to be copied to a managed host. The `audit` and `verify` roles (FREES-49,
FREES-54) are expected to call them after the scan, roughly like this:

```yaml
---
- name: Apply the exceptions file to the scan run
  ansible.builtin.set_fact:
    linux_compliance_audit_evaluation: >-
      {{ linux_compliance_audit_scan_run
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

`linux_compliance_audit_scan_run` stands for the scan run that the scan module returns, either as a mapping or as its
JSON text. The variable names are illustrative; the roles define the real ones when they wire the filters in. An
invalid file fails the task with a message that names the entry or line.

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
| Hosts or groups per scope | 256 |
| Validity | 365 days |
| `id` | 64 characters |
| `justification` | 4096 characters |
| `owner`, `approver` | 256 characters |
