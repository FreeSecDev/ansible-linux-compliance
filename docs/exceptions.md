# Exceptions and waivers

Scope: the policy for accepted risks, the exceptions file format and how the collection applies it. Audience:
operators who write exceptions, the people who approve them, and role and report authors. Jira: FREES-50,
FREES-132 (report), FREES-136 (audit role). Decisions:
[ADR 0013, amendment of FREES-50](adr/0013-normalized-findings-model.md#amendment-2026-10-25-exceptions-file-and-waivers-frees-50)
and
[amendment of FREES-132](adr/0013-normalized-findings-model.md#amendment-2026-10-26-exception-review-verified-evaluations-and-owner-identity-frees-132).

An exception (waiver) records that a specific rule may fail on specific hosts for a limited time, why, who owns that
decision and who approved it. Exceptions live in a YAML file in Git, next to the inventory, so every change is
reviewed in a pull request and the history shows who accepted which risk and when. A waived finding is still a
finding: reports show it as `waived` with the exception that covers it, and a waiver never counts as a pass. A scan
provides evidence, not certification; an exception does not make a host compliant with any framework.

Code: `plugins/module_utils/compliance/exceptions.py` (validation and matching),
`plugins/module_utils/compliance/yamlsubset.py` (strict loader), and the controller filters
`freesecdev.linux_compliance.apply_exceptions`, `freesecdev.linux_compliance.stale_exceptions`,
`freesecdev.linux_compliance.exception_removal_candidates`,
`freesecdev.linux_compliance.validate_exceptions` and `freesecdev.linux_compliance.scan_summary` in
`plugins/filter/`. The `audit` role applies the file ([below](#using-the-exceptions-file-with-the-audit-role)).

## Policy

1. **Every field is required.** An exception without an identifier, rule, framework, scope, justification, owner,
   approval (approver and date), creation date, expiry date or risk is rejected. No field may be null or empty.
2. **Exceptions expire.** The maximum validity is **365 days** from `created` to `expires`. There are no permanent
   exceptions. To renew, add a new entry with a new `id`, a new approval and new dates, and remove or keep the old
   one; Git keeps the history either way.
3. **Separation of duties.** Owner and approver are each an email address or a handle (see
   [Owner and approver](#owner-and-approver)), and the approver must not be the owner. The names are compared after
   NFKC normalisation, trimming and case folding, and they are the same person when their identities are equal (see
   [Same person](#same-person)): `alice`, `alice@example.com`, `alice+audit@example.com` and `alice@other.example` are
   all one person. The file records the names; the authority to approve comes from
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

### Same person

The approver must not be the owner. Two canonical names denote the same person when their identities are equal. The
identity of a handle is the handle; the identity of an email address is its local part without a plus-address suffix
(everything from the first `+`), on any domain.

| Owner | Approver | Result |
|---|---|---|
| `alice` | `alice@example.com` | Same person, rejected |
| `alice+audit@example.org` | `alice@example.org` | Same person (plus-addressing), rejected |
| `alice@a.example` | `alice@b.example` | Same person (same local part on another domain), rejected |
| `alice.smith@example.org` | `alicesmith@example.org` | Different people, accepted |
| `alice` | `alicia@example.com` | Different people, accepted |

Decision (FREES-132): plus-addressing delivers to the same mailbox, so it never makes a second person. The same local
part on another domain is treated as the same person as well, because a handle already matches that local part on
every domain; treating `alice@a.example` and `alice@b.example` as different people while both equal `alice` would let a
second address of the owner approve the owner's own exception. The rule fails closed: if two different people really
share a local part, give one of them a distinct handle or address. Provider-specific aliases such as dots are not
folded, because providers treat them differently. Names are still not authenticated identities; the review of the pull
request is the authority.

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
| `benchmark.id`, `benchmark.version` | The `benchmark_id` and the content version (`content.content_version`) of the scan run; both must be equal. The version is a token (`[A-Za-z0-9][A-Za-z0-9._+~:-]*`, at most 64 characters). Requires `profiles` |

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

**Review across hosts.** One host cannot tell whether an exception is still needed, so the evaluations of all hosts
(one per scan run) are reviewed together. Each exception gets one verdict, decided by the first of these statuses that
any evaluation reports:

| Verdict | When |
|---|---|
| `expired` | It is `expired` in at least one evaluation: a failure it covered is no longer waived |
| `in_effect` | It is `waived` in at least one evaluation |
| `not_yet_effective` | A failure it covered was scanned before its approval date |
| `superseded` | Another exception was chosen for every failure it covered |
| `not_failing` | Its rule did not fail wherever its scope matched |
| `stale` | It is `unmatched` in every evaluation: its rule or scope matched nothing |

`stale`, `superseded` and `not_failing` exceptions are **candidates for removal**: they waived nothing, covered no
failure that expired and none scanned before their approval, on any evaluated host. An exception superseded on every
host is therefore a removal candidate, just like a stale one.

- `freesecdev.linux_compliance.stale_exceptions` returns the stale identifiers.
- `freesecdev.linux_compliance.exception_removal_candidates` returns every removal candidate, stale ones included.
- Both refuse evaluations of different exceptions files and evaluations whose `schema_version` they do not know
  (only `"1.0"` today), so a future evaluation format is never misread.

The answer covers only the hosts that were evaluated; an exception for a host outside the play is reported as stale.
`playbooks/audit.yml` computes the stale exceptions once in a final play, after every host and every `serial`
batch ([audit guide](audit.md#stale-exceptions-once-for-all-hosts)).
The report shows the same verdicts (see [Reporting](#reporting)).

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

## Using the exceptions file with the audit role

Jira: FREES-136. The `audit` role applies the file when `linux_compliance_exceptions_file` is the absolute path of
the file on the controller; the default `null` applies nothing. The full behaviour is in the
[audit guide](audit.md#exceptions-in-the-audit-role). In short:

```text
ansible-playbook -i inventory.yml freesecdev.linux_compliance.audit \
  -e linux_compliance_target_hosts=web01 \
  -e linux_compliance_discover_content_path=/opt/freesecdev/content/ssg-ubuntu2404-ds.xml \
  -e linux_compliance_discover_content_sha256=<sha256 from content/manifest.yml> \
  -e linux_compliance_exceptions_file=/srv/compliance/exceptions.yml
```

- The file is read once with `lookup('ansible.builtin.file', path, rstrip=false)` and validated once with
  `freesecdev.linux_compliance.validate_exceptions`, both `run_once` on the controller, before any host is scanned. An
  invalid file fails the play; nothing is applied from it. Every host of the play must use the same file.
- An exception that sets `framework` without `profiles` produces a `WARNING:` message, because it applies to every
  profile scanned on the hosts in its scope.
- Each host applies the file to its own scan run with `freesecdev.linux_compliance.apply_exceptions`. A scan start
  more than five minutes after the controller time fails that host.
- The raw result stays in `linux_compliance_audited.scan_run` and `linux_compliance_audited.summary`. The waived result
  is `linux_compliance_audited.exceptions.evaluation` (the evaluation document below, whose `scan_run` has the waived
  findings) and `linux_compliance_audited.exceptions.summary` (the count per outcome, from
  `freesecdev.linux_compliance.scan_summary`).
- Check mode without a scan (`run_status: not_run`, `scan_run` null) skips the filter and reports that waivers were not
  applied. A run that did not complete is never waived.
- `linux_compliance_audit_fail_on_noncompliant` counts the **raw** result by default, so a waiver never passes the gate.
  `linux_compliance_audit_fail_on_noncompliant_after_waivers: true` counts the waived result instead. `error` always
  counts in both modes.
- `playbooks/audit.yml` ends with a play on the controller. It runs the role's `stale.yml` entry point once over every
  target host and publishes `linux_compliance_audit_stale_exceptions`. Exceptions are called stale, and removal is
  advised, only when every target host was evaluated. With partial coverage (`--limit`, unreachable or failed
  hosts) the report says `unmatched on N of M target hosts` and names the hosts it does not cover.
- Only the linear strategy is supported, with or without `serial`; every host of the play must resolve the same file.

The `verify` role (FREES-54) is still a skeleton. When it is implemented it must compare raw with raw or waived with
waived, from the same exceptions file, and must never count a waived result as an improvement over a failed one.

The filters remain usable on their own, for example on a scan run read from `scan-run.json`. They accept the scan run as
a mapping or as its JSON text. An invalid file fails the task with a message that names the entry or line.

## Reporting

Write each evaluation document (with the `audit` role, `linux_compliance_audited.exceptions.evaluation`) to a JSON
file and pass them to `tools/reporting` (FREES-75, FREES-132) with `--exceptions-evaluation`, one per scan run,
together with the exceptions file they were made from:

```bash
python -m tools.reporting --scope fleet --output build/report/report.json --html build/report/report.html \
  --exceptions-file inventory/exceptions.yml \
  --exceptions-evaluation web01-evaluation.json --exceptions-evaluation web02-evaluation.json
```

`--exceptions-file` is required with `--exceptions-evaluation`: it is the reviewed exceptions file that the
evaluations were made from.

An evaluation is a compliance input on its own; do not pass its scan run with `--scan-run` as well, because two
completed scan runs of one host and profile are refused as a repeated scan. The report then shows:

- waived findings as their own `waived` count, which never counts as a pass and stays in the denominator;
- the exception identifier, state, reason and expiry of every finding, in the embedded scan run;
- `expired_waivers`, the number of failures whose exception expired, **including** waivers that lapsed between the
  scan start and the controller time (the finding carries no exception data in that case, so only the evaluation
  records it; the rule is listed in `lapsed_waivers`);
- an `exceptions` section that lists every exception of the file with its review verdict, removal candidacy, expiry,
  structured scope, the inventory hosts where its scope matched, its status per scan run and the SHA-256 of the
  exceptions file ([reporting data model](reporting-data-model.md#exceptions-section));
- the stale, expired and removal-candidate counts in the overview. None of this changes a compliance percentage.

The report does not trust the evaluation file. It checks the evaluation against the exceptions file:

- the SHA-256 of the exceptions file must be the evaluation's `source_sha256`. The `audit` role reads the file with
  `rstrip=false`, so the digests are those of the file's bytes. The `ansible.builtin.file` lookup removes trailing
  whitespace by default, so for a play that uses the default the report also accepts the digest of the file without
  trailing whitespace;
- the exceptions file must pass the same validation as in the filter, at the evaluation's controller time;
- the scan run, with its waiver marks removed, is evaluated again with that file and the inventory host, groups,
  controller time and scan lag limit the evaluation records, and the result must be identical.

An edited status, count, mark or time, or an evaluation made from another exceptions file, is an input error, and
nothing from it is shown as waived. The report records the exceptions file path and SHA-256 in the exceptions
section once every evaluation passed. Only the reviewed Git history makes the file itself trustworthy; signed
evidence is proposed in [ADR 0018](adr/0018-evidence-bundle-provenance.md).

Passing only the marked scan run with `--scan-run` still works, but then the report has no exceptions section and does
not count waivers that lapsed during the scan.

`tests/unit/tools/reporting/test_exceptions_report.py` runs the committed `tests/fixtures/reporting/exceptions.yml`
through `exceptions.evaluate_run` and the report, checks every verdict and count against the report schema, and checks
that the committed evaluation fixture is exactly what the filter writes.

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
