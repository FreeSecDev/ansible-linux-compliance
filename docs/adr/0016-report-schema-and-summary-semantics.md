# 0016. Report schema and summary semantics

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** FREES-75, FREES-76
- **Pull requests:** introduced by the pull request that adds `tools/reporting/`
- **Related:** [ADR 0013](0013-normalized-findings-model.md), [reporting data model](../reporting-data-model.md)

## Context

[ADR 0013](0013-normalized-findings-model.md) defines the findings model and the invariants of a single scan run.
It does not define how a report combines scan runs with test, coverage, lint, vulnerability, SBOM and build
results, how a summary is computed from outcomes, or what a report says when an input is missing or damaged. The
HTML dashboard (FREES-77) and any later consumer need one versioned document, and the rules that turn outcomes into
numbers decide whether a report is honest. A report that rounds a broken scan up to "100 percent" is a false
assurance ([AGENTS.md](../../AGENTS.md) rule 13).

## Decision

### One versioned document with explicit section states

The reporting package (`tools/reporting/`, controller side, Python 3.12 or newer) writes one JSON document that
validates against `tools/reporting/schema/report-v1.json` (JSON Schema 2020-12). `schema_version` is `"1.0"`
(superseded by `report-v2.json` and `"2.0"`, see the [amendment of FREES-130 and
FREES-132](#amendment-2026-10-26-schema-20-host-identity-and-waivers-frees-130-frees-132)).
The document has `metadata`, one `scope`, nine `sections`, an `overview` and `raw_artifacts`.

Every item and section has a `status`:

- `unavailable` means there was no input, or an input file does not exist.
- `error` means an input exists but is empty, oversized, not a regular file, malformed, truncated, unsafe or
  unexpected (unknown root, unknown format version, inconsistent counts), or the tool that wrote it reports that it
  failed (pytest exit codes 2 to 5, SARIF `executionSuccessful: false`).
- `available` means the input parsed.
- A section is `available` when every input is, `error` when any input is `error`, `partial` when some inputs are
  available and the others are missing, and `unavailable` when it has no input or all inputs are missing.

A section that is not `available` has a `reason`, a list of `gaps` and no `summary`, and its good items stay visible
beside the bad ones. The CLI exits non-zero when a supplied input is missing or invalid; a section without any input
is `unavailable`, which is not an error and is never shown as passed. Nothing defaults to a pass; the schema enforces
the coupling between status, items, gaps, reason, data, summary and overview, and bounds every array.

### The scope is part of the document

`scope` is one of `single_host`, `multi_host`, `benchmark` or `fleet` and applies to every statistic in the
document. It is validated against the data: `single_host` with more than one host, or `benchmark` with more than one
benchmark or content version, is rejected. A figure is computed per (benchmark, content version, host) (`groups`). A
pooled figure (`aggregates`, labelled with the scope and `host_count`) exists only per benchmark and content version,
and the section-level `summary` exists only when there is exactly one benchmark and content version. No figure
combines benchmarks or versions, and no percentage appears without its denominator. (Since 2.0 every key also
includes the profile, and `benchmark` is refused for several profiles; see the [amendment](#amendment-2026-10-26-schema-20-host-identity-and-waivers-frees-130-frees-132).)

### Summary semantics

These rules come from the FREES-75 acceptance comment and are implemented in `tools/reporting/compliance.py`.

1. Only `pass` counts as pass. `notchecked`, `error`, `notapplicable`, `disabled` and `waived` never do.
2. The denominator (`evaluated`) is every outcome except `notapplicable` and `disabled`. Those two are counted and
   shown separately.
3. `compliance_percent` is `pass` divided by `evaluated`, rounded down to one decimal, so 100.0 appears only when
   everything evaluated passed (99999 of 100000 is 99.9). `notchecked`, `error` and `waived` stay in the denominator,
   so they lower the percentage, and every outcome count is present in the summary.
4. A scan run that did not complete (`failed` or `timed_out`) is never summarised as compliant. The run status is
   reported first (`run_status`), `compliance_percent` is `null` and `assessment` is `run_not_completed`. For several
   runs the status is `not_completed` as soon as one run did not complete.
5. `assessment` is never a compliance claim: `run_not_completed`, `nothing_evaluated`, `all_evaluated_passed` or
   `findings_open`. A report never states compliance with a framework (AGENTS.md rule 9).
6. A waived finding is its own count. An expired exception does not change the outcome (ADR 0013 already reports it
   as `fail`); `expired_waivers` counts those findings so that the expiry stays visible.
7. `open_by_severity` counts `fail`, `error` and `notchecked` rules per severity.
8. `notselected` results in XCCDF and ARF files (which list every benchmark rule) never enter the maths; they are
   reported as `not_selected`. For a ScanRun JSON, whose expected rules are known, the ADR 0013 backend semantics
   apply and a `notselected` result for an expected rule is `notchecked`.
9. The schema ties status, percentage and assessment together: a run that is not `completed` has no percentage.

### Deduplication across frameworks

Rules are deduplicated by full rule ID within the same host and content version (ADR 0013: the rule is counted
once however many frameworks reference it). The worst outcome wins (`error`, `fail`, `notchecked`, `waived`,
`pass`, `notapplicable`, `disabled`), the highest severity is kept and every originating artifact, benchmark and
profile is listed in `sources` with the outcome each source reported. Different content versions and different hosts
stay separate. (Since 2.0 rules are deduplicated within one host, benchmark, content version and profile; see the
[amendment](#amendment-2026-10-26-schema-20-host-identity-and-waivers-frees-130-frees-132).) A host key is a structured object (lower-cased host name, machine ID, or the content hash of an input that names no
host), never joined text, so a crafted name cannot take over another key. A ScanRun host is its host name plus machine ID; XCCDF and ARF files name their host (`target`, fqdn
fact, ARF asset), which is self-asserted. A name must satisfy the ScanRun host rule or the file is an error. Files are grouped only when the keys are equal, a file without a name is its
own host and is never merged, and an ARF asset that disagrees with its TestResult target is an error. Input files with the same SHA-256 count
once.

### Determinism and input-supplied times

The document is deterministic: sorted keys, stable ordering of every list, ASCII output. Equal inputs give
byte-identical output. Timestamps (`started_at`, `finished_at`, `generated_at`) are validated input and are
`null` when not supplied; the package never reads the clock.

### Parsing rules

Report files are attacker-controlled. Every parser bounds the file size (64 MiB by default), reads regular files only
(no symlinks), rejects DOCTYPE, entity and external-reference constructs in XML through defusedxml, bounds XML depth
and element count while parsing, rejects duplicate JSON keys and non-finite numbers, bounds the depth of JSON,
rejects numbers that overflow to infinity, opens files component by component with `O_NOFOLLOW` and `O_NONBLOCK`
(no symlinks in the path, no FIFO, no check-then-open gap), strips control and formatting characters from text and
caps free text and detail lists. Unknown versions of a format
are `error`. The original path is kept in the artifact reference together with the SHA-256 of the exact bytes that
were parsed.

XCCDF is read with the hardened parser of the findings model (`openscap.parse_results`), and ScanRun JSON with
`model.loads`; the reporting package imports both and does not copy them.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Treat a missing input as an empty successful result | An absent scan would read as a clean one |
| Count `notchecked` and `error` outside the denominator | Failing to check would raise the percentage |
| Exclude `waived` from the denominator | A waiver would improve the score without a pass |
| Average percentages over hosts or benchmarks | Mixes scopes and benchmark versions; forbidden by the reporting skill |
| One document per format | The dashboard would need to reimplement status coupling and scope handling |
| `jsonschema` at runtime | The runtime stays small; `jsonschema` is a pinned development dependency used in tests |

## Benefits

One validated document for all consumers, honest handling of missing and damaged inputs, summaries that cannot
overstate compliance, and reproducible output that can be diffed and cached.

## Trade-offs

- A section with one missing file among several is `partial` and has no summary, so consumers see less aggregate
  data than they could; the per-item data and the gaps remain.
- The host in an XCCDF or ARF file is self-asserted, so grouping by it trusts the file; two files that claim the
  same name are one host.
- A `single_host` or `benchmark` report over data from several hosts or versions is refused rather than labelled.
- Detail lists are capped at 1000 items with a `truncated` flag; totals are always complete.

## Security implications

Parsers treat every file as hostile input; see the parsing rules above and the per-parser limits in the data model
page. The package does not execute, import or follow anything from an input and does not touch the network. Text
from reports can contain markup; consumers must escape it when rendering (FREES-77 renders with DOM text APIs only).

## Operational consequences

- A schema change bumps `schema_version` and updates this ADR and `docs/reporting-data-model.md`.
- Adding a format means a new parser module, a schema definition and tests for the missing, corrupt and unexpected
  cases; `make test-coverage` requires 100% line and branch coverage for `tools/`.
- `make report` writes the normalized JSON; the HTML dashboard is delivered by FREES-77.

## References

- [ADR 0013](0013-normalized-findings-model.md), [reporting data model](../reporting-data-model.md)
- JSON Schema 2020-12: <https://json-schema.org/draft/2020-12>

## Amendment 2026-10-26: schema 2.0, host identity and waivers (FREES-130, FREES-132)

The report schema is now `tools/reporting/schema/report-v2.json` with `schema_version` `"2.0"`. The 1.0 schema file
is removed from the tree; it stays in the Git history at the commit before this amendment.

### Why a major version

Version 1.0 readers cannot read 2.0 documents, so the major version is bumped and the schema file is renamed:

- **Profiles are part of every figure key.** `groups`, `aggregates` and `rules` gain `profile_id` (and `rules` gains
  `benchmark_id`), and figures that 1.0 pooled over the profiles of one benchmark are now separate (see below).
- **Notes changed.** The meaning and shape of `sections.compliance.notes` changed. The 1.0 note
  `shared_self_asserted_host` (one note per host name across benchmarks, with a bare `host` string) no longer exists;
  its replacements are structured per group.
- **New required keys.** `sections` has a tenth section, `exceptions`, and `overview` has a required key
  `exceptions`. Both schemas reject unknown keys, so this alone breaks a strict 1.0 reader.
- **New input kind.** Compliance items have a new format and kind, `exceptions_evaluation`; compliance data has a
  required `lapsed_waivers` list; `raw_artifacts` has the format `exceptions_file`.

### Compatibility with 1.0

These keep their 1.0 meaning:

- `metadata`, `scope` and the status coupling of every section;
- items, gaps and `raw_artifacts`;
- the summary fields and the percentage rules: only `pass` counts, and the denominator is everything except
  `notapplicable` and `disabled`.

Two counting changes are deliberate:

- **One figure per profile.** A figure now covers one benchmark, content version and profile instead of one benchmark
  and content version. A 1.0 report of a host with a CIS and a STIG run had one group figure; a 2.0 report has two. The
  section `summary` exists only for exactly one benchmark, content version and profile. The `benchmark` scope is
  refused for several profiles.
- **Lapsed waivers count as expired.** A waiver that lapsed between the scan start and the controller time now counts
  in `expired_waivers`. 1.0 could not see it and counted the finding as a plain `fail`. No outcome or percentage
  changes: the finding stays `fail` either way.

A consumer migrates by:

1. accepting `schema_version` `"2.0"` and `exceptions` in the section lists of `overview`;
2. reading `profile_id` in groups, aggregates and rules, and never combining figures of different profiles;
3. reading `notes` by `kind` (`merged_inputs`, `same_host_across_groups`) instead of `shared_self_asserted_host`;
4. treating `exceptions_evaluation` as a ScanRun input in the compliance section; its data embeds the scan run, as
   for `scan_run`;
5. ignoring `sections.exceptions` and `overview.exceptions` if it does not need waivers; they never change a figure.

A 1.0 document is not converted. Reports are rebuilt from their inputs, which are unchanged with three exceptions:

- an XCCDF file whose names disagree is now an error;
- repeated scan runs are refused unless allowed;
- an exceptions evaluation needs its exceptions file.

All three are described below. The dashboard reads 2.0 only.

### Profiles are never pooled (FREES-130 review)

In ComplianceAsCode the CIS and STIG profiles of a distribution share one benchmark identifier (ADR 0013). A 1.0
group keyed on benchmark, content version and host therefore pooled a CIS run and a STIG run of one host into one
percentage that describes neither framework. It also let a forged run with another `profile_id` add passing rules to
a real host's figure, with only a benign-looking note.

The group key is now **(benchmark, content version, profile, host)**. Every place that derives a figure uses the
same key:

- `rules` deduplicates by rule ID within one host, benchmark, content version and profile. ADR 0013 counts a rule
  once however many frameworks reference it; that holds within one scan, and is not a reason to pool two profile
  runs.
- `groups` has one figure per key.
- `aggregates` has one pooled figure per (benchmark, content version, profile), over hosts.
- The section `summary` exists only when exactly one benchmark, content version and profile is present.
- The `benchmark` scope is refused when the inputs cover more than one benchmark, content version or profile.
- The `single_host` scope still counts hosts, so a CIS and a STIG run of one host is a valid `single_host` report
  with two separate figures.

A host that has inputs in several groups (for example its CIS and STIG groups) gets the host-level note described
below. That note is a list of groups, never a figure. There is no cross-profile figure.

### Notes per group (FREES-130)

- **Per-group note.** Every group built from more than one input gets one note
  `{"kind": "merged_inputs", "group": {benchmark_id, content_version, profile_id, host}, "sources": [sha256, ...],
  "repeated_profile": bool}`, whatever the input types. Two ScanRuns that share `hostname` and `machine_id` are noted
  like two XCCDF files that claim one name. `repeated_profile` is true when two or more inputs of the group completed,
  which means the same profile was scanned again.
- **Host-level note.** Every host key with inputs in more than one group gets one note
  `{"kind": "same_host_across_groups", "host": {...}, "groups": [{benchmark_id, content_version, profile_id}, ...],
  "sources": [...]}`. Those inputs are counted as one host for scope checks and `host_count`, but their figures stay
  separate; the note never claims that a group combines anything.
- **Content and bounds.** Notes carry only validated identifiers and digests. There is at most one note of each kind
  per group or host, so the 1000-entry bound of `notes` holds: each input is in at most one note of each kind, and
  each note has at least two inputs.

### Repeated scan runs are refused by default (FREES-130)

More than one **completed** ScanRun (`scan_run` or `exceptions_evaluation`) in one group is refused with exit status 2
and no report, unless the caller sets `allow_repeated_scans` (`--allow-repeated-scans`). The group key is the host
key, benchmark, content version and profile. With the flag, the runs are merged rule by rule, worst outcome first, and
the group's note has `repeated_profile: true`.

- **Other profiles.** A run of another profile is a different group (see above), so it can neither be refused as a
  repeat nor change the other group's figure.
- **Completed runs only.** A failed or timed-out run cannot raise a figure: the group becomes `not_completed` and has
  no percentage.
- **XCCDF and ARF are not refused.** Their host names are self-asserted by construction, and several files per host
  and profile are common (for example a scan repeated by hand). They are always noted. Signed evidence (ADR 0018) is
  the long-term answer for every input type.

Rejected alternatives:

- keeping the newest run only: `started_at` is self-asserted, so a forgery would simply claim to be newer;
- turning repeated runs into an input `error`: the merge is a contradiction between inputs, like a contradicted
  scope, not a defect of one file.

### XCCDF target and fqdn fact (FREES-130)

An XCCDF or ARF TestResult is an input `error` when its `target` elements and fqdn facts
(`urn:xccdf:fact:asset:identifier:fqdn`) do not all name the same host, compared lower-cased. In 1.0 the fact
silently won.

### The `exceptions` section (FREES-132)

- **Input.** Exceptions evaluation documents (`--exceptions-evaluation`, one per scan run) are the output of the
  `apply_exceptions` filter. They are accepted only together with the exceptions file they were made from
  (`--exceptions-file`). The CLI refuses with exit status 2:
  - evaluations without the file;
  - the file without evaluations;
  - a file that cannot be read.
- **Verification.** Each evaluation is checked with `exceptions.verify_evaluation` (ADR 0013, amendment of
  FREES-132):
  - The SHA-256 of the file must be the evaluation's `source_sha256`. The Ansible file lookup strips trailing
    whitespace, so the file as read and the file without trailing whitespace are both tried.
  - The file must be valid.
  - The evaluation's scan run is evaluated again with that file and with the target, controller time and lag limit
    the document records. The result must equal the document.

  An evaluation that fails is an input `error` in both the compliance and the exceptions section; this includes an
  evaluation made from another, unreviewed exceptions file. The inventory host must satisfy the exceptions host
  pattern.
- **Compliance input.** The scan run of an evaluation is a compliance input like a ScanRun JSON file. A rule whose
  chosen exception lapsed between the scan start and the controller time counts in `expired_waivers`, because the
  finding carries no exception data (ADR 0013). The rule IDs are listed in the item's `lapsed_waivers`. The outcome
  stays `fail`.
- **Section content.** `sections.exceptions` follows the standard section coupling. When it is available:
  - `exceptions_file` holds `{path, sha256, verified: true}`;
  - `exceptions` lists every exception of the file once (at most 1000) with these fields:
    - `id`, `rule_id`, `framework`, `risk`
    - `owner`, `approver`, `approval_date`, `created`, `expires`, `expires_at`
    - `justification`
    - a structured `scope` with hosts, groups, profiles and benchmark. All of it comes from the reviewed file, and
      each value is pattern-checked; the benchmark version is a version token.
    - `host_statuses`: the count per evaluation status
    - `matched_hosts`: one entry per evaluation in which the scope matched, with the inventory host, benchmark,
      content version, profile, run, status, `superseded_by` and input SHA-256
    - `lapsed`, `removal_candidate`, `source_sha256` and the review `status`
- **Review status.** It is one of `in_effect`, `expired`, `not_yet_effective`, `superseded`, `not_failing` or
  `stale`. The first evaluation status in this order decides: `expired`, `waived`, `not_yet_effective`,
  `superseded`, `not_failing`. An exception that is `unmatched` everywhere is `stale`.
- **Removal candidates.** `removal_candidate` is true exactly for `stale`, `superseded` and `not_failing`. Such an
  exception, on every evaluated host, waived nothing, covered no failure that expired, and covered no failure
  scanned before its approval. Superseded on every host is therefore a removal candidate. The schema ties
  `removal_candidate` to the status, and `matched_hosts` to `stale`.
- **Matched hosts.** They are the controller's inventory names, never the host names that scan runs report.
- **Several evaluations.** Two evaluations that both verify against the file but record different digests (one made
  with the trailing whitespace, one without) are a contradiction and are refused with exit status 2.
- **Summary.** `summary` and `overview.exceptions` hold the counts per review status, `removal_candidates`, `lapsed`
  (expiry passed at an evaluation time), `evaluations`, `total` and `source_sha256`. They are `null` unless the
  section is available. No compliance figure reads them.
- **Raw artifacts.** Evaluations appear once in `raw_artifacts` (format `exceptions_evaluation`), although they are
  items of two sections. The exceptions file appears once (format `exceptions_file`). `raw_artifacts` is bounded by
  9001.
- **Residual.** Waived findings carried directly in a ScanRun JSON (`--scan-run`) have no exceptions file to check
  against. They are shown as the scan run records them. This predates schema 2.0 and is covered by ADR 0018.
