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
combines benchmarks or versions, and no percentage appears without its denominator.

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
stay separate. A host key is a structured object (lower-cased host name, machine ID, or the content hash of an input that names no
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

The report schema is now `tools/reporting/schema/report-v2.json` with `schema_version` `"2.0"`. The figures and the
summary semantics above are unchanged; what changes is how merges are recorded, how a repeated scan is treated, and a
new `exceptions` section. The 1.0 schema file is removed from the tree; it stays in the Git history at the commit
before this amendment.

### Why a major version

Version 1.0 readers cannot read 2.0 documents, so the major version is bumped and the schema file is renamed:

- The meaning and shape of `sections.compliance.notes` changed. The 1.0 note `shared_self_asserted_host` (one note per
  host name across benchmarks, with a bare `host` string) no longer exists. Its replacements are structured per group.
- `sections` has a tenth section, `exceptions`, and `overview` a required key, `exceptions`. Both schemas reject
  unknown keys, so this alone is a breaking change for a strict 1.0 reader.
- Compliance items have a new format and kind, `exceptions_evaluation`, and compliance data a required
  `lapsed_waivers` list.

### Compatibility with 1.0

Everything else is unchanged and keeps its 1.0 meaning: `metadata`, `scope`, the status coupling of every section,
items, gaps, `raw_artifacts`, `rules`, `groups`, `aggregates`, every compliance summary and the counting rules. A
consumer migrates by:

1. accepting `schema_version` `"2.0"` and `exceptions` in the section lists of `overview`;
2. reading `notes` by `kind` (`merged_inputs`, `same_host_across_groups`) instead of `shared_self_asserted_host`;
3. treating `exceptions_evaluation` as a ScanRun input in the compliance section (its data embeds the scan run like
   `scan_run`);
4. ignoring `sections.exceptions` and `overview.exceptions` if it does not need waivers; they never change a figure.

A 1.0 document is not converted. Reports are rebuilt from their inputs, which are unchanged; the only inputs that now
behave differently are an XCCDF file whose names disagree (now an error) and repeated scan runs (now refused unless
allowed), both described below. The dashboard reads 2.0 only.

### Notes per group (FREES-130)

- Every group (benchmark, content version, host) built from more than one input gets one note
  `{"kind": "merged_inputs", "group": {benchmark_id, content_version, host}, "sources": [sha256, ...],
  "repeated_profile": bool}`, whatever the input types, so two ScanRuns that share `hostname` and `machine_id` are
  noted like two XCCDF files that claim one name. `repeated_profile` is true when two completed inputs of the group
  report the same profile.
- Every host key with inputs in more than one group gets one host-level note
  `{"kind": "same_host_across_groups", "host": {...}, "groups": [{benchmark_id, content_version}, ...],
  "sources": [...]}`. Those inputs are counted as one host (scope checks, `host_count`), but their figures stay
  separate; the note never claims that a group combines anything.
- Notes carry only validated identifiers and digests. At most one note of each kind exists per group or host, so the
  1000-entry bound of `notes` holds: each input is in at most one note of each kind and each note has at least two.

### Repeated scan runs are refused by default (FREES-130)

More than one **completed** ScanRun (`scan_run` or `exceptions_evaluation`) for the same host key, benchmark, content
version and **profile** is refused (exit status 2, no report), unless the caller sets `allow_repeated_scans`
(`--allow-repeated-scans`). With the flag the runs are merged rule by rule, worst outcome first, as before, and the
group's note has `repeated_profile: true`.

- The profile is part of the key because the CIS and STIG profiles of a ComplianceAsCode distribution share one
  benchmark identifier (ADR 0013), and two runs of different profiles on one host are the deduplication case that the
  model is built for. They are merged and noted, not refused.
- Only completed runs count. A failed or timed-out run cannot raise a figure: the group becomes `not_completed` and has
  no percentage.
- XCCDF and ARF files are not refused: their host names are self-asserted by construction, and several files per host
  are common (one per profile run, or a scan repeated by hand). They are always noted. Signed evidence (ADR 0018) is the
  long-term answer for every input type.

Rejected alternatives: refusing per host and benchmark version without the profile (it refuses the CIS-plus-STIG case),
keeping the newest run only (`started_at` is self-asserted, so a forgery would simply claim to be newer), and turning
repeated runs into an input `error` (the merge is a contradiction between inputs, like a contradicted scope, not a
defect of one file).

### XCCDF target and fqdn fact (FREES-130)

An XCCDF or ARF TestResult whose `target` elements and fqdn facts (`urn:xccdf:fact:asset:identifier:fqdn`) do not all
name the same host (compared lower-cased) is an input `error`. In 1.0 the fact silently won.

### The `exceptions` section (FREES-132)

- Input: exceptions evaluation documents (`--exceptions-evaluation`), the output of the `apply_exceptions` filter,
  one per scan run. Each document is verified with `exceptions.load_evaluation` (ADR 0013, amendment of FREES-132): it
  is evaluated again from its own scan run, exceptions, target and times and accepted only when the result is
  identical. A document that fails is an input `error` in both the compliance and the exceptions section. The
  inventory host of the evaluation must satisfy the exceptions host pattern.
- The scan run of an evaluation is a compliance input like a ScanRun JSON file. A rule whose chosen exception lapsed
  between the scan start and the controller time counts in `expired_waivers` (the finding carries no exception data,
  ADR 0013); the rule IDs are listed in the item's `lapsed_waivers`. The outcome stays `fail`, so no percentage changes.
- `sections.exceptions` follows the standard section coupling. When it is available it lists every exception of the
  exceptions file once (`exceptions`, at most 1000), with `id`, `rule_id`, `framework`, `risk`, `owner`, `approver`,
  `approval_date`, `created`, `expires`, `expires_at`, `justification`, a structured `scope` (hosts, groups, profiles,
  benchmark; all from the reviewed file and pattern-checked), `host_statuses` (count per evaluation status),
  `matched_hosts` (one entry per evaluation in which the scope matched: inventory host, benchmark, content version,
  profile, run, status, `superseded_by`, input SHA-256), `lapsed`, `removal_candidate`, `source_sha256` and the review
  `status`.
- The review `status` is `in_effect`, `expired`, `not_yet_effective`, `superseded`, `not_failing` or `stale`, decided
  by the first evaluation status in the order `expired`, `waived`, `not_yet_effective`, `superseded`, `not_failing`;
  an exception `unmatched` everywhere is `stale`. `removal_candidate` is true exactly for `stale`, `superseded` and
  `not_failing`: the exception waived nothing, covered no failure that expired and none scanned before its approval,
  on any evaluated host. Superseded on every host is therefore a removal candidate. The schema ties
  `removal_candidate` to the status and `matched_hosts` to `stale`.
- Matched hosts are the controller's inventory names, never the host names that scan runs report.
- Evaluations of different exceptions files (different `source_sha256` or different records) in one report are a
  contradiction and are refused (exit status 2).
- `summary` and `overview.exceptions` hold the counts per review status, `removal_candidates`, `lapsed` (expiry passed
  at an evaluation time), `evaluations`, `total` and `source_sha256`; they are `null` unless the section is available.
  No compliance figure reads them.
- Evaluations appear once in `raw_artifacts` (format `exceptions_evaluation`) although they are items of two
  sections, so `raw_artifacts` stays bounded by 9000.
