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
validates against `tools/reporting/schema/report-v1.json` (JSON Schema 2020-12). `schema_version` is `"1.0"`.
The document has `metadata`, one `scope`, nine `sections`, an `overview` and `raw_artifacts`.

Every section has a `status` of `available`, `unavailable` or `error`:

- `unavailable` means there was no input, or an input file does not exist.
- `error` means an input exists but is empty, oversized, not a regular file, malformed, truncated, unsafe or
  unexpected (unknown root, unknown format version, inconsistent counts).
- `available` means every input of the section parsed.

A section takes the worst state of its inputs (`error`, then `unavailable`, then `available`). A section that is not
`available` has a `reason`, no `summary`, and its good items stay visible beside the bad ones. Nothing defaults to a
pass; the schema enforces the coupling between status, reason, data and summary.

### The scope is part of the document

`scope` is one of `single_host`, `multi_host`, `benchmark` or `fleet` and applies to every statistic in the
document. A document has exactly one scope, so no figure combines scopes or benchmark versions, and no percentage
appears without its denominator.

### Summary semantics

These rules come from the FREES-75 acceptance comment and are implemented in `tools/reporting/compliance.py`.

1. Only `pass` counts as pass. `notchecked`, `error`, `notapplicable`, `disabled` and `waived` never do.
2. The denominator (`evaluated`) is every outcome except `notapplicable` and `disabled`. Those two are counted and
   shown separately.
3. `compliance_percent` is `pass` divided by `evaluated`, rounded half up to two decimals. `notchecked`, `error`
   and `waived` stay in the denominator, so they lower the percentage, and every outcome count is present in the
   summary.
4. A scan run that did not complete (`failed` or `timed_out`) is never summarised as compliant. The run status is
   reported first (`run_status`), `compliance_percent` is `null` and `assessment` is `run_not_completed`. For several
   runs the status is `not_completed` as soon as one run did not complete.
5. `assessment` is never a compliance claim: `run_not_completed`, `nothing_evaluated`, `all_evaluated_passed` or
   `findings_open`. A report never states compliance with a framework (AGENTS.md rule 9).
6. A waived finding is its own count. An expired exception does not change the outcome (ADR 0013 already reports it
   as `fail`); `expired_waivers` counts those findings so that the expiry stays visible.
7. `open_by_severity` counts `fail`, `error` and `notchecked` rules per severity.

### Deduplication across frameworks

Rules are deduplicated by full rule ID within the same host and content version (ADR 0013: the rule is counted
once however many frameworks reference it). The worst outcome wins (`error`, `fail`, `notchecked`, `waived`,
`pass`, `notapplicable`, `disabled`), the highest severity is kept and every originating artifact, benchmark and
profile is listed in `sources`. Different content versions and different hosts stay separate. XCCDF and ARF files
carry no host identity, so each file is its own host key and two files are never merged.

### Determinism and input-supplied times

The document is deterministic: sorted keys, stable ordering of every list, ASCII output. Equal inputs give
byte-identical output. Timestamps (`started_at`, `finished_at`, `generated_at`) are validated input and are
`null` when not supplied; the package never reads the clock.

### Parsing rules

Report files are attacker-controlled. Every parser bounds the file size (64 MiB by default), reads regular files only
(no symlinks), rejects DOCTYPE, entity and external-reference constructs in XML through defusedxml, bounds XML depth
and element count while parsing, rejects duplicate JSON keys and non-finite numbers, bounds the depth of JSON,
strips control and formatting characters from text and caps free text and detail lists. Unknown versions of a format
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

- A section with one missing file among several is `unavailable` as a whole, so consumers see less aggregate data
  than they could; the per-item data remains.
- XCCDF and ARF do not identify a host, so multi-host reports from them list each file separately; ScanRun JSON
  carries the host and deduplicates by it.
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
