# Reporting data model

The reporting package `tools/reporting/` turns heterogeneous reports into one versioned JSON document. The decision
record is [ADR 0016](adr/0016-report-schema-and-summary-semantics.md); the findings model is
[ADR 0013](adr/0013-normalized-findings-model.md). The schema is
`tools/reporting/schema/report-v1.json` (JSON Schema 2020-12, `schema_version` `"1.0"`).

## Running it

```bash
make report REPORT_SCOPE=single_host REPORT_ARGS='--scan-run run.json --junit junit.xml'
python -m tools.reporting --scope fleet --output build/report/report.json --xccdf results.xml
```

`make report` writes `build/report/report.json` (`REPORT_OUTPUT` overrides it) and states that the HTML dashboard is
pending FREES-77. `--scope` and `--output` are required. Every input option can be repeated.

| Option | Format |
|---|---|
| `--scan-run` | ScanRun JSON written by the findings model |
| `--xccdf`, `--arf` | OpenSCAP XCCDF 1.2 results, ARF 1.1 |
| `--junit`, `--pytest-json` | JUnit XML, pytest JSON |
| `--cobertura` | Cobertura coverage XML |
| `--lint` | ansible-lint SARIF 2.1.0 or JSON |
| `--grype` | Grype JSON |
| `--sbom` | SPDX 2.x JSON, CycloneDX 1.x JSON |
| `--packer` | Packer `manifest.json` |
| `--codebuild` | `aws codebuild batch-get-builds` JSON |
| `--molecule` | Molecule results summary (below) |

Metadata options are `--commit`, `--pull-request`, `--workflow-run`, `--started-at`, `--finished-at` and
`--generated-at`. They are validated and written as given; timestamps use `YYYY-MM-DDTHH:MM:SSZ`. Nothing is read
from the clock, so a value that is not supplied is `null`. `--max-bytes` changes the size limit (default 64 MiB).

Exit status:

- 0: the report was written and every supplied input parsed. A section without any input is `unavailable`; that is
  not an error, and it is never shown as passed.
- 1: the report was written, but a supplied input is missing or invalid (a section is `partial` or `error`).
- 2: invalid arguments or metadata, a scope that the data contradicts (below), or an output that cannot be written.
  No report is written for a contradicted scope.

At most 1000 input files per section are accepted.

## Document outline

| Key | Content |
|---|---|
| `schema_version` | `"1.0"` |
| `scope` | `single_host`, `multi_host`, `benchmark` or `fleet`; applies to every statistic |
| `metadata` | `commit`, `pull_request`, `workflow_run`, `started_at`, `finished_at`, `generated_at`; all nullable |
| `sections` | `codebuild`, `compliance`, `coverage`, `lint`, `molecule`, `packer`, `sbom`, `tests`, `vulnerabilities` |
| `overview` | Section names grouped by `available`, `partial`, `unavailable` and `error` |
| `raw_artifacts` | One reference per input: `format`, `path` as supplied, `sha256`, `size`, `status` |

Each section has `status`, `reason`, `items`, `gaps` and `summary`; `compliance` also has `rules`, `groups` and
`aggregates` and `notes`. Each item has `format`, `status`, `reason`, `artifact` (`path`, `sha256`, `size`) and `data`. `gaps`
lists every item that is not `available` with its path, status and reason.

| Section | Item formats | Summary |
|---|---|---|
| `compliance` | `scan_run`, `xccdf`, `arf` | Compliance summary (below) |
| `tests` | `junit`, `pytest_json` | `total`, `passed`, `failed`, `errors`, `skipped` |
| `coverage` | `cobertura` | none |
| `lint` | `ansible_lint` | `total`, `by_severity` |
| `vulnerabilities` | `grype` | `total`, `by_severity` |
| `sbom` | `sbom` | none |
| `packer` | `packer_manifest` | none |
| `codebuild` | `codebuild` | `total`, `succeeded`, `failed` (FAILED, FAULT, TIMED_OUT, STOPPED), `in_progress` |
| `molecule` | `molecule_summary` | `total`, `passed`, `failed`, `skipped`, `error` |

### Status rules

- An item is `unavailable` when its file does not exist, and `error` for every other problem.
- A section is `unavailable` when it has no items or every item is missing. It is `error` when any item is `error`.
  It is `partial` when some items are available and the rest are missing. It is `available` only when every item is.
- When a section is not `available` its `summary` is `null` and `rules`, `groups` and `aggregates` are empty. Its
  `reason` is a string and `gaps` lists the missing or invalid inputs. Available items keep their `data`.
- Limits of the schema: JSON Schema 2020-12 cannot compare counts or sum values, so a forged document with
  `all_evaluated_passed` next to non-zero `fail` counts, or a section `summary` next to groups of two versions, still
  validates; the producer never writes them. A test walks the whole schema and compares every `maxItems`, `maxProperties`, `maxLength` and `pattern` with
  a Python constant by its full path; a limit without a mapping fails the test. The timestamp pattern accepts only
  years from 0001, valid months, days (29 February in any year) and times.
- The schema enforces these couplings (status against items, gaps, reason, summary, overview, and an available item
  having a checksum and size), so a consumer can rely on them. Every array has a `maxItems`.

## Compliance summary

Figures are never pooled across benchmarks or content versions. The compliance section has:

- `groups`: one figure per (benchmark, content version, host).
- `aggregates`: for scopes other than `single_host`, one pooled figure per (benchmark, content version), with
  `host_count` and the report `scope` as its label. It pools hosts of the same benchmark and version only.
- `summary`: the pooled figure when exactly one benchmark and content version is present, otherwise `null`.
- Each item also carries the summary of its own file.

The declared `scope` is checked against the data. `single_host` with inputs from more than one host, or `benchmark`
with more than one benchmark or content version, is rejected (exit 2). The schema also bounds `aggregates` (none for
`single_host`, at most one for `benchmark`).

A host name taken from a file must satisfy the ScanRun host rule (letters, digits and `._:+-`, starting with a letter or
digit, at most 253 characters), otherwise the file is an error. The schema applies the same pattern wherever a host
appears. A file that names no host is keyed `unnamed:<hash of its path>`. A host is identified by `host.hostname` (plus `machine_id` when present) for ScanRun JSON, and by the self-asserted
name in the file for XCCDF (`target` or the fqdn fact) and ARF (asset fqdn and hostname, which must match the
TestResult target, otherwise the file is an error). A file that names no host is its own host, keyed by its path. Names
are lower-cased, and files are grouped only when the names are equal; differing identities are never merged. Input
files with the same SHA-256 count once. When several input files claim the same self-asserted host, they are
merged and `notes` records it as a structured entry, `{"kind": "shared_self_asserted_host", "host": ..., "sources": [sha256, ...]}`;
consumers build the wording, so no input text becomes prose.

| Field | Meaning |
|---|---|
| `run_status` | `completed`, `failed`, `timed_out`, or `not_completed` when several runs include one that did not complete. Read it first. |
| `assessment` | `run_not_completed`, `nothing_evaluated`, `all_evaluated_passed` or `findings_open`; never a compliance claim |
| `compliance_percent` | `pass` divided by `evaluated`, rounded down to one decimal (99999 of 100000 is 99.9); 100.0 only when everything evaluated passed; `null` when the run did not complete or `evaluated` is 0 |
| `evaluated` | The denominator: all outcomes except `notapplicable` and `disabled` |
| `counts` | Number of rules for each of `pass`, `fail`, `waived`, `notchecked`, `error`, `notapplicable`, `disabled` |
| `not_selected` | XCCDF and ARF results that the profile did not select. Informational; never in the maths |
| `expired_waivers` | Rules whose exception expired; they count as their evaluated outcome |
| `open_by_severity` | `fail`, `error` and `notchecked` rules per severity |
| `runs_total`, `runs_not_completed` | How many runs were summarised and how many did not complete |

Rules:

- Only `pass` counts as pass. `notchecked`, `error`, `notapplicable`, `disabled` and `waived` never do.
- `notchecked`, `error` and `waived` are in the denominator, so they lower the percentage and are always counted.
- `notapplicable` and `disabled` are shown separately and not in the denominator.
- `notselected` results of XCCDF and ARF files (`oscap` lists every rule of the benchmark) are dropped from the
  findings and only counted in `not_selected`. For a ScanRun JSON, which knows its expected rules, the backend
  semantics of ADR 0013 apply: a `notselected` result for an expected rule is `notchecked` and counts.
- All `error` gives 0.0 percent. All `notapplicable` gives `nothing_evaluated` and no percentage.
- A run that did not complete is never compliant: the percentage is `null` and the assessment is
  `run_not_completed`, whatever its findings say.

- The JSON schema ties these together: a run that is not `completed` has no percentage and the assessment
  `run_not_completed`, `evaluated` 0 has no percentage, 100 means `all_evaluated_passed` and the reverse.

Example: 2 pass, 1 fail, 1 notchecked, 1 error, 1 waived, 1 notapplicable and 1 disabled give `evaluated` 6 and
33.3 percent. Every `fixed` XCCDF result is `pass` and every `informational` result is `notchecked` (ADR 0013).
A profile that selects 10 rules, all passing, among 90 `notselected` rules gives 100.0 percent with `not_selected` 90.

### Deduplication and sources

`rules` has one entry per rule ID, host and content version, with the worst `outcome`, the highest `severity`,
`expired_waiver` (of the sources that have the worst outcome) and every contributing `sources` entry (`artifact`,
`benchmark_id`, `profile_id`, `outcome`, `expired_waiver`), so the outcome of each file stays visible. Two runs of
one host with the same benchmark and version are merged, worst outcome first.

## Parsers and their limits

Common behaviour of every parser:

- The file must be a regular file at most `--max-bytes` long (64 MiB by default). It is opened component by component
  with `O_NOFOLLOW` and `O_NONBLOCK`, so a symlink in the path (including a parent directory) or a FIFO is rejected and
  there is no gap between the check and the read. The read itself is bounded.
- Missing is `unavailable`; empty, oversized, malformed, truncated, wrongly encoded or unexpected is `error`.
- XML goes through defusedxml with DTDs, entities and external references forbidden; nesting is limited to 100 and
  the element count to 1,000,000 while parsing. JSON is UTF-8 only, rejects duplicate keys, `NaN`, `Infinity` and
  numbers that overflow to infinity (`1e999`), and deep nesting.
- A tool that reports its own failure is an `error`, never a clean result (see the notes for pytest, ansible-lint,
  JUnit and CodeBuild below).
- Text is cleaned of control and formatting characters (bidi overrides included) and cut to 512 characters.
  Detail lists are capped at 1000 entries with a `truncated` flag; totals are never capped.
- The artifact reference keeps the path as supplied and the SHA-256 of the bytes that were parsed.

| Format | Module | Notes and limitations |
|---|---|---|
| XCCDF 1.2 results | `parsers/xccdf.py` | Reuses `openscap.parse_results` of the findings model (more than 100000 selected rule results is an error): result mapping through `map_xccdf_result`, unknown values become `error`, exactly one TestResult. `notselected` results are counted in `not_selected`, not in the findings. `host` is `null`; `reported_host` is the self-asserted `target` or fqdn fact. |
| ARF 1.1 | `parsers/xccdf.py` | Bounds and parses with defusedxml, then requires exactly one embedded XCCDF 1.2 TestResult and hands it to the same parser. The asset fqdn and hostname must agree with the target and fact names. Other report contents are ignored. |
| ScanRun JSON | `parsers/scanrun.py` | `model.loads`; the validated run is embedded unchanged and `findings` is empty in the item to avoid duplication. |
| JUnit XML | `parsers/junit.py` | Roots `testsuite` or `testsuites`. Totals come from `testcase` elements. The `tests`, `failures` and `errors` attributes of a `testsuite`, if present, must match its own test cases, otherwise the file is an error. `error` outranks `failure`; no test cases is an error. Durations are not read. |
| Cobertura | `parsers/cobertura.py` | Root `coverage`; `line-rate` and `branch-rate` must be numbers from 0 to 1 (also per package). Counts are optional, and `lines-covered` or `branches-covered` above its `-valid` count is an error. Per-class and per-line data are ignored. |
| pytest JSON | `parsers/pytest_json.py` | pytest-json-report layout. `exitcode` is required: 2, 3, 4 and 5 (interrupted, internal error, usage error, no tests) are errors, 0 must agree with zero failures and 1 with at least one. `summary.total` must equal the sum of the outcome counts. `xpassed` counts as failed, `xfailed` as skipped. |
| ansible-lint | `parsers/lint.py` | SARIF 2.1.0 (levels map to severities: error high, warning medium, note low, none info) or JSON/code-climate (blocker and critical map to critical, major high, minor medium, info info; others unknown). The SARIF driver must be `ansible-lint`; `executionSuccessful: false` or a `toolExecutionNotifications` entry at level `error` makes the file an error. The JSON format carries no tool name. A clean run with zero issues is `available`. |
| Grype | `parsers/grype.py` | `descriptor.name` must be `grype`. Severities: Negligible is `info`, unlisted values are `unknown`. The severity is the highest of the match and its `relatedVulnerabilities`. Matches are deduplicated by vulnerability, package and version, keeping the highest severity. The database date is read from `descriptor.db.status.built` or `descriptor.db.built`, else `null`. Ignored matches are not read. |
| SPDX and CycloneDX | `parsers/sbom.py` | SPDX-2.2 and SPDX-2.3 JSON (not SPDX 3, not tag-value; the document must be `SPDXRef-DOCUMENT` with a namespace and every package an `SPDXID`) and CycloneDX 1.4 to 1.6 JSON (every component a `type`). Other versions are errors. Only top-level packages or components are read. A licence is the first asserted of `licenseConcluded` and `licenseDeclared`, or the first CycloneDX licence id, name or expression. An SBOM with no components, or more than 10000 distinct licences, is an error. |
| Packer manifest | `parsers/packer.py` | Requires at least one build with `name`, `builder_type` and `artifact_id`. `build_time` (epoch seconds from the file) is written in UTC and must be valid if present. `in_last_run` marks the builds of `last_run_uuid`. `custom_data` keys and values must be non-empty strings of at most 512 characters (longer is an error, never cut), at most 1000 keys. At most 10000 builds and 1000 files. |
| CodeBuild | `parsers/codebuild.py` | `batch-get-builds` output. `buildStatus` must be a known CodeBuild status. Any entry in `buildsNotFound` makes the file an error, because a requested build is missing. The section summary counts succeeded, failed and in-progress builds, so a failed build is never shown as clean. Times are numbers (epoch seconds, written in UTC) or strings as supplied. |
| Molecule summary | `parsers/molecule.py` | The project-defined format below. |

### Molecule results summary format

```json
{
  "format": "freesecdev-molecule-summary",
  "version": 1,
  "scenarios": [{ "name": "default", "platform": "debian-12", "result": "passed" }]
}
```

`result` is `passed`, `failed`, `skipped` or `error`. A `(name, platform)` pair may appear once and at least one
scenario is required. Any other `format` or `version` is an error.

## Schema version notes

- 1.0: first version (FREES-75), including the `partial` section status, `groups`, `aggregates` and `gaps`. A change that adds a field bumps the minor version; a breaking change bumps the major
  version, and `report-v<major>.json` is a new file. The version, this page and ADR 0016 change together.
