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

Exit status: 0 when the report was written and no section is `error`, 1 when it was written and at least one
section is `error`, 2 for invalid arguments or metadata or an unwritable output.

## Document outline

| Key | Content |
|---|---|
| `schema_version` | `"1.0"` |
| `scope` | `single_host`, `multi_host`, `benchmark` or `fleet`; applies to every statistic |
| `metadata` | `commit`, `pull_request`, `workflow_run`, `started_at`, `finished_at`, `generated_at`; all nullable |
| `sections` | `codebuild`, `compliance`, `coverage`, `lint`, `molecule`, `packer`, `sbom`, `tests`, `vulnerabilities` |
| `overview` | Section names grouped by `available`, `unavailable` and `error` |
| `raw_artifacts` | One reference per input: `format`, `path` as supplied, `sha256`, `size`, `status` |

Each section has `status`, `reason`, `items` and `summary`; `compliance` also has `rules`. Each item has `format`,
`status`, `reason`, `artifact` (`path`, `sha256`, `size`) and `data`.

| Section | Item formats | Summary |
|---|---|---|
| `compliance` | `scan_run`, `xccdf`, `arf` | Compliance summary (below) |
| `tests` | `junit`, `pytest_json` | `total`, `passed`, `failed`, `errors`, `skipped` |
| `coverage` | `cobertura` | none |
| `lint` | `ansible_lint` | `total`, `by_severity` |
| `vulnerabilities` | `grype` | `total`, `by_severity` |
| `sbom` | `sbom` | none |
| `packer` | `packer_manifest` | none |
| `codebuild` | `codebuild` | none |
| `molecule` | `molecule_summary` | `total`, `passed`, `failed`, `skipped`, `error` |

### Status rules

- An item is `unavailable` when its file does not exist, and `error` for every other problem.
- A section is `unavailable` when it has no items, otherwise it has the worst status of its items.
- When a section is not `available` its `summary` is `null`, its `reason` is a string, and the available items keep
  their `data`.
- The schema enforces these couplings, so a consumer can rely on them.

## Compliance summary

`sections.compliance.summary` is computed from the deduplicated `rules`; every item carries the same summary for
its own run.

| Field | Meaning |
|---|---|
| `run_status` | `completed`, `failed`, `timed_out`, or `not_completed` when several runs include one that did not complete. Read it first. |
| `assessment` | `run_not_completed`, `nothing_evaluated`, `all_evaluated_passed` or `findings_open`; never a compliance claim |
| `compliance_percent` | `pass` divided by `evaluated`, rounded half up to two decimals; `null` when the run did not complete or `evaluated` is 0 |
| `evaluated` | The denominator: all outcomes except `notapplicable` and `disabled` |
| `counts` | Number of rules for each of `pass`, `fail`, `waived`, `notchecked`, `error`, `notapplicable`, `disabled` |
| `expired_waivers` | Rules whose exception expired; they count as their evaluated outcome |
| `open_by_severity` | `fail`, `error` and `notchecked` rules per severity |
| `runs_total`, `runs_not_completed` | How many runs were summarised and how many did not complete |

Rules:

- Only `pass` counts as pass. `notchecked`, `error`, `notapplicable`, `disabled` and `waived` never do.
- `notchecked`, `error` and `waived` are in the denominator, so they lower the percentage and are always counted.
- `notapplicable` and `disabled` are shown separately and not in the denominator.
- All `error` gives 0.0 percent. All `notapplicable` gives `nothing_evaluated` and no percentage.
- A run that did not complete is never compliant: the percentage is `null` and the assessment is
  `run_not_completed`, whatever its findings say.

Example: 2 pass, 1 fail, 1 notchecked, 1 error, 1 waived, 1 notapplicable and 1 disabled give `evaluated` 6 and
33.33 percent. Every `fixed` XCCDF result is `pass` and every `informational` and `notselected` result is
`notchecked` (ADR 0013).

### Deduplication and sources

`rules` has one entry per rule ID, host and content version, with the worst `outcome`, the highest `severity`,
`expired_waiver` and every contributing `sources` entry (`artifact`, `benchmark_id`, `profile_id`). XCCDF and ARF
carry no host identity, so the artifact path is their host key and files are never merged.

## Parsers and their limits

Common behaviour of every parser:

- The file must be a regular file (symlinks are rejected) and at most `--max-bytes` long (64 MiB by default); the
  read itself is bounded.
- Missing is `unavailable`; empty, oversized, malformed, truncated, wrongly encoded or unexpected is `error`.
- XML goes through defusedxml with DTDs, entities and external references forbidden; nesting is limited to 100 and
  the element count to 1,000,000 while parsing. JSON is UTF-8 only, rejects duplicate keys, `NaN` and `Infinity`,
  and deep nesting.
- Text is cleaned of control and formatting characters (bidi overrides included) and cut to 512 characters.
  Detail lists are capped at 1000 entries with a `truncated` flag; totals are never capped.
- The artifact reference keeps the path as supplied and the SHA-256 of the bytes that were parsed.

| Format | Module | Notes and limitations |
|---|---|---|
| XCCDF 1.2 results | `parsers/xccdf.py` | Reuses `openscap.parse_results` of the findings model: result mapping through `map_xccdf_result`, unknown values become `error`, exactly one TestResult. No host identity, so `host` is `null`. |
| ARF 1.1 | `parsers/xccdf.py` | Bounds and parses with defusedxml, then requires exactly one embedded XCCDF 1.2 TestResult and hands it to the same parser. Other report contents (assets, datastream) are ignored. |
| ScanRun JSON | `parsers/scanrun.py` | `model.loads`; the validated run is embedded unchanged and `findings` is empty in the item to avoid duplication. |
| JUnit XML | `parsers/junit.py` | Roots `testsuite` or `testsuites`. Totals come from `testcase` elements, never from `tests=` attributes. `error` outranks `failure`; no test cases is an error. Durations are not read. |
| Cobertura | `parsers/cobertura.py` | Root `coverage`; `line-rate` and `branch-rate` must be numbers from 0 to 1 (also per package). Counts are optional. Per-class and per-line data are ignored. |
| pytest JSON | `parsers/pytest_json.py` | pytest-json-report layout. `summary.total` must equal the sum of the outcome counts. `xpassed` counts as failed, `xfailed` as skipped. |
| ansible-lint | `parsers/lint.py` | SARIF 2.1.0 (levels map to severities: error high, warning medium, note low, none info) or JSON/code-climate (blocker and critical map to critical, major high, minor medium, info info; others unknown). A clean run with zero issues is `available`. |
| Grype | `parsers/grype.py` | `descriptor.name` must be `grype`. Severities: Negligible is `info`, unlisted values are `unknown`. Matches are deduplicated by vulnerability, package and version; the first occurrence wins. The database date is read from `descriptor.db.status.built` or `descriptor.db.built`, else `null`. Ignored matches are not read. |
| SPDX and CycloneDX | `parsers/sbom.py` | SPDX 2.x JSON (not SPDX 3, not tag-value) and CycloneDX 1.x JSON. Only top-level packages or components are read. A licence is the first asserted of `licenseConcluded` and `licenseDeclared`, or the first CycloneDX licence id, name or expression. An SBOM with no components is an error. |
| Packer manifest | `parsers/packer.py` | Requires at least one build with `name`, `builder_type` and `artifact_id`. `build_time` (epoch seconds from the file) is written in UTC. `custom_data` values must be strings. |
| CodeBuild | `parsers/codebuild.py` | `batch-get-builds` output. `buildStatus` must be a known CodeBuild status. Any entry in `buildsNotFound` makes the file an error, because a requested build is missing. Times are numbers (epoch seconds, written in UTC) or strings as supplied. |
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

- 1.0: first version (FREES-75). A change that adds a field bumps the minor version; a breaking change bumps the major
  version, and `report-v<major>.json` is a new file. The version, this page and ADR 0016 change together.
