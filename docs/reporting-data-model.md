# Reporting data model

The reporting package `tools/reporting/` turns heterogeneous reports into one versioned JSON document. The decision
record is [ADR 0016](adr/0016-report-schema-and-summary-semantics.md); the findings model is
[ADR 0013](adr/0013-normalized-findings-model.md). The schema is
`tools/reporting/schema/report-v2.json` (JSON Schema 2020-12, `schema_version` `"2.1"`); see
[schema version notes](#schema-version-notes) for what changed from 1.0 and 2.0.

## Running it

```bash
make report REPORT_SCOPE=single_host REPORT_ARGS='--scan-run run.json --junit junit.xml'
python -m tools.reporting --scope fleet --output build/report/report.json --html build/report/report.html \
  --xccdf results.xml
```

`make report` writes `build/report/report.json` and the HTML dashboard `build/report/report.html` (`REPORT_OUTPUT`
and `REPORT_HTML` override them). `--scope` and `--output` are required; `--html` is optional and writes the
[dashboard](dashboard.md) of the same document. Every input option can be repeated.

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
| `--exceptions-evaluation` | Exceptions evaluation JSON written by the `apply_exceptions` filter, one per scan run ([exceptions](exceptions.md#reporting)); requires `--exceptions-file` |
| `--exceptions-file` | The reviewed exceptions file the evaluations were made from (one file, not repeatable); required with `--exceptions-evaluation` and with evidence bundles whose exceptions were applied |
| `--evidence-bundle` | An evidence bundle directory written by the `evidence` role ([evidence bundles](evidence.md#in-the-report)); verified, then read as its evaluation or, without exceptions, its raw scan run |
| `--evidence-collection` | The collection summary that `playbooks/evidence.yml` wrote next to the bundles ([collection summary](evidence.md#the-collection-summary)); one file, not repeatable. The report then accounts for every target host of the run ([host coverage](#host-coverage)) |

Metadata options are `--commit`, `--pull-request`, `--workflow-run`, `--started-at`, `--finished-at` and
`--generated-at`. They are validated and written as given; timestamps use `YYYY-MM-DDTHH:MM:SSZ`. Nothing is read
from the clock, so a value that is not supplied is `null`. `--max-bytes` changes the size limit (default 64 MiB).
`--allow-repeated-scans` merges several completed scan runs of one host, benchmark, content version and profile
instead of refusing them (see [Repeated scan runs](#repeated-scan-runs)).

Exit status:

- 0: the report was written and every supplied input parsed. A section without any input is `unavailable`; that is
  not an error, and it is never shown as passed.
- 1: the report was written, but a supplied input is missing or invalid (a section is `partial` or `error`). With
  `--evidence-collection`, a target host without a bundle in the report is a missing input, and a bundle that the
  summary does not list is an invalid one, so both give status 1.
- 2: invalid arguments or metadata, `--html` naming the same file as `--output`, a scope that the data contradicts
  (below), repeated scan runs without `--allow-repeated-scans`, `--exceptions-evaluation` or an evidence bundle with
  applied exceptions without `--exceptions-file`, `--exceptions-file` without any evaluation, an evidence bundle whose
  copy of the exceptions file is not byte-identical to `--exceptions-file`, an exceptions file that cannot be read,
  an evidence collection summary that cannot be read or is not valid, `--evidence-collection` together with
  `--scan-run`, `--xccdf`, `--arf` or `--exceptions-evaluation`, a collection summary of more than 1000 target hosts,
  or an output that cannot be written. No report is written in these cases.
- 3: the JSON report was written, but the dashboard was not, because the report is above the dashboard size cap
  (128 MiB embedded, see [ADR 0017](adr/0017-offline-html-dashboard.md)). A dashboard left at that path by an earlier
  run is removed. Status 3 takes precedence over 1; the sections of the JSON still show any missing or invalid input.

Both files are written atomically (a temporary file in the target directory, synced, then renamed over the target),
so a crash or a full disk never leaves a truncated file. They are created with mode 0600, because a report can hold
host evidence.

At most 1000 input files per section are accepted.

## Document outline

| Key | Content |
|---|---|
| `schema_version` | `"2.1"` |
| `scope` | `single_host`, `multi_host`, `benchmark` or `fleet`; applies to every statistic |
| `metadata` | `commit`, `pull_request`, `workflow_run`, `started_at`, `finished_at`, `generated_at`; all nullable |
| `sections` | `codebuild`, `compliance`, `coverage`, `exceptions`, `lint`, `molecule`, `packer`, `sbom`, `tests`, `vulnerabilities` |
| `overview` | Section names grouped by `available`, `partial`, `unavailable` and `error`, and `exceptions`: the exception counts of the [exceptions section](#exceptions-section) or `null` |
| `raw_artifacts` | One reference per input: `format`, `path` as supplied, `sha256`, `size`, `status`; the collection summary has the format `evidence_collection` |

Each section has `status`, `reason`, `items`, `gaps` and `summary`; `compliance` also has `rules`, `groups` and
`aggregates`, `notes` and `host_coverage`, and `exceptions` also has `exceptions` and `source_sha256`. Each item has `format`, `status`, `reason`, `artifact` (`path`, `sha256`, `size`) and `data`. `gaps`
lists every item that is not `available` with its path, status and reason.

| Section | Item formats | Summary |
|---|---|---|
| `compliance` | `scan_run`, `xccdf`, `arf`, `exceptions_evaluation` | Compliance summary (below) |
| `exceptions` | `exceptions_evaluation` | Exception counts ([exceptions section](#exceptions-section)) |
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

Figures are never pooled across benchmarks, content versions or profiles. In ComplianceAsCode the CIS and STIG
profiles of a distribution share one benchmark identifier, so the profile is part of every key; a host with a CIS and
a STIG run has two separate figures and no combined one. The compliance section has:

- `groups`: one figure per (benchmark, content version, profile, host).
- `aggregates`: for scopes other than `single_host`, one pooled figure per (benchmark, content version, profile),
  with `host_count` and the report `scope` as its label. It pools hosts of the same benchmark, version and profile
  only.
- `summary`: the pooled figure when exactly one benchmark, content version and profile is present, otherwise `null`.
- Each item also carries the summary of its own file.

The declared `scope` is checked against the data. `single_host` with inputs from more than one host, or `benchmark`
with more than one benchmark, content version or profile, is rejected (exit 2). The schema also bounds `aggregates` (none for
`single_host`, at most one for `benchmark`).

A host name taken from a file must satisfy the ScanRun host rule (letters, digits and `._:+-`, starting with a letter or
digit, at most 253 characters), otherwise the file is an error. The schema applies the same pattern wherever a host
appears. Host keys are structured objects, never joined text: `groups[].host` and `rules[].host` are
`{hostname, machine_id, input_sha256}` where a named host has `hostname` (lower-cased for ScanRun and XCCDF/ARF alike) and
`machine_id` (ScanRun only) and an input that names no host has only `input_sha256`, the SHA-256 of its content. An
unnamed input is never merged with anything, and a crafted name cannot take over another key. A host is identified by `host.hostname` (plus `machine_id` when present) for ScanRun JSON, and by the self-asserted
name in the file for XCCDF (`target` or the fqdn fact) and ARF (asset fqdn and hostname, which must match the
TestResult target, otherwise the file is an error). Names
are lower-cased, and files are grouped only when the names are equal; differing identities are never merged. An XCCDF
or ARF TestResult whose `target` and fqdn facts do not all name the same host is an input error. Input files with the
same SHA-256 count once.

### Merge notes

`notes` records, as structured entries without prose, every place where inputs were combined or counted as one host.
Consumers build the wording, so no input text becomes prose.

- `{"kind": "merged_inputs", "group": {"benchmark_id", "content_version", "profile_id", "host"},
  "sources": [sha256, ...], "repeated_profile": bool}`: one note for **every group built from more than one input**, whatever the input types.
  Two ScanRuns with the same `hostname` and `machine_id`, a ScanRun and an XCCDF file that name the same host, or two
  XCCDF files that claim one name all get it. `group` is the key of the group in `groups`, so a consumer attaches the
  note by key. `repeated_profile` is true when two or more inputs of the group completed: the same profile was
  scanned again.
- `{"kind": "same_host_across_groups", "host": {...}, "groups": [{"benchmark_id", "content_version",
  "profile_id"}, ...], "sources": [...]}`: one note for every host key with inputs in more than one group. These inputs count as one host
  (for the scope checks and `host_count`), but every group keeps its own figure and nothing is combined across them.

A group with a single input has no note. Each input is in at most one note of each kind.

### Repeated scan runs

More than one completed ScanRun (`--scan-run` or `--exceptions-evaluation`) for the same host key, benchmark,
content version and profile is refused with exit status 2. A machine ID is not a secret: a forged run with the identity
of a real host could add passing rules that the real run did not evaluate, and the rule-by-rule merge would raise the
host's figure (the FREES-130 probe went from 0.0 to 99.0 percent). `--allow-repeated-scans` merges such runs, worst
outcome first, and the group's note has `repeated_profile: true`. Runs of different profiles on one host (for example
CIS and STIG, which share a benchmark ID) are different groups with their own figures, so a forged run with another
profile can neither be refused as a repeat nor change the real run's figure; runs that did not complete are never
refused and withhold the group's figure; XCCDF and ARF files are self-asserted by construction and always merged with
a note. Signed evidence that tells a genuine run from a forged one is proposed in
[ADR 0018](adr/0018-evidence-bundle-provenance.md).

### Summary fields

| Field | Meaning |
|---|---|
| `run_status` | `completed`, `failed`, `timed_out`, or `not_completed` when several runs include one that did not complete. Read it first. |
| `assessment` | `run_not_completed`, `nothing_evaluated`, `all_evaluated_passed` or `findings_open`; never a compliance claim |
| `compliance_percent` | `pass` divided by `evaluated`, rounded down to one decimal (99999 of 100000 is 99.9); 100.0 only when everything evaluated passed; `null` when the run did not complete or `evaluated` is 0 |
| `evaluated` | The denominator: all outcomes except `notapplicable` and `disabled` |
| `counts` | Number of rules for each of `pass`, `fail`, `waived`, `notchecked`, `error`, `notapplicable`, `disabled` |
| `not_selected` | XCCDF and ARF results that the profile did not select. Informational; never in the maths |
| `expired_waivers` | Rules whose exception expired, also between the scan start and the controller time (exceptions evaluations only); they count as their evaluated outcome |
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

`rules` has one entry per rule ID, host, benchmark, content version and profile (all part of the entry), with the
worst `outcome`, the highest `severity`,
`expired_waiver` (of the sources that have the worst outcome) and every contributing `sources` entry (`artifact`,
`benchmark_id`, `profile_id`, `outcome`, `expired_waiver`), so the outcome of each file stays visible. Two inputs of
one host with the same benchmark, version and profile are merged, worst outcome first.

## Host coverage

`sections.compliance.host_coverage` (schema 2.1, FREES-142) says whether the report accounts for every target host.
A report built from evidence bundles alone cannot see a host that has no bundle (unreachable, limited out, failed
before the scan, check mode, collection failed), and a fleet figure over the hosts that are present reads as if it
covered the fleet. The collection summary of the run (`--evidence-collection`) names every target host, so the report
can account for each one.

| Field | Content |
|---|---|
| `status` | `unknown` without `--evidence-collection`; `complete` when every target host has a bundle in the report; `incomplete` when at least one has not |
| `reason` | Why the coverage is `unknown` or `incomplete` (`2 of 4 target host(s) have no evidence bundle in this report`); `null` when `complete` |
| `collection` | `path`, `sha256` and `size` of the summary as read, its `collection_id` and `collected_at`; `null` when `unknown` |
| `summary` | `target_hosts`, `in_report`, `missing` and `by_status` (one count per collection status); `null` when `unknown` |
| `hosts` | One entry per target host, sorted by name: inventory `host`, collection `status`, `in_report`, and the `run_id` and `manifest_sha256` of a collected bundle (else `null`); empty when `unknown` |

The collection statuses are `collected`, `unreachable`, `limited_out`, `no_audit_result`, `no_evidence_written` and
`collection_failed` ([collection summary](evidence.md#the-collection-summary)).

Rules:

- A bundle that verified must be listed in the summary as `collected` with the same inventory host, run ID and SHA-256
  of `bundle.json`. Otherwise it is an input `error` (format `exceptions_evaluation` when it carries an evaluation,
  else `scan_run`, artifact `<bundle>/bundle.json`), and its host is not in the report.
- Every target host without such a bundle is a missing input: an `unavailable` compliance item whose artifact is
  where its bundle would be (`<summary directory>/<host>`, or `<summary directory>/<host>/<run_id>` for a collected
  host whose bundle was not supplied) and whose reason names the host and its status. When the report has exceptions
  evaluations, the same missing input is also an `exceptions_evaluation` item of the exceptions section, so the
  section is `partial` and calls no exception stale because a host is missing.
- The compliance section is therefore `partial` while a host is missing (`unavailable` when no bundle is present,
  `error` when an input is invalid), so it has no `summary`, `groups`, `aggregates` or `rules`: **no figure is
  presented as covering the fleet**. The figures of the hosts that are present stay visible in their items, and the
  command exits with status 1. The schema forbids an `available` section with `incomplete` coverage.
- Missing inputs are listed in `gaps` and `raw_artifacts` like any other missing input.
- `--evidence-collection` accounts for evidence bundles only. A ScanRun, XCCDF, ARF or evaluation file names a
  self-asserted host that the summary cannot bind to an inventory host, so supplying one with the summary is refused.
- Without `--evidence-collection` nothing else changes: the report is written as before, exits with status 0 when
  every input parsed, and labels its coverage `unknown`. A bundle report is not refused without a summary (the
  FREES-142 decision), because the label states the gap without blocking existing pipelines.

## Exceptions section

The `exceptions` section is built from exceptions evaluations (`--exceptions-evaluation`) and the exceptions file
they were made from (`--exceptions-file`, required with evaluations; a file without evaluations, or a file that cannot
be read, is refused with exit status 2). Every evaluation is verified against the file
(`exceptions.verify_evaluation`, see [exceptions](exceptions.md#reporting)):

- the SHA-256 of the file, exactly as supplied, must be the evaluation's `source_sha256`: the evaluation must have been made from the byte-exact file. The
  `audit` role reads it that way (`rstrip=false`); a play that uses the `ansible.builtin.file` lookup's default
  `rstrip=true` hashes a different text, and its evaluations are refused;
- the file must be a valid exceptions file, checked with the controller time of the evaluation as "today";
- the evaluation's scan run, with the waiver marks removed, is evaluated again with that file and the target,
  controller time and scan lag limit the evaluation records, and the result must be exactly the evaluation.

An evaluation that fails any of these, including one made from another exceptions file, has an unknown
`schema_version`, or names an inventory host that is not a host name, is an input error in both the compliance and the
exceptions section. `exceptions_file` (`path`, `sha256` of the bytes read, `verified: true`) is set only when the
section is available, that is, when every evaluation passed.

The scan run of an evaluation is also a compliance input, with the format `exceptions_evaluation`. A rule whose
exception lapsed between the scan start and the controller time stays `fail` and counts in `expired_waivers`; its ID is
listed in the item's `lapsed_waivers`. Compliance percentages are the same as for the scan run alone.

When the section is available, `exceptions` lists every exception of the exceptions file once:

| Field | Content |
|---|---|
| `id`, `rule_id`, `framework`, `risk` | As in the file |
| `owner`, `approver`, `approval_date`, `created`, `expires`, `expires_at` | As in the file; `expires_at` is the first instant it no longer applies |
| `justification` | As in the file (free text from the reviewed file, rendered as text) |
| `scope` | `hosts`, `groups`, `profiles` (lists, empty when not set) and `benchmark` (`id`, `version` or `null`), from the file only; every value is checked against the pattern of its field |
| `status` | The review: `in_effect`, `expired`, `not_yet_effective`, `superseded`, `not_failing` or `stale` |
| `removal_candidate` | True for `stale`, `superseded` and `not_failing`: it waived nothing on any evaluated host |
| `lapsed` | True when its expiry had passed at the evaluation time of at least one evaluation |
| `host_statuses` | Number of evaluations per status (`waived`, `expired`, `not_yet_effective`, `not_failing`, `superseded`, `unmatched`) |
| `matched_hosts` | One entry per evaluation where the scope matched: inventory `host`, `benchmark_id`, `content_version`, `profile_id`, `run_id`, `status`, `superseded_by`, `input_sha256` |
| `source_sha256` | SHA-256 of the exceptions file, as the evaluation records it |

The review status is the first of these that any evaluation reports: `expired` (a failure the exception covered is no
longer waived), `waived` (`in_effect`), `not_yet_effective`, `superseded`, `not_failing`. An exception `unmatched` in
every evaluation is `stale`. Matched hosts are the controller's inventory names, never the host names that scan runs
report. `summary` (and `overview.exceptions`) has `by_status` (exceptions per review status), `removal_candidates`,
`lapsed`, `evaluations` (unique evaluation files), `total` and `source_sha256`. They are `null` and `exceptions` is
empty when the section is not available. An evaluation of any other exceptions file, even one that differs only in
trailing whitespace, is an input error.

The answer covers only the evaluations supplied: an exception for a host that was not evaluated is stale.

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
| XCCDF 1.2 results | `parsers/xccdf.py` | Reuses `openscap.parse_results` of the findings model (more than 100000 selected rule results is an error): result mapping through `map_xccdf_result`, unknown values become `error`, exactly one TestResult. `notselected` results are counted in `not_selected`, not in the findings. `host` is `null`; `reported_host` is the self-asserted `target` or fqdn fact; a `target` and fqdn fact that name different hosts make the file an error. |
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
| Exceptions evaluation | `parsers/evaluation.py` | The evaluation document of `apply_exceptions` (evaluation `schema_version` `"1.0"`), verified by `exceptions.verify_evaluation` against `--exceptions-file`: same SHA-256, valid file, and a new evaluation of the scan run with that file equal to the document. The target host must match the exceptions host pattern. At most 1000 exceptions. |
| Exceptions file | `parsers/evaluation.py` | Read as UTF-8 with the common size and path rules and parsed by the collection's strict exceptions loader; listed in `raw_artifacts` as `exceptions_file`. |

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
- The HTML dashboard (FREES-77, ADR 0017) adds no field to the document and refuses every version it does not
  know; it reads 2.0 and 2.1.
- 2.1 (FREES-142, [ADR 0016 amendment](adr/0016-report-schema-and-summary-semantics.md#amendment-2026-10-26-schema-21-host-coverage-frees-142)):
  a field addition, so a minor version in the same `report-v2.json`. `sections.compliance.host_coverage` is new and
  required in a 2.1 document, `raw_artifacts` gains the format `evidence_collection` and its bound grows to 9002.
  Nothing else changes; a 2.0 document (no `host_coverage`, no `evidence_collection` artifact) still validates against
  `report-v2.json`, and the schema refuses `host_coverage` in a 2.0 document. A 2.0 consumer migrates by accepting
  `"2.1"` and the `host_coverage` key; the dashboard reads 2.0 and 2.1 and shows a 2.0 report's coverage as unknown.
  The command line still writes the same 2.1 document without `--evidence-collection`, with coverage `unknown`.
- 2.0 (FREES-130, FREES-132, [ADR 0016 amendment](adr/0016-report-schema-and-summary-semantics.md#amendment-2026-10-26-schema-20-host-identity-and-waivers-frees-130-frees-132)):
  `report-v2.json`. Breaking: every figure key includes the profile (`groups`, `aggregates` and `rules` gain
  `profile_id`, `rules` also `benchmark_id`, and a CIS and a STIG run of one host are two figures); the 1.0 note
  `shared_self_asserted_host` is replaced by the per-group `merged_inputs` and the host-level
  `same_host_across_groups` notes; `sections.exceptions` and `overview.exceptions` are new required keys; compliance
  items and data gain the format and kind `exceptions_evaluation` and the `lapsed_waivers` list; raw artifacts gain
  the format `exceptions_file`. Deliberate counting changes: figures are per profile, and waivers that lapsed during
  the scan count in `expired_waivers` (the outcome stays `fail`). Unchanged: metadata, scope, every section status
  coupling, items, gaps and the percentage rules. A 1.0 consumer migrates by accepting `"2.0"` and the `exceptions`
  section name, reading `profile_id`, reading notes by their new kinds and treating `exceptions_evaluation` like
  `scan_run`. Inputs are unchanged, except that an XCCDF file whose target and fqdn fact disagree is now an error,
  repeated scan runs are refused unless allowed, and evaluations need their exceptions file. `report-v1.json` is in
  the Git history.
