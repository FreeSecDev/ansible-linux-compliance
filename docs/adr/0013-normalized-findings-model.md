# 0013. Normalized compliance findings model

- **Status:** accepted
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** FREES-26, FREES-39
- **Pull requests:** [#6](https://github.com/FreeSecDev/ansible-linux-compliance/pull/6)
- **Research:** [2026-10 upstream compatibility](../research/2026-10-upstream-compatibility.md)

## Context

Scanners, the audit module, remediation, exceptions and the report all exchange results. They need one typed,
versioned representation that is independent of the scanner backend, the benchmark and the distribution
([component map](../../.agents/skills/architecture/references/component-map.md)). The model has three constraints.

- It is produced on managed hosts by modules, so it can only use the Python standard library and must run on every
  managed-node Python version that the oldest supported ansible-core supports.
- It is consumed on the controller by the reporting package, which must reuse it rather than redefine it.
- It carries security decisions: an outcome that is wrongly `pass` is a false assurance
  ([ADR 0010](0010-initial-os-and-benchmark-scope.md), [ADR 0011](0011-control-toggles-and-cleanup.md)).

The collection requires ansible-core 2.20 or newer (`requires_ansible: ">=2.20.0"` in `meta/runtime.yml`). The
official ansible-core support matrix, checked on 2026-10-25, lists 2.20 as supported (general availability
03 November 2025, end of life May 2027) with control node Python 3.12 to 3.14 and **managed-node (target) Python 3.9 to
3.14**. Source:
<https://docs.ansible.com/projects/ansible/devel/reference_appendices/release_and_maintenance.html>. Python 3.9 is
therefore the floor for all code in `plugins/modules` and `plugins/module_utils`. ansible-core 2.19 (target Python 3.8
to 3.13) leaves support in November 2026 and is not supported by the collection.

## Decision

The findings model is a single standard-library module, `plugins/module_utils/compliance/model.py`, made of frozen
dataclasses, enums and two functions for JSON. The reporting package imports the same module on the controller.

### Entities

| Entity | Fields |
|---|---|
| Framework | `framework_id` (`cis`, `stig`, `nist_800_53`, `nist_800_171`, `pci_dss`, `anssi`), `name` |
| FrameworkVersion | `framework`, `version` |
| Provenance | `source` (for example the ComplianceAsCode reference field), `content_version`, `content_sha256` |
| Benchmark | full XCCDF benchmark ID, `title`, `version`, optional `framework_version`, `provenance`, `profiles`, `rules` |
| Profile | full XCCDF profile ID, `title`, `rule_ids` |
| Rule | see below |
| Applicability | `distribution_id`, `versions` (at least one) |
| Reference | `framework`, `control_id`, `provenance` |
| HostIdentity | `hostname`, `distribution_id`, `distribution_version`, `architecture`, optional `machine_id` |
| Evidence | `kind`, `source`, `content` (bounded text) |
| ExceptionStatus | `state` (`none`, `active`, `expired`), `exception_id`, `reason`, `expires_at` (required for `active` and `expired`) |
| RemediationResult | `rule_id`, `status`, `changed`, `message` |
| Finding | `rule_id`, `outcome`, `evaluated_outcome`, `severity`, `message`, `evidence`, `exception`, `remediation`, `disabled_by`, `flags` |
| ScannerInfo | `name`, `version` |
| ScanRun | `run_id`, `started_at`, `finished_at`, `host`, `scanner`, `content` (provenance including the datastream SHA-256), `benchmark_id`, `profile_id`, `status`, `error_message`, `findings` |

A **Rule** has a stable full XCCDF ID (`xccdf_org.ssgproject.content_rule_<id>`, short IDs are display-only), `title`,
`description`, `severity` (`unknown`, `info`, `low`, `medium`, `high`), `category` (the control family), `control_class`,
`applicability` by distribution and version, `evaluation_method` (`oval`, `sce`, `ocil`, `evidence`, `manual`, `none`),
`remediation_method` (`native_module`, `none`), `revert_strategy` per [ADR 0011](0011-control-toggles-and-cleanup.md)
(`owned_dropin`, `recorded_value`, `recorded_state`, `irreversible`, or none) and `references` to CIS, STIG, NIST
800-53, NIST 800-171, PCI DSS and ANSSI controls. Every reference carries its own provenance: source, content version
and datastream SHA-256.

`ScanRun` records when the scan ran (`started_at`, `finished_at`, UTC, second precision, `YYYY-MM-DDTHH:MM:SSZ`),
which scanner and version produced it, and which content it evaluated, identified by source, version and digest. The
digest is the SHA-256 that the content manifest verified before use.

### Outcome enum and XCCDF mapping

Outcomes are `pass`, `fail`, `notapplicable`, `notchecked`, `error`, `waived` and `disabled`. `disabled` means an
operator toggle excluded the rule ([ADR 0011](0011-control-toggles-and-cleanup.md)); it is never counted as passing
and a disabled finding names the controlling variable in `disabled_by`.

`map_xccdf_result` maps scanner output with this explicit table. The match is exact and case-sensitive.

| XCCDF result | Platform outcome | Retained flag |
|---|---|---|
| `pass` | `pass` | none |
| `fail` | `fail` | none |
| `notapplicable` | `notapplicable` | none |
| `notchecked` | `notchecked` | none |
| `error` | `error` | none |
| `fixed` | `pass` | `fixed` |
| `informational` | `notchecked` | `informational` |
| `notselected` | `notchecked` | `notselected` |
| `unknown` | `error` | none |

**Any value that is not listed maps to `error`**, including other case spellings, empty strings, `waived`,
`disabled` and every non-string. `waived` and `disabled` are never produced from scanner output: `waived` comes from an
active exception record and `disabled` from tailoring data. A finding validates that its flags match its outcome
(`fixed` only with `pass`, `informational` and `notselected` only with `notchecked`).

### Control classification

Every rule has exactly one `control_class`:

| Class | Allowed evaluation methods | Remediation |
|---|---|---|
| `directly_auditable` | `oval`, `sce`, `ocil` | `none`, no revert strategy |
| `automatable_remediation` | `oval`, `sce`, `ocil` | `native_module` and a revert strategy |
| `evidence_only` | `evidence` | `none`, no revert strategy |
| `manual_organizational` | `manual` | `none`, no revert strategy |
| `unsupported` | `none` | `none`, no revert strategy |

A rule that contradicts its class is rejected at construction. A revert strategy is required exactly for rules whose
class is `automatable_remediation`.

### Invariants

- **A scanner execution failure is never `fail` or `pass`.** A `ScanRun` whose `status` is `failed` or `timed_out`
  requires an `error_message` and may only contain findings with outcome `error`. A `completed` run must not have an
  `error_message`. Unlisted XCCDF values map to `error` for the same reason.
- **Cross-framework deduplication is by rule ID.** A `ScanRun`, a `Benchmark` and a `Profile` reject duplicate rule IDs,
  so a rule is scanned, remediated and counted once however many frameworks reference it. Frameworks are reached
  through `Rule.references`, never by repeating the rule.
- **A waiver only turns an evaluated `fail` into `waived`.** `outcome` is what is reported and `evaluated_outcome` is
  what the scanner decided. They are equal except for a waived finding, whose `evaluated_outcome` is always `fail`, so a
  report can show what was waived. A rule that the scanner evaluated as `error` stays `error` (or any other
  non-`fail` outcome stays as it is) even when an active exception exists; a broken check is never hidden behind a
  waiver. A failed rule under an active exception must be reported as `waived`, never as `fail`.
- **Waivers apply only while valid.** An exception has an expiry: `expires_at` is required for `active` and
  `expired`, so the model has no permanent waivers. `ScanRun` compares it with `started_at` as UTC instants: an
  `active` exception must expire strictly after `started_at` and an `expired` exception must expire at or before
  `started_at`. An expiry exactly at `started_at` is therefore expired, one second later is active.
- `disabled` holds exactly when `disabled_by` is set; a remediation result must belong to the rule of its finding.
- Profiles may only select rules that their benchmark contains.
- Collections of keyed items are stored sorted (findings, rules and profiles by ID, references by framework and
  control), so equal models serialize identically whatever the input order.

### Serialization

The model serializes to JSON with `schema_version` (currently `"1.0"`) at the top level of a `ScanRun`. `dumps` writes
sorted keys, compact separators, ASCII escapes and no non-finite numbers. `loads` rejects oversized documents,
invalid JSON, duplicate keys, `NaN` and `Infinity`, unknown or missing keys at every level, unknown enum values and
unsupported schema versions. Readers accept only versions listed in `SUPPORTED_SCHEMA_VERSIONS`. A change that adds a
field bumps the minor version and readers are updated before writers emit it; a breaking change bumps the major
version.

All text fields are bounded (identifiers 256 characters, titles 512, descriptions and messages 8192 or 4096, evidence
content 65536, 64 evidence items per finding, 256 references per rule, 100000 findings per run, 128 MiB per document)
and reject control and formatting characters. Identifier-like fields (IDs, names, titles, versions, sources,
control IDs, host fields, error and exception identifiers) reject every character of Unicode category Cc, Cf, Zl or
Zp, which includes bidi overrides, zero-width characters and line separators. Free-text fields (descriptions,
messages, reasons, evidence content) allow tab, newline and carriage return but reject all other Cc characters and the
bidi embedding, override and isolate controls; they allow ordinary Unicode such as accents and emoji joiners. Reports
must still escape everything they render. Identifiers, digests, timestamps and variable names are checked against
anchored patterns. Error messages never echo untrusted text raw: keys and values are escaped with `repr` and cut to
64 characters, and at most five unknown keys are listed. Validation failures raise `ModelError`, a `ValueError` subclass.

### Placement and compatibility

The model runs on managed hosts, so it lives in `plugins/module_utils/compliance/model.py`.

- It imports only the standard library and no Ansible internals, so the reporting package can import it on the
  controller without installing anything.
- It supports Python 3.9, the oldest managed-node interpreter of ansible-core 2.20 (see Context). It uses
  `from __future__ import annotations`, `TypeVar` instead of PEP 695 syntax, plain `Enum` instead of `StrEnum`
  (Python 3.11) and `datetime.timezone.utc` instead of `datetime.UTC` (Python 3.11).
- **Dataclass slots are not used.** `@dataclass(slots=True)` needs Python 3.10, so the dataclasses are frozen but not
  slotted. The memory cost is irrelevant at the bounded sizes above and `__post_init__` validation is unaffected.
- `ansible-test sanity` runs the `compile` and `import` tests on Python 3.9 to 3.14 and `ansible-test units` runs the
  tests on 3.9, 3.12 and 3.14, so the claim is checked against real interpreters rather than asserted.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| pydantic | A third-party package with a compiled core; target-side code may only use the standard library, and installing it on every managed host is not acceptable |
| Plain dictionaries | No validation, no type checking, and key typos silently produce wrong outcomes; every consumer would re-implement the checks |
| `TypedDict` | Static typing only, with no runtime validation of untrusted scanner output or host-supplied documents and no enforcement of invariants |
| Dataclasses (chosen) | Standard library on Python 3.9, immutable with `frozen=True`, typed for mypy and Pyright strict, and validation fits in `__post_init__` |
| Hand-written classes with `__slots__` | More code for the same behaviour; dataclasses give equality, hashing and `repr` for free |

## Benefits

One schema for scan, remediation, exceptions and reporting. Unsafe states (a failed scan reported as `pass`, a
disabled rule counted as passing, a rule counted once per framework) cannot be constructed. Documents from hosts are
validated before the controller uses them. The mapping table and classification are executable and tested at 100% line
and branch coverage.

## Trade-offs

- Python 3.9 compatibility rules out newer syntax (slots, `StrEnum`, PEP 695, `X | Y` at runtime) until the oldest
  supported ansible-core drops 3.9 as a target version.
- Strict unknown-key rejection means a producer that adds a field must bump `schema_version` and readers must be
  upgraded first.
- Validation duplicates a small amount of logic that pydantic would provide; the helpers are internal and tested.
- The module is large because Ruff formatting spreads every call over several lines.

## Security implications

Documents from managed hosts are untrusted input to the controller. `loads` bounds size, text length and item counts,
rejects duplicate keys and non-finite numbers, and validates every field before an object exists, so a hostile host
cannot smuggle an outcome the model forbids. A scanner crash, timeout or malformed output cannot become `pass` or
`fail`. Evidence is bounded and may contain host data: producers must not put credentials in evidence, and consumers
must escape it when rendering. The model never asserts compliance with a framework; references are evidence mappings
with provenance (AGENTS.md rule 9).

## Operational consequences

- Modules and the reporting package import the model and never define their own outcome or finding types.
- Changing an entity or an enum value requires an update to this ADR and a `schema_version` decision.
- `make test-coverage` requires 100% line and branch coverage for `plugins/`, `make test-sanity` and
  `make test-ansible-units` run the collection through `ansible-test`, and `make package` builds the tarball.
- When ansible-core 2.20 leaves support, raising `requires_ansible` is a deliberate change with its own review.

## Amendment 2026-10-25: result integrity (FREES-48)

The scanner backends reconcile results with the rules that the caller selected, and consumers must not derive a
verdict from findings alone. These invariants apply to every backend and every report.

- A `ScanRequest` names the rules that the profile selects (`expected_rule_ids`, required and non-empty). The audit module
  supplies them from the selected profile.
- On a `completed` run, every expected rule without a rule-result is an `error` finding whose message says why. This holds
  for exit status 2. With exit status 0 oscap promises that every rule passed, so a missing expected rule contradicts it
  and the run is `failed` (with `error` findings for all expected rules).
- oscap lists every rule of the benchmark, writing `notselected` for the rules that the profile does not select. A
  rule-result whose rule is not in `expected_rule_ids` **and** whose result is `notselected` is skipped (it is not counted
  in the run, because the model has no field for it). Any other result for a rule that was not expected, a duplicate
  result for one rule (selected or not), or a result element in another XCCDF namespace makes the run `failed`, because
  findings would otherwise be dropped silently. An expected rule that reports `notselected` maps through the table above
  (`notchecked` with the `notselected` flag).
- A run whose status is not `completed` counts **every expected rule as `error`** in reports and summaries. A backend
  fills the findings accordingly, but a consumer must apply the rule even when it receives fewer findings.
- A `ScanRun` whose status is not `completed` is never summarised as compliant or partially compliant, and "0 failures"
  is never derived from the findings of such a run. Reports and summaries show the run status first, before any count.
- The SHA-256 of a tailoring file is recorded in `Provenance.source` next to the datastream name, because the model has
  no separate field; a dedicated field is a candidate for the next schema version. The OpenSCAP backend writes the label
  with this grammar, where file names are restricted to the alphabet below and anything else is a request error, so the
  label cannot be spoofed by a file name:

  ```text
  source   = name [ " tailoring=" name " tailoring_sha256=" hex64 ]
  name     = 1*64( ALPHA / DIGIT / "." / "_" / "+" / "-" )
  hex64    = 64( DIGIT / %x61-66 )
  ```

## Amendment 2026-10-25: exceptions file and waivers (FREES-50)

The source of `waived` findings is a version-controlled exceptions file, documented in
[Exceptions and waivers](../exceptions.md). The model entities are unchanged and `schema_version` stays `"1.0"`.

- `plugins/module_utils/compliance/exceptions.py` validates the file and applies it to a `ScanRun`; it is standard
  library only, like the model. The model gains two public helpers, `validate_xccdf_id` and `validate_text`, so the
  exceptions code checks rule IDs and text with exactly the model's rules instead of copying them.
- The standard library has no YAML parser, so `plugins/module_utils/compliance/yamlsubset.py` reads a strict subset
  of YAML. It rejects duplicate keys, anchors, aliases, tags and unquoted values that other loaders would not read as
  strings. Writing a parser was preferred to accepting data pre-parsed by Ansible, because Ansible's loader only warns
  on duplicate keys by default, and to adding PyYAML to target-side code, which the repository guard forbids.
- Every exception needs `id`, `rule`, `framework`, `scope`, `justification`, `owner`, `approval` (`approver`,
  `date`), `created`, `expires` and `risk` (`low`, `medium`, `high`, `critical`). The validity is capped at **365 days**
  from `created` to `expires`, `created` must not be in the future, `approval.date` lies between `created` and today
  and before `expires`, and the approver must not be the owner. An invalid entry rejects the whole file.
- Dates are UTC calendar dates. An exception is in effect from `approval.date` 00:00:00 UTC until `expires`
  00:00:00 UTC (exclusive), evaluated at `ScanRun.started_at`. `ExceptionStatus.expires_at` is `expires` at
  00:00:00 UTC, which keeps the existing invariant: `active` expires strictly after the scan start, `expired` at or
  before it.
- A scope has `hosts` (inventory host names), `groups` (inventory groups) and `benchmark` (`benchmark_id` and content
  version); all present dimensions must match. Hosts are matched against the controller's inventory name, never
  against the host name in `ScanRun.host`, which the scanned host reports itself. `framework` is recorded, not matched,
  because rules are deduplicated by rule ID across frameworks.
- Only a `fail` finding of a `completed` run becomes `waived`; the invariant "a waiver only turns an evaluated `fail`
  into `waived`" above is enforced again by the model when the finding is rebuilt. An expired exception leaves the
  finding `fail` with exception state `expired`. A scan run whose findings already carry exception data is refused.
- The reason of a waived or expired finding contains the justification, risk, framework, owner, approver and dates, so
  the finding is self-describing. The controller filter returns an evaluation document with one status per exception
  (`waived`, `expired`, `not_yet_effective`, `not_failing`, `superseded`, `unmatched`); exceptions that are `unmatched`
  on every evaluated host are stale.

Rejected alternatives: matching on `ScanRun.host.hostname` (self-asserted by the host), an end-of-day expiry
(it would keep a waiver alive on its expiry date), exceptions without a cap (permanent waivers), and silently skipping
invalid entries (a typo would turn a waiver into an unexplained failure or hide that the file is broken).

## References

- ansible-core release and maintenance matrix:
  <https://docs.ansible.com/projects/ansible/devel/reference_appendices/release_and_maintenance.html>
- [ADR 0010](0010-initial-os-and-benchmark-scope.md), [ADR 0011](0011-control-toggles-and-cleanup.md)
- [Collection design](../collection-design.md)

## Amendment 2026-10-25: audit module semantics (FREES-49)

`freesecdev.linux_compliance.compliance_scan` is the first producer of `ScanRun` documents on managed hosts
([audit guide](../audit.md)). The model is unchanged; these are the producer rules.

- **`changed` is always false.** An audit never changes the configuration of a host (AGENTS.md rule 7). The evidence that
  a run writes (scanner output, the tailoring file and `scan-run.json`, in a new root-owned `0700` run directory with
  `0600` files) is reported separately as `evidence_written` and `evidence.files` (path, kind, SHA-256, size), so a
  report can always tell a host change from an audit record. Evidence is never overwritten; a repeated run reports
  `changed: false` again and writes a new run directory.
- **Check mode scans and keeps nothing.** The scan is read-only, so check mode runs it and returns the real findings,
  but into a private `0700` directory `<output_dir>/.check-<run_id>` that is removed with every file in it before the
  module returns, also on failure (`cleanup_failed` if that is impossible). `evidence_written` is false and no evidence
  file is listed. Check mode never creates the output directory; when it is missing no scan runs and the run status is
  `not_run`.
- **Scanner failures are results, not exceptions.** A `failed` or `timed_out` run is returned with all findings `error`
  and, by default (`fail_on_incomplete: true`), the task fails with `error_type: scan_incomplete` and the full result.
  The audit role registers the result first and fails afterwards, so the evidence of a failed scan is kept.
- **The scanner reads only a verified private copy.** Hashing the operator's file before and after the scan does not
  bind what `oscap` read: the file could be swapped during the scan and restored. The module therefore copies the
  datastream into the root-only `0700` run directory (`content/<name>`, `0600`), hashes exactly the bytes it writes and
  stops with `digest_mismatch` unless they are the pinned content; `oscap` reads only that copy, which only root can
  change. The copy is removed after the scan and reported as `content` (`source_path`, `sha256`, `size`,
  `private_copy`, `copy_removed`). A completed run whose recorded `content.content_sha256` differs from the pinned
  digest still becomes `failed`.
- **Summary.** The module summary is the count per outcome, the total and `run_status`; it contains no percentage and no
  compliance statement ([ADR 0016](0016-report-schema-and-summary-semantics.md)). `scan-run.json` is the `model.dumps`
  document that the reporting package reads as ScanRun JSON.
