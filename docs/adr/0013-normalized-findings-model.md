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
  and before `expires`. Owner and approver are each an email address or a handle after NFKC normalisation, trimming
  and case folding, and must not denote the same person (a handle equals an email address with that local part). An
  invalid entry rejects the whole file.
- Dates are UTC calendar dates. An exception is in effect from `approval.date` 00:00:00 UTC until `expires`
  00:00:00 UTC (exclusive). `ScanRun.started_at` comes from the scanned host and is untrusted, so the controller
  filter takes its own UTC time: a scan start more than 5 minutes after it is refused, expiry is judged at the later of
  the scan start and the controller time, and approval is judged at the scan start. A host whose clock runs behind can
  therefore make a waiver lapse sooner but never later. A scan more than 24 hours (configurable) older than the
  controller time is still evaluated and flagged. `ExceptionStatus.expires_at` is `expires` at 00:00:00 UTC, which
  keeps the existing invariant: `active` expires strictly after the scan start, `expired` at or before it. An
  exception that expired between the scan start and the controller time is reported `expired` in the evaluation and
  leaves the finding `fail` without exception data, because the model cannot mark it `expired`.
- A scope has `hosts` (inventory host names), `groups` (inventory groups), `profiles` (XCCDF profile IDs) and
  `benchmark` (`benchmark_id` and content version); all present dimensions must match. In ComplianceAsCode the CIS and
  STIG profiles of a distribution share one benchmark ID, so `benchmark` requires `profiles`, failing closed. Hosts are
  matched against the controller's inventory name, never against the host name in `ScanRun.host`, which the scanned
  host reports itself. `framework` is recorded but does not restrict matching, because rules are deduplicated by rule
  ID across frameworks; `profiles` is how an exception is limited to one framework.
- Only a `fail` finding of a `completed` run becomes `waived`; the invariant "a waiver only turns an evaluated `fail`
  into `waived`" above is enforced again by the model when the finding is rebuilt. An expired exception leaves the
  finding `fail`. A scan run whose findings already carry exception data is refused.
- The reason of a waived or expired finding contains the justification, risk, framework, owner, approver and dates, so
  the finding is self-describing. The controller filter returns an evaluation document with one status per exception
  (`waived`, `expired`, `not_yet_effective`, `not_failing`, `superseded`, `unmatched`); exceptions that are `unmatched`
  on every evaluated host are stale.

Rejected alternatives: matching on `ScanRun.host.hostname` (self-asserted by the host), an end-of-day expiry
(it would keep a waiver alive on its expiry date), exceptions without a cap (permanent waivers), silently skipping
invalid entries (a typo would turn a waiver into an unexplained failure or hide that the file is broken), judging
expiry at `min(started_at, controller time)` (a lagging host clock would extend a waiver), and an optional
`profiles` next to `benchmark` (a benchmark scope would silently cover every framework's profile).

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

### Note 2026-10-26: content directory and SCE checks (FREES-134)

Superseded for SCE by [ADR 0026](0026-no-content-scripts-on-hosts.md) (FREES-191): the SCE checks and scripts are
removed on the controller, the hosts refuse content that has them, and the former SCE-only rules are `notchecked`.

- **The content directory is vetted before root opens the datastream.** The plan refuses, with
  `unsafe_content_dir`, a datastream reached through a symlink, a directory above it (including the one that holds it)
  that is not owned by root or is writable by group or others without the sticky bit, and a datastream that is not
  owned by root or is writable by group or others. These are the rules for the ancestors of the output directory. The
  check runs before the datastream is opened and before the run directory is created, so a non-root user can no longer
  swap the file for a FIFO between the `lstat` and the `open` and make the audit hang. It replaces the FREES-49 rule that
  accepted symlinks above `content_path`. Residual risk is in the [audit guide](../audit.md#content-directory-rules).
  The refusal of every symlink above `content_path` is superseded by the FREES-139 note below, which vets the resolved
  chain and the links followed instead.
- **SCE checks are root-executed content, trusted through the pin.** The pinned datastreams embed SCE shell check
  scripts (81 in Ubuntu 24.04) that `oscap` runs as root; with OpenSCAP 1.3.9 only the 18 rules without an OVAL check
  use them (16 in `cis_level1_server`). The pinned `oscap` has no option to disable SCE; without it those rules would be
  `notchecked`, and operators who do not want them to run list them in `disabled_rules`, which makes them `disabled`.
  They are checks, not fixes, and `--remediate` stays refused, so [ADR 0003](0003-native-module-remediation.md) is
  unaffected. The model is unchanged: an SCE result maps through the same XCCDF result table as an OVAL result. See
  [T-AUDIT-2](../security/threat-model.md#t-audit-2-sce-check-scripts-run-as-root).

### Note 2026-10-26: resolved content path, shared with discovery (FREES-138, FREES-139)

- **The resolved chain is vetted, not every symlink refused.** The FREES-134 rule refused every symlink above
  `content_path`. That is stricter than the hang requires, because a root-owned link in a root-controlled directory
  cannot be repointed by another user, and it refused image-mode RHEL (`/opt` is a link to `var/opt`) and hosts with a
  relocated `/opt` or `/var`. `catalog.vetted_content_path` now resolves the directory part of `content_path` to its
  real path once, walking from `/` with `lstat`. Every component of the resolved chain must satisfy the FREES-134
  directory rules (a directory, not a symlink, owned by root, not writable by group or others unless sticky), every
  symlink followed must be owned by root, and the directory that holds such a link is a component of the resolved
  chain, so it is root-controlled. More than 40 symlinks, which every loop reaches, are refused. The final component of
  `content_path` is still not followed, and the datastream rules are unchanged. A missing component or a dangling link
  is `invalid_content`, as it was when the path could not be resolved.
- **The audit reads the resolved path.** The plan verifies and parses the resolved file, the private copy is made and
  hashed from it, and `planned.content_path` and `content.source_path` report it. `content_path` as given is never
  opened.
- **One check for audit and discovery.** `benchmark_info` and `profile_info` call the same function before they open
  anything and fail with the same `unsafe_content_dir`. For them the check always applies, with root and the user the
  module runs as (the owner of `/proc/self`, or root only when it cannot be read) as the accepted owners, so under
  `become` the rules are those of the audit. Their `content_path` result is the resolved path.
- **Hard links.** Ownership and mode belong to the inode, so the datastream rules apply whatever name reaches it, and
  another name gives no user more write access.

Rejected alternatives: keep refusing every symlink (breaks the layouts above without making the audit safer), follow
links with `Path.resolve` and vet only the result (the links themselves, and their directories, would not be vetted, so
a user-owned link could be repointed after the check), apply the discover check only when the module runs as root
(another user could still stall an unprivileged task, and both modes would need separate tests), and accept only root
in the discover modules (it would refuse content in the connecting user's own directory, which only that user can
change).

## Amendment 2026-10-26: exceptions in the audit role (FREES-136)

The `audit` role applies the exceptions file ([audit guide](../audit.md#exceptions-in-the-audit-role)). The model is
unchanged; these are the consumer rules.

- **Raw and waived results are both kept.** `linux_compliance_audited.scan_run` and `summary` stay exactly what the
  scanner reported. The waived scan run and its counts are added as `linux_compliance_audited.exceptions.evaluation`
  and `exceptions.summary`. A consumer that needs the scanner's verdict reads the raw result; a waived finding still
  carries `evaluated_outcome: fail`.
- **The failure gate counts the raw result by default.** `linux_compliance_audit_fail_on_noncompliant` counts `fail` and
  `error` before any waiver, so a waiver never silently passes it. `linux_compliance_audit_fail_on_noncompliant_after_waivers`
  opts into counting `fail` of the waived result. `error` is taken from the raw result and counts in both modes.
- **Fail closed.** The file is read and validated once on the controller (`run_once`, `any_errors_fatal`) before any host
  is scanned; an invalid file fails the play and nothing is applied. Every host of the play, across `serial` batches,
  must resolve the same file, and each host checks that the SHA-256 of the text it applied is the validated one. Under
  the `free` strategy, at least one host of every batch with two or more hosts is always refused, and any host that
  finishes has applied exactly the validated file. The strategy itself cannot be detected from a task (FREES-143). A
  batch with a single host is not refused under `free`; that is harmless, because no other host can race it. A scan
  start more than five minutes after the controller time fails that host. Waivers are never applied to a run that is not
  `completed`, and check mode without a scan reports that they were not applied.
- **Stale exceptions are aggregated once, after every host**, in a final play on the controller, because a `run_once`
  task inside the role would run once per `serial` batch (or on every host with the `free` strategy) and see only part of
  the evaluations. The result names every target host that was not evaluated (limited out, unreachable, failed,
  check mode), and an exception is called stale, with the advice to remove it, only when every target host was
  evaluated.
- **Verification compares like with like.** The `verify` role (FREES-54) must compare raw with raw or waived with waived,
  from the same exceptions file, and must never count a waived result as an improvement over a failed one.

Rejected alternatives: gating on the waived result by default (an approved waiver would make a failing host pass the
gate without anyone opting in), reading the file once per host (a file changed during the play would give hosts
different waivers; the digest check of `stale_exceptions` would only catch it at the end), and replacing
`linux_compliance_audited.scan_run` with the waived run (consumers could no longer see what the scanner decided).

## Amendment 2026-10-26: exception review, verified evaluations and owner identity (FREES-132)

The model entities and `schema_version` `"1.0"` of the ScanRun and of the evaluation document are unchanged.

- **Benchmark scope version.** `scope.benchmark.version` must be a version token
  (`[A-Za-z0-9][A-Za-z0-9._+~:-]*`, at most 64 characters). It only ever matched a content version of that form, and
  the token keeps free text out of the scope that reports show.
- **Same person.** `exceptions.same_person` compares `person_identity`: a handle is its own identity, and an email
  address is its local part without a plus-address suffix, whatever the domain. `alice+audit@example.org` and
  `alice@example.org` are the same person, and so are `alice@a.example` and `alice@b.example`. The handle rule already
  matched `alice` with an address of that local part on any domain, so treating two such addresses as different
  people would make the relation intransitive and let a second address approve an owner's own exception. The check
  fails closed: two people who share a local part on different domains must use distinct handles or addresses. Dots
  and other provider-specific aliases are not folded, because providers differ (`alice.smith` and `alicesmith` stay
  different). The names remain unauthenticated; the reviewed pull request is the authority.
- **Review across hosts.** `exceptions.review` turns the statuses of one exception in several evaluations into one
  verdict: `expired` if any is `expired`, else `in_effect` if any is `waived`, else `not_yet_effective`, `superseded`,
  `not_failing` in that order, and `stale` when every status is `unmatched`. `review_exceptions`,
  `stale_exception_ids` and the new `removal_candidate_ids` read evaluation documents. Removal candidates are the
  verdicts `stale`, `superseded` and `not_failing`: the exception waived nothing, covered no failure that expired and
  none scanned before its approval, on any evaluated host. The filter
  `freesecdev.linux_compliance.exception_removal_candidates` wraps `removal_candidate_ids`.
- **Evaluation versions.** Every reader of evaluation documents checks `schema_version` against
  `SUPPORTED_EVALUATION_SCHEMA_VERSIONS` (`{"1.0"}`) and refuses any other value, including a missing one.
- **Evaluations verified against the exceptions file.** `exceptions.verify_evaluation(document, exceptions_text)`
  reads an evaluation document for the reporting package and trusts none of it:
  - it parses and validates `exceptions_text` with the file rules (`today` is the controller time of the document);
  - it requires the SHA-256 of that text to be the document's `source_sha256`;
  - it removes the waiver marks from the scan run (`waived` back to its evaluated `fail`, exception data to `none`);
  - it evaluates the run again with that file and the target, controller time and scan lag limit of the document.

  The document is accepted only when the new evaluation serializes identically, so no status, count, mark, reason,
  record or time can be edited. An evaluation made consistently from another, unreviewed exceptions file is refused,
  because its digest or its records differ. The reporting package requires the file (`--exceptions-file`). A waived
  finding inside a plain ScanRun JSON has no such check; [ADR 0018](0018-evidence-bundle-provenance.md) proposes
  signed evidence for that.
- **Lapsed waivers.** `Evaluation.lapsed_rule_ids` lists the rules whose chosen exception is `expired` in the
  evaluation but had not expired at the scan start. Their findings stay `fail` without exception data, because the
  model only allows the state `expired` for an expiry at or before the scan start; the report counts them in
  `expired_waivers` (ADR 0016, amendment of FREES-130 and FREES-132).

## Amendment 2026-10-26: comparing two scan runs (FREES-54)

The `verify` role compares a baseline audit with a later audit of the same host through the controller filter
`freesecdev.linux_compliance.compare_scans` ([verify guide](../verify.md)). The model and `schema_version` are
unchanged; these are the consumer rules.

- **Only like is compared with like.** Two scan runs are compared only when they are different runs of the same host
  identity, benchmark, content version and datastream SHA-256, profile and scanner name and version, and the later run
  started at or after the baseline finished. Anything else is refused, never compared approximately.
- **Raw with raw, waived with waived.** The default compares the raw `scan_run` of both audits, which must carry no
  exception data. Waived mode compares `exceptions.evaluation.scan_run` of both, only when both recorded the same
  exceptions `source_sha256` and each waived run belongs to its raw run (same `run_id`, same evaluated outcome per
  rule). This implements the FREES-136 rule above.
- **Classification uses `evaluated_outcome`.** The scanner's verdict decides, so a waiver can never be an improvement:
  `fail` to `waived` is unchanged, while `waived` to `pass` is an improvement because the evaluated outcome went from
  `fail` to `pass`. Only an evaluated `fail` that becomes `pass` is improved.
- **Regressions first.** A rule that passed in the baseline and is anything but `pass` or `notapplicable` afterwards
  (including `error`, `notchecked`, `disabled` and missing) is regressed. Any other transition from or to `error`, and
  any other rule missing from one run, is `error`, never improved.
- **Applicability changes are visible.** A rule that was `notapplicable` or missing in the baseline and fails
  afterwards is `newly_failing` and is gated like a regression by default; `notapplicable` to `pass` is
  `newly_applicable`. A rule that passed and is `notapplicable` afterwards is `newly_not_applicable`, not a regression,
  but it is listed separately and printed. Transitions from or to `notchecked` or `disabled` that no rule above covers
  are `not_comparable`. These are eight categories in all; the two beyond the six of the issue (`newly_failing` and
  `not_comparable`) exist so that no transition is forced into a category that misstates it.
- **The baseline is recorded in this run.** The verify role compares only a baseline that its `baseline.yml` entry
  point recorded, marked in the facts of the host (which inventory and play variables cannot set), and compares it
  once.
- **A run that did not complete yields no figures.** If either run is not `completed` (or no scan ran in check mode),
  the comparison is incomplete: no counts, no rules, no regressions and no statement that there are none. As in the
  FREES-48 amendment, "0 regressions" is never derived from such a run, and the role fails the host.
- A comparison is evidence about two scans of one host and never asserts compliance (AGENTS.md rule 9).

Rejected alternatives: classifying on the reported `outcome` (a new waiver would turn a failure into a change, and
`waived` to `pass` would need special cases), treating `error` to `pass` as an improvement (a repaired check proves
nothing about the host), reporting partial figures for an incomplete run (they would read as "no regressions"), and
comparing scans of different content versions rule by rule (rule semantics can change between releases).

## Amendment 2026-10-26: off-platform marker (FREES-161)

[ADR 0019](0019-scc-scanner-backend-and-ci-image.md#amendment-2026-10-26-off-platform-opt-in-for-ubuntu-2604-frees-161)
lets the SCC backend scan an Ubuntu 26.04 host with the Ubuntu 24.04 STIG benchmark, by explicit opt-in. Such results
must never pass for results of a benchmark made for the host, so the model marks them.

### Entities

| Entity | Fields |
|---|---|
| Platform | `distribution_id`, `distribution_version`, validated like the same fields of HostIdentity |
| OffPlatform | `benchmark_platform` (the platform the benchmark is made for), `target_platform` (the platform of the host); the two must differ |

`ScanRun` and `Finding` gain an optional `off_platform`, the default `None`. The invariants:

- **The target is the host.** A marked run's `target_platform` equals the distribution and version of `host`.
- **Every finding of a marked run carries the run's marker.**
  - `ScanRun` gives the marker to every finding that has none, so findings that are added later (disabled rules,
    `error` findings of a failed run or of a digest mismatch) are marked too.
  - A finding with another marker is refused.
- **An unmarked run has no marked finding.**
- **The marker survives every rebuild.** It is kept on failed and timed-out runs, and through waivers, because
  exceptions rebuild findings with `dataclasses.replace`.

### Schema version 1.1

Adding a field bumps the minor version, as the serialization rules above require.

- **Which version is written.** A run with a marker serializes as `schema_version` `"1.1"`, with `off_platform` on the
  run and on every finding. Every other run still serializes as `"1.0"`, byte for byte as before. Evidence bundles,
  exceptions evaluations and their digest checks, which compare serializations, are therefore unchanged for
  on-platform runs.
- **What readers accept.** `SUPPORTED_SCHEMA_VERSIONS` is `{"1.0", "1.1"}`. A `1.0` document must not hold
  `off_platform` at any level. A `1.1` document must hold it, as an object, on the run and on every finding. Every
  other key rule is unchanged.
- **Readers come first.** Readers were updated in the same change as the only writer. A reader that knows only 1.0
  refuses a 1.1 document instead of reading it as on-platform.
- **Older documents.** 1.0 documents are read exactly as before. The model has no conversion: a 1.0 run is
  unmarked by definition, because no marked run could be produced before this amendment.

Rejected alternatives:

| Alternative | Reason rejected |
|---|---|
| A field in `Provenance` | `Provenance` also describes benchmarks and references, which never have a target host |
| Always writing 1.1 with `off_platform: null` | Changes the bytes and digests of every on-platform run, evaluation and bundle for no information |
| Marking only the run | A finding copied out of its run, for example into a checklist, would lose the label |
| A new outcome such as `offplatform` | The outcome is what the scanner decided; the marker says under which benchmark it decided it, and every outcome needs it |

## Amendment 2026-10-27: control placement and schema 1.2 (FREES-170)

[ADR 0019](0019-scc-scanner-backend-and-ci-image.md#amendment-2026-10-27-toggles-and-control-families-for-scc-frees-170)
places SCC findings under the collection's control families through the STIG mapping, so the model carries a
placement.

### Entities

| Entity | Fields |
|---|---|
| ControlPlacement | `family` and `topic` (slugs `[a-z][a-z0-9_]{0,63}`), `tags` (such slugs, at most 64, never the family), `stig_id` (a STIG ID or null), `mapped_rules` (full XCCDF rule IDs, at most 64), `partially_disabled_by` (variable names; only with mapped rules) |

`Finding` gains an optional `control`, the default `None`. The family and topic `unmapped` go together and have no
tags. Lists are stored sorted and must be unique.

### Placement module

`ControlPlacement` lives in `plugins/module_utils/compliance/placement.py`, not in `model.py`, because `model.py`
reached the module line limit of 1500 lines, which takes no justification. Every field of a placement is an
identifier with an anchored ASCII pattern, so the module validates pattern, length and counts itself, with the
standard library only and the Python 3.9 grammar, and raises `PlacementError`. The model imports that one sibling
module and turns a `PlacementError` into `ModelError` when it reads a document. The rule "the model uses only the
standard library" therefore becomes: `model.py` imports the standard library and `placement`, and `placement.py`
imports only the standard library; the unit test checks exactly that, and checks the grammar and the absence of
comments for both files. Unit tests pin `placement.RULE_PATTERN`, `MAX_ID_LENGTH` and `MAX_VARIABLES` to the model's.

### Schema version 1.2

- **Which version is written.** A run in which any finding carries a placement serializes as `"1.2"`, with `control` on
  every finding (`null` where there is none). Every other run serializes exactly as before (`"1.0"` or `"1.1"`), so
  evidence bundles and evaluations of runs without placements keep their bytes and digests.
- **Off-platform in 1.2.** `off_platform` is on the run and every finding exactly when the run is marked; the key's
  presence on the run decides.
- **What readers accept.** `SUPPORTED_SCHEMA_VERSIONS` is `{"1.0", "1.1", "1.2"}`. A `1.0` or `1.1` document must not
  hold `control`. A `1.2` document must hold it on every finding and must have at least one placement; a document whose
  content serializes as another version is refused, so every document has one canonical form.
- **Readers come first.** The report and the dashboard read 1.2 in the same change as the only writer, the audit.

Rejected alternatives:

| Alternative | Reason rejected |
|---|---|
| A family field on the finding only | Topic, tags and the mapped rules are needed to explain the grouping and the partial disables |
| Placing findings in the report from the catalogue | The report has no STIG mapping of the scanned DISA content; the audit has it, and the evidence should carry what the run was told |
| Always writing `control: null` | Changes the bytes of every existing run for no information |
