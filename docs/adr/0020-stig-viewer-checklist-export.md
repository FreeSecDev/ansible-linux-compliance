# 0020. STIG Viewer checklist export (CKL and CKLB)

- **Status:** proposed
- **Date:** 2026-10-26
- **Deciders:** lead architect; product owner (scope, decided 2026-10-26)
- **Jira:** FREES-147 (this ADR and the exporter), FREES-146 (STIG to ComplianceAsCode mapping, see the
  [amendment](#amendment-2026-10-27-complianceascode-findings-through-the-stig-mapping-frees-146)), FREES-166 and
  FREES-171 (hardening, see the
  [second amendment](#amendment-2026-10-27-export-hardening-and-pinned-disa-identifiers-frees-166-frees-171))
- **Pull requests:** introduced by the pull request for FREES-147; amended by the pull requests for FREES-146 and for
  FREES-166 and FREES-171
- **Related:** [ADR 0013](0013-normalized-findings-model.md), [ADR 0016](0016-report-schema-and-summary-semantics.md),
  [ADR 0018](0018-evidence-bundle-provenance.md), [ADR 0019](0019-scc-scanner-backend-and-ci-image.md) (decision 9 and
  the FREES-161 amendment, decision 7)

## Context

Government users load DISA STIG checklists into STIG Viewer and upload them to eMASS. The product owner put an export
of normalized findings as CKL (STIG Viewer 2, XML) and CKLB (STIG Viewer 3, JSON) in scope. ADR 0019 decision 9
already decided that the collection writes its own checklists on the controller instead of using SCC's, and sketched a
status table. This ADR fixes the formats, the exact status strings, the waiver rule, the sources and the safety rules.

### What the findings carry

A `Finding` (ADR 0013) has the full XCCDF rule ID, the outcome, the evaluated outcome, the severity, a message, the
exception status, `disabled_by`, flags and the off-platform marker. It carries no group ID, no STIG ID, no titles and
no CCIs. A checklist needs all of them, so they must come from the benchmark that the scan evaluated.

- **SCC results carry DISA IDs natively.** Observed in the SCC 5.15 CI image on 2026-10-26 (`make scc-integration`):
  the findings' rule IDs are DISA rule IDs, `xccdf_mil.disa.stig_rule_SV-270645r1068357_rule`, and SCC's XCCDF results
  file embeds the evaluated benchmark. Every one of its 194 groups has the ID `xccdf_mil.disa.stig_group_V-<n>` and
  holds exactly one rule with a `severity` (`high`, `medium` or `low`), a `weight`, the STIG ID as `version`
  (`UBTU-24-100010`), a title, a description with DISA's escaped `<VulnDiscussion>` and related fields, CCIs
  (`ident system="http://cyber.mil/cci"`), a fix text, a DPMS target `reference`, and checks. The NIWC Enhanced content
  adds an OCIL check with check text. The `TestResult` has `target`, `target-address` and `target-facts`, whose fact
  names are `urn:scap:fact:asset:identifier:*` (OpenSCAP writes `urn:xccdf:fact:asset:identifier:*`).
- **ComplianceAsCode findings do not.** OpenSCAP findings carry ComplianceAsCode rule IDs
  (`xccdf_org.ssgproject.content_rule_*`). The CaC STIG profile references STIG IDs (`UBTU-24-*`) through `reference`
  elements (ADR 0019 decision 8), but neither the findings nor the CaC content carry the DISA group ID (`V-`) or rule
  ID with revision (`SV-...r..._rule`) that a checklist is keyed on. They come only from the DISA benchmark, through the
  join of FREES-146, which is not built.

### Format research

DISA publishes neither a CKL XML schema nor a CKLB JSON schema. The facts below come from public sources, read on
2026-10-26. No source file is committed; none of their text is reproduced beyond field and status names.

| Source | What it establishes |
|---|---|
| DISA, *STIG Viewer 3.x User Guide*, Version 1, Release 5, 11 February 2025, <https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_STIG_Viewer_3-x_User_Guide_V1R5.pdf> (8,683,744 bytes, `Last-Modified` 2026-04-28, SHA-256 `d4a27b64e717dbc9d721fd43c80b1ff08c0666c12cba0a408200a9f0be20a039` computed here) | The four statuses are Open, Not a Finding, Not Reviewed and Not Applicable (5.4.1). A checklist exports as "CKL (SV v2 format)" or CKLB, and "CKLB format can now be imported into eMASS" (5.8). STIG Viewer 2 checklists are imported with "Import V2 Checklist". XCCDF results are matched to a checklist by rule ID including its revision (5.6). Rule weight feeds the checklist score (5.4.1). Target data has a classification and is imported separately (5.4.4, 5.7). No schema is given. |
| NUWC Division Newport, STIG Manager (open source), <https://github.com/NUWCDIVNPT/stig-manager> at `300be599ace2c5b428a89ca253acd26e126dc335`: `api/source/service/AssetService.js` (`cklFromAssetStigs`, `cklbFromAssetStigs`) and `api/source/service/migrations/sql/current/20-stigman-static.sql` (table `result`) | The CKL tree `CHECKLIST` / `ASSET` / `STIGS` / `iSTIG` / `STIG_INFO` (`SI_DATA` with `SID_NAME` and `SID_DATA`) / `VULN` (`STIG_DATA` with `VULN_ATTRIBUTE` and `ATTRIBUTE_DATA`, then `STATUS`, `FINDING_DETAILS`, `COMMENTS`, `SEVERITY_OVERRIDE`, `SEVERITY_JUSTIFICATION`); the `ASSET` fields with `ROLE` `None` and `ASSET_TYPE` `Computing`; the `SI_DATA` names; the `VULN_ATTRIBUTE` names, the `STIGRef` text and repeated `CCI_REF`; the CKLB keys `title`, `id`, `active`, `mode`, `has_path`, `target_data`, `stigs` and the per-rule keys including `rule_id` without and `rule_id_src` with the `_rule` suffix. Its `result` table maps XCCDF results to CKL and CKLB statuses: `pass` to `NotAFinding` / `not_a_finding`, `fail` to `Open` / `open`, `notapplicable` to `Not_Applicable` / `not_applicable`, and `notchecked`, `unknown`, `error`, `notselected` and `informational` to `Not_Reviewed` / `not_reviewed`. |
| MITRE, hdf-libs, <https://github.com/mitre/hdf-libs> at `6fbb858ced8d311a596026cbf0fded350d6f8eac`: `hdf-converters/shared/go/checklist/ckl.go`, `cklb.go`, `status.go` | The order of the `VULN_ATTRIBUTE` entries "matching real STIG Viewer output", with `LEGACY_ID` before `CCI_REF`; the attributes STIG Viewer always writes, even empty; `cklb_version` `"1.0"` as the default; empty `ccis` written as an array, never `null`; `overrides` written as `{}`; the same four status spellings in each format. |

Where the sources differ the exporter follows the stricter one: it writes every attribute that either writes, and it
writes `cklb_version` (STIG Manager omits it). Whether STIG Viewer 3 and eMASS accept a file is not something a test
can show here; FREES-147 makes that a manual check by the owner.

## Decision

### 1. A reporting exporter over the report's own inputs

`python -m tools.reporting` gains `--export-ckl DIR`, `--export-cklb DIR` and `--checklist-content FILE`
(repeatable). The export reads exactly the scan inputs that the report reads, after the same checks: ScanRun JSON,
exceptions evaluations verified against `--exceptions-file`, and evidence bundles verified by `evidence_check`, all
size-bounded, strict and untrusted (ADR 0016, ADR 0018). `build_report_and_inputs` returns the report and those inputs,
so nothing is read twice. One checklist is written per host and benchmark:
`<host>_<benchmark>.ckl` and `.cklb`, where `<host>` is the scan run's host name and `<benchmark>` the benchmark ID
without `xccdf_mil.disa.stig_benchmark_`, each with every character outside `[A-Za-z0-9._-]` replaced by `_`.

| Module | Role |
|---|---|
| `tools/reporting/stig_content.py` | Reads DISA STIG groups, rules and `TestResult` facts from XCCDF 1.2 benchmarks, XCCDF results and SCAP 1.2 or 1.3 source data streams |
| `tools/reporting/checklist.py` | The status mapping, the asset fields and the format-neutral checklist |
| `tools/reporting/checklist_formats.py` | The CKL and CKLB writers and strict readers |
| `tools/reporting/checklist_export.py` | Selects the runs and their content, refuses what cannot be exported, renders and reads back |

### 2. Status mapping

The first row that applies decides. Statuses are written as the CKL and CKLB strings of the sources above.

| Normalized finding | Checklist status | CKL `STATUS` | CKLB `status` |
|---|---|---|---|
| any finding with an `off_platform` marker, or of a run with one, whatever its outcome (ADR 0019, FREES-161 decision 7) | Not Reviewed | `Not_Reviewed` | `not_reviewed` |
| any finding of a run that is not `completed` | Not Reviewed | `Not_Reviewed` | `not_reviewed` |
| `pass` with the flag `fixed` | Not Reviewed | `Not_Reviewed` | `not_reviewed` |
| `pass` | Not a Finding | `NotAFinding` | `not_a_finding` |
| `fail` | Open | `Open` | `open` |
| `waived` (evaluated outcome always `fail`) | Open | `Open` | `open` |
| `notapplicable` | Not Applicable | `Not_Applicable` | `not_applicable` |
| `notchecked` (including the flags `informational` and `notselected`), `error` (SCC's `unknown` and every unlisted value, ADR 0013), `disabled` | Not Reviewed | `Not_Reviewed` | `not_reviewed` |
| a rule of the content without a finding (not selected by the profile, or missing) | Not Reviewed | `Not_Reviewed` | `not_reviewed` |

- **Only a plain `pass` of a completed, on-platform run is Not a Finding.** Nothing else can be: a unit test runs every
  outcome against every run status, with and without the marker.
- **`fixed`.** ADR 0013 maps `fixed` to `pass`; the SCC backend already maps it to `error`. A remediation result is not
  a review that the requirement holds, so the exporter does not let it reach Not a Finding through any producer. This
  is stricter than STIG Manager, whose table maps `fixed` to Not a Finding.
- **The finding details explain the status.** `FINDING_DETAILS` (CKLB `finding_details`) starts with the reason for
  every Not Reviewed entry: the off-platform label `off-platform: the ubuntu 24.04 benchmark on an ubuntu 26.04 host`
  of ADR 0019, the run status and error message, the `fixed` flag, or the missing result. It then names the scanner's
  result, the reported outcome when it differs, the flags, `disabled_by`, the message, and the run (ID, scanner and
  version, start and end, profile).

### 3. Waivers keep the scanner's status

An `active` exception turns a `fail` into `waived` (ADR 0013). The exporter keeps the scanner's status, **Open**, and
writes the waiver into `COMMENTS` (CKLB `comments`): the exception ID, that it was in effect for the scan, its expiry,
the scanner's result, that a waiver never changes the checklist status and is not a review that the requirement is
met, and the exception's reason (justification, risk, framework, owner, approver and dates, as ADR 0013 builds it).
An `expired` exception and a waiver that lapsed after the scan started (`lapsed_waivers` of the evaluation) leave the
finding `fail`, Open, with a comment that says so. The comments never state the status, because rows 1 and 2 of the
table can make a waived finding Not Reviewed (off-platform, or a run that did not complete).

Why not Not Applicable for some waivers: the exceptions file has no waiver type. Every exception is a risk acceptance
of a requirement that applies and fails (ADR 0013, FREES-50); none states that a requirement does not apply to the
host, which is what Not Applicable asserts. A waiver therefore never changes the status, and in particular a `fail`
never becomes Not a Finding. eMASS and the assessor see the open finding and the documented acceptance side by side,
and STIG Viewer's own severity override stays empty for them to use.

### 4. Sources

- **SCC results** are exported directly: their rule IDs are DISA rule IDs and their content is DISA content.
- **OpenSCAP and ComplianceAsCode findings** are refused. The rule is data-driven, not by scanner name: a scan run
  with any finding whose rule ID is not a DISA STIG rule ID (`xccdf_mil.disa.stig_rule_SV-<n>r<n>_rule`) is refused
  with a message that names FREES-146, and nothing is written. A STIG mapping in the content is not enough: the CaC
  content has STIG IDs, but a checklist entry needs the DISA group and rule IDs, which only the FREES-146 join
  through the pinned DISA benchmark supplies. When FREES-146 exists, the exporter reads its mapping instead of this
  refusal; this ADR is amended then.
- **XCCDF and ARF inputs** are refused for the export: they carry neither waivers nor the off-platform marker.

### 5. Benchmark text at export time, never committed

The descriptive fields come from DISA content that the operator supplies, read at export time:

- an evidence bundle's own XCCDF results (`raw/scan/results.xml`, or `raw/scan/results.off-platform.xml`), which embed
  the pinned stream that SCC evaluated and are covered by the bundle's checksums;
- otherwise, and for ScanRun JSON and evaluations, a `--checklist-content` file: an XCCDF 1.2 benchmark, XCCDF results
  or a SCAP source data stream, such as the pinned DISA stream.

The content must describe the run, or the export is refused: exactly one benchmark with the run's benchmark ID (and, for
a completed run, its version), a `TestResult` of the run's benchmark and profile when the bundle's results have one,
and every finding's rule in it. A run that did not complete takes the single content of its benchmark whatever the
version, since it reports no result. The content is read with the hardened XML reader (no DTD, no entities, size, depth
and element bounds), text is cut and stripped of control and formatting characters, and nothing from it is committed:
tests use synthetic, DISA-shaped content with made-up text, and the CI integration test exports a real scan inside
the SCC container and discards the files.

| Checklist field | From |
|---|---|
| `Vuln_Num`, CKLB `group_id` | the group ID, `V-<n>` |
| `Rule_ID`, CKLB `rule_id_src` (`rule_id` without `_rule`) | the rule ID, `SV-<n>r<n>_rule` |
| `Rule_Ver`, `Severity`, `Weight`, `Group_Title`, `Rule_Title`, `Fix_Text` | the rule's `version`, `severity`, `weight`, the group and rule titles, `fixtext` |
| `Vuln_Discuss`, `False_Positives`, `False_Negatives`, `Documentable`, `Mitigations`, `Potential_Impact`, `Third_Party_Tools`, `Mitigation_Control`, `Responsibility`, `Security_Override_Guidance`, `IA_Controls` | the tags of the rule's description |
| `Check_Content`, `Check_Content_Ref` | the first check text and the first check content reference |
| `CCI_REF`, `LEGACY_ID`, `TargetKey` | the CCI and legacy idents and the DPMS target reference |
| `STIG_INFO` `version`, `stigid`, `title`, `description`, `releaseinfo`, `notice`; `STIGRef` | the benchmark |
| `filename` | the run's content source (`Provenance.source`) |
| `Class`, `classification`, `customname`, `source`, `MARKING` | not written or empty: nothing in the scan states them |

### 6. Asset fields

`ROLE` is `None` and `ASSET_TYPE` (CKLB `target_type`) is `Computing`, the neutral values of the sources. `HOST_NAME`
is the scan run's host name. `HOST_IP` (every routable `target-address`, loopback, link-local and unspecified
addresses dropped, in document order) and `HOST_FQDN` (the first fqdn fact) come only from the run's own XCCDF results
in its bundle, and only when every `target`, host name fact and fqdn fact in them names the run's host (first label,
case-insensitive). Otherwise they are empty; nothing is invented, and content given with `--checklist-content` never
supplies them, because it cannot be tied to the run. `HOST_MAC`, `TECH_AREA` and the web and database fields are
empty. `TARGET_COMMENT` names the exporter, the run, the scanner and the content digest, and says that the host
identity and the addresses are self-asserted by the scanned host (ADR 0018: a bundle is consistent, not authentic).

### 7. Output safety

- **A small serializer, not string templates or ElementTree.** Element names are fixed. Every text value is escaped
  (`&`, `<`, `>`, carriage return as `&#13;` so it survives parsing) and every character that XML 1.0 does not allow,
  such as a lone surrogate from a JSON escape, is replaced by U+FFFD in both formats. CKLB is written with
  `json.dumps`, ASCII escapes and no non-finite numbers.
- **Deterministic.** The same inputs give the same bytes: entries in content order, fixed key order, UUIDs version 5
  from the host, machine ID, run ID, start time, benchmark and rule, and CKLB `createdAt` and `updatedAt` set to the
  run's `finished_at`.
- **Read back before writing.** Each document is parsed again with a strict reader of the exporter's exact structure
  (`read_ckl` checks well-formedness and the element tree, `read_cklb` the exact key sets), and its statuses must equal
  the mapping. A difference refuses the export.
- **All or nothing.** When any input that parsed cannot be exported, no file is written, not even the report, and the
  status is 2. An input that did not parse has no checklist and is reported by the report (status 1).
- **Files.** Written atomically, mode 0600, into directories created with mode 0700, like the report.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| SCC's own CKL and CKLB (`saveDISACKL`, `saveDISACKLB`) | ADR 0019 decision 9: written on the untrusted host, only for NIWC Enhanced content, and blind to waivers, toggles and runs that did not complete |
| Not Applicable for waived findings | The exceptions file has no waiver type that states non-applicability; every waiver accepts the risk of a failing, applicable requirement |
| Not a Finding for waived findings | A false claim of compliance (AGENTS.md rule 9, ADR 0019 decision 9) |
| Deriving `V-<n>` from `SV-<n>` | True of current DISA content, but an inference; the group ID is in the content the scan evaluated, so it is read, never invented |
| Exporting CaC findings with STIG IDs only | A checklist entry without the DISA group and rule IDs cannot be matched by STIG Viewer or eMASS; FREES-146 supplies them |
| `xml.etree.ElementTree` to write | Writes characters that XML forbids without complaint, and Bandit flags every `xml.etree` import (B405); a fixed-name serializer is smaller to review |
| Exporting what can be exported and skipping the rest | A partial set of checklists would look complete; refusing names the problem |
| Asset IP and FQDN from any XCCDF file | `--checklist-content` cannot be tied to the run; only the bundle's own results can |
| `Class` `Unclass` and a `MARKING` | Neither is stated by the scan; the user sets classification and marking in STIG Viewer |

## Security implications

Everything the export reads is untrusted (threat model): the scan run, the bundle and the content may come from a
hostile host. The input checks of the report apply unchanged, the content reader is bounded and refuses DTDs and
entities, and every value is escaped, so a hostile string can neither add an element nor change a status; tests feed
markup, entity declarations, carriage returns and lone surrogates through findings and content. No status can be
better than the findings: the mapping is a closed table with the off-platform and incomplete-run rows first, and the
read-back refuses a file whose statuses differ. Checklists hold host data (names, addresses, messages) and the
exceptions' justifications; share them like the report. They are never committed: `.gitignore` ignores `*.ckl` and
`*.cklb`, the no-redistribution test refuses tracked checklist files, and the integration test keeps its files in the
container.

## Consequences

- The export is the only route to a checklist; `saveDISACKL` and `saveDISACKLB` stay off (ADR 0019 decision 2).
- OpenSCAP users get a clear refusal until FREES-146 lands; that issue then amends section 4.
- A new field in the findings model that changes a verdict (another outcome or flag) must be added to the table of
  section 2 first; `OUTCOME_STATUSES` covers every outcome and a unit test fails when one is added.

## Open items

1. Manual check by the owner that a CKL and a CKLB of a real SCC scan open in STIG Viewer 2 and 3 and upload to eMASS
   (FREES-147 acceptance criterion). Until then the format claims rest on the sources above.
2. `cklb_version` is `"1.0"` after MITRE hdf-libs; STIG Manager writes none and one community example writes `"1"`.
   Change it only on the owner's evidence from STIG Viewer 3.
3. OpenSCAP and ComplianceAsCode findings: FREES-146, closed by the amendment below for mapped STIG profiles.

## Amendment 2026-10-27: ComplianceAsCode findings through the STIG mapping (FREES-146)

This amendment replaces the refusal of section 4 for OpenSCAP and ComplianceAsCode findings of a ComplianceAsCode
STIG profile. Every other rule of this ADR stands.

### What the pinned ComplianceAsCode streams carry

Read from the pinned, digest-verified streams of `content/manifest.yml` (ComplianceAsCode 0.1.82) on 2026-10-27:

| Stream | STIG profile and its `version` | STIG IDs | V- and SV- IDs |
|---|---|---|---|
| `ssg-ubuntu2404-ds.xml` | `xccdf_org.ssgproject.content_profile_stig`, `V1R5` | 194 distinct `UBTU-24-*` on 239 rules, one per rule | none |
| `ssg-rhel9-ds.xml` | `..._stig` and `..._stig_gui`, both `V2R9` | 441 and 437 distinct `RHEL-09-*` on 480 and 476 rules | 488 `V-*` and 488 `SV-*r*_rule` references in the stream |

- The STIG IDs are `reference` elements of the rules whose `href` is
  `https://www.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux`. The SRG IDs use another
  `href` and are not read.
- A rule that other STIG rules need, but that checks no requirement itself, carries the text `needed_rules` there
  (`enable_authselect` in RHEL 9). It is listed as a rule without a STIG ID.
- The STIG profile states the DISA release it implements as its own `version`; no other pinned profile has a
  `V<n>R<n>` version.
- The Ubuntu stream carries neither group IDs nor rule IDs, so they must come from DISA content in any case. The RHEL 9
  `SV-` IDs carry a revision that need not be the one of the DISA content the operator has. Neither is used as a join
  key.
- Mappings are many-to-many. In Ubuntu, 23 STIG IDs have several rules, up to 6. In RHEL 9, 17 have several rules,
  up to 7, and 9 rules have several STIG IDs.

### Decision

1. **A pinned derived table from the ComplianceAsCode streams alone.** `tools/content/generate_stig_mapping.py`
   (`make stig-mapping`) reads every pinned stream through `catalog.read_benchmarks`. That function verifies the
   pinned SHA-256 before it parses a byte, and now keeps each rule's STIG ID references and each profile's `version`.
   The tool writes `content/stig-mapping.json`. For every pinned profile whose version is a DISA release, the file
   holds the release, the sorted ComplianceAsCode rules of each STIG ID, and the selected rules without one. It also
   holds the stream's file name, SHA-256, benchmark ID and version.
   - The file holds identifiers of BSD-licensed content only; no DISA content is read to make it.
   - A malformed STIG ID, or a release profile that maps none, is an error.
   - `make test-content-golden` (CI job `test-suites`) regenerates it with `--check` and fails on drift.
2. **Joined to DISA content at export time on the STIG ID.** The DISA group ID (`Vuln_Num`), rule ID (`Rule_ID`)
   and all benchmark text of an entry come from the `--checklist-content` file, which the operator supplies. They are
   joined on the DISA rule `version` (`Rule_Ver`). Nothing of DISA's is committed. The entries are the DISA rules of
   that content, in its order.
3. **Which runs.** A scan run whose benchmark and profile are in the mapping is exported through it. Otherwise a run
   whose findings are not DISA rules is still refused, now with a message that names the mapping file, the benchmark
   and the profile. The export is refused with status 2, and nothing is written, when:
   - **another ComplianceAsCode version:** the run's content SHA-256 is not the mapping's, so a scan of other content
     is never read through this mapping;
   - **no DISA benchmark, or more than one:** the content files do not hold exactly one DISA benchmark with a rule of a
     mapped STIG ID;
   - **another DISA release:** that benchmark states another release than the profile implements, or none. The
     release is `V<a>R<b>` from a version `<a>.<b>[.<n>]` (SCAP benchmarks; SCC's `001.005.007` is V1R5), or from a
     version `<a>` with `Release: <b>` in `release-info` (XCCDF STIG benchmarks).

   A mapped run's own ComplianceAsCode results are never its content. Its asset IP and FQDN therefore stay empty.
4. **Aggregation.** Each mapped ComplianceAsCode check first gets its status from the table of section 2, in the same
   order: off-platform, incomplete run, `fixed`, `waived` and the rest. A check without a finding is Not Reviewed. The
   entry then takes:

   | Mapped checks | Entry |
   |---|---|
   | any check Open (`fail`, `waived`) | Open |
   | every check with the same status | that status, so Not a Finding only when every mapped check passed |
   | checks that disagree otherwise, for example `pass` and `notapplicable` | Not Reviewed, with the counts as the reason |
   | no ComplianceAsCode rule for the STIG ID | Not Reviewed: "no ComplianceAsCode check" |

   - A ComplianceAsCode finding whose rule checks no DISA rule of the content is not exported. The asset comment
     counts such findings.
   - The finding details start with the reason of every Not Reviewed entry and name the STIG ID and every mapped check
     with its result.
   - The comments carry each check's waiver, expiry or lapse, prefixed with the check when there are several. A waiver
     therefore still never changes a status, and off-platform and incomplete runs are Not Reviewed whatever their
     outcomes.
5. **Comparison.** `--compare-stig FILE` builds the checklist of every exported run, then pairs, per host and DISA
   benchmark, the SCC run with the mapped run. It writes the status counts of both sides and every DISA rule whose
   statuses differ, as JSON with mode 0600 that holds identifiers and statuses only. A host without exactly one run of
   each kind is refused.

### Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Generate the whole mapping at export time from both files | The ComplianceAsCode side would be re-derived from whichever stream the operator has, unpinned and unreviewed; the pinned table is reviewable in pull requests and checked against the digest-verified streams in CI |
| Commit a table with the DISA `V-` and `SV-` IDs | The Ubuntu stream has none, so they would come from DISA content, which is not committed; the revision of a committed `SV-` ID would go stale against the operator's content |
| Join RHEL 9 on the `SV-` IDs it carries | The revision may differ from the operator's DISA content, and a join that works for one stream only is two code paths for one rule |
| Not Applicable when some checks pass and the rest do not apply | Not a review of the whole requirement; Not Reviewed with the reason lets the assessor decide |
| Use a mapped run's own results as its content | They hold ComplianceAsCode text, not the DISA rules a checklist needs |

### Consequences

- OpenSCAP results of a ComplianceAsCode STIG profile export as CKL and CKLB. Results of other profiles (CIS) are still
  refused.
- A ComplianceAsCode bump regenerates the mapping in the same pull request, or `make test-content-golden` fails. A run
  of the previous content is then refused by its SHA-256.
- `make scc-integration` scans the CI-only OpenSCAP image, which has the SCC image's pinned base, with the STIG
  profile. It then exports that run inside the SCC image with the DISA stream that SCC ships. The files are read back
  against an independent re-implementation of the aggregation, and the run is compared with the real SCC run of the
  same host name. The checklists and the comparison stay in the container.
- Not done here, and still open in FREES-146:
  - SCC findings that honour topic and rule toggles through SCC's tailoring (ADR 0019 decision 8);
  - SCC findings grouped by control family.

  The mapping file is the input both need.

## Amendment 2026-10-27: export hardening and pinned DISA identifiers (FREES-166, FREES-171)

This amendment follows the independent reviews of FREES-147, FREES-146 and FREES-170. Every other rule of this ADR and
of the amendment above stands, except where this one says it replaces it.

### Decision

1. **All or nothing.** Every output of one run is written to a temporary file in its target directory, with a short
   fixed-length name so that a target name at the file-system limit can still be staged. The files are renamed only
   after all of them were written. A failed write removes every temporary file, creates no output and gives status 2.
   A rename that fails after others succeeded removes the remaining temporary files; the outputs already renamed are
   complete files.
2. **File name length.** `build_all` refuses a checklist whose file name, with its longest suffix, is over 255 bytes,
   before anything is written.
3. **Bundle cross-check.** When a bundle carries its own XCCDF results, their rule results must agree with the scan run
   before the export. A rule of the run needs the same evaluated result and flags; a rule that SCC scanned and a toggle
   disabled needs SCC's result in its evidence (`scanner_result`) to be the result in the file; a rule that a
   tailoring file disabled is absent or not selected; a selected rule that the run lacks is a mismatch. This checks
   consistency only. Authenticity needs the signed bundles of FREES-140.
4. **One version rule.** The content version must be the version the run recorded, for every run. This **replaces** the
   exemption of runs that did not complete for runs that recorded a version. A run that recorded the sentinel
   `unknown` (both scanners record it when a run did not complete) recorded no version: it takes exactly one content of
   its benchmark, every entry is Not Reviewed because the run did not complete (the row of the status table stays
   reachable), and the asset comment says that the content version is unverified. A completed run with `unknown` is
   refused.
5. **Comparison pairing.** `--compare-stig` pairs the entries of the two sides by DISA rule ID, requires the same
   release, the same set of rule IDs and the same STIG ID per rule ID, and refuses anything else with `ChecklistError`.
   This **replaces** the pairing by position of the FREES-146 amendment (decision 5).
6. **Pinned DISA benchmark.** `content/stig-mapping.json` pins `disa_benchmark_id` for every profile. It is set in
   `tools/content/generate_stig_mapping.py` by hand, per ComplianceAsCode benchmark, because no pinned stream carries
   it. The export refuses DISA content of another benchmark, and the SCC toggle mapping refuses a host that reports
   another benchmark.
7. **Pinned DISA rule to STIG ID pairs, RHEL 9 only.** The pinned RHEL 9 stream states the DISA rule ID next to the
   STIG ID of a rule. The mapping holds a pair for each rule that references exactly one STIG ID (`disa_rules`, 426 for
   `stig` and 422 for `stig_gui`), as identifiers only. The generator refuses malformed IDs and a DISA rule ID paired
   with two STIG IDs. DISA content that contradicts a pair is refused, for the mapped export and for the own content
   of any run whose DISA benchmark the mapping pins; the SCC toggle mapping refuses the same from the rule list that
   the host reports (`stig.check_reported`).
   - A profile with no pairs is reported at run time: the export warns on standard error and says so in the asset
     comment, and the `scc_toggles` filter returns `pairs_checked`, which the audit role reports with a `WARNING:`
     when it is zero.
   - **Ubuntu 24.04 has no pairs, and its `disa_rules` is empty.** Its stream carries no DISA rule IDs, and the only
     source is the DISA content inside the SCC image, which is not committed. Closing the gap needs a pinned,
     digest-verified source of those IDs, as IDs only.
8. **Scanner result of a toggled SCC rule.** The details of a rule that a toggle disabled name SCC's real result from
   the finding's evidence (`Scanner result: pass`), then `Reported outcome: disabled`. A result that is not a lower-case
   word is not shown and the line falls back to `disabled`. The status stays Not Reviewed.
9. **Partial disables.** The comments of a rule whose `control.partially_disabled_by` is set carry
   `Partially disabled by: <toggles>`.
10. **Strength of an OpenSCAP result.** The guide states that a Not a Finding from OpenSCAP is only as strong as the
    ComplianceAsCode check, that the integration run had 4 rules Open under SCC but Not a Finding through OpenSCAP, and
    that SCC is the source for eMASS uploads where the DISA checks are required.

### Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Write each output as it is produced | A failure part-way leaves a partial set, which is what FREES-166 forbids |
| Join the mapped export on the pinned `SV-` IDs | The pairs cover only the unambiguous rules of one stream, and a join that works for one stream is two code paths; they are a check, not a key |
| Pairs for Ubuntu from the SCC image | The DISA content may not be committed, and the IDs would need a pinned extraction that does not exist yet |
| Keep exporting incomplete runs with unknown content versions | The version rule would differ by run status, and a mismatch could not be told from an unknown version |

### Consequences

- A bundle whose XCCDF results were edited, or that does not belong to its run, no longer exports.
- Failed scan runs export as all Not Reviewed with an unverified content version, so the record of the failure
  reaches eMASS reviewers.
- A ComplianceAsCode bump regenerates `disa_rules` with the mapping.

## References

- DISA, STIG Viewer 3.x User Guide V1R5:
  <https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_STIG_Viewer_3-x_User_Guide_V1R5.pdf>, read 2026-10-26.
- NUWC Division Newport, STIG Manager: <https://github.com/NUWCDIVNPT/stig-manager>, commit
  `300be599ace2c5b428a89ca253acd26e126dc335`, read 2026-10-26.
- MITRE, hdf-libs: <https://github.com/mitre/hdf-libs>, commit `6fbb858ced8d311a596026cbf0fded350d6f8eac`, read
  2026-10-26.
- [Checklist export guide](../ckl-export.md), [ADR 0019](0019-scc-scanner-backend-and-ci-image.md),
  [ADR 0013](0013-normalized-findings-model.md).
