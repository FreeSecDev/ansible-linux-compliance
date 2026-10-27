# STIG Viewer checklist export

The reporting command can write DISA STIG Viewer checklists from normalized findings: CKL files for STIG Viewer 2
(XML) and CKLB files for STIG Viewer 3 (JSON), one per host and DISA STIG benchmark. STIG Viewer 3 imports both, and its
user guide says that CKLB can be imported into eMASS. The decision record, with the format sources and the full status
table, is [ADR 0020](adr/0020-stig-viewer-checklist-export.md).

A checklist is evidence about one scan of one host. It is never a statement of compliance, and nothing in it is better
than the findings: only a plain `pass` of a completed scan made with a benchmark for the host's own release becomes
Not a Finding.

## Running it

The export rides on the normal report command and reads the same inputs. Add `--export-ckl DIR`, `--export-cklb DIR`
or both:

```bash
python -m tools.reporting --scope fleet --output build/report/report.json \
  --exceptions-file exceptions.yml \
  --evidence-bundle evidence/web01/20261026T080000.000000Z \
  --evidence-bundle evidence/db01/20261026T080001.000000Z \
  --export-ckl build/checklists --export-cklb build/checklists
```

With `make report`, pass the options in `REPORT_ARGS`. The command still writes the report (and, with `--html`, the
dashboard), then one file per host and benchmark:

```text
build/checklists/web01.example_CAN_Ubuntu_24-04_STIG.ckl
build/checklists/web01.example_CAN_Ubuntu_24-04_STIG.cklb
```

The name is the scan run's host name and the benchmark ID without `xccdf_mil.disa.stig_benchmark_`, with every
character outside `A-Z`, `a-z`, `0-9`, `.`, `_` and `-` replaced by `_`. An existing file of that name is replaced
atomically; other files in the directory are left alone, so use a fresh directory per export.

| Option | Meaning |
|---|---|
| `--export-ckl DIR` | Write CKL files (STIG Viewer 2) into `DIR`, created with mode 0700 when missing |
| `--export-cklb DIR` | Write CKLB files (STIG Viewer 3) into `DIR`; it may be the same directory |
| `--checklist-content FILE` | DISA content for runs that have none of their own, and for OpenSCAP runs (see below); repeatable |
| `--stig-mapping FILE` | The STIG to ComplianceAsCode mapping; default `content/stig-mapping.json` of the repository |
| `--compare-stig FILE` | Also write a JSON comparison of the SCC run and the OpenSCAP run of each host by DISA STIG rule |

## Inputs

| Input | Exported | Content |
|---|---|---|
| `--evidence-bundle` of an SCC scan | yes; with exceptions, from the verified evaluation | the bundle's own XCCDF results, which embed the evaluated benchmark; `--checklist-content` when the bundle has none (a scan that did not complete writes none) |
| `--scan-run` (ScanRun JSON) of an SCC scan | yes | `--checklist-content` |
| `--exceptions-evaluation` with `--exceptions-file` | yes, waivers included | `--checklist-content` |
| an input of a ComplianceAsCode STIG profile (`backend: openscap`, for example `xccdf_org.ssgproject.content_profile_stig`) of the pinned content | yes, through the [STIG mapping](#openscap-results-through-the-stig-mapping) | `--checklist-content`, always; never the bundle's own results |
| any other input with ComplianceAsCode rule IDs (a CIS profile, or other content) | **refused** | the mapping has no entry for its benchmark and profile |
| `--xccdf`, `--arf` | **refused** | they carry neither waivers nor the off-platform marker |

`--checklist-content` accepts an XCCDF 1.2 benchmark, XCCDF results or a SCAP 1.2 or 1.3 source data stream. Use the
pinned DISA stream that the scan evaluated, for example SCC's installed copy:

```bash
python -m tools.reporting --scope single_host --output build/report/report.json \
  --scan-run scan-run.json \
  --checklist-content /opt/scc/Resources/Content/SCAP12_Content/U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.xml \
  --export-cklb build/checklists
```

Rule titles, discussions, fix texts and the other benchmark text are copied from this content when the command runs.
They are never part of the collection or the repository, and the checklists must not be committed either (`.gitignore`
ignores `*.ckl` and `*.cklb`).

## Statuses

The first row that applies decides.

| Finding | Status |
|---|---|
| the scan used a benchmark for another release (off-platform, ADR 0019), whatever the outcome | Not Reviewed |
| the scan run did not complete | Not Reviewed |
| `pass` reported as `fixed` | Not Reviewed |
| `pass` | Not a Finding |
| `fail` | Open |
| `waived` | Open, with the waiver in the comments |
| `notapplicable` | Not Applicable |
| `notchecked`, `error`, `disabled` | Not Reviewed |
| a rule of the benchmark with no result | Not Reviewed |

`FINDING_DETAILS` (CKLB `finding_details`) starts with the reason for every Not Reviewed entry, for example
`off-platform: the ubuntu 24.04 benchmark on an ubuntu 26.04 host`, then names the scanner's result, the message and
the scan run.

### Waivers

A waiver from the [exceptions file](exceptions.md) never changes the status. A waived rule failed the scan, so it is
**Open**, and `COMMENTS` (CKLB `comments`) names the exception ID, that it was in effect for the scan, its expiry and
its reason (justification, risk, owner, approver and dates). An expired exception, or a waiver that lapsed after the
scan started, is named in the comments too, and the rule stays Open. The assessor sees the open finding and the
accepted risk together; STIG Viewer's severity override is left for them.

## OpenSCAP results through the STIG mapping

OpenSCAP findings are ComplianceAsCode rules. A ComplianceAsCode rule names the DISA STIG requirements it checks by
their STIG ID (`UBTU-24-100010`), which is the DISA rule's `Rule_Ver`. It does not name the DISA group ID (`V-`) or
rule ID (`SV-...r..._rule`) that a checklist needs. The export therefore joins three things on the STIG ID (ADR 0020,
amendment of FREES-146):

1. `content/stig-mapping.json`. It is generated from the pinned, digest-verified ComplianceAsCode streams alone by
   `make stig-mapping`, and checked against them in CI by `make test-content-golden`. For each ComplianceAsCode STIG
   profile it holds the DISA release the profile implements (Ubuntu 24.04: V1R5; RHEL 9: V2R9), the
   ComplianceAsCode rules of every STIG ID, and the SHA-256 of the stream. It holds identifiers only.
2. The OpenSCAP scan run of that profile and stream.
3. The DISA STIG content of that release, given with `--checklist-content`, for example SCC's copy. The group and rule
   IDs and all benchmark text come from it at export time, and are never committed.

```bash
python -m tools.reporting --scope single_host --output build/report/report.json \
  --evidence-bundle evidence/web01/20261027T080000.000000Z \
  --checklist-content U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.xml \
  --export-ckl build/checklists --export-cklb build/checklists
```

The checklist has one entry per DISA rule of the content. One STIG rule can map to several ComplianceAsCode rules,
and one rule to several STIG rules. Each mapped check gets its status by the table above, then:

| Mapped ComplianceAsCode checks | Entry |
|---|---|
| any of them Open (`fail`, `waived`) | Open |
| all of them with the same status | that status: Not a Finding only when every mapped check passed |
| otherwise, for example one `pass` and one `notapplicable` | Not Reviewed, with the disagreement as the reason |
| none: the STIG ID has no ComplianceAsCode rule | Not Reviewed: "no ComplianceAsCode check" |

Off-platform runs, runs that did not complete, `fixed` and waivers behave exactly as for SCC: every check of such a
run is Not Reviewed, and a waived check is Open with its waiver in the comments. `FINDING_DETAILS` names the STIG ID and
every mapped check with its result. A ComplianceAsCode finding that checks no rule of the DISA content is not in the
checklist, and the asset comment says how many there are. `HOST_IP` and `HOST_FQDN` stay empty, because the
ComplianceAsCode results are not DISA content.

The export refuses an OpenSCAP run, and writes nothing, when:

- it is of another ComplianceAsCode version (a SHA-256 the mapping was not generated from);
- the content files do not hold exactly one DISA benchmark with the profile's STIG IDs;
- the DISA content is of another release than the profile implements, or states none.

### Comparing SCC and OpenSCAP

`--compare-stig FILE` takes the SCC run and the OpenSCAP run of each host, with the DISA content of both. It builds
both checklists as above and writes one JSON document, mode 0600, with each side's status counts and every DISA rule on
which they differ: group, rule and STIG ID, both statuses and the mapped ComplianceAsCode rules.

```bash
python -m tools.reporting --scope single_host --output build/report/report.json \
  --scan-run scc-scan-run.json --scan-run oscap-scan-run.json \
  --checklist-content U_CAN_Ubuntu_24-04_LTS_V1R5_STIG_SCAP_1-4_Benchmark-enhancedV7-signed.xml \
  --compare-stig build/checklists/stig-comparison.json
```

A host without exactly one run of each kind is refused. A disagreement is a lead for review, not a verdict.
ComplianceAsCode treats rules that only apply to a real machine as not applicable in a container, for example, while
SCC evaluates them.

## Asset fields

| Field | Value |
|---|---|
| `HOST_NAME`, CKLB `host_name` | the scan run's host name |
| `HOST_IP`, `HOST_FQDN` | from the bundle's own XCCDF results only, and only when every target name in them is the run's host; loopback and link-local addresses are dropped; otherwise empty |
| `ROLE`, `ASSET_TYPE` | `None`, `Computing` |
| `TARGET_COMMENT`, CKLB `comments` | the exporter, the scan run and the content digest, and that the identity and addresses are self-asserted by the scanned host |
| `HOST_MAC`, `TECH_AREA`, web and database fields, classification, marking | empty: set them in STIG Viewer |

## Exit status

| Status | Meaning |
|---|---|
| 0 | the report and every checklist were written, and every input parsed |
| 1 | written, but an input is missing or invalid; that input has no checklist |
| 2 | nothing was written: invalid arguments, or an input that parsed cannot be exported honestly |
| 3 | as for the report: the dashboard was too large (checklists are written) |

Refusals with status 2 name the input and the reason:

- the findings are ComplianceAsCode rules of a profile that the STIG mapping does not cover: the message names the
  mapping, the benchmark and the profile;
- an OpenSCAP run of another ComplianceAsCode version, or DISA content of another release ("version mismatch"), or
  not exactly one DISA benchmark with the profile's STIG IDs;
- an XCCDF or ARF input;
- no DISA content of the run's benchmark and version, or more than one;
- content of another benchmark, profile or version, or a finding whose rule it lacks;
- two runs of the same host and benchmark (for example two profiles): export them separately.

Every checklist is read back with a strict reader before anything is written, and its statuses must equal the table
above.

## Security

Checklists hold host names, addresses, scanner messages and the exceptions' justifications. Share them like the report,
and keep them out of public tickets. Every input is treated as untrusted: the content is read without DTDs or entities
and within size bounds, and every value is escaped; characters that XML does not allow are replaced by U+FFFD.

## Tests

- `tests/unit/tools/reporting/checklist/`: the status table for every outcome and run status, waivers, expired and
  lapsed exceptions, off-platform runs, refusals (ComplianceAsCode findings, XCCDF inputs, missing, ambiguous or
  mismatched content, duplicate hosts), hostile strings, the asset rules, the CKLB structure schema
  `tools/reporting/schema/cklb-export.json`, and golden files from synthetic content in `tests/fixtures/checklist/`.
- `tests/unit/tools/reporting/checklist/test_checklist_mapped.py` and `test_stig_mapping.py`: the mapping with
  synthetic ComplianceAsCode and DISA-shaped fragments, covering one-to-one, one-to-many and many-to-one rules, a STIG
  rule without a check, a finding without a STIG rule, and version mismatches of either side. They also cover every
  pair of outcomes (Not a Finding only when both pass), off-platform and incomplete runs, waivers, the comparison and a
  golden CKLB. `tests/unit/tools/test_generate_stig_mapping.py` covers the generator.
- `make scc-integration` exports the real SCC scan of the CI image, once with SCC's results and once with the pinned
  stream as content, and the off-platform scan of the Ubuntu 26.04 image, and reads every file back
  (`tests/system/scc/checklist_check.py`). It also scans the CI-only OpenSCAP image with the ComplianceAsCode STIG
  profile, exports that run through the mapping with SCC's DISA stream, checks every entry against an independent
  aggregation of its findings, and compares it with the SCC run (`tests/system/scc/test_scc_oscap_checklist.py`). The
  files stay in the container.
- Opening the files in STIG Viewer and uploading them to eMASS is a manual check (ADR 0020, open item 1).
