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
| `--checklist-content FILE` | DISA content for runs that have none of their own (see below); repeatable |

## Inputs

| Input | Exported | Content |
|---|---|---|
| `--evidence-bundle` of an SCC scan | yes; with exceptions, from the verified evaluation | the bundle's own XCCDF results, which embed the evaluated benchmark; `--checklist-content` when the bundle has none (a scan that did not complete writes none) |
| `--scan-run` (ScanRun JSON) of an SCC scan | yes | `--checklist-content` |
| `--exceptions-evaluation` with `--exceptions-file` | yes, waivers included | `--checklist-content` |
| any input with ComplianceAsCode rule IDs (`backend: openscap`) | **refused** | needs the STIG to ComplianceAsCode mapping of FREES-146 |
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

- the findings are ComplianceAsCode rules: the message names FREES-146;
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
- `make scc-integration` exports the real SCC scan of the CI image, once with SCC's results and once with the pinned
  stream as content, and the off-platform scan of the Ubuntu 26.04 image, and reads every file back
  (`tests/system/scc/checklist_check.py`). The files stay in the container.
- Opening the files in STIG Viewer and uploading them to eMASS is a manual check (ADR 0020, open item 1).
