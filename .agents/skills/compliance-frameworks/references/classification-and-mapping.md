# Classification and mapping

## Control classification

| Class | Meaning | Platform action |
|---|---|---|
| directly auditable | Machine-checkable by the scanner | Audit and report |
| automatable remediation | Auditable and fixable with native modules | Opt-in remediation |
| evidence-only | Host evidence supports a human assessment | Collect, never score |
| manual or organizational | Process, policy or physical control | Out of scope for scans |
| unsupported | No implementation for this platform or content | Report as not covered |

## XCCDF result mapping

| XCCDF | Platform outcome |
|---|---|
| pass | pass |
| fail | fail |
| notapplicable | notapplicable |
| notchecked | notchecked |
| error | error |
| fixed | pass, flagged as fixed during scan |
| informational | notchecked, flagged informational |
| notselected | notchecked, flagged notselected |
| unknown | error |
| waived (exception file) | waived |
| excluded by operator toggle (tailoring) | disabled |

Any value not in this table is an `error`.

## Provenance record

Each mapping carries: source (ComplianceAsCode reference field), content version, datastream SHA-256, framework and control identifier.

## Support matrix fields

`os`, `version`, `arch`, `benchmark_versions`, `profiles`, `scanner_available`, `remediation_available`, `testing_status`, `restrictions`. Testing status is one of the documented enum values and links to the run that produced it.

## Licensing quick rules

- Allowed: SSG content under BSD-3-Clause with notices retained.
- Allowed: user-supplied content fetched by the user, never stored in the repository.
- Forbidden: CIS PDFs, CIS-CAT content, vendor-restricted benchmark text.
