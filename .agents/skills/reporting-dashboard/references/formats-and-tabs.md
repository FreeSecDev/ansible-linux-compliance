# Input formats and dashboard tabs

## Input formats

| Format | Notes |
|---|---|
| OpenSCAP ARF and XCCDF results | defusedxml, size limit, no entities, no network |
| Scanner JSON | Backend-neutral normalized scanner output |
| JUnit XML | Test suites and cases |
| Cobertura coverage XML | Line and branch rates |
| pytest JSON | Test results |
| Molecule results | Scenario outcomes per platform |
| ansible-lint | SARIF or JSON |
| Trivy and Grype JSON | Vulnerabilities, with scanner and database date |
| SPDX and CycloneDX SBOM | Components and licences |
| Packer manifest | Built images and metadata |
| CodeBuild metadata | Build id, status, source version |

Each parser returns either normalized records or an explicit `unavailable` or `error` result with a reason. Unknown versions of a format are `error`, never guessed.

## Normalized result

- Top-level `schema_version`, `generated_from` (input checksums), `scopes`, `records`, `waivers`, `raw_artifacts`.
- Status values: `pass`, `fail`, `waived`, `not_applicable`, `not_checked`, `error`, `unavailable`.
- Severity values: `critical`, `high`, `medium`, `low`, `info`, `unknown`.

## Tabs

Overview, Compliance, CIS, DISA STIG, ANSSI, Other frameworks, Ansible lint, Ansible tests, Molecule, Python tests, Coverage, Vulnerabilities, Container security, Packer images, AWS builds, Dependencies, Exceptions, Raw artifacts.

A tab is rendered only when its report type is present. Overview always renders and states which report types are missing.

## Scope labels

`single host`, `multi-host`, `benchmark`, `fleet`. Shown beside every statistic. Different scopes are never combined into one figure.
