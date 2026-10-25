---
name: reporting-dashboard
description: Builds the standalone Python reporting package under tools/reporting and its offline single-file HTML dashboard for the FreeSecDev compliance platform. Use when adding or changing report parsers (OpenSCAP ARF and XCCDF, scanner JSON, JUnit, Cobertura, pytest, Molecule, ansible-lint, Trivy, Grype, SBOM, Packer, CodeBuild), the normalized result schema, aggregation and waiver logic, or the HTML dashboard, make report and make report-serve.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Reporting dashboard

Turns heterogeneous reports into one versioned, honest result model and a self-contained
dashboard. Report files are attacker-controlled input.

## When to use

- Adding or changing a parser, the normalized schema or the aggregation rules.
- Changing the HTML dashboard, its tabs, filters or styling.
- Changing waiver, severity, deduplication or summary logic.
- Changing `make report` or `make report-serve`.

## Inputs

- Reports from [references/formats-and-tabs.md](references/formats-and-tabs.md), plus exception files.
- The ADR for the schema and the current `docs/reporting-data-model.md`.
- Real fixtures; adversarial fixtures live in `tests/fixtures/adversarial/`.

## Outputs

- Package `tools/reporting/`: Python 3.12 or newer, strictly typed, no dependency on a concrete scanner backend.
- A JSON schema with `schema_version` and the normalized result document.
- Original reports copied unchanged as raw artifacts with checksums.
- One HTML file, deterministic for equal inputs.
- Tests per [references/test-matrix.md](references/test-matrix.md).

## Conventions

- Parse XML only with defusedxml, with input size limits, entities and DTDs disabled and no network access.
- Missing, corrupt, truncated, oversized or unknown inputs become explicit `unavailable` or `error` states; they are never `pass`.
- Every statistic carries a scope label: single host, multi-host, benchmark or fleet. No averages across scopes or benchmark versions; no pass percentages without their denominator.
- Waived is a separate state from pass. An expired waiver does not suppress a finding.
- Cross-framework deduplication keeps the originating standard and rule identifiers for each finding.
- Trends use only real history supplied as input; never fabricate or interpolate points.
- HTML is one file: inline CSS and JS only, no CDN, no fonts, no network calls, a strict Content-Security-Policy meta tag, and no inline event handlers.
- Data is embedded as JSON in a non-executable script block (`type="application/json"`) with `<`, `>` and `&` escaped; rendering uses `textContent` and DOM APIs only, never `innerHTML` with report data.
- Output is deterministic: stable sorting, no random identifiers, timestamps only from inputs or an explicit parameter.
- Tabs follow the WAI-ARIA tabs pattern with keyboard navigation and appear only for available report types; see the reference for the list.
- Dark and light themes meet WCAG 2.1 AA contrast; search, sortable tables, filters (standard, distro, severity, status, host) and expandable findings are provided.
- `make report` builds the dashboard; `make report-serve` serves it locally on loopback only.

## Quality gates

- `mypy --strict`, Pyright strict, Ruff, Pylint and Bandit pass.
- Tests cover every item in [references/test-matrix.md](references/test-matrix.md).
- Classification and waiver logic has 100% line and branch coverage.
- A test proves the HTML makes no network request and contains no external URL.
- Two runs on identical inputs produce byte-identical output.

## Common failures

- Counting a parse error or empty report as a pass.
- Rendering rule titles or remediation text with `innerHTML`, enabling script injection from a crafted report.
- Averaging pass rates across hosts or benchmarks and presenting a single number.
- Letting an expired waiver keep hiding a failure.
- Embedding `</script>` from report data inside the JSON block.
- Putting the generation time in the output and breaking reproducibility.
- Merging findings from different benchmark versions as if identical.

## Security requirements

- Treat every report as hostile: bounded sizes, bounded depth, no entity expansion, no external references, no path traversal when preserving raw artifacts.
- The dashboard must not leak host evidence beyond what the user supplied; raw artifacts are included only when explicitly requested.
- `make report-serve` binds to 127.0.0.1.
- Changes to classification, parsing or HTML rendering require the `security-review` skill.

## Documentation requirements

- Update `docs/reporting-data-model.md` and the schema version notes in the same pull request.
- Document each supported format, its limits and its unavailable and error states.
- Record schema changes in an ADR.

## Completion criteria

- All formats parse or fail explicitly, and tests pass in CI.
- The schema is versioned and documented; the dashboard builds offline and deterministically.
- Accessibility and sanitization tests pass.
- The Jira issue links the pull request, CI run and an example generated from fixtures.

## Interaction with other skills

- Schema and interfaces are defined with `architecture`; the data model page is written with `documentation`.
- Benchmark identifiers and licensing constraints come from `compliance-frameworks`.
- Typing and coverage rules come from `python-quality`; injection and parser review is performed by `security-review`.
- Report artifacts are produced by workflows from `github-actions`, and scan inputs come from `container-security` and `dependency-management`.
