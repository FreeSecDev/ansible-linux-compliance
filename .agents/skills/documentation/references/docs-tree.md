# Documentation tree and page contract

Scope: where each kind of documentation lives. Audience: contributors and reviewers.

## Tree

| Path | Content |
|---|---|
| `docs/index.md` | Overview and entry point to every page |
| `docs/getting-started.md` | First audit run, prerequisites, safe defaults |
| `docs/architecture/` | Component map, diagrams, interfaces |
| `docs/collection-design.md` | Roles, modules, plugins, variables |
| `docs/policy-model.md` | Profiles, mappings, exceptions model |
| `docs/benchmarks.md` | Benchmark sources, licensing, provenance |
| `docs/support-matrix.yml` | Machine-readable OS and benchmark support, each entry citing evidence |
| `docs/os-support.md` | Human view generated from or consistent with the matrix |
| `docs/aws/` | Accounts, OIDC, CodeBuild, ECR, S3 |
| `docs/cicd.md` | Workflows, required checks, environments |
| `docs/container-build.md` | Runner image build and digest consumption |
| `docs/packer.md` | Golden image templates |
| `docs/molecule.md` | Scenarios and how to run them |
| `docs/reporting-data-model.md` | Normalized result schema and versions |
| `docs/exceptions.md` | Waiver format, expiry, approval |
| `docs/security/threat-model.md` | Assets, trust boundaries, threats |
| `docs/security/operations.md` | Operational security controls |
| `docs/runbooks/` | One file per operational symptom |
| `docs/release.md` | Release process and verification |
| `docs/development.md` | Local setup, `make` targets, conventions |
| `docs/adr/` | Numbered decision records |

Repository root: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `NOTICE` (third-party attribution).

## Page contract

1. H1 title, then a line stating scope and a line stating audience.
2. Content limited to verified facts; unverified items marked untested or planned with a tracking issue key.
3. Relative links only; every page linked from `docs/index.md`.
4. Last section lists related ADRs and issues.

## Build

`make docs` runs markdownlint-cli2 and lychee. Tool versions come from the pinned tool manifest, not from this page.

## Required ADR

`docs/adr/` holds "Documentation in Git instead of Confluence": all long-form documentation is stored in Git, reviewed in pull requests, and versioned with the code.
