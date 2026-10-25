---
name: documentation
description: Documentation authoring for the FreeSecDev compliance platform, with all long-form documentation kept in Git under docs/. Use when adding or changing user, architecture, security, operations, runbook, release or ADR pages, repository-root files such as README and SECURITY.md, or the docs build with markdownlint-cli2 and lychee. Ensures docs change in the same pull request as the code and never claims untested support.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Documentation

Documentation is part of the product and lives in Git. By decision of the project owner
there is no Confluence space: see ADR "Documentation in Git instead of Confluence" in
`docs/adr/`. This replaces any earlier plan that required Confluence.

## When to use

- Any change to behaviour, interfaces, variables, workflows, images or reports that users or operators can observe.
- Writing or updating an ADR, runbook, support matrix, threat model or release note.
- Editing README, CONTRIBUTING, SECURITY.md, CODE_OF_CONDUCT.md or third-party attribution.
- Changing the docs build, lint or link-check configuration.

## Inputs

- The Jira issue, the diff, and the ADRs the change implements.
- The existing page being changed, including its Git history and authorship.
- Verified facts only: test results, CI runs and support matrix data that actually exist.

## Outputs

- Pages following the tree and page contract in [references/docs-tree.md](references/docs-tree.md).
- Runbooks using [references/runbook-template.md](references/runbook-template.md).
- Root files as listed in the tree reference.
- A passing `make docs` run.

## Conventions

- Everything under `docs/`: index and overview, getting started, `architecture/`, collection design, policy model, benchmarks, `support-matrix.yml` with OS support, `aws/`, CI/CD, container build, Packer, Molecule, reporting data model, exceptions, `security/threat-model.md`, `security/operations.md`, `runbooks/`, release, development and `adr/`.
- Every page opens with its scope and intended audience in the first lines.
- Docs change in the same pull request as the code. A pull request that changes behaviour without docs is incomplete.
- Runbooks follow symptom, diagnosis, fix, verification, escalation, in that order.
- Never fabricate status, tested support or results. Unverified items are marked as untested or planned, with the issue that tracks them.
- Never silently overwrite documentation authored by others: edit in place, keep unrelated content, and rely on Git history; explain removals in the pull request.
- Use relative links, one H1 per page, fenced code blocks with a language, and no restricted benchmark text.
- Third-party content is attributed in `NOTICE` and the page that uses it.

## Quality gates

- `make docs` passes: markdownlint-cli2 for style and lychee for links, without new ignore entries.
- Every new page is reachable from the docs index.
- Every claim about support, coverage or results cites a source in the repository or a CI run.
- Command examples run as written, or are marked illustrative.
- Interface changes link their ADR.

## Common failures

- Updating code and leaving the page, variable table or example stale.
- Support matrix entries stating "supported" without a passing test run.
- Pages without scope or audience, or runbooks missing the verification step.
- Copying CIS or other restricted benchmark text into pages.
- Rewriting a colleague's page wholesale instead of making a focused edit.
- Treating a lychee failure as flaky and ignoring the URL.
- Referring to Confluence as a source of truth.

## Security requirements

- No credentials, tokens, account identifiers beyond what policy allows, or host evidence in docs or examples; use obvious placeholders.
- Security-sensitive procedures in `security/operations.md` describe the control and escalation path, not secrets.
- `SECURITY.md` states the private disclosure route and supported versions truthfully.
- Do not claim ISO 27001, PCI DSS, NIST or NIS2 compliance from a host scan.

## Documentation requirements

- This skill's own trees and templates stay in [references/docs-tree.md](references/docs-tree.md) and [references/runbook-template.md](references/runbook-template.md); update them when the structure changes.
- Record structural decisions as ADRs.
- Keep `docs/index.md` and the root README links consistent.

## Completion criteria

- All affected pages are updated in the same pull request as the code.
- `make docs` passes in CI.
- No page makes an unverified claim.
- The Jira issue lists the changed pages.

## Interaction with other skills

- Writes the ADRs requested by `architecture` and mirrors the threat model owned with `security-review`.
- Support matrix content is verified with `compliance-frameworks` and `molecule-testing`.
- Release notes and changelog pages are coordinated with `release-engineering`.
- Reporting data model pages follow `reporting-dashboard`.
- Pull request completeness is checked by `code-review`, and work is tracked through `jira-management`.
