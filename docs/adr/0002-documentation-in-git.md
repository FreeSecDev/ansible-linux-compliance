# 0002. Documentation in Git instead of Confluence

- **Status:** accepted
- **Date:** 2026-10-25
- **Deciders:** project owner, lead architect
- **Jira:** pending (documentation epic)
- **Pull requests:** pending

## Context

The original requirements asked for Confluence as the long-form knowledge base, with Git as the
canonical technical source. The project owner decided on 2026-10-25 that documentation is written in GitHub.

## Decision

All long-form documentation, runbooks, the threat model and ADRs live in `docs/` in each repository.
No Confluence space is created. Documentation may later be published as a static site via GitHub Pages.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Confluence space synchronised from Git | Owner decision; duplicate sources drift |
| Confluence only | Not versioned with code; inaccessible to public contributors |

## Benefits

One source of truth, reviewed in pull requests, available to every open-source contributor.

## Trade-offs

Non-technical stakeholders must read Markdown on GitHub. Jira issues link to Git paths instead of wiki pages.

## Security implications

Public documentation must never include host evidence, account identifiers or secrets.

## Operational consequences

The `confluence-documentation` skill from the original requirements is replaced by the `documentation` skill.
