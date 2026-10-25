# 0001. Record architecture decisions

- **Status:** accepted
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending (governance epic)
- **Pull requests:** pending

## Context

The platform is built by a lead agent and delegated subagents across two repositories.
Future maintainers must be able to trace why each decision was made without undocumented knowledge.

## Decision

Record every significant decision as a numbered Markdown ADR in `docs/adr/` using the template in
`.agents/skills/architecture/references/adr-template.md`. ADRs are accepted before or with the first
implementation that depends on them and are never deleted; superseded ADRs link to their successor.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Decisions in Jira comments only | Not versioned with the code; hard to review in pull requests |
| A wiki outside Git | Rejected by ADR 0002 |
| No formal records | Fails the traceability requirement |

## Benefits

Decisions are reviewed in the same pull requests as code and are searchable with the source.

## Trade-offs

Writing ADRs adds overhead to each significant change.

## Security implications

Security-relevant decisions become reviewable artefacts; ADRs must never contain secrets.

## Operational consequences

The `code-review` skill rejects interface changes without a linked ADR.
