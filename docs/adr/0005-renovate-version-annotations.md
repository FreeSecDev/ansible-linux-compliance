# 0005. Version annotations on pinned GitHub Actions

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending (CI/CD epic)
- **Pull requests:** pending

## Context

Third-party actions must be pinned to full commit SHAs and kept current by Renovate. The project
forbids inline code comments. Renovate relies on a trailing `# vX.Y.Z` annotation to know which release a
SHA corresponds to and to propose readable updates.

## Decision

A trailing version annotation of the exact form `# vX.Y.Z` on a `uses:` line that pins a full SHA is the
only permitted comment in workflow files. It is machine-maintained metadata, not explanatory commentary.
A lint check rejects any other comment in YAML files.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| SHA without annotation | Renovate cannot present or verify release versions; reviewers cannot audit pins |
| Tags instead of SHAs | Mutable; violates immutable pinning |

## Benefits

Immutable pins that remain reviewable and automatically updatable.

## Trade-offs

A narrow, documented exception to the no-comments rule.

## Security implications

Reviewers verify that the annotation matches the SHA's release during dependency review.

## Operational consequences

The comment-lint check allows exactly this pattern and nothing else.
