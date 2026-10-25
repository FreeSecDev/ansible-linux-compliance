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

## Amendment 2026-10-25

**Status:** accepted by the lead architect on 2026-10-25.

The single permitted comment is extended to a trailing `# vX.Y.Z` on `rev: <40-hex>` lines in
`.pre-commit-config.yaml`, in addition to `uses: owner/repo@<40-hex>` lines in workflow files.

Reason: the same as for workflow pins. Renovate's pre-commit manager and reviewers need the release version
that a pinned commit SHA corresponds to, and a bare SHA is not auditable.

Scope and enforcement: the comment must match exactly `# vX.Y.Z` after at least one space and follow a
`rev: <40-hex>` value, so mutable tags and any other comment remain rejected. `tools/lint/check_repo_rules.py`
allows exactly these two forms. Only non-Python hook repositories are pinned this way; Python tools run as
local hooks from the locked environment and are owned by Dependabot through `pyproject.toml` and `uv.lock`.

Introduced in: [pull request #3](https://github.com/FreeSecDev/ansible-linux-compliance/pull/3) (FREES-69, FREES-71).
