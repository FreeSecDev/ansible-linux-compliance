# Ownership and triage reference

## Ownership

| Ecosystem | Owner |
|---|---|
| Container image digests | Renovate |
| GitHub Actions SHAs | Renovate |
| Packer plugins | Renovate |
| OpenTofu providers | Renovate |
| Pinned tool versions (Makefile, version files) | Renovate custom managers |
| Ansible Galaxy collection requirements | Renovate |
| pre-commit hooks | Renovate |
| Python (pip, uv) versions and security updates | Dependabot |

Renovate Python managers stay disabled.

## Severity SLA

| Severity | Fix or documented exception within |
|---|---|
| critical | 48 hours |
| high | 7 days |
| medium | 30 days |
| low | next scheduled update |

A fixable critical or high finding blocks release.

## Ignore entry format

Each entry records: finding ID, affected component, justification, owner, Jira issue,
created date and an expiry date no later than 90 days out. CI fails on expired entries.

## Pull request body template

```
Summary of updates and release notes links.

Refs: FREES-<maintenance-issue>
```
