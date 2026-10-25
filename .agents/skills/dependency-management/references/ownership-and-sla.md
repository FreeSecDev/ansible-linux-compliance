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
| `setup-uv` `version:` input | Renovate |
| Python runtime (`.python-version`, `setup-python`) | Manual pull request |
| Security updates for Python and GitHub Actions | Dependabot security updates |
| Security fixes for images, hooks, Galaxy, providers, plugins | Renovate schedule (documented residual risk) |

Renovate Python managers stay disabled, and Renovate also disables the `pypi` and `python-version` datasources and
the `actions/python-versions` package. Renovate's `vulnerabilityAlerts` is disabled. The `pre-commit` manager is
enabled explicitly because it is off by default.

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

```text
Summary of updates and release notes links.

Refs: FREES-<maintenance-issue>
```
