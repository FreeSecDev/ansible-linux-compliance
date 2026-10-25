# Dependency management

Scope: which bot updates which dependency, the update policy, and the vulnerability response targets.
Audience: contributors, reviewers and maintainers.

Two bots run side by side, each owning distinct ecosystems so that no dependency receives duplicate pull requests.
Pinning rules from [`AGENTS.md`](../AGENTS.md) are kept current, never relaxed.

## Status

The configuration files are committed, but the bots are not confirmed active:

- Dependabot is built into GitHub and reads `.github/dependabot.yml` from the default branch.
- Renovate needs the **Mend Renovate GitHub App** to be installed on the FreeSecDev organisation and granted this
  repository. That is a one-time setup step for the organisation owner, tracked on FREES-81. Until it is done,
  `.renovaterc.json` has no effect.

## Ownership

| Ecosystem | Owner | Why |
|---|---|---|
| Python (`uv`, `pyproject.toml`) versions and security updates | Dependabot | Native GitHub security alerts and the `uv` ecosystem keep Python updates and advisories in one place |
| GitHub Actions, pinned to full commit SHAs | Renovate | Digest pinning with release annotations ([ADR 0005](adr/0005-renovate-version-annotations.md)) |
| Container image digests | Renovate | Images are consumed by digest only |
| pre-commit hooks | Renovate | Hooks are pinned by revision |
| Terraform and OpenTofu providers | Renovate | Provider lock handling and version constraints |
| Packer plugins (future `extensions/packer/**/*.pkr.hcl`) | Renovate | Custom regex manager over `required_plugins` blocks |
| Ansible Galaxy collection requirements | Renovate | Galaxy is not supported by Dependabot |

Renovate's Python managers (`pep621`, `pip_requirements`, `pip_setup`, `pipenv`, `poetry`, `setup-cfg`) are disabled, and
Renovate runs only an explicit allow-list of managers. Dependabot is configured for the `uv` ecosystem only and never
manages GitHub Actions, containers, Terraform or anything else. A new ecosystem must be assigned to exactly one bot in
this table in the same pull request that adds it.

## Update policy

- Routine updates run weekly, on Monday morning (Europe/Amsterdam), and are grouped where related.
- Renovate waits 7 days after a release before proposing it (`minimumReleaseAge`) to reduce supply-chain risk.
  Vulnerability fixes skip that wait and the schedule.
- Major updates need approval on the Renovate dependency dashboard before a pull request is created.
- Concurrency is limited (Dependabot 5 open pull requests, Renovate 5 concurrent and 2 per hour).
- Commits use the Conventional Commit type `build`, for example `build(deps): bump ...`.
- Labels: `dependencies` plus an ecosystem label such as `python` or `ci`.
- Automerge is disabled. Every update goes through the same review and required checks as any other change.
- Update pull requests are untrusted code: they receive no cloud role and no secrets. Reviewers check changelogs,
  provenance, new maintainers and licence changes, and confirm that an action or image digest matches its release.
- Hash-locked files are regenerated, never edited by hand.

## Vulnerability response targets

| Severity | Fix or documented exception within |
|---|---|
| critical | 48 hours |
| high | 7 days |
| medium | 30 days |
| low | next scheduled update |

A fixable critical or high finding blocks a release. Ignore entries need a justification, owner, Jira issue and an expiry
no later than 90 days out. The authoritative tables are in
[the dependency-management skill reference](../.agents/skills/dependency-management/references/ownership-and-sla.md).

## Related

- [ADR 0005](adr/0005-renovate-version-annotations.md), [ADR 0006](adr/0006-toolchain-selection.md)
- [`SECURITY.md`](../SECURITY.md) for reporting vulnerabilities
- Jira: FREES-81
