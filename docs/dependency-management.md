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
| `astral-sh/setup-uv` `version:` input (the uv tool version) | Renovate | Read by the `github-actions` manager; Dependabot does not manage it |
| Python runtime version (`.python-version`, `setup-python` inputs) | Manual pull request | A runtime change needs full testing; Renovate disables the `python-version` datasource and the `actions/python-versions` package that `setup-python` resolves through |
| Security updates for ecosystems in GitHub's dependency graph (Python `uv`, GitHub Actions) | Dependabot | GitHub security updates are enabled for the repository; Renovate's `vulnerabilityAlerts` is disabled |
| Security fixes for container digests, pre-commit hooks, Galaxy, OpenTofu providers and Packer plugins | Renovate (scheduled) | No advisory-driven pull requests exist for these; see residual risk below |

Renovate runs only an explicit allow-list of managers, none of which is a Python manager. Two enabled managers could
still see Python data, so Renovate also disables the `pypi` datasource (Python packages in pre-commit
`additional_dependencies`), the `python-version` datasource and the `actions/python-versions` package that the
`setup-python` action's version input resolves through. Renovate's `pre-commit` manager is off by default, so it is
enabled explicitly; listing it in `enabledManagers` alone does not turn it on. Python tools used by pre-commit
run as local hooks through `uv`, so their versions live only in `pyproject.toml` and `uv.lock`, which Dependabot owns.

Dependabot version updates cover the `uv` ecosystem only. GitHub's Dependabot security updates are enabled for the whole
repository, so security pull requests for ecosystems in GitHub's dependency graph, Python (`uv`) and GitHub Actions,
come from Dependabot.
Renovate's `vulnerabilityAlerts` is disabled so the two bots never open competing security pull requests.

One overlap is accepted on purpose: a Dependabot security update to a GitHub Action can land between Renovate's
scheduled digest updates. Renovate then rebases or closes its own pull request. This keeps security fixes fast without
waiting for the Renovate schedule.

A new ecosystem must be assigned to exactly one bot in this table in the same pull request that adds it.

## Update policy

- Routine updates run weekly, on Monday morning (Europe/Amsterdam), and are grouped where related.
- Renovate waits 7 days after a release before proposing it (`minimumReleaseAge`) to reduce supply-chain risk.
  Dependabot security updates for Python and GitHub Actions are not delayed by that wait or by the schedule.
- Major updates wait 14 days, are labelled `breaking-change` and get their own pull request. Like every other update,
  they are reviewed by the `freesecdev-review` App and must pass the required checks. Nobody is asked to approve them
  on the dependency dashboard, which is informational only.
- Concurrency is limited (Dependabot 5 open pull requests, Renovate 5 concurrent and 2 per hour).
- Commits use the Conventional Commit type `build`, for example `build(deps): bump ...`.
- Labels: `dependencies` plus an ecosystem label such as `python` or `ci`.
- Automerge is disabled. Every update goes through the same review and required checks as any other change.
- Update pull requests are untrusted code: they receive no cloud role and no secrets. Reviewers check changelogs,
  provenance, new maintainers and licence changes, and confirm that an action or image digest matches its release.
- Hash-locked files are regenerated, never edited by hand.

## Residual risk

GitHub's dependency graph does not cover container images, pre-commit hooks, Ansible Galaxy collections, OpenTofu
providers or Packer plugins, and Renovate's own vulnerability alerts are disabled to avoid competing security pull
requests. A security fix in one of these ecosystems therefore arrives with the next weekly Renovate run, after the
7-day (or 14-day for majors) release age. Image and dependency scanning in CI with Grype (ADR 0006) is planned in
FREES-82 and is not active yet. Once active it will fail a build on a fixable critical or high finding in container
images and Python dependencies, and the response targets below then require a manual update pull request. It will
not cover pre-commit hooks, Galaxy collections, OpenTofu providers or Packer plugins; for those, fixes arrive only
through the Renovate schedule unless a maintainer acts on an advisory. Revisit this if Renovate's OSV-based alerts can be scoped to these ecosystems without overlapping
Dependabot. Tracked on FREES-81.

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
