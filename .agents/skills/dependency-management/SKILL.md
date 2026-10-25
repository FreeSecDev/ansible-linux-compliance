---
name: dependency-management
description: Automated dependency updates and vulnerability triage for the FreeSecDev platform using Renovate and Dependabot with non-overlapping ownership. Use when adding or changing Renovate or Dependabot configuration, update grouping and schedules, pinned tool versions, vulnerability ignore entries, or when triaging dependency or image vulnerability findings. Produces validated configs and documented triage decisions.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Dependency management

Renovate and Dependabot both run, each owning distinct ecosystems so no dependency receives
duplicate pull requests. Pinning rules from `AGENTS.md` are kept current, not relaxed.

## When to use

- Changing `renovate.json` or `.github/dependabot.yml`.
- Adding a new pinned tool, plugin, action, image or Python package source.
- Adding a custom manager for versions held in the Makefile or version files.
- Triaging a vulnerability finding or adding, renewing or removing an ignore entry.
- Reviewing a dependency update pull request.

## Inputs

- The Jira maintenance issue that update pull requests reference.
- Current Renovate and Dependabot configuration and the version files they manage.
- Scanner output from the pipelines described in `container-security` and `python-quality`.

## Outputs

- Renovate and Dependabot configs with the ownership split below.
- Custom manager patterns for pinned versions in the Makefile and version files.
- A pull request body template with `Refs: FREES-<maintenance-issue>`.
- Vulnerability triage records and expiring ignore entries.
- Reference tables in [references/ownership-and-sla.md](references/ownership-and-sla.md) kept current.

## Conventions

- Renovate owns: container image digests, GitHub Actions SHAs, Packer plugins, OpenTofu providers, pinned tool versions through regex or custom managers (Makefile and version files), Ansible Galaxy collection requirements and pre-commit hooks.
- Dependabot owns: Python ecosystem (pip and uv) version updates and security updates.
- Renovate's Python managers are explicitly disabled to avoid duplicate pull requests.
- Group related updates; weekly schedule for routine updates; security updates are raised immediately.
- Set pull request concurrency and hourly limits.
- Major updates require approval through the Renovate dependency dashboard.
- Labels: `dependencies` plus an ecosystem label.
- Pull request body includes `Refs: FREES-<maintenance-issue>`; commits follow Conventional Commits.
- No automerge that bypasses required checks. Automerge, if allowed at all, applies only to digest and patch updates after every required check passes; an ADR decides.
- Triage uses the severity SLA table in the reference. Never suppress a finding without a written justification, and every ignore entry has an owner and an expiry date.

## Quality gates

- `renovate-config-validator` passes in CI.
- The Dependabot file is schema-valid and covers only Python ecosystems.
- No ecosystem appears in both configurations.
- Every update pull request passes the full required checks before merge.
- Expired ignore entries fail CI.

## Common failures

- Enabling Renovate pip managers while Dependabot also manages Python.
- Unpinned tool versions that no custom manager can find, so they never update.
- Regex managers that match comments or docs instead of the pinned value.
- Automerging a major update, or merging past a failing check.
- Ignore entries with no expiry or justification, hiding a real vulnerability.
- Updating a digest or SHA without confirming the release annotation matches.

## Security requirements

- Treat update pull requests as untrusted code; they get no AWS role or secrets.
- Review changelogs and provenance for new maintainers, new transitive dependencies and licence changes.
- Security updates are never delayed by schedules or grouping.
- Hash-locked files are regenerated, never hand-edited.
- Bot tokens are minimal-scope and stored in repository or environment secrets.

## Documentation requirements

- Document the ownership table, schedules, labels and triage SLAs in `docs/`.
- Record an ADR for the dual-bot model, automerge policy and ignore-entry format.
- Record each accepted vulnerability exception on the Jira issue.

## Completion criteria

- Both configs validate and a bot run produced expected pull requests with no duplicates.
- Triage decisions for open findings are recorded with owners and dates.
- The Jira maintenance issue links the configuration change and sample pull requests.

## Interaction with other skills

- Updates action pins for the `github-actions` skill and image digests for the `container-security` skill.
- Updates plugins for `packer-images` and providers for `aws-infrastructure`.
- Python update checks are enforced by the `python-quality` skill.
- High-risk updates are escalated to `security-review`; triage is logged through `jira-management`.
- Policy decisions go through the `architecture` skill; release impact is assessed by `release-engineering`.
