---
name: github-actions
description: GitHub Actions workflow design and hardening for the FreeSecDev platform. Use when adding or changing workflows, triggers, permissions, caches, environments, required checks, merge queue support, AWS OIDC usage, or the ci-gate aggregate check. Produces minimal-YAML workflows that call Makefile targets and pass actionlint and zizmor.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# GitHub Actions

Workflows are thin wrappers around Makefile targets. All logic lives in the Makefile and tools so
that `make ci` reproduces CI locally. Pull request validation and publishing are separate.

## When to use

- Adding or changing any file under `.github/workflows/` or `.github/actions/`.
- Changing triggers, permissions, environments, caches, artifacts or concurrency.
- Changing required status checks, the aggregate gate or merge queue behaviour.
- Wiring AWS OIDC roles, expensive AWS or libvirt stages, or report artifacts.

## Inputs

- The Jira issue and ADRs for runner choice, action pinning and comment exceptions.
- The Makefile target the workflow should call.
- Role and environment names from the `aws-infrastructure` skill.

## Outputs

- Workflow files that call `make` targets with minimal YAML logic.
- A single always-running aggregate required check, for example `ci-gate`.
- Job summaries that link the HTML report artifact.
- Review checklist in [references/workflow-hardening.md](references/workflow-hardening.md) completed.

## Conventions

- Every third-party action is pinned to a full commit SHA. The trailing `# vX.Y.Z` annotation on `uses:` lines is the single permitted comment exception because Renovate needs it; this exception is recorded in an ADR.
- Top-level `permissions: {}`; each job declares only what it needs.
- `actions/checkout` always sets `persist-credentials: false`.
- Never use `pull_request_target`, and never use `workflow_run` with secrets on untrusted input.
- Untrusted values (branch names, titles, inputs) pass through `env:` and are never interpolated into `run:`.
- Caches are keyed so a cache written by an untrusted pull request cannot be restored by a privileged job.
- Publishing jobs run only from trusted refs, run in tag- or branch-restricted GitHub environments and assume AWS OIDC roles. Environments have no human required reviewers; gates are automated checks in the workflow (ADR 0012).
- Every workflow sets `concurrency`; every job sets `timeout-minutes`.
- The aggregate `ci-gate` job runs with `if: always()`, depends on all required jobs and fails if any needed job failed or was cancelled, so required checks always report.
- Support the `merge_group` trigger alongside `pull_request`.
- Expensive AWS and libvirt stages use `workflow_dispatch` or explicit selective triggers.
- Self-hosted runners require an ADR. Whether libvirt runs on GitHub-hosted runners with KVM or elsewhere is an ADR decision.

## Quality gates

- `actionlint` and `zizmor` pass in CI with no undocumented suppressions.
- Every `uses:` line has a full SHA; the pin check in `make` passes.
- `ci-gate` is the only required check configured in branch protection or rulesets.
- A workflow that needs AWS shows the OIDC role, environment and condition in its pull request description.

## Common failures

- Interpolating `${{ github.head_ref }}` or `${{ inputs.* }}` inside `run:`.
- Granting `contents: write` or `id-token: write` at workflow level.
- Required checks that never report because the job was skipped by path filters.
- Restoring a cache populated by a fork pull request in a release job.
- Uploading artifacts that contain credentials or unredacted host evidence.
- Putting build logic in YAML so it cannot be reproduced locally.
- Missing `timeout-minutes`, leaving hung jobs to bill for hours.

## Security requirements

- Workflows from forks get a read-only token and no secrets and no AWS role.
- `id-token: write` is granted only to the specific job that assumes a role.
- Publishing environments are restricted to trusted refs, have administrator bypass disabled and scope their secrets; they never list human required reviewers.
- Artifacts and summaries never contain tokens or sensitive host data.
- Every workflow change is reviewed by `security-review`.

## Documentation requirements

- Update `docs/` with the workflow map, required checks and how to run each stage manually.
- Record ADRs for the comment exception, runner strategy and any trigger that expands trust.
- Document which Makefile target each job calls.

## Completion criteria

- The workflow ran on a real pull request or dispatch, and links to the run are on the Jira issue.
- actionlint, zizmor and the pin check pass.
- `ci-gate` reports on every pull request and merge group event.
- No job in the workflow lacks a timeout, concurrency group or minimal permissions.

## Interaction with other skills

- Calls targets defined under the `python-quality`, `molecule-testing` and `documentation` skills.
- Consumes roles and environments from the `aws-infrastructure` skill.
- Triggers builds owned by the `packer-images` and `container-security` skills and publishing owned by `release-engineering`.
- Action SHA updates come from the `dependency-management` skill.
- Reviewed through `security-review` and `code-review`; decisions go through `architecture`.
- Reports are produced by the `reporting-dashboard` skill.
