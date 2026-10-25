# Workflow hardening checklist

## Triggers and trust

- [ ] No `pull_request_target`.
- [ ] No `workflow_run` that exposes secrets to untrusted code.
- [ ] `pull_request` and `merge_group` both trigger validation.
- [ ] Publishing runs only on protected refs or manual dispatch.

## Permissions and credentials

- [ ] `permissions: {}` at the top level.
- [ ] Each job lists the minimum scopes; `id-token: write` only where a role is assumed.
- [ ] `persist-credentials: false` on every checkout.
- [ ] Environments with required reviewers guard publishing jobs.

## Injection

- [ ] No `${{ ... }}` of untrusted data inside `run:`; values pass through `env:`.
- [ ] Shell steps quote variables; logic is in Makefile targets.

## Supply chain

- [ ] Every `uses:` pinned to a full SHA with a `# vX.Y.Z` annotation as the only comment.
- [ ] Caches keyed by trust level; privileged jobs never restore untrusted caches.
- [ ] Artifacts from untrusted runs are treated as data only.

## Reliability

- [ ] `concurrency` group on every workflow; cancel in progress only for pull requests.
- [ ] `timeout-minutes` on every job.
- [ ] `ci-gate` runs with `if: always()` and checks the result of every needed job.

## Gate sketch

The gate job lists every required job in `needs`, then fails when any needed result is
`failure` or `cancelled`. Path filters must never skip the gate itself.
