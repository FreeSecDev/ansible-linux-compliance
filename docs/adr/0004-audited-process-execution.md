# 0004. Single audited helper for external process execution

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending (audit engine epic)
- **Pull requests:** pending

## Context

OpenSCAP must be executed as a binary. `AnsibleModule.run_command` accepts argument lists but does not
offer a timeout, and scattered process calls are hard to review.

## Decision

All external process execution in target-side code goes through
`plugins/module_utils/compliance/process.py`, which resolves the binary to an absolute path, accepts only an
argument list, runs with `shell=False`, an explicit minimal environment, a mandatory timeout and bounded
output capture, and returns a typed result. Callers validate every user-derived argument against an
allow-list or strict pattern before calling it. Ruff, Bandit and a repository test forbid `subprocess`
usage anywhere else.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| `AnsibleModule.run_command` everywhere | No timeout; harder to enforce environment and output bounds |
| Unrestricted `subprocess` per module | Not reviewable; inconsistent validation |

## Benefits

One place to review, test adversarially and keep at 100% branch coverage.

## Trade-offs

Uses `subprocess` directly rather than the Ansible wrapper, which is documented here as deliberate.

## Security implications

Eliminates shell injection paths, enforces timeouts and keeps secrets out of child environments.

## Operational consequences

Adding a new executable requires extending the helper's allow-list and a security review.
