# 0003. Native-module remediation keyed by ComplianceAsCode rule identifiers

- **Status:** accepted (to be widened by [ADR 0032](0032-operator-control-community-modules-and-value-overrides.md) once it is accepted)
- **Date:** 2026-10-25
- **Deciders:** lead architect
- **Jira:** pending (remediation epic)
- **Pull requests:** pending

## Context

The platform must remediate controls without `ansible.builtin.shell`, `command`, `raw` or `script`,
must not disguise shell execution, and must keep one hardening implementation shared by Packer and the collection.
ComplianceAsCode generates per-profile Ansible playbooks and Bash fixes. Its generated Ansible content
uses shell and command tasks for many rules, and `oscap xccdf eval --remediate` executes Bash fixes on the host.

## Decision

Audit uses OpenSCAP with ComplianceAsCode datastreams. Remediation is implemented in this collection as
narrow control-family task files that use only native Ansible modules or this collection's typed modules.
Each remediation task is keyed by the full ComplianceAsCode XCCDF rule identifier, so one remediation
satisfies every framework that maps to that rule. Rules without a native implementation are reported as
`not remediated` and are never fixed by running upstream Bash or shell-based playbooks.

Amended by [ADR 0025](0025-own-ansible-remediation-only.md) (FREES-188): the collection also never reads the
content's `fix` elements, for values or anything else; values come from the profile's XCCDF values through pinned
mappings in `content/catalogue.yml`, and a repository guard enforces the decision.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Import ComplianceAsCode generated playbooks | Uses shell and command modules; violates the hard rule |
| `oscap --remediate` from a module | Runs upstream Bash fixes on the host; disguised shell execution |
| Third-party hardening roles | Licensing and shell usage vary; not keyed to SCAP rule identifiers |

## Benefits

Remediation is idempotent, check-mode and diff-mode aware, reviewable and tied to stable rule identifiers.

## Trade-offs

Remediation coverage grows incrementally and will lag ComplianceAsCode's coverage. The support matrix
must report remediation availability per rule family honestly.

## Security implications

Removes execution of large upstream shell fragments as root. Each family is reviewed with the `security-review` skill;
disruptive families require explicit opt-in.

## Operational consequences

Remediation coverage is tracked per profile and published in the support matrix and report.

## Amendment 2026-11-09: community modules, pending ADR 0032 (FREES-203)

[ADR 0032](0032-operator-control-community-modules-and-value-overrides.md) §1 proposes to widen the module rule.
**Once ADR 0032 is accepted**, remediation may also use modules of community collections that are pinned to an exact
version in `galaxy.yml` and the requirements files, are on the allow list of a new repository rule, and run no
process outside ADR 0004. Until then this ADR applies unchanged. The ban on `shell`, `command`, `raw` and `script`
and on every form of scanner remediation stays either way.
