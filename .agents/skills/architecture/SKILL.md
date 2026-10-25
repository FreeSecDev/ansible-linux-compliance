---
name: architecture
description: Architecture design for the FreeSecDev Linux compliance platform. Use when defining or changing module boundaries, public interfaces (module arguments, role variables, report schema, scanner backend protocol), repository responsibilities, cross-repository contracts, or when a decision needs an ADR. Produces ADRs in docs/adr and updates to docs/architecture.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# Architecture

Keeps the platform coherent: small composable components, stable interfaces and
recorded decisions. Only the lead architect accepts an ADR; any agent may propose one.

## When to use

- Before implementing anything that adds or changes a public interface:
  module arguments or return values, role argument specs, the normalized findings model,
  the report JSON schema, the scanner backend protocol, the image manifest or the exception file format.
- When work crosses the boundary between `ansible-linux-compliance` and `linux-compliance-runner`.
- When choosing between technologies, upstream projects or build strategies.
- When a subagent finds that its task cannot be completed without an undocumented design change.

## Inputs

- The Jira issue describing the need, its acceptance criteria and dependencies.
- Existing ADRs in `docs/adr/` and the component overview in [references/component-map.md](references/component-map.md).
- Research notes in `docs/research/` for upstream versions and compatibility.

## Outputs

- A numbered ADR `docs/adr/NNNN-kebab-title.md` following [references/adr-template.md](references/adr-template.md), status `proposed` until accepted.
- Updates to `docs/architecture/` diagrams and interface descriptions.
- Interface definitions as code where possible: typed dataclasses, argument specs, JSON schema.
- Jira tasks for the implementation work the decision implies.

## Conventions

- ADR numbers are sequential and never reused; superseded ADRs keep their file and gain a `Superseded by` link.
- An ADR records context, decision, alternatives evaluated, benefits, trade-offs, security implications, operational consequences, related Jira issues and pull requests.
- Accept the ADR in the same pull request as, or before, the first implementation that depends on it.
- Interfaces are versioned: report schema and image manifest carry a `schema_version`; module return values are additive within a major version.
- Orchestration (playbooks, top-level roles) stays separate from components (modules, task-family roles).
- Scanner backends implement one protocol; reporting and orchestration never import a concrete backend.
- Prefer maintained upstream tools over in-house implementations; justify every in-house component in an ADR.
- Avoid speculative abstraction: an extension point needs a second real consumer or a documented roadmap item.

## Quality gates

- Every new public interface has an ADR or extends one explicitly.
- The ADR lists at least two evaluated alternatives with reasons for rejection.
- Security implications are reviewed with the `security-review` skill for any change to trust boundaries.
- `docs/architecture/` matches the implemented component map after merge.

## Common failures

- Implementing first and writing the ADR afterwards to match the code.
- Letting a subagent change a schema or argument spec without an ADR.
- Coupling roles to a specific scanner, distribution or benchmark identifier.
- Duplicating hardening logic between Packer and the collection.
- Duplicating container build logic between the two repositories.
- Introducing a new repository or service without a documented need.

## Security requirements

- Every ADR has a non-empty security implications section; "none" must be justified.
- Trust boundaries are explicit: controller, managed host, CI runner, AWS build host, artifact storage, report viewer.
- Defaults are safe: audit-only, no remediation without explicit opt-in, no network access required for offline content.

## Documentation requirements

- ADRs and architecture pages live in Git; there is no separate wiki copy.
- Each ADR links its Jira issues and pull requests, and each implementing pull request links the ADR.
- Update [references/component-map.md](references/component-map.md) when components are added or removed.

## Completion criteria

- The ADR is merged with status `accepted` or `rejected`.
- Implementation tasks exist in Jira with dependency links to the ADR issue.
- Affected skills are updated if conventions changed.

## Interaction with other skills

- Requests threat analysis from `security-review` and benchmark constraints from `compliance-frameworks`.
- Defines interfaces consumed by `ansible-collection`, `ansible-modules`, `reporting-dashboard`, `packer-images` and `molecule-testing`.
- Coordinates cross-repository contracts with `container-security` and `release-engineering`.
- Records decisions through `documentation` and tracks work through `jira-management`.
