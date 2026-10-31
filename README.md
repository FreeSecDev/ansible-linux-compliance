# freesecdev.linux_compliance

An open-source Ansible collection to audit, harden, verify and report on Linux systems against open security
baselines, using [OpenSCAP](https://www.open-scap.org/) and
[ComplianceAsCode](https://github.com/ComplianceAsCode/content) content.

> **Status: pre-alpha.** The project is in its governance and architecture phase. Nothing in this repository is
> usable for auditing or hardening yet, and no operating system or benchmark is supported until it appears as tested
> in `docs/support-matrix.yml`.

## Principles

- Audit-only by default; remediation needs explicit opt-in, and disruptive controls need explicit allow-listing.
- Remediation uses only native Ansible modules and this collection's typed modules. There is no shell, command,
  raw or script module anywhere ([ADR 0003](docs/adr/0003-native-module-remediation.md)).
- Every remediation is this project's own Ansible. ComplianceAsCode and OpenSCAP remediation (their playbooks, Bash
  fixes, `fix` elements and `oscap --remediate`) is never run, read or shipped. The scanner content is used only to
  audit and as a reference in tests. Values come from the profile's XCCDF values through our own pinned mappings. A
  rule without a native remediation is scan-only and is reported as `not_implemented`
  ([ADR 0025](docs/adr/0025-own-ansible-remediation-only.md)).
- Restricted benchmark content (such as CIS benchmark documents) is never redistributed, and coverage is never invented.
- A host scan never proves ISO 27001, PCI DSS, NIST or NIS2 compliance on its own. Mappings are evidence only.

## Repository map

| Path | Contents |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Mandatory rules for contributors and AI agents |
| [`.agents/skills/`](.agents/skills/) | Task-specific engineering skills |
| [`docs/adr/`](docs/adr/) | Architecture decision records |
| [`docs/research/`](docs/research/) | Verified upstream compatibility research |
| [`docs/planning/`](docs/planning/) | Work breakdown mirrored to Jira project FREES |

The CI toolbox image is built in [FreeSecDev/linux-compliance-runner](https://github.com/FreeSecDev/linux-compliance-runner).

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for third-party attribution.
