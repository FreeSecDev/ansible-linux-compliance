# Security policy

Scope: how to report a vulnerability in `freesecdev.linux_compliance` and what to expect.
Audience: security researchers, users and contributors.

## Supported versions

The project is **pre-alpha**. No version has been released and no version is supported yet. Security fixes land on
`main`. This section will list supported versions once the first release exists.

## Reporting a vulnerability

Report privately using GitHub private vulnerability reporting:
<https://github.com/FreeSecDev/ansible-linux-compliance/security/advisories/new>

Do not open a public issue, discussion or pull request for a suspected vulnerability.

Please include:

- the affected component and commit or version;
- steps or a minimal, synthetic proof of concept to reproduce it;
- the impact you expect, and any suggested fix.

**Never include secrets in a report.** Do not send passwords, tokens, keys, cloud credentials, real host evidence or
scan output from systems you do not own. If you found a live credential, say where it was exposed without pasting its
value, and rotate it if it is yours. Maintainers will never ask you for secrets either.

## Scope

In scope:

- the collection, its modules, action plugins, roles, playbooks and `module_utils` code;
- the CI/CD workflows, build configuration and repository settings in this repository;
- release artifacts of this project, such as the collection tarball, checksums, SBOMs and attestations, once published.

Out of scope: vulnerabilities in third-party software such as OpenSCAP, ComplianceAsCode content, Ansible or GitHub
itself (report those upstream), and findings that need an already compromised managed host or controller.

## What to expect

This is a volunteer project and the following are targets, not guarantees.

| Step | Target |
|---|---|
| Acknowledge your report | within 3 working days |
| Initial assessment and severity | within 7 days |
| Fix or documented exception, critical | 48 hours |
| Fix or documented exception, high | 7 days |
| Fix or documented exception, medium | 30 days |
| Fix or documented exception, low | next scheduled update |

The fix targets match the severity table in
[`.agents/skills/dependency-management/references/ownership-and-sla.md`](.agents/skills/dependency-management/references/ownership-and-sla.md)
and start when the report is confirmed. We will coordinate disclosure with you, publish a GitHub security advisory for
confirmed issues, and credit you if you wish.

Reports of unacceptable behaviour, not vulnerabilities, follow the [Code of Conduct](CODE_OF_CONDUCT.md).
