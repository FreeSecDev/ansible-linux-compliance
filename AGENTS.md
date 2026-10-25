# AGENTS.md

Mandatory instructions for every human or AI agent working in this repository.
Detailed, task-specific guidance lives in [`.agents/skills/`](.agents/skills/); load the
relevant skill before starting work. This file only states the rules that always apply.

## Project

`freesecdev.linux_compliance` is an Ansible collection that audits, remediates, verifies
and reports on Linux hosts against open security baselines (OpenSCAP / ComplianceAsCode).
The CI toolbox image is built in the separate
[`FreeSecDev/linux-compliance-runner`](https://github.com/FreeSecDev/linux-compliance-runner)
repository and is consumed here by digest only.

## Traceability

- Every change maps to a Jira issue in project `FREES` on `vidlunnia.atlassian.net`.
- Branch names: `<type>/FREES-<number>-<short-slug>`, for example `feat/FREES-42-openscap-audit-module`.
- Commits follow Conventional Commits and end with a `Refs: FREES-<number>` footer.
- Every change lands through a pull request into `main`; squash merge only, rebased on the latest `main`.
- Significant decisions are recorded as ADRs in [`docs/adr/`](docs/adr/) before implementation.
- Documentation lives in Git under [`docs/`](docs/) and changes in the same PR as the code it describes.
- Record progress, decisions, blockers, failed tests, PR links and CI links on the Jira issue.

## Hard rules

1. Never use `ansible.builtin.shell`, `ansible.builtin.command`, `ansible.builtin.raw`,
   `ansible.builtin.script` or their aliases, anywhere, including Molecule and test playbooks.
   Missing functionality becomes a typed Python module, action plugin or `module_utils` code.
2. External executables (for example `oscap`) are only run from Python with an explicit argument
   list, `shell=False`, a resolved absolute binary path, validated inputs and a timeout.
3. Use fully qualified collection names for every module, role, plugin and collection reference.
4. Every YAML file starts with `---` followed by a newline.
5. No inline code comments. Use clear names, docstrings, module documentation and `docs/`.
6. Python is strictly typed (`mypy --strict`, Pyright strict) and passes Ruff, Pylint and Bandit.
7. Audit mode never changes a managed host. Remediation requires explicit opt-in.
8. Never redistribute restricted benchmark content (for example CIS PDFs or CIS-CAT content).
   Never invent rule coverage and never substitute one benchmark for another silently.
9. Never claim ISO 27001, PCI DSS, NIST or NIS2 compliance from a host scan alone.
10. Never print, commit or log credentials. AWS access is OIDC-only; no long-lived keys.
11. Pin GitHub Actions to full commit SHAs, container images to digests and tools to exact versions.
12. Never suppress a lint rule, test or security finding without a documented justification.
13. Never report work, tests, artifacts or integrations as successful unless they actually ran.

## Developer interface

The `Makefile` is the single entry point for developers and CI. Run `make help` for targets.
`make ci` reproduces standard CI locally without AWS credentials.

## Skills

| Skill | Use it for |
|---|---|
| `architecture` | Module boundaries, interfaces, ADRs |
| `ansible-collection` | Roles, playbooks, collection layout, Galaxy metadata |
| `ansible-modules` | Python modules, action plugins, `module_utils` |
| `compliance-frameworks` | Benchmarks, profiles, mappings, licensing, provenance |
| `molecule-testing` | Docker and libvirt Molecule scenarios |
| `packer-images` | Packer templates and golden images |
| `aws-infrastructure` | OpenTofu, IAM, OIDC, CodeBuild, EC2, ECR, S3 |
| `github-actions` | Workflows, permissions, required checks |
| `container-security` | Containerfiles, SBOMs, signing, image hardening |
| `python-quality` | Typing, tests, coverage, static analysis |
| `security-review` | Threat modelling and adversarial review |
| `jira-management` | Issues, links, transitions, progress logging |
| `documentation` | Repository documentation and ADRs |
| `reporting-dashboard` | Report aggregation and the HTML dashboard |
| `release-engineering` | Versioning, changelogs, packaging, signing, publishing |
| `dependency-management` | Renovate, Dependabot, vulnerability handling |
| `code-review` | Pull request review and acceptance checks |
