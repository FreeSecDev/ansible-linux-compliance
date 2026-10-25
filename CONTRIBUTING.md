# Contributing

Scope: how to propose, build and submit changes to `freesecdev.linux_compliance`.
Audience: anyone contributing code, documentation, benchmark requests or reviews.

> **Status: pre-alpha.** Nothing in this repository is released or supported yet. Interfaces will change.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security issues privately, as
described in [SECURITY.md](SECURITY.md), never in a public issue or pull request.

## Before you start

- Read [`AGENTS.md`](AGENTS.md). It holds the mandatory rules for every contributor, human or AI. Highlights: no
  `shell`, `command`, `raw` or `script` modules, fully qualified collection names, every YAML file starts with `---`,
  no inline code comments, pinned dependencies, and no restricted benchmark content.
- Open an issue or a [Discussion](https://github.com/FreeSecDev/ansible-linux-compliance/discussions) for anything
  larger than a small fix, so the approach is agreed before you invest time.
- Use the issue forms for bugs, feature requests and benchmark requests. Never attach restricted material such as CIS
  benchmark PDFs or CIS-CAT content, and never paste credentials or real host evidence.

## Workflow

1. Every change is tracked by a Jira issue in project `FREES`. Maintainers create the issue and tell you its key. If you
   do not have one yet, say so in your GitHub issue and a maintainer will assign it.
2. Create a branch from the latest `main` named `<type>/FREES-<number>-<short-slug>`, for example
   `feat/FREES-42-openscap-audit-module`.
3. Commit with [Conventional Commits](https://www.conventionalcommits.org/). End the message with a
   `Refs: FREES-<number>` footer:

   ```text
   docs: clarify audit-only default

   Refs: FREES-22
   ```

4. Keep the branch rebased on the latest `main`. The history is linear.
5. Open a pull request into `main`. Never push to `main` directly. The title is a Conventional Commit and includes the
   Jira key, for example `feat: add OpenSCAP audit module (FREES-42)`. Fill in the pull request template.
6. A reviewer other than the author must approve. All review threads must be resolved and required checks must pass.
   Approvals come from an independent review agent through the `freesecdev-review` GitHub App. The repository has no
   `CODEOWNERS` file on purpose: code-owner rules would automatically request the maintainer's review, and the project
   owner decided not to be asked for reviews.
7. Pull requests are merged by squash merge only.

User-visible changes need a changelog fragment in `changelogs/fragments/`, and behaviour changes need documentation
in the same pull request.

## Local setup

The `Makefile` is the single entry point for developers and CI. Run `make help` to list targets.

```bash
make bootstrap
make ci
```

`make bootstrap` prepares and checks the local toolchain. `make ci` reproduces standard CI locally without AWS
credentials. Details, tool versions and troubleshooting are in [docs/development.md](docs/development.md).

## Skills and AGENTS.md

Task-specific engineering guidance lives in [`.agents/skills/`](.agents/skills/), one folder per topic such as
`ansible-modules`, `python-quality`, `documentation` and `code-review`. Read the relevant skill before working in that
area. [`AGENTS.md`](AGENTS.md) lists all skills and wins over a skill if they ever disagree. AI-assisted contributions
follow exactly the same rules and review as human ones, and the human submitting them is responsible for the result.

## Decisions and ADRs

Significant decisions are recorded as Architecture Decision Records in [`docs/adr/`](docs/adr/) before or with the first
implementation that depends on them, using the template in
[`.agents/skills/architecture/references/adr-template.md`](.agents/skills/architecture/references/adr-template.md).
ADRs are numbered, never deleted, and superseded ones link to their successor. Propose an ADR in a pull request, and
link it from any change that alters an interface.

## Dependencies

Dependency updates are opened by bots with divided ownership. See
[docs/dependency-management.md](docs/dependency-management.md). Do not hand-edit lock files.

## Licence

This project is licensed under the [Apache License 2.0](LICENSE). By submitting a contribution you agree that it is
licensed under the same terms, as set out in section 5 of that licence. A Developer Certificate of Origin (DCO)
sign-off is not required. Third-party material must be compatible with Apache-2.0 and attributed in
[`NOTICE`](NOTICE).
