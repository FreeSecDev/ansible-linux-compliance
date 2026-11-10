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

   The squash merge uses the pull request body as the commit message, so the last line of the body is the
   `Refs: FREES-<number>` footer. Attribution lines come before it. A note such as "Generated with ..." goes in a
   paragraph of its own; only trailer lines (`Key: value`, such as `Co-Authored-By:`) may share the footer's paragraph:

   ```text
   Generated with <tool>

   Co-Authored-By: <name> <email>
   Refs: FREES-22
   ```

   The footer is the last line of the body, not of the commit. GitHub appends a `---------` line and
   `Co-authored-by:` lines after the body of every squash commit, so on `main` the footer is followed by those lines
   and Git does not read it as a trailer (`git log --format='%(trailers:key=Refs)'` finds nothing). To find the key
   of a commit on `main`, search its message for a line that matches `^Refs: FREES-`. The `pr-body` workflow checks the
   footer whenever the pull request is opened, edited, reopened or pushed to; run the same check locally with
   `gh pr view <number> --json body -q .body > build/pr-body.txt` and `make lint-pr-body PR_BODY_FILE=build/pr-body.txt`.
   Dependabot pull requests are exempt: Dependabot writes its own body and has no Jira key (FREES-81).
6. An independent reviewer, an agent or a human that did not write the change, reviews the current head and posts the
   verdict on the pull request, ending with the marker
   `<!-- freesecdev-verdict: <verdict> head=<sha> reviewer=<id> -->`. A pull request merges only with an `approve` or
   `approve-with-follow-ups` verdict for its current head. When a push after the verdict only brings in `main`, a
   re-review of that update is enough: a range-diff check for a rebase, and the merge re-review for a merge of `main`
   ([ADR 0033](docs/adr/0033-review-policy-independent-verdict-without-required-approval.md), amendment of
   2026-11-10). All review threads must be resolved and `ci-gate` must pass. GitHub does not require an approving review
   ([ADR 0033](docs/adr/0033-review-policy-independent-verdict-without-required-approval.md)). The repository has no
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
