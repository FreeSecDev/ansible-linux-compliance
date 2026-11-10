# Pull request acceptance checklist

Record each item as satisfied, not applicable (with reason) or violated.

## Traceability

- [ ] Branch name matches `<type>/FREES-<n>-<slug>`.
- [ ] Title is a Conventional Commit and references `FREES-<n>`.
- [ ] Commits end with `Refs: FREES-<n>`.
- [ ] The last line of the pull request body is `Refs: FREES-<n>`, in a paragraph of trailer lines only, with any
  attribution lines before it; the `pr-body` check passed for the current body. Not applicable to a Dependabot
  pull request (FREES-81).
- [ ] If the pull request changes `.github/workflows/pr-body.yml`, `tools/lint/check_pr_body.py` or the
  `lint-pr-body` target, that change was reviewed: a pull request runs its own copy of the workflow and the checker,
  so its `pr-body` result proves only what its own version checks.
- [ ] Jira issue updated with PR and CI links.
- [ ] Interface change links an accepted ADR.

## Content rules

- [ ] No `shell`, `command`, `raw`, `script` modules or aliases, anywhere.
- [ ] FQCN for every module, role, plugin and collection reference.
- [ ] Every YAML file starts with `---`.
- [ ] No inline comments, except Renovate `# vX.Y.Z` on pinned action lines.
- [ ] Actions pinned to full SHAs, images to digests, tools to exact versions.
- [ ] No secrets, tokens, host evidence or restricted benchmark content.
- [ ] Audit mode changes nothing on a managed host; remediation is opt-in.
- [ ] No suppression without documented justification.

## Verification

- [ ] Tests added or updated and passing.
- [ ] Documentation updated in this pull request; `make docs` passes.
- [ ] Changelog fragment present for user-visible changes.
- [ ] Required CI green, including the report artifact; no skipped required checks.
- [ ] No claim of success that CI does not show.

## Process

- [ ] Reviewer is not the author.
- [ ] `security-review` invoked when its triggers apply, verdict linked.
- [ ] Branch rebased onto latest `main`.
- [ ] A push after the last verdict that only brings in `main` passed the range-diff check (rebase) or the merge
  re-review (merge of `main`) of [re-review-after-main.md](re-review-after-main.md), including the semantic checks.
- [ ] Squash merge selected; branch auto-delete enabled.
- [ ] Verdict and PR link recorded in Jira.
