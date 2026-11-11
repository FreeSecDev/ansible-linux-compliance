# Reviews in the daily integration flow

[ADR 0034](../../../../docs/adr/0034-daily-integration-branch.md) and
[ADR 0033, amendment of 2026-11-11](../../../../docs/adr/0033-review-policy-independent-verdict-without-required-approval.md#amendment-2026-11-11-the-daily-integration-branch-frees-215).

## A pull request into `integration`

GitHub runs only the fast tier, without Molecule. Before the verdict:

1. Check out the reviewed head in a worktree of your own and run `make -s affected-legs`. Compare the plan with the one
   the author posted; a different scope or other legs is a finding.
2. Run every leg marked `worker` on the Docker host, one at a time, or check the author's results and logs for exactly
   this head. Run an optional leg too when the change reaches beyond the named topics (shared harness, a plugin that
   every topic uses, the images); it then becomes required.
3. Put the table in the verdict with a result for every row: `passed`, `failed`, or `not run` with the reason. The
   libvirt rows stay `deferred`.

A required leg that did not pass is `request-changes`. A new push needs the legs again for the new head.

## The daily promotion `integration` -> `main`

A merge re-review; the promotion has no content of its own. With `head` the promotion's head commit:

```text
git fetch origin
test "$(git merge-tree --write-tree origin/main "$head")" = "$(git rev-parse "$head^{tree}")"
git log --first-parent --format='%H %s' origin/main.."$head"
```

- a. The head is the branch `integration` of this repository at `head`, and the base is `main`.
- b. The first command passes: the promotion adds nothing that `integration` does not hold. If it fails, `main` has a
  hotfix that `integration` lacks; it is brought into `integration` first.
- c. Every line of the log is a squash commit of a pull request merged into `integration`, its subject ending with
  `(#<number>)`. List those pull requests in the verdict.
- d. Each listed pull request had an `approve` or `approve-with-follow-ups` marker for the head that was merged, with
  the table of worker legs.
- e. The body lists the pull requests and ends with `Refs:` and their Jira keys.

The marker names `head`. A new commit on `integration` needs a new merge re-review. Nothing is merged into
`integration` while the promotion is in the merge queue.

## When the daily full run fails

The queue removes the promotion; `main` is unchanged. Rerun the failing leg on the integration tip; if it passes there
and on a rerun of the failed job, record the flake and queue the promotion again. Otherwise bisect in a separate
worktree with `git bisect start origin/integration origin/main` and `git bisect run` with the leg's command, then fix
forward or revert the culprit's commit with a pull request into `integration`, reviewed as above.
