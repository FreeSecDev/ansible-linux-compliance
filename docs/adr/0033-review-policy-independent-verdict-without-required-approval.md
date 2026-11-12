# 0033. Review policy: an independent verdict on the pull request, without a required GitHub approval

- **Status:** accepted
- **Date:** 2026-11-09
- **Amended:** 2026-11-10 (re-review after an update from `main`, pull request body footer, merge queue timeout;
  FREES-204); 2026-11-11 (daily integration branch: worker legs in the verdict, merge re-review of the promotion;
  FREES-215)
- **Deciders:** project owner (decision of 2026-11-09: the owner's account may merge its own pull requests, and the
  agent reviews, accepts and merges)
- **Jira:** FREES-204
- **Pull requests:** introduced by the pull request for FREES-204
- **Related:** `code-review` skill, [CONTRIBUTING](../../CONTRIBUTING.md),
  [ADR 0012](0012-github-native-releases-and-packages.md) (amended here), `.github/rulesets/main.json`

## Context

The `main-protection` ruleset required one approving review, approval of the most recent push, and dismissed stale
approvals. The repository has one human account, the owner's (`stefanfluit`), which also authors every pull request.
GitHub never counts an author's approval of their own pull request. Approvals therefore came only from the
`freesecdev-review` GitHub App, whose credentials are not available to the agent that writes and merges the code.
Pull requests waited on the owner to start a review session, and the owner does not want to be asked.

The independence the `code-review` skill requires is between the author and the reviewer of a change. Until now GitHub
also enforced it, through a separate account. This ADR keeps the independence as a rule and gives up that
enforcement.

**Order of events:** the owner applied the ruleset change on 2026-11-09, at the agent's request, before this ADR was
written. AGENTS.md asks for a decision record before implementation. This ADR records the decision after the fact,
in the same session.

## Decision

1. In ruleset `main-protection`, `required_approving_review_count` is 0 and `require_last_push_approval` is false.
   `.github/rulesets/main.json` holds the new state; its Git history holds the old one.
   - **Unchanged:**
     - the merge queue, with squash merge;
     - the strict required status check `ci-gate`;
     - required linear history, non-fast-forward and deletion protection;
     - resolution of review threads.
   - **Still set but without effect:** `dismiss_stale_reviews_on_push` and
     `require_extra_approval_for_unattributed_changes`. With no approval required, there is nothing to dismiss and no
     extra approval to ask for. They stay set, so that restoring one required approval brings back their full
     behaviour.
2. Every pull request is reviewed by an independent reviewer: an agent started without the authoring context and
   given only the change and the repository, or a human who did not write the change. The reviewer reviews the diff
   and the evidence, not the description.
3. The verdict is posted on the pull request as a comment review. It ends with a machine-readable marker:

   ```text
   <!-- freesecdev-verdict: <approve|approve-with-follow-ups|request-changes> head=<40-hex SHA> reviewer=<agent or person id> -->
   ```

   A Jira comment on the issue records the same verdict, head and reviewer.
4. A pull request is added to the merge queue only when:
   - a marker with `approve` or `approve-with-follow-ups` names its current head;
   - every blocking finding is fixed and verified again by a reviewer;
   - `ci-gate` is green.

   A push after the verdict needs a new verdict for the new head. When the push only brings in `main`, a re-review
   of that update is enough. That is either a rebase whose range-diff against the reviewed head is empty, or a merge
   of `main` whose tree equals an automatic merge apart from the conflicts it resolved.
   The [amendment of 2026-11-10](#amendment-2026-11-10-re-review-after-an-update-from-main-frees-204) replaces this
   exception.
5. The release gate of ADR 0012 checks the marker instead of an approval (ADR 0012, amendment of 2026-11-09).

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Keep one required approval from the reviewer App | Blocks every merge on the owner starting a review session, which the owner rejected |
| Admin bypass of the ruleset | A bypass skips the required status checks and the merge queue as well |
| A second human account to approve | No second person; an account only for approvals would be a formality, not a review |

## Benefits

- Pull requests merge once an independent review and CI pass, without a manual step by the owner.
- CI, the merge queue and linear history are still enforced by GitHub, not by convention.

## Trade-offs

**This weakens the protection of `main`.**

- GitHub no longer enforces that any review happened, let alone an independent one.
- The verdict comment is posted from the owner's account, the same account that authors the pull request. GitHub
  cannot tell an independent verdict from a self-verdict.
- The agent that wrote a change works under the same account, so it can technically merge the change without a
  review.
- The rule rests on the `code-review` skill, on the reviewer named in the marker and on the Jira record. These make a
  missing or self-written verdict detectable afterwards, not impossible.

## Security implications

- A merge without a review, or with a verdict written by the author, is no longer technically prevented. CI still
  blocks every merge that fails a check, including the security scanners behind `ci-gate`.
- **The release gate of ADR 0012 is weaker.** It now trusts a marker posted from the author's account, where before
  it trusted an approval from a separate App identity. A release of a commit merged without a marker is still
  refused.
- If a second person gets write access, or if the App's credentials become available to the review agent, revisit
  this ADR. Restoring one required approval is a single ruleset change.

## Operational consequences

- `CONTRIBUTING.md` and the `code-review`, `release-engineering` and `dependency-management` skills state the
  verdict-based merge condition.
- `docs/dependency-management.md` and ADR 0012 state it too.
- `.github/rulesets/main.json` matches the live ruleset.

## Amendment 2026-11-10: re-review after an update from `main` (FREES-204)

**Context.** The independent re-review of this ADR asked to drop "a merge of `main`" from the re-review exception of
§4, because AGENTS.md asks for a rebase. On 2026-11-09 and 2026-11-10 (UTC commit dates) several pull requests brought
in `main` with a merge instead:

- #79: 29f206e on 2026-11-09;
- #78: 728943e on 2026-11-09, aca9658 and adef6d7 on 2026-11-10;
- #86: e0e32d4 on 2026-11-09, 6819d6a and e4d5bc1 on 2026-11-10;
- #89: 3af7609 on 2026-11-09, a80145c on 2026-11-10.

Those merges needed real conflict resolution, and the reviews around them and CI found semantic conflicts that Git
did not report:

- the merge into #78 at 728943e dropped two families from a native family list in a test;
- the merge into #86 at e4d5bc1 kept the branch's count of natively remediated rules (192) where the merged
  catalogue held 203;
- after that merge exactly 1000 rules were left `audit_only`, so a playbook floor of more than 1000 failed in CI;
- on 2026-11-10 a review found that #86 and #78 used 12 of the same internal variable names, and #86 renamed its
  prefix from `sc_` to `kp_`.

The independent re-reviews of these merges compared the merged tree with `git merge-tree` and looked for semantic
conflicts. A clean rebase can hide the same semantic conflicts.

**Decision.** Rebasing stays the rule. The last paragraph of §4 is replaced by:

A push after the verdict needs a new verdict for the new head. When the push only brings in `main`, a re-review of
that update replaces the full review. It is done by a reviewer independent of the author and of whoever resolved the
conflicts, and its verdict names the new head. Anything else in the push needs a full re-review.

- **Rebase.** `git range-diff` between the branch's commits before and after the rebase shows every commit as
  unchanged. A commit shown as changed, added or removed is reviewed as a conflict resolution (as in c. below) or
  gets a full re-review. Checks d. to f. below apply as well.
- **Merge of `main`.** Always a merge re-review with these checks, also when Git reported no conflict:
  - a. **Parents:** the merge commit has exactly two parents, the reviewed head and a commit on `main`.
  - b. **Diff against the automatic merge:** every difference between the merge commit's tree and the tree of
    `git merge-tree --write-tree <reviewed head> <main commit>` is either the resolution of a conflict that command
    reports or the fix of a semantic conflict found in d. to f., and the review names each one.
  - c. **Resolutions:** every resolved hunk keeps the intent of both sides; no line of either side is lost, and no
    line comes from neither side.
  - d. **Values both sides changed:** in every file both sides changed, conflicted or not, counts, totals, floors and
    thresholds, lists that hold the union of both sides, names and prefixes both sides introduce, and numbering are
    recomputed from their source.
  - e. **Generated files:** every generated file either side touched equals its generator's output for the merged
    sources.
  - f. **Tests:** the tests both sides added or changed pass on the merge commit, and `ci-gate` is green on it.

The review states the kind of update, the reviewed and new heads, and the result of each check. The steps and
commands are in `.agents/skills/code-review/references/re-review-after-main.md`.

## Amendment 2026-11-10: the pull request body ends with the Jira footer (FREES-204)

The repository squash merges with the pull request body as the commit message (`squash_merge_commit_message:
PR_BODY`). Several commits on `main`, among them b623e7b (this ADR), have a body that ends with attribution lines
instead of the `Refs: FREES-<n>` footer that AGENTS.md asks for.

**Decision.** The last line of the pull request body is `Refs: FREES-<n>`, in a paragraph of trailer lines only, with
attribution lines before it. The acceptance check of the `code-review` skill includes it. The `pr-body` workflow
(`make lint-pr-body`) checks it on every pull request; it is not a required status check, and a pull request runs its
own copy of the workflow and the checker. Dependabot pull requests are exempt, because Dependabot writes its own body
and has no Jira key (FREES-81).

**What this guarantees.** The squash commit on `main` carries the footer. The footer is the last line of the body,
not of the commit: GitHub appends a `---------` line and `Co-authored-by:` lines after the body of every squash
commit, so Git does not read the footer as a trailer (`git log --format='%(trailers:key=Refs)'` finds nothing).
Tooling that needs the key searches the message for a line that matches `^Refs: FREES-`.

## Amendment 2026-11-10: merge queue check timeout (FREES-204)

On 2026-11-10 the merge queue's check timeout (`check_response_timeout_minutes`) in the live ruleset was raised from
30 to 90 minutes, and the same day to 240 minutes after merge queue runs took 90 to 108 minutes.
`.github/rulesets/main.json` follows, so it still matches the live ruleset.

## Amendment 2026-11-11: the daily integration branch (FREES-215)

**Context.** [ADR 0034](0034-daily-integration-branch.md) moves the work pull requests to the branch `integration`,
where GitHub runs only the fast tier of `ci.yml`, and promotes `integration` into `main` once a day through the merge
queue, whose merge group runs the full matrix. The Molecule legs of a pull request run on a Docker host before it
merges, and GitHub does not see them.

**Decision.**

1. **Pull requests into `integration`.** Every one needs an independent verdict on its current head, as in §2 to §4;
   the merge condition is that verdict and a green `ci-gate`, which is the fast tier there. The verdict also lists the
   Molecule legs of `make affected-legs` for that head, each with its result (`passed`, `failed`, or `not run` with
   the reason), and states the plan's scope. Every required leg must have passed on the reviewed head: the reviewer
   runs them, or checks the author's results and logs for exactly that head. An optional leg of a `full` plan that
   the reviewer asks for becomes required. A verdict without the table, or with a required leg that did not pass, is
   `request-changes`.
2. **The promotion pull request** (`integration` -> `main`, once a day) brings no content of its own, so it gets a
   merge re-review by a reviewer independent of the authors of the day's pull requests where possible, and at least
   of whoever opened the promotion, with these checks:
   - a. **Head and base:** its head is the branch `integration` of this repository at the commit the verdict names,
     and its base is `main`.
   - b. **Tree:** `git merge-tree --write-tree origin/main <head>` gives exactly the tree of the head
     (`git rev-parse <head>^{tree}`), so the promotion adds nothing that `integration` does not hold; a hotfix on
     `main` that `integration` lacks is brought into `integration` first (ADR 0034, decision 6).
   - c. **Contents:** `git log --first-parent --format='%H %s' origin/main..<head>` lists only squash commits of pull
     requests merged into `integration`, each subject ending with its pull request number. The re-review lists those
     pull requests.
   - d. **Verdicts:** each of those pull requests had an `approve` or `approve-with-follow-ups` marker for the head that
     was merged, with the table of worker legs of item 1, and its follow-ups are recorded on its Jira issue.
   - e. **Footer:** the body lists the pull requests and ends with `Refs:` and their Jira keys.

   The marker names the promotion's head. A new commit on `integration` changes that head and needs a new merge
   re-review. The full matrix of the merge group decides the merge; if it fails, the procedure of ADR 0034
   (decision 7) applies and the promotion is reviewed again once `integration` holds the fix or the revert.
3. **Hotfix pull requests into `main`** stay possible. They get a full verdict as in §2 to §4 and run the full matrix
   on their own run and in their merge group, as before.

**Unchanged:** the independence of the reviewer, the marker, the re-review after an update from the target branch
(amendment of 2026-11-10; for a pull request into `integration`, read `integration` where it says `main`), the `Refs`
footer, and the release gate of ADR 0012, which for a merge commit on `main` checks the promotion's verdict, and for
each commit that a promotion brings the verdict of its pull request.

**Trade-off.** GitHub enforces only the fast tier for `integration`. That the required worker legs ran and passed
rests on the verdict, posted from the owner's account like every verdict, not on a check that GitHub can verify.
