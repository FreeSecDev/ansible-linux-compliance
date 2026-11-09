# 0033. Review policy: an independent verdict on the pull request, without a required GitHub approval

- **Status:** accepted
- **Date:** 2026-11-09
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
