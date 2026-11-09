# 0033. Review policy: an independent verdict on the pull request, without a required GitHub approval

- **Status:** accepted
- **Date:** 2026-11-09
- **Deciders:** project owner (decision of 2026-11-09: the owner's account may merge its own pull requests, and the
  agent reviews, accepts and merges)
- **Jira:** FREES-204
- **Pull requests:** introduced by the pull request for FREES-204
- **Related:** `code-review` skill, [CONTRIBUTING](../../CONTRIBUTING.md), [ADR 0012](0012-github-native-releases-and-packages.md)

## Context

The `main-protection` ruleset required one approving review, approval of the most recent push, and dismissed stale
approvals. The repository has one human account, the owner's (`stefanfluit`), which also authors every pull request.
GitHub never counts an author's approval of their own pull request. Approvals therefore came only from the
`freesecdev-review` GitHub App, whose credentials are not available to the agent that writes and merges the code. Pull
requests waited on the owner to start a review session, and the owner does not want to be asked.

The independence the `code-review` skill requires is between the author and the reviewer of a change. That is a
property of who reviews, not of which GitHub account clicks "approve".

## Decision

1. In ruleset `main-protection`, `required_approving_review_count` is 0 and `require_last_push_approval` is false
   (applied on 2026-11-09). Everything else is unchanged:
   - the merge queue, with squash merge;
   - the strict required status check `ci-gate`;
   - required linear history, non-fast-forward and deletion protection;
   - resolution of review threads.
2. Every pull request is still reviewed by an independent reviewer: an agent started without the authoring context, or
   a human, who did not write the change. The reviewer reviews the diff and the evidence, not the description. The
   verdict (`approve`, `approve-with-follow-ups` or `request-changes`) is posted on the pull request as a review
   comment that names the reviewed head SHA. A Jira comment records it.
3. A pull request is added to the merge queue only when:
   - a verdict of `approve` or `approve-with-follow-ups` exists for its current head;
   - every blocking finding is fixed and verified again by a reviewer;
   - `ci-gate` is green.

   A push after the verdict needs a new verdict for the new head. A merge of `main` with an empty diff outside the
   merged commits needs a re-review of the merge resolution only.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Keep one required approval from the reviewer app | Blocks every merge on the owner starting a review session, which the owner rejected |
| Admin bypass of the ruleset | A bypass skips the required status checks and the merge queue as well |
| A second human account to approve | No second person; an account only for approvals would be a formality, not a review |

## Benefits

- Pull requests merge as soon as an independent review and CI pass, without a manual step by the owner.
- CI, the merge queue and linear history are still enforced by GitHub, not by convention.

## Trade-offs

- GitHub no longer enforces that a review happened. The rule rests on the `code-review` skill and on the verdict
  recorded on the pull request and in Jira. Anyone with write access could merge without a review. Today that is
  only the owner.

## Security implications

- A merge without a review is no longer technically prevented. CI, including the security scanners and `ci-gate`,
  still blocks every merge that fails a check.
- Release integrity is unaffected. Releases are built only from `main` by GitHub-hosted runners and verified with
  `--deny-self-hosted-runners` (ADR 0012).
- If a second contributor gets write access, this ADR is revisited before they do.

## Operational consequences

- `CONTRIBUTING.md` and the `code-review` skill state the verdict-based merge condition.
- The ruleset's previous state is the JSON of ruleset 25825459 before 2026-11-09. Restoring one required approval is
  a single ruleset change.
