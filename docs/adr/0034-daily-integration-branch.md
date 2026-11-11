# 0034. Daily integration branch: the fast tier per pull request, the full matrix once a day

- **Status:** accepted
- **Date:** 2026-11-11
- **Deciders:** project owner (request of 2026-11-11: merge more efficiently, test on the second machine before a
  merge, run the full GitHub Actions matrix once a day)
- **Jira:** FREES-215
- **Pull requests:** introduced by the pull request for FREES-215
- **Related:** [ADR 0033](0033-review-policy-independent-verdict-without-required-approval.md) (amended the same day),
  [ADR 0011](0011-control-toggles-and-cleanup.md) (affected legs, amended the same day),
  [ADR 0019](0019-scc-scanner-backend-and-ci-image.md) (SCC smoke test, unchanged), FREES-214 (measurements),
  `tools/ci/affected_legs.py`, `tools/ci/rulesets/`

## Context

FREES-214 measured `ci.yml` on 2026-11-10 with up to nine pull requests open:

- A run with the full matrix has 161 jobs: 107 Docker lifecycle legs, 29 libvirt legs and 25 other jobs. It takes
  about 1,200 runner-minutes, 94 percent of them in `molecule-lifecycle` and `molecule-libvirt`; the other jobs take
  about 65. The merge group run 42980075024 of 2026-11-11 took 1,232 runner-minutes, of which the jobs other than
  Molecule took 46, the longest of them `test` with 8.8 minutes.
- Every pull request ran that matrix on its `pull_request` run, again in its merge group and a third time on the push
  to `main`. The organisation ran at most 60 jobs at a time, so one full run occupies all runners for at least 20
  minutes. Merge groups took 55 to 140 minutes from creation to their last job, the median job waited 12 to 56
  minutes, and groups that passed the queue's check timeout were removed (`checks_timed_out`) and rebuilt together
  with every group behind them.
- Each merge into `main` put the other open pull requests behind `main`, and several of them needed a merge or rebase
  with a new full run before they could be queued (ADR 0033, amendment of 2026-11-10).

The owner has a second machine, a Docker host with 20 threads and 14 GB of memory (about 9 GB free), that runs one
Molecule leg at a time next to one unit suite. It is reached over SSH by a helper that syncs a worktree; it holds no
credentials. A self-hosted GitHub runner is ruled out: the repository is public, so a runner would execute the code of
any fork's pull request on the owner's network.

## Decision

1. **Branches.** A long-lived branch `integration` takes the work pull requests. They are squash merged, one
   Conventional Commit per pull request, title and body from the pull request (the body ends with the
   `Refs: FREES-<n>` footer, ADR 0033). `main` advances only through the merge queue: once a day by the promotion
   pull request `integration` -> `main`, and by a hotfix pull request when one is needed. Dependabot keeps opening its
   pull requests into `main` until the switch (below) and into `integration` after it.
2. **Two tiers of `ci.yml`.** The job `ci-tier` decides the tier of a run from the event, through environment
   variables only:

   | Event | Tier |
   |---|---|
   | `pull_request` into `integration` | fast |
   | `pull_request` into `main` whose head is the branch `integration` of this repository (the promotion) | fast |
   | `push` to `main` | fast |
   | `merge_group`, every other `pull_request` into `main` (a hotfix, or a branch named `integration` in a fork), `schedule`, `workflow_dispatch` | full |

   The fast tier is every job of the workflow except the five Molecule jobs: `lint`, `docs` (new: `make docs`),
   `typecheck`, `test` (unit tests with both 100% coverage gates), `test-suites`, the three check-mode playbook jobs,
   `oscap-integration`, `scc-changes` and `scc-smoke` (with their path filter, unchanged), `name-sets`, `security`,
   `collection` (sanity, ansible-test units, package check), `iac` and `molecule-collections`. About 22 jobs, about 50
   runner-minutes and ten minutes of wall clock. `molecule-images`, `molecule-docker`, `molecule-plan`,
   `molecule-lifecycle` and `molecule-libvirt` need `ci-tier` and run only in the full tier. The `pr-body` workflow
   runs for pull requests into both branches.
3. **One required check, `ci-gate`, on both branches.** `ci-gate` needs every job, as before. It accepts the fast
   tier only for the three events above, compared exactly, and only when every Molecule job was skipped; in the full
   tier it checks what it checked before. A single name keeps the rulesets simple and lets the promotion pull request
   meet the required check of `main` with its fast tier to enter the queue, while its merge group's full run decides
   the merge. The required check per branch:

   | Branch | Required check | Its run |
   |---|---|---|
   | `integration` | `ci-gate` | the fast tier of the pull request |
   | `main` | `ci-gate` | the fast tier of the promotion pull request to enter the queue; the full matrix of the merge group to merge; the full matrix for a hotfix pull request |

4. **Molecule before the merge into `integration`, on the worker.** `make affected-legs` plans the legs of the
   branch against `integration` (`origin/integration`, or `origin/main` before the switch) with the base revision's
   planner, the same as the `molecule-plan` job (`tools/molecule/plan-lifecycle.sh`), and
   `tools/ci/affected_legs.py` lists them with their `make` commands. A plan that is missing, unreadable or not a
   subset of the full matrices lists the full matrices (fail safe), and so does every path that the planner cannot
   confine to topics.
   - An `affected` plan: the standard scenarios of `molecule-docker` (when it keeps any lifecycle leg) and every
     lifecycle leg are required.
   - A `full` plan: the standard scenarios, the self-test and the legs of the topics that the plan names are
     required; the other lifecycle legs are optional, because one host runs about ten legs an hour (a full Docker
     matrix is about eleven hours there) and the daily full run covers them. The reviewer asks for more legs, or for a
     full run of the branch on GitHub (`gh workflow run ci.yml --ref <branch>`, one full run as before), when the
     change reaches beyond the named topics, for example the shared harness, a plugin that every topic uses or the
     images.
   - The libvirt legs need KVM and the hosted runner's libvirt packages and are left to the daily full run.

   The author runs the required legs before asking for a review; the independent reviewer runs them again on the
   reviewed head, or checks the author's results for that head, and the verdict lists every leg with its result
   (ADR 0033, amendment of 2026-11-11).
5. **The daily promotion.** Once a day, when `integration` holds commits that `main` lacks, one pull request
   `integration` -> `main` is opened, titled `chore: promote integration into main (<date>)`. Its body lists the pull
   requests it carries (number, title, Jira key, verdict) and the legs left to the full run, and ends with
   `Refs:` and the keys of the carried pull requests (`tools/lint/check_pr_body.py` accepts a list). It gets the merge
   re-review of ADR 0033 (amendment of 2026-11-11), its own fast tier, and is added to the merge queue, where its merge
   group runs the full matrix: the one full run of the day. The queue merges it with a merge commit (`MERGE`), so the
   squash commits of the day stay on `main` as they were reviewed and `git log --first-parent main` lists one commit
   per promotion or hotfix. No pull request is merged into `integration` while the promotion is in the queue: a new
   head removes it from the queue and costs its full run.
6. **`integration` is not reset or fast-forwarded.** After a promotion, `main` holds a merge commit that
   `integration` lacks, with the same tree. The next promotion merges cleanly, because the merge base is the last
   promoted tip. `main` therefore does not require a branch to be up to date (`strict` off); the merge queue builds
   every group on the current `main`, which is the guarantee that `strict` gave. A hotfix that lands on `main` is
   brought into `integration` by a pull request from a branch of `integration` that cherry-picks it, before the next
   promotion; the merge re-review checks that the promotion adds nothing that `integration` does not hold.
7. **A red daily run.** The queue removes the promotion and `main` stays as it was: `main` never holds a commit that
   failed the full matrix. Then, on the worker:
   1. Rerun the failed leg on the integration tip (`make affected-legs` prints its command). If it passes there and on
      a rerun of the failed job, it was a flake: record it on the Jira issue of the promotion and queue the promotion
      again.
   2. Otherwise find the culprit among the day's commits, in a separate worktree:
      `git bisect start origin/integration origin/main`, then `git bisect run <the leg's command>`. Each commit of the
      range is one squash merged pull request. A command that exits 125 skips a commit, above 127 it aborts the
      bisect (an SSH failure of the worker helper exits 255).
   3. Fix forward with a pull request into `integration`, or revert the culprit's commit there with a pull request
      (`git revert <sha>`), with the usual fast tier, legs and verdict. The promotion pull request follows
      `integration`; it gets a new merge re-review and is queued again.

   A libvirt leg cannot run on the worker: its candidates are the day's pull requests that touch its topic or the
   shared harness, and the fix is confirmed by the next full run.
8. **Hotfix path.** A pull request from any other branch into `main` stays possible. It runs the full matrix on its
   own run and in its merge group, as before, gets a full verdict, and lands as a merge commit. Its branch is one
   Conventional Commit with the `Refs` footer, because the queue no longer squashes.
9. **`push` to `main` runs the fast tier.** The merge queue fast-forwards `main` to the merge group's head, the commit
   whose full run passed, so a second full run of the same commit tells nothing new. The daily `schedule` (05:17 UTC)
   and `workflow_dispatch` still run the full matrix on `main`. This changes the statement of ADR 0011 that a push
   to `main` always runs the full matrix ([amendment](0011-control-toggles-and-cleanup.md#amendment-2026-11-11-a-push-to-main-runs-the-fast-tier-frees-215)).

### Repository settings to apply

The maintainer applies them outside the pull request; the agent may not change rulesets. Until they are applied,
nothing changes for a pull request into `main`: it runs the full matrix on its run and in its merge group as before.
The JSON files are in `tools/ci/rulesets/`; `tests/unit/tools/test_ci_tiers.py` pins them. In this order:

1. Allow merge commits, titled and described by the pull request (the queue's merge commit then carries the
   promotion's body and its `Refs` footer):

   ```text
   gh api -X PATCH repos/FreeSecDev/ansible-linux-compliance --input tools/ci/rulesets/repository-merge-settings.json
   ```

2. Create `integration` at the current `main`:

   ```text
   gh api -X POST repos/FreeSecDev/ansible-linux-compliance/git/refs -f ref=refs/heads/integration \
     -f sha="$(gh api repos/FreeSecDev/ansible-linux-compliance/git/ref/heads/main -q .object.sha)"
   ```

3. Protect `integration`: ruleset `integration-protection` with deletion and force-push protection, linear history,
   pull requests with 0 approvals, resolved threads and squash only, the required check `ci-gate` (not strict), no
   merge queue and no bypass. The deletion rule also keeps the repository's `delete_branch_on_merge` from deleting
   `integration` when the promotion merges:

   ```text
   gh api -X POST repos/FreeSecDev/ansible-linux-compliance/rulesets --input tools/ci/rulesets/integration-protection.json
   ```

4. Switch `main` (ruleset `main-protection`, ID 25825459): merge queue method `MERGE` instead of `SQUASH`, pull request
   merge method `merge` instead of `squash`, no required linear history, `ci-gate` required but not strict. The
   queue's check timeout stays 240 minutes, above the longest merge group measured (140) with room for the day's one
   full run; every other setting stays:

   ```text
   gh api -X PUT repos/FreeSecDev/ansible-linux-compliance/rulesets/25825459 --input tools/ci/rulesets/main-protection.json
   ```

After the switch, a follow-up pull request copies `tools/ci/rulesets/main-protection.json` to
`.github/rulesets/main.json`, adds `.github/rulesets/integration.json` with the live state, and sets
`target-branch: integration` for every ecosystem in `.github/dependabot.yml` (Dependabot fails on a target branch that
does not exist, so it cannot be set before). Step 4 can be reverted by applying `.github/rulesets/main.json` of the
commit before that pull request.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Keep the full matrix on every pull request and in its merge group | About 2,400 to 3,600 runner-minutes per pull request; the queue waits and timeouts measured in FREES-214 |
| Only the full matrix in the merge queue, pull requests straight into `main` | Still one full run per pull request, and every merge still puts the other pull requests behind `main` |
| A self-hosted runner on the worker | The repository is public: fork pull requests would run on the owner's network |
| A merge queue on `integration` | Its groups would rerun the fast tier that each pull request already passed; one more wait for no new evidence |
| Squash the promotion | One commit per day on `main`: a red daily run could not be bisected on `main`'s history, and each pull request's own commit, verdict and footer would be folded into one |
| Fast-forward `integration` to `main` after each promotion | A direct push to `integration`, so a bypass of its ruleset for the owner's account, which would also let that account merge into `integration` without `ci-gate` |
| A separate required check `ci-fast` | The promotion pull request must report the check that `main` requires to enter the queue; two names would need both on both branches or a check that the fast tier reports for `main` anyway |
| A larger `min_entries_to_merge` | Every queue entry still gets a merge group and a full run |

## Benefits

- One full run per day (about 1,200 runner-minutes) for all of the day's pull requests, instead of two or three per
  pull request; each pull request's GitHub run takes about ten minutes and does not wait behind a full matrix.
- Merges into `integration` do not wait for a queue, and pull requests are not put behind `main` several times a day.
- Every commit on `main` passed the full matrix in the merge queue, as before.
- The day's Molecule evidence for each pull request is still collected before its merge, on the legs its change can
  affect, by the author and again by the reviewer.

## Trade-offs

- **Partial Molecule coverage before a merge.** The worker runs one leg at a time, so a pull request runs only the
  Docker legs of its plan before it merges into `integration`, and of a `full` plan only the legs of its named topics.
  The other legs, the libvirt legs and the interactions between the day's pull requests are first tested by the
  daily full run, after the merge into `integration`. A red daily run blocks the whole day's promotion until the
  culprit is fixed or reverted.
- **`main` lags `integration` by up to a day**, and a release can only be cut from what was promoted.
- **Worker results are attested, not checked by GitHub.** GitHub sees only the fast tier of a pull request into
  `integration`; the Molecule results are in the reviewer's verdict, posted from the owner's account (ADR 0033). A
  missing or wrong table is detectable afterwards, not prevented.
- **`integration` is not strict.** Two pull requests that pass the fast tier on their own can conflict semantically
  once both are merged; the next pull request's fast tier or the daily run finds it.
- **History.** `main` holds merge commits and is no longer linear; `git log --first-parent main` reads as one entry
  per promotion or hotfix. A hotfix branch must be a single commit.
- **Image cache.** The push run on `main` no longer runs `molecule-images`, and the scheduled run never saves an image
  (T-MOLECULE-1), so each full run builds the two instance images (about 30 seconds on a normal mirror, up to ten
  minutes with its bounded retries on a slow one).

## Security implications

- No job gains a permission; `ci-tier` has none and reads the event only through environment variables, and the head
  branch name of a pull request is attacker-controlled but only compared. A fork's branch named `integration` runs
  the full matrix: the promotion is recognised only when the head repository is this repository.
- The security jobs (`security`, `lint` with zizmor and the repository rules, `collection`, `typecheck`, the coverage
  gates) run in the fast tier on every pull request, as before.
- The Molecule jobs no longer run for a pull request into `integration`, so a change to the Molecule harness or the
  images is first exercised by GitHub in the daily run, after an independent review and the worker legs. A pull
  request still cannot reach `main` without the full matrix.
- The worker holds no credentials and receives only tracked and unignored files.

## Operational consequences

- `docs/development.md` (pull request workflow, tiers, required checks), `docs/molecule.md` (legs before a merge),
  `CONTRIBUTING.md`, `AGENTS.md`, the pull request template and the `code-review` skill describe the flow.
- `tests/unit/tools/test_ci_tiers.py` pins the tier events, the jobs of each tier, the gate and the settings files;
  `tests/unit/tools/test_affected_legs.py` covers `tools/ci/affected_legs.py` to 100%.
- Until the switch, pull requests keep targeting `main` and `make affected-legs` plans against `origin/main`.
