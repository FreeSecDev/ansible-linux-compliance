# Re-review after an update from `main`

A push after a verdict needs a new verdict for the new head
([ADR 0033](../../../../docs/adr/0033-review-policy-independent-verdict-without-required-approval.md) §4). When the
push only brings in `main`, the re-review covers that update instead of the whole change. The rules are in the ADR's
amendment of 2026-11-10; this page lists the steps.

The re-reviewer is independent of the author and of whoever resolved the conflicts. The review body states which
kind of update it covers, the reviewed head and the new head, and the result of every step below. It ends with the
verdict marker for the new head. A finding in a step is a finding like any other; anything that is not `main` or the
resolution of a conflict with `main` needs a full re-review.

Names used below:

- `R`: the head named in the last verdict marker.
- `H`: the new head of the pull request.
- `M`: the commit of `main` that the update brings in.

## Rebase onto `main`

1. **Range-diff.** Compare the commits of the branch before and after the rebase:

   ```sh
   git range-diff "$(git merge-base R origin/main)..R" "$(git merge-base H origin/main)..H"
   ```

   Every commit pair is shown as equal (`=`). A commit shown as changed (`!`), added (`>`) or removed (`<`) is not
   only `main`: review each such change as a conflict resolution (step 3 of the merge re-review) or ask for a full
   re-review.
2. **Semantic conflicts.** A rebase without conflicts can still be wrong in meaning. Apply steps 4 to 6 of the merge
   re-review, with `R` as the branch side and `M` as `main`.

## Merge of `main` into the branch

`H` is the merge commit. Run every step; none of them is optional, also when Git reported no conflict.

1. **Parents.** `git rev-list --parents -n 1 H` lists exactly two parents. The first is `R`. The second is `M`, a
   commit on `main`: `git merge-base --is-ancestor M origin/main` succeeds. Any other commit between `R` and `H`
   needs a full re-review.
2. **Diff against the automatic merge.** Recreate what Git merges on its own and compare it with `H`:

   ```sh
   git merge-tree --write-tree --name-only R M
   git diff <tree printed on the first line> H
   ```

   The first command lists the conflicted files after the tree. Every difference from the automatic tree is either the
   resolution of one of those conflicts or the fix of a semantic conflict found in steps 4 to 6, and the review names
   each one. Any other difference is a new change.
3. **Resolutions.** Read every resolved hunk next to what each side changed (`git diff <base> R -- <file>` and
   `git diff <base> M -- <file>`, with `<base>` from `git merge-base R M`). The resolution keeps the intent of both
   sides: no line of either side is lost, and no line comes from neither side.
4. **Values both sides changed.** List the files both sides changed, including those that merged without conflict:
   `comm -12 <(git diff --name-only <base> R | sort) <(git diff --name-only <base> M | sort)`. In each, look for values
   that combine rather than merge: counts and totals, floors and thresholds, lists that should hold the union of both
   sides, name prefixes and variable names that both sides introduce, and numbering such as ADR numbers. Recompute each
   value from its source.
5. **Generated files.** Regenerate every generated file that either side touched (for example `make catalogue`,
   `make toggles`, `make role-guards`, or the `lint-toggles`, `lint-role-guards` and `lint-lifecycle` checks) and
   confirm that `H` holds exactly the generated result, not a hand-merged one.
6. **Tests.** The tests both sides added or changed pass on `H`, and `ci-gate` is green on `H`. Record the commands
   and results.

## Examples from 2026-11-09 and 2026-11-10

The merges of `main` into #78 (FREES-186) and #86 (FREES-107) needed real conflict resolution. The reviews around
those merges and CI found semantic conflicts that Git did not report:

- **A count that merged silently.** In `docs/remediation.md` Git kept the branch's total of natively remediated
  rules, because `main` had not changed that paragraph. The merged catalogue held 203, not 192.
- **A list that lost entries.** Git dropped two families from a native family list in a test.
- **Shared variable prefixes.** The kernel parameter tasks and the faillock and pwhistory tasks used 12 of the same
  internal variable names (`__linux_compliance_remediate_sc_*`). The role-guard generator refused two of them; the
  other ten would have shared state between two families. The prefix was renamed to `kp_`.
- **A floor of 1000 rules.** After the merge exactly 1000 rules were left `audit_only`, so the playbook assertion
  `audit_only_rules | length > 1000` failed in CI. Every new native family lowers that count.
