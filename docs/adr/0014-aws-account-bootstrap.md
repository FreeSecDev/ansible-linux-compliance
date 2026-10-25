# 0014. AWS account bootstrap

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** project owner, lead architect
- **Jira:** FREES-30 (state backend), FREES-31 (OIDC provider and roles), FREES-33 (bootstrap template), FREES-34 (budget, tagging), FREES-69 (IaC hooks)
- **Pull requests:** pending
- **Related:** [0006](0006-toolchain-selection.md), [0007](0007-registry-build-and-signing.md), [0008](0008-qcow2-builds-nested-virtualization.md), [0012](0012-github-native-releases-and-packages.md)

## Context

The platform needs an AWS account baseline before any build resource exists: a state backend for OpenTofu, a GitHub
OIDC trust so that CI never holds long-lived keys, a cost budget and a tagging standard. Account `910736812072`,
region `eu-west-1`. The `aws-infrastructure` skill requires bootstrap credentials to be SSO or short-lived and
requires the script to refuse root.

## Decision

### Bootstrap runs once as the root user (accepted deviation)

The project owner authorized their logged-in root session for the one-time bootstrap, because the account has no other
administrative identity yet. The skill's "refuse root" rule is therefore deliberately not followed. The script warns
loudly when it detects root instead of refusing.

This is an accepted risk owned by the project owner. Mitigations:

- one-time use: the procedure is idempotent but is not part of any workflow, and after it succeeds root is not used;
- typed confirmations: `yes-910736812072` before any change and `apply-910736812072` after the plan is shown;
- no keys are written: the script uses the credentials already in the session and never creates or stores access keys;
- CI is OIDC-only: workflows assume roles through the OIDC provider, and no root credential or access key exists in
  GitHub;
- the owner enables MFA on the root user after the bootstrap (recommended, and listed in the bootstrap output).

The follow-up that removes the deviation is an IAM Identity Center or administrator role for the owner, after which the
bootstrap should be run with that identity.

### State backend

State is stored in the S3 bucket `freesecdev-tfstate-910736812072-eu-west-1` with native S3 locking
(`use_lockfile = true`, OpenTofu 1.10 and later). There is no DynamoDB table: it would add a resource, a cost and an
IAM surface for the same guarantee. The bucket is created by the bootstrap script, not by OpenTofu, because the
backend must exist before `init`. It has `BucketOwnerEnforced`, versioning, all public access blocked, a TLS-only
policy and a lifecycle rule for noncurrent versions. Encryption is SSE-KMS with the AWS-managed key `aws/s3`, chosen
over SSE-S3 for the CloudTrail record of key use at no key cost. The backend block uses partial configuration; the
bucket and key come from a generated, gitignored `backend.hcl` whose shape is the committed `backend.hcl.example`.

### OIDC trust

One OIDC provider `token.actions.githubusercontent.com` with audience `sts.amazonaws.com`. AWS no longer needs
thumbprints for this provider, so none is configured. The role `freesecdev-gha-ansible-linux-compliance-plan` trusts
only tokens with:

- `aud` equal to `sts.amazonaws.com`,
- `sub` equal to `repo:FreeSecDev/ansible-linux-compliance:ref:refs/heads/main`,
- `job_workflow_ref` equal to `FreeSecDev/ansible-linux-compliance/.github/workflows/oidc-check.yml@refs/heads/main`.

All comparisons are `StringEquals`; there are no wildcards. The maximum session duration is 3600 seconds. No role is
issued to pull requests or forks. The role is read-only for `tofu plan` plus state and lock-file access on its prefix.
Build and release roles are added by later issues with their own trust: the release role is pinned to the `release`
environment of [ADR 0012](0012-github-native-releases-and-packages.md), which accepts `main` only and has no human
reviewers, so the gate is automated and the trust must not depend on a reviewer.

### Tooling

OpenTofu is pinned to `1.13.2`. It is four days old at the time of writing, but it is a security release that
replaces compromised intermediate certificates, and security fixes are exempt from the seven-day release age rule.
The AWS provider is pinned to `6.69.1` (released 2026-10-15) with a committed `.terraform.lock.hcl` holding hashes for
`linux_amd64` and `linux_arm64`. Checkov `3.3.29` (released 2026-10-13) scans `infra/` in `make security` and the
pre-commit hook, and no check is skipped. CI installs OpenTofu with `tools/iac/install-tofu.sh`, which verifies a pinned
SHA-256 for the release archive.

## Alternatives evaluated

| Alternative | Reason rejected |
|---|---|
| Refuse root and wait for an administrator role | Blocks all AWS work; the owner explicitly accepted the one-time risk |
| DynamoDB state locking | Deprecated in favour of native S3 locking; extra resource and cost |
| Create the state bucket with OpenTofu | Chicken-and-egg: the backend must exist before the first `init` |
| SSE-S3 for the state bucket | No CloudTrail record of key use; kept as fallback |
| Customer-managed KMS key | Monthly fee and policy maintenance for no extra access control here |
| `sub` wildcard such as `repo:FreeSecDev/*` or `pull_request` | Lets forks or other repositories assume the role |

## Benefits

No long-lived AWS credentials anywhere; the trust is pinned to one repository, ref and workflow; the baseline costs
close to nothing ([costs](../aws/costs.md)).

## Trade-offs

Root credentials are used once. `job_workflow_ref` pins the workflow file name, so adding a plan workflow is a
reviewed trust change. The plan role can write the state and lock objects of its own prefix, so a compromised
workflow on `main` could corrupt that state, which versioning allows recovering.

## Security implications

Reviewed against the IAM and bootstrap checklist of the `aws-infrastructure` skill. The deviation from the "refuse
root" item is recorded above. Trust policy changes require `security-review` before apply.

## Operational consequences

`make aws-bootstrap` is run once by the owner; [bootstrap.md](../aws/bootstrap.md) is the procedure. Developers need
OpenTofu `1.13.2` on `PATH` for `make lint-iac`, installed with `tools/iac/install-tofu.sh`.
