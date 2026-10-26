# 0014. AWS account bootstrap

- **Status:** proposed
- **Date:** 2026-10-25
- **Deciders:** project owner, lead architect
- **Jira:** FREES-30 (state backend), FREES-31 (OIDC provider and roles), FREES-33 (bootstrap template), FREES-34 (budget, tagging), FREES-69 (IaC hooks), FREES-36 (runner image build role and resources)
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
- the owner enables MFA on the root user before the bootstrap (recommended; the script warns and the typed
  confirmation is the last chance to stop), and stops using root afterwards.

The follow-up that removes the deviation is an IAM Identity Center or administrator role for the owner, after which the
bootstrap should be run with that identity.

### State backend

State is stored in the S3 bucket `freesecdev-tfstate-910736812072-eu-west-1` with native S3 locking
(`use_lockfile = true`, OpenTofu 1.10 and later). There is no DynamoDB table: it would add a resource, a cost and an
IAM surface for the same guarantee. The bucket is created by the bootstrap script, not by OpenTofu, because the
backend must exist before `init`. It has `BucketOwnerEnforced`, versioning, all public access blocked, a TLS-only
policy and a lifecycle rule for noncurrent versions. Encryption is SSE-KMS with the AWS-managed key `aws/s3`, chosen
over SSE-S3 for the CloudTrail record of key use at no key cost. The backend sets `kms_key_id = "alias/aws/s3"`, because `encrypt = true` alone makes it send SSE-S3
on every write, overriding the bucket default. The backend block uses partial configuration; the
bucket and key come from a generated, gitignored `backend.hcl` whose shape is the committed `backend.hcl.example`.

### OIDC trust

One OIDC provider `token.actions.githubusercontent.com` with audience `sts.amazonaws.com`. An account holds at most one
provider per URL and this account already has it, shared with other projects, so `infra/account` reads it as a data
source by ARN and never creates, changes or destroys it. A lookup by ARN needs only `iam:GetOpenIDConnectProvider`
on that ARN, so the plan role needs no list permission. A postcondition requires the audience `sts.amazonaws.com`.
AWS no longer needs thumbprints for this provider. The role `freesecdev-gha-ansible-linux-compliance-plan` trusts
only tokens with:

- `aud` equal to `sts.amazonaws.com`,
- `sub` equal to `repo:FreeSecDev@347867179/ansible-linux-compliance@1433323044:ref:refs/heads/main`: the repository
  uses GitHub immutable subjects, so the numeric owner and repository IDs are part of the subject and come from
  variables,
- `repository_id` equal to `1433323044` and `repository_owner_id` equal to `347867179`,
- `job_workflow_ref` equal to `FreeSecDev/ansible-linux-compliance/.github/workflows/oidc-check.yml@refs/heads/main`.

All comparisons are `StringEquals`; there are no wildcards. The maximum session duration is 3600 seconds. No role is
issued to pull requests or forks. The role is read-only for `tofu plan`: it reads state and may write only the `.tflock` object for the native lock.
Build and release roles are added by later issues with their own trust: the release role is pinned to the `release`
environment of [ADR 0012](0012-github-native-releases-and-packages.md), which accepts `main` only and has no human
reviewers, so the gate is automated and the trust must not depend on a reviewer.

### Runner image build (FREES-36)

The runner image is built by CodeBuild, as [ADR 0007](0007-registry-build-and-signing.md) decides. The resources
live in this stack (`infra/account/image_build.tf` and `iam_image_build_role.tf`) because this repository owns the
account IaC. They are:

- the CodeBuild project `freesecdev-linux-compliance-runner`. It builds the public runner repository at the
  requested commit with the digest-pinned builder `quay.io/buildah/stable@sha256:7c2b6052...`
  (`image_builder_image`), and its settings are:
  - `BUILD_GENERAL1_MEDIUM`;
  - a concurrency limit of 1;
  - a 45-minute build timeout and a 15-minute queue timeout;
  - no artifacts;
  - CloudWatch logs only;
- the private ECR repository `linux-compliance-runner-staging`: immutable tags, scan on push, KMS encryption with
  the AWS-managed key, and a lifecycle rule that expires images 14 days after the push;
- the log group `/aws/codebuild/freesecdev-linux-compliance-runner`, kept 365 days and encrypted with a
  customer-managed key;
- the KMS key, with yearly rotation and a 30-day deletion window. Its key policy lets the account administer it
  and lets CloudWatch Logs use it only for that log group (the `kms:EncryptionContext:aws:logs:arn` condition). It is
  also the CodeBuild project's encryption key;
- the CodeBuild service role `freesecdev-codebuild-linux-compliance-runner`, trusted only by `codebuild.amazonaws.com`
  with `aws:SourceAccount` equal to this account and `aws:SourceArn` equal to the project ARN;
- the GitHub build role `freesecdev-gha-linux-compliance-runner-build` (below);
- a second inline policy on the plan role, `plan-read-image-build`. It lets `tofu plan` read the resources above
  without changing the existing `plan-read-only` policy.

Every resource carries the default tags plus `component = runner-image-build` and
`consumer = FreeSecDev/linux-compliance-runner`. There is no EC2 builder, so no reaper is needed; the CodeBuild
timeouts bound every build.

The build role trusts only tokens where all of these hold, all compared with `StringEquals`:

- `aud` is `sts.amazonaws.com`;
- `sub` is `repo:FreeSecDev@347867179/linux-compliance-runner@1433323102:environment:release`. The runner
  repository also uses immutable subjects, and `1433323102` is its repository ID
  (`gh api repos/FreeSecDev/linux-compliance-runner --jq .id`);
- `repository_id` is `1433323102`;
- `repository_owner_id` is `347867179`;
- `job_workflow_ref` is `FreeSecDev/linux-compliance-runner/.github/workflows/image-build.yml@refs/heads/main`.

The `release` environment of the runner repository accepts `main` only and administrators cannot bypass it, so
no pull request, fork or other branch can assume the role. The maximum session is 3600 seconds.

The build role's permissions:

| Statement | Actions | Resource |
|---|---|---|
| RunTheImageBuild | `codebuild:StartBuild`, `codebuild:BatchGetBuilds`, `codebuild:StopBuild` | the project ARN |
| ReadTheBuildLogs | `logs:GetLogEvents` | the project's log streams |
| GetRegistryToken | `ecr:GetAuthorizationToken` | `*` |
| PullAndDescribeStagedImages | `ecr:BatchCheckLayerAvailability`, `ecr:BatchGetImage`, `ecr:DescribeImages`, `ecr:GetDownloadUrlForLayer` | the staging repository ARN |

The CodeBuild service role's permissions:

| Statement | Actions | Resource |
|---|---|---|
| WriteBuildLogs | `logs:CreateLogStream`, `logs:PutLogEvents` | the project's log streams |
| GetRegistryToken | `ecr:GetAuthorizationToken` | `*` |
| PushStagingImage | `ecr:BatchCheckLayerAvailability`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:PutImage` | the staging repository ARN |
| UseBuildKey | `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey`, `kms:DescribeKey` | the KMS key ARN |

Wildcard resources, each required by AWS:

- **`ecr:GetAuthorizationToken` on `*`:** the action has no resource type. It returns a registry login token, and
  the repository-scoped statements decide what that token may pull or push. The GitHub role cannot push at all.
- **`Resource: "*"` in the KMS key policy:** in a key policy, `*` means this key and no other.
- **`logs:DescribeLogGroups` on `log-group:*` for the plan role:** the action lists log groups and cannot be limited
  to one group. The grant is scoped to this account and region and is read-only.

Neither role can pass a role (`iam:PassRole`) or call `sts:AssumeRole`. `codebuild:StartBuild` accepts overrides of
the build specification, image and environment, and IAM offers no condition key to restrict them. The mitigation is
that only reviewed workflow code on `main` can assume the role, and that the service role cannot be swapped without
`iam:PassRole`.

Rootless Buildah needs user namespaces, and an unprivileged container is denied them, so the CodeBuild project uses
`privileged_mode = true`. Buildah still runs as a non-root user inside the build container. The build container is
single-use, holds no secret, and its only credential is the service role above. The runner repository's ADR 0002
records the tests and the alternatives.

### Tooling

OpenTofu is pinned to `1.13.2`. It is four days old at the time of writing, but it is a security release that
replaces compromised intermediate certificates, and security fixes are exempt from the seven-day release age rule.
The AWS provider is pinned to `6.69.1` (released 2026-10-15) with a committed `.terraform.lock.hcl` holding hashes for
`linux_amd64` and `linux_arm64`. Checkov `3.3.29` (released 2026-10-13; its `packaging`, `asteval`, `virtualenv` and `certifi` resolution is overridden
in `pyproject.toml` for security reasons) scans `infra/` in `make security` and the
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
reviewed trust change. The plan role cannot write state, only the lock object, so it can at worst block a lock.

## Security implications

Reviewed against the IAM and bootstrap checklist of the `aws-infrastructure` skill. The deviation from the "refuse
root" item is recorded above. Trust policy changes require `security-review` before apply.

`infra/.checkov.baseline` exempts exactly three findings:

- **CKV_AWS_358 on `aws_iam_policy_document.plan_trust`:** the check only recognises the `repo:<owner>/<repo>:...`
  subject. It fails the stricter immutable subject `repo:<owner>@<owner_id>/<repo>@<repo_id>:ref:refs/heads/main`
  that the trust policy pins, together with the `repository_id`, `repository_owner_id`, `aud` and
  `job_workflow_ref` conditions. The product owner accepted the exemption on 2026-10-26.
- **CKV_AWS_358 on `aws_iam_policy_document.image_build_trust`:** the same immutable-subject false positive for the
  runner build role. The subject is `...:environment:release`, with the same four extra conditions. This is the
  pattern the owner accepted on 2026-10-26.
- **CKV_AWS_316 on `aws_codebuild_project.runner_image`:** the privileged build container that rootless Buildah
  needs (above).

`tests/unit/infra/test_image_build_role.py` is the control that replaces the two build-related exemptions. It pins:

- the single trust statement, its principal and its five exact `StringEquals` conditions, and fails on wildcards or
  on a condition that is added or removed;
- the subject and workflow expressions and their rendered values;
- every permission statement of both build roles, with `*` allowed only for `ecr:GetAuthorizationToken`;
- the CodeBuild service-role trust;
- the CodeBuild guardrails: concurrency 1, timeouts, the digest-pinned builder, no artifacts, the GitHub source and
  the CMK;
- the ECR settings;
- the exact content of the baseline.

Every other check, and both check IDs on any other resource, still applies. A change to a trust policy or to the
project needs the baseline and that test reviewed again.

`tests/unit/infra/test_plan_role_trust.py` is the control that replaces CKV_AWS_358 for `plan_trust`. It parses the
OpenTofu files with `hcl2` and pins exactly one statement, its effect, action and Federated principal, the five
`StringEquals` conditions (`aud`, `sub`, `repository_id`, `repository_owner_id`, `job_workflow_ref`), the `plan_subject`
and `plan_workflow_refs` expressions, the defaults and validations of `github_owner_id` and `github_repository_id`, and
the `oidc.tf` lookup by `arn` with its audience postcondition. Mutated copies of the files (a `repo:*` subject,
`StringLike`, a removed or extra condition, a second statement, a changed principal, a URL lookup) must make it fail.
Any change to the trust policy must update this test in the same reviewed pull request.

The same test pins the stack around the trust policy, because an override file, a second role on the OIDC provider, a
`*.tf.json` file or an auto-loaded `*.tfvars` file would otherwise bypass it. It compares the exact set of files that
Git tracks in `infra/account` (the gitignored `backend.hcl` and `account.local.tfvars` must stay untracked), the exact
set of `resource` and `data` blocks across all `*.tf` files, and refuses any `module` block. It also pins every
attribute of `aws_iam_role.plan`. Adding a file or a resource to `infra/account` therefore needs a deliberate edit of
`EXPECTED_FILES` or `EXPECTED_BLOCKS` in that test, in the same reviewed pull request.

## Operational consequences

`make aws-bootstrap` is run once by the owner; [bootstrap.md](../aws/bootstrap.md) is the procedure. Developers need
OpenTofu `1.13.2` on `PATH` for `make lint-iac`, installed with `tools/iac/install-tofu.sh`.
