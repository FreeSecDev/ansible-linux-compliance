# AWS account bootstrap

Jira: FREES-30 (state backend), FREES-31 (OIDC provider and roles), FREES-33 (bootstrap template),
FREES-34 (budget and tagging), FREES-69 (IaC hooks). Decision record: [ADR 0014](../adr/0014-aws-account-bootstrap.md).
Cost: [costs.md](costs.md).

Account `910736812072`, region `eu-west-1`. This is a one-time procedure run by the project owner from a trusted
workstation. CI never uses root or access keys; it assumes the OIDC role created here.

## Prerequisites

- A shell on a workstation with `aws` (CLI v2), `gh`, `git`, GNU `make` and `uv` installed.
- OpenTofu `1.13.2` on `PATH`. Install the pinned, checksum-verified release with `tools/iac/install-tofu.sh`.
- `gh auth status` succeeds with a token that may write repository variables on `FreeSecDev/ansible-linux-compliance`
  and `FreeSecDev/linux-compliance-runner`.
- AWS credentials for the account in the environment (the project owner's authorized root session for this one
  time; any administrator role works too and is preferred). `AWS_REGION` is `eu-west-1`.
- MFA enabled on the root user, done before the bootstrap if you use the root session. The script warns about this and
  the typed confirmation is your last chance to stop.
- An email address for budget alerts. The script asks for it and stores it only in the gitignored
  `infra/account/account.local.tfvars`.

## What the script does

`make aws-bootstrap-render` renders `infra/bootstrap/bootstrap.sh.tmpl` into the gitignored
`infra/bootstrap/bootstrap.local.sh`, substituting the account ID, region, state bucket name and repository.
`make aws-bootstrap` renders and then runs it. The script, in order:

1. Verifies `aws`, `tofu` and `gh` exist and that it runs in a terminal.
2. Calls `aws sts get-caller-identity`, requires the configured region and the account to match, prints the caller ARN
   and warns loudly if the caller is the root user.
3. Requires the typed confirmation `yes-910736812072` before any change.
4. Creates the state bucket `freesecdev-tfstate-910736812072-eu-west-1` if it does not exist, or verifies that this
   account owns it. Every run (re)applies and then checks the hardening:
   - `BucketOwnerEnforced` object ownership (ACLs disabled),
   - all four public access block settings,
   - versioning,
   - default encryption with SSE-KMS and the AWS-managed key `aws/s3`, with an S3 Bucket Key,
   - a bucket policy denying any request without TLS or with a TLS version below 1.2,
   - a lifecycle rule expiring noncurrent versions after 90 days while keeping the 10 newest, and aborting
     incomplete multipart uploads after 7 days,
   - the standard tags.
5. Writes the gitignored `infra/account/backend.hcl` from the same values as the committed
   `backend.hcl.example`.
6. Runs `tofu -chdir=infra/account init`, then `plan -out`, shows the plan and requires the second typed confirmation
   `apply-910736812072` before `apply`. The plan file is deleted when the script exits.
7. Sets the GitHub repository variables `AWS_REGION` and `AWS_PLAN_ROLE_ARN` on this repository, and `AWS_REGION`
   and `AWS_BUILD_ROLE_ARN` on `FreeSecDev/linux-compliance-runner`, with `gh variable set`. They are variables, not
   secrets: an ARN is an identifier, and trust is enforced by the role's trust policy.
8. Prints the commands that verify OIDC from a workflow.

The script never writes access keys or secrets to disk. The state bucket is created by the script and not by OpenTofu
because the OpenTofu backend needs it before the first `init`.

### Why SSE-KMS with the AWS-managed key

The OpenTofu backend sets `kms_key_id = "alias/aws/s3"`, because with `encrypt = true` alone the backend sends SSE-S3
(`AES256`) on every write, which overrides the bucket default.

Both options encrypt at rest at no key cost. SSE-KMS with `aws/s3` additionally records each key use in CloudTrail,
which gives an audit trail for state access, and the Bucket Key keeps KMS request charges negligible. A
customer-managed key would add a monthly fee and key policy to maintain for no extra access control on a state
bucket that already restricts access with IAM. SSE-S3 is the fallback if KMS audit is not wanted.

## Commands

```bash
tools/iac/install-tofu.sh
export AWS_REGION=eu-west-1
aws sts get-caller-identity
make aws-bootstrap
```

Render without running, to review the script:

```bash
make aws-bootstrap-render
less infra/bootstrap/bootstrap.local.sh
```

Offline validation (no AWS access): `make lint-iac` and `uv run --frozen checkov --config-file .checkov.yaml`.

## Role and trust model

OpenTofu in `infra/account` reads the existing GitHub OIDC provider `token.actions.githubusercontent.com` as a data
source, and creates a monthly cost budget and the role `freesecdev-gha-ansible-linux-compliance-plan`.

An AWS account can hold only one provider per URL, and other projects in this account already use it. The stack
therefore never creates, changes or destroys the provider; `tofu destroy` of `infra/account` leaves it in place. The
provider must exist with audience `sts.amazonaws.com` before the bootstrap runs, and a postcondition fails the plan
otherwise. The stack looks it up by ARN, because a lookup by URL calls `iam:ListOpenIDConnectProviders`, which can
only be granted on `*` and which the plan role does not have.

The role trust policy allows `sts:AssumeRoleWithWebIdentity` only for tokens where all of these hold:

| Condition key | Operator | Value |
|---|---|---|
| `token.actions.githubusercontent.com:aud` | `StringEquals` | `sts.amazonaws.com` |
| `token.actions.githubusercontent.com:sub` | `StringEquals` | `repo:FreeSecDev@347867179/ansible-linux-compliance@1433323044:ref:refs/heads/main` |
| `token.actions.githubusercontent.com:repository_id` | `StringEquals` | `1433323044` |
| `token.actions.githubusercontent.com:repository_owner_id` | `StringEquals` | `347867179` |
| `token.actions.githubusercontent.com:job_workflow_ref` | `StringEquals` | `FreeSecDev/ansible-linux-compliance/.github/workflows/oidc-check.yml@refs/heads/main` |

This repository uses GitHub immutable subjects (`use_immutable_subject: true`, checked with
`gh api repos/FreeSecDev/ansible-linux-compliance/actions/oidc/customization/sub`), so the `sub` embeds the numeric
organization and repository IDs. They come from the variables `github_owner_id` and `github_repository_id` and also
feed the `repository_owner_id` and `repository_id` conditions.

The maximum session duration is 3600 seconds. There is no role for pull requests or forks: a token from any other
ref, event or repository matches nothing. Adding another workflow to the trust is a reviewed change to the
`plan_workflow_files` variable.

The role is read-only for `tofu plan` of `infra/account`:

| Statement | Actions | Resource |
|---|---|---|
| ReadOidcProvider | `iam:GetOpenIDConnectProvider`, `iam:ListOpenIDConnectProviderTags` | the provider ARN |
| ReadPlanRole | `iam:GetRole`, `iam:GetRolePolicy`, `iam:ListRolePolicies`, `iam:ListAttachedRolePolicies`, `iam:ListRoleTags` | the plan role ARN |
| ReadBudget | `budgets:ViewBudget`, `budgets:ListTagsForResource` | the budget ARN |
| ListStateBucketPrefix | `s3:ListBucket` | the state bucket, only for prefixes `account/*` and `env:/*` |
| ReadState | `s3:GetObject` | `account/terraform.tfstate` in the state bucket |
| ManageStateLock | `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` | `account/terraform.tfstate.tflock` in the state bucket |

No action uses a wildcard and no resource is `*`. The role can read state but not write it; only the lock object is writable, which a plan needs for the native S3 lock
(`use_lockfile = true`). `aws iam simulate-custom-policy` confirms `PutObject` and `DeleteObject` on the state object are
implicitly denied. The role cannot change any AWS resource.

## Runner image build resources (FREES-36)

The stack also holds the AWS side of the runner image build. The trust, the permissions, the justification for each
`*` and the Checkov baseline are in [ADR 0014](../adr/0014-aws-account-bootstrap.md), "Runner image build". The
pipeline is documented in the runner repository's `docs/image-build.md`.

| Resource | Name |
|---|---|
| CodeBuild project | `freesecdev-linux-compliance-runner`: `NO_SOURCE`, with the inline gate buildspec |
| ECR repository (private staging) | `linux-compliance-runner-staging` |
| CloudWatch log group | `/aws/codebuild/freesecdev-linux-compliance-runner` (365 days, CMK) |
| KMS key | customer managed, yearly rotation, used by the log group and the project |
| CodeBuild service role | `freesecdev-codebuild-linux-compliance-runner` |
| GitHub build role | `freesecdev-gha-linux-compliance-runner-build` |
| Plan role policy | `plan-read-image-build`, a new inline policy on the existing plan role |

### Applying the build resources

CI can only plan, so the owner applies them once from the logged-in administrator session, with the same idempotent
command as the first bootstrap:

```bash
git switch main && git pull --ff-only
tools/iac/install-tofu.sh
export AWS_REGION=eu-west-1
aws sts get-caller-identity
make aws-bootstrap
```

Type `yes-910736812072` after the identity check. Review the plan, then type `apply-910736812072`. The expected plan
on the applied 2026-10-26 state is `Plan: 10 to add, 0 to change, 0 to destroy.`, followed by three added
outputs. It adds exactly these resources:

- `aws_kms_key.image_build`
- `aws_cloudwatch_log_group.image_build`
- `aws_ecr_repository.runner_staging`
- `aws_ecr_lifecycle_policy.runner_staging`
- `aws_iam_role.codebuild_service`
- `aws_iam_role_policy.codebuild_service`
- `aws_codebuild_project.runner_image`
- `aws_iam_role.image_build`
- `aws_iam_role_policy.image_build`
- `aws_iam_role_policy.plan_image_build`

The added outputs are `image_build_role_arn`, `image_build_project_name` and `image_staging_repository_url`. Stop if the
plan shows any change to `aws_iam_role.plan`, `aws_iam_role_policy.plan`, `aws_budgets_budget.monthly` or the OIDC
provider. The provider is a data source and is never changed.

Then the script sets `AWS_REGION` and `AWS_BUILD_ROLE_ARN` on the runner repository. A rerun shows `No changes`.
Verify with:

```bash
gh workflow run image-build.yml --repo FreeSecDev/linux-compliance-runner --ref main
gh run watch --repo FreeSecDev/linux-compliance-runner
```

A successful run prints the staged ECR digest and the GHCR release digest in its job summary and uploads them as the
`image-build` and `image-release` artifacts.

## Workflow permissions

`.github/workflows/oidc-check.yml` is `workflow_dispatch` only, runs only on `main` and requests
`id-token: write` and `contents: read` in its single job. `id-token: write` lets the job request the OIDC token that
`aws-actions/configure-aws-credentials` exchanges for the role. It grants no write access to the repository. The
zizmor `undocumented-permissions` audit ignores only `oidc-check.yml:20` in `.github/zizmor.yml` because YAML comments are banned and this
paragraph is the explanation.

## Verification

The trust policy accepts `main` only, so the check runs after this change is merged:

```bash
gh workflow run oidc-check.yml --repo FreeSecDev/ansible-linux-compliance --ref main
gh run watch --repo FreeSecDev/ansible-linux-compliance
```

The job output must show an ARN of the form
`arn:aws:sts::910736812072:assumed-role/freesecdev-gha-ansible-linux-compliance-plan/oidc-check`.

After a successful check, sign out of the root session and stop using root.

## Local files

| File | Tracked | Purpose |
|---|---|---|
| `infra/bootstrap/bootstrap.sh.tmpl` | yes | Template of the bootstrap script |
| `infra/bootstrap/bootstrap.local.sh` | no | Rendered script |
| `infra/account/backend.hcl.example` | yes | Shape of the partial backend configuration |
| `infra/account/backend.hcl` | no | Generated backend configuration |
| `infra/account/account.example.tfvars` | yes | Shape of the variable file |
| `infra/account/account.local.tfvars` | no | Holds `budget_alert_email` |
| `infra/account/.terraform.lock.hcl` | yes | Provider hashes for `linux_amd64` and `linux_arm64` |

## Recovery

- Re-running `make aws-bootstrap` is safe: bucket creation is skipped when the bucket exists, hardening is reapplied
  and `tofu plan` shows no changes once the stack is applied.
- If `apply` fails part-way, fix the cause and re-run; state is in the versioned bucket.
- To pin a different provider or OpenTofu version, update `versions.tf`, run `tofu providers lock` for both platforms
  and update `tools/iac/install-tofu.sh` with the new checksums from the signed `SHA256SUMS` of the release.
