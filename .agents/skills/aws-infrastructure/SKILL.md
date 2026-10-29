---
name: aws-infrastructure
description: AWS infrastructure as code for the FreeSecDev platform using OpenTofu. Use when adding or changing resources under infra/, GitHub OIDC trust, IAM roles, CodeBuild projects, ECR, S3 artifact buckets, ephemeral EC2 builders, budgets, tagging, or the bootstrap script template. Produces linted OpenTofu, least-privilege roles and documented cost estimates.
license: Apache-2.0
metadata:
  owner: lead-architect
  version: "1.0.0"
---

# AWS infrastructure

Each repository manages its own AWS resources with OpenTofu under `infra/`. Access from CI is
OIDC-only, scoped per repository, ref or environment, and short-lived.

## When to use

- Creating or changing anything under `infra/` in either repository.
- Changing IAM roles, policies, the GitHub OIDC provider or trust conditions.
- Adding CodeBuild projects, ECR repositories, S3 buckets, KMS keys or log groups.
- Changing ephemeral EC2 builders, the reaper or budget alerts.
- Changing `infra/bootstrap/bootstrap.sh.tmpl` or the repository variables it sets.

## Inputs

- The Jira issue and the ADR covering the design, including the IaC scanner choice.
- Existing `infra/` code, state backend configuration and tag standard.
- The consumer needs from the `packer-images`, `container-security` or `github-actions` skills.

## Outputs

- OpenTofu modules and stacks under `infra/`, region `eu-west-1`.
- A tracked bootstrap template that renders to a gitignored local script.
- Cost estimates in `docs/` for every new always-on or per-build resource.
- Review checklist in [references/iam-and-bootstrap-checklist.md](references/iam-and-bootstrap-checklist.md) completed.

## Conventions

- Use OpenTofu (open-source licence), not Terraform; providers are pinned to the versions in the lock file.
- State lives in an encrypted, versioned S3 bucket with locking enabled.
- One GitHub OIDC provider. Trust policies require `token.actions.githubusercontent.com:aud` equal to `sts.amazonaws.com` and a `sub` pinned to an exact repository plus ref or environment, for example `repo:FreeSecDev/linux-compliance-runner:environment:release`. No wildcard `sub` values.
- Separate roles for read-only validation, image build and release. Untrusted pull requests assume no AWS role. Maximum session duration is one hour.
- No administrator or wildcard-action or wildcard-resource policies; scope actions and ARNs explicitly.
- Provision CodeBuild projects with their own service roles, ECR repositories with scan-on-push and immutable tags, and CloudWatch log groups with explicit retention.
- S3 artifact buckets: block public access, TLS-only bucket policy, KMS or SSE encryption, versioning and lifecycle rules.
- Mandatory tags on every taggable resource: `project`, `repo`, `owner`, `cost-center`, `ttl`.
- Ephemeral EC2 builders use instance-initiated shutdown behaviour `terminate`, a max-lifetime tag and are swept by a reaper function.
- AWS Budgets alerts exist for the account scope used by each repository.
- Bootstrap: tracked `infra/bootstrap/bootstrap.sh.tmpl` renders to gitignored `infra/bootstrap/bootstrap.local.sh` and gitignored `*.local.env`. See the checklist for required script behaviour.
- `.gitignore` covers rendered scripts, credentials, local env files, state and plan files.

## Quality gates

- `tofu fmt -check` and `tofu validate` pass.
- The IaC scanner selected by the ADR (Trivy config or Checkov) passes without undocumented suppressions.
- Every IAM policy and trust policy is reviewed against the checklist and by `security-review`.
- A plan was produced for changed stacks; destructive changes are called out in the pull request.
- Cost estimate present for new resources.

## Common failures

- A trust policy that pins `aud` but leaves `sub` as a wildcard or only the organisation.
- One role shared by validation, build and release.
- Granting `iam:PassRole` or `sts:AssumeRole` on `*`.
- Buckets without TLS-only policy, lifecycle rules or versioning.
- Builders that outlive a failed build because shutdown behaviour was left at stop.
- Bootstrap that accepts a profile silently, writes access keys, or runs as root.
- Missing log retention, producing unbounded CloudWatch cost.

## Security requirements

- No long-lived access keys anywhere; bootstrap uses SSO or short-lived credentials and refuses root.
- Secrets and account-sensitive values never appear in tracked files, logs or Jira.
- State files are never committed; state bucket access is limited to the infrastructure roles.
- KMS key policies grant least privilege and key rotation is enabled.
- Changes to trust policies always receive `security-review` before apply.

## Documentation requirements

- Update `docs/` with architecture, role matrix, bootstrap procedure and cost estimates.
- Record an ADR for new AWS services, scanner selection or trust model changes.
- Document the repository variables the bootstrap sets and where workflows consume them.

## Completion criteria

- Lint gates pass in CI and the plan was reviewed.
- Applied resources were verified: OIDC assume-role from a workflow, CodeBuild start, S3 write and ECR access.
- Cost estimate and tags verified on created resources.
- Jira issue records the applied stack, verification evidence and residual risks.

## Interaction with other skills

- Supplies roles and buckets to the `github-actions` skill and builders to the `packer-images` skill.
- Does not supply the runner image build: it runs on GitHub-hosted runners (`container-security`). AWS hosts VM
  golden image builds only.
- Reviewed by `security-review` for IAM and trust changes; design choices go through `architecture`.
- Provider updates are handled by the `dependency-management` skill; documentation by the `documentation` skill.
- Release roles are consumed by the `release-engineering` skill; work is tracked via `jira-management`.
