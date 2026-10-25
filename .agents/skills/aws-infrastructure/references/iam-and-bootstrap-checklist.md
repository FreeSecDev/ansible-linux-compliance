# IAM and bootstrap checklist

## Trust policy

- [ ] Federated principal is the GitHub OIDC provider of this account.
- [ ] Condition on `token.actions.githubusercontent.com:aud` equals `sts.amazonaws.com`.
- [ ] Condition on `token.actions.githubusercontent.com:sub` is an exact string for one repository and one ref or environment.
- [ ] Release roles require a protected GitHub environment such as `release`.
- [ ] Pull requests from forks or untrusted branches match no role.
- [ ] Maximum session duration is at most one hour.

## Permissions

- [ ] Validation role is read-only.
- [ ] Image-build role can launch tagged builders, create AMIs and write to the artifact bucket only.
- [ ] Release role can push to ECR and write release artifacts only.
- [ ] No `*` action, no `*` resource without a documented condition, no administrator policy.
- [ ] `iam:PassRole` restricted to named roles and the intended service.

## Bucket baseline

- [ ] Block public access on all four settings.
- [ ] Policy denies requests without TLS.
- [ ] Encryption with KMS or SSE, versioning on, lifecycle rules set.

## Bootstrap script behaviour

- [ ] Verifies the aws CLI is present and reports the caller identity.
- [ ] Refuses root credentials and long-lived access keys; accepts SSO or short-lived credentials.
- [ ] Requires the operator to type the account ID and region before any change.
- [ ] Checks the permissions it needs before applying.
- [ ] Never writes access keys or secrets to disk.
- [ ] Deploys the tracked OpenTofu configuration.
- [ ] Sets GitHub repository variables with `gh`.
- [ ] Verifies OIDC through a harmless sts call from a workflow.
- [ ] Verifies CodeBuild, S3 and ECR access.
- [ ] Rendered script and `*.local.env` are gitignored.
