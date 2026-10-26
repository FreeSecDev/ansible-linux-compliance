# AWS cost estimate

Jira: FREES-34. Region `eu-west-1`, currency USD. These are estimates from AWS public list prices, not a bill. The
prices below were taken from the pages named in the Source column and were not re-fetched on the day of writing
(2026-10-25); confirm them there before relying on them for budgeting. Free tier is ignored unless stated.

| Resource | Pricing basis | Assumed usage | Monthly estimate | Source |
|---|---|---|---|---|
| GitHub OIDC provider | IAM has no additional charge | one provider | 0.00 | [IAM pricing](https://aws.amazon.com/iam/pricing/) |
| IAM role and inline policy | IAM has no additional charge | one role | 0.00 | [IAM pricing](https://aws.amazon.com/iam/pricing/) |
| STS `AssumeRoleWithWebIdentity` | no charge for STS | a few calls a day | 0.00 | [STS FAQ](https://aws.amazon.com/iam/faqs/) |
| AWS Budget, cost type | monitoring budgets (alerts only) are free with no cap; only action-enabled budgets are charged | one monitoring budget with six email alerts | 0.00 | [AWS Budgets pricing](https://aws.amazon.com/aws-cost-management/aws-budgets/pricing/) |
| State bucket storage | S3 Standard, about 0.023 per GB-month in `eu-west-1` | under 1 MB of state, up to 11 versions kept | below 0.01 | [S3 pricing](https://aws.amazon.com/s3/pricing/) |
| State bucket requests | PUT about 0.005 and GET about 0.0004 per 1,000 requests | a few hundred requests including lock files | below 0.01 | [S3 pricing](https://aws.amazon.com/s3/pricing/) |
| KMS, AWS-managed key `aws/s3` | no monthly key fee; requests about 0.03 per 10,000 after a free tier of 20,000 | Bucket Key enabled, a few hundred calls | 0.00 | [KMS pricing](https://aws.amazon.com/kms/pricing/) |
| **Total** | | | **below 0.05, effectively 0** | |

Notes:

- Nothing in this stack is always-on compute, a NAT gateway, a load balancer or a log group, so there is no cost that
  scales with time or traffic.
- The budget limit defaults to 50 USD per month, with actual and forecasted alerts at 50, 80 and 100 percent. It
  covers the whole account, so it will also alert on the future builder, CodeBuild and ECR resources.
- Additional monitoring budgets are also free. Only budgets with actions are charged, after a free allowance; none is
  created here.
- Costs of resources added later are estimated in the pull request that adds them; the runner image build follows.

## Runner image build (FREES-36)

Prices from the AWS price list API offer files for `eu-west-1`: CodeBuild published 2026-09-11, ECR 2026-09-11,
CloudWatch 2026-10-07 and KMS 2026-10-26. They were read on 2026-10-26. The usage assumes about 15 builds a month
(pushes to `main` that change an image input, plus manual runs). Each build takes 8 to 10 minutes on
`BUILD_GENERAL1_MEDIUM`; the build took 4.6 minutes on a 2026 workstation, plus the gate's clone, the builder image
pull and the push.

| Resource | Pricing basis | Assumed usage | Monthly estimate |
|---|---|---|---|
| CodeBuild `BUILD_GENERAL1_MEDIUM` (Linux) | 0.010 per build minute; the free tier covers `general1.small` only | 15 builds x 10 minutes | 1.50 |
| ECR private storage | 0.10 per GB-month | images of about 0.28 GB, kept 14 days: about 7 images, 2 GB on average | 0.20 |
| ECR data transfer to GitHub runners | internet egress; the first 100 GB a month are free across the account | 4 pulls of 0.28 GB per run (pull, scan, SBOM, copy), about 17 GB | 0.00 |
| ECR basic scan on push | no charge | 15 images | 0.00 |
| CloudWatch Logs | 0.57 per GB ingested, 0.03 per GB-month stored | about 3 MB a build, kept 365 days | below 0.05 |
| KMS customer-managed key | 1.00 per key version a month; requests 0.03 per 10,000 | 1 key with yearly rotation, a few hundred requests | 1.00 (2.00 after the first rotation, 3.00 at most) |
| IAM roles, policies, STS | no charge | 2 roles, 3 inline policies | 0.00 |
| **Total** | | | **about 2.75 in the first year, at most about 4.75** |

Notes:

- The cost scales with builds. A role holder can raise the project timeout with `timeoutInMinutesOverride`, which
  has no IAM condition key and allows up to 2160 minutes, about 21.60 USD for one build. The inline gate caps the
  billed time anyway: the clone has a 5-minute `timeout` and the build script a 35-minute `timeout`, so one build
  costs at most about 41 minutes, 0.41 USD.
- With concurrency 1, a role holder who starts builds back to back would spend about 0.60 USD an hour, 14.40 USD a
  day. Only the `image-build` workflow on `main` can assume the role. The 50 USD budget alert is the backstop, and
  an EventBridge rule on long or frequent builds is a cheap follow-up.
- Images expire from ECR after 14 days, so storage is bounded by the build rate. GHCR storage is free for public
  packages.
- There is no always-on compute and no EC2 builder.
- The account budget (50 USD with alerts at 50, 80 and 100 percent) covers these resources.
