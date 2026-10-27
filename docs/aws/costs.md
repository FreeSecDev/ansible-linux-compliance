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
  covers the whole account, so it will also alert on the future VM golden image builders.
- Additional monitoring budgets are also free. Only budgets with actions are charged, after a free allowance; none is
  created here.
- AWS is used only for VM golden images (Packer, ADR 0008). The CI runner image is built on GitHub-hosted runners
  at no AWS cost ([ADR 0007](../adr/0007-registry-build-and-signing.md), amendment of 2026-10-27).
- Costs of resources added later (EC2 builders and their artifact storage) are estimated in the pull request that
  adds them.
