output "oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC provider."
  value       = data.aws_iam_openid_connect_provider.github.arn
}

output "plan_role_arn" {
  description = "ARN of the read-only plan role assumed from main."
  value       = aws_iam_role.plan.arn
}

output "budget_name" {
  description = "Name of the monthly cost budget."
  value       = aws_budgets_budget.monthly.name
}

output "image_build_role_arn" {
  description = "ARN of the runner image build role, assumed from the release environment of the runner repository on main."
  value       = aws_iam_role.image_build.arn
}

output "image_build_project_name" {
  description = "Name of the CodeBuild project that builds the runner image."
  value       = aws_codebuild_project.runner_image.name
}

output "image_staging_repository_url" {
  description = "URL of the private ECR staging repository for the runner image."
  value       = aws_ecr_repository.runner_staging.repository_url
}
