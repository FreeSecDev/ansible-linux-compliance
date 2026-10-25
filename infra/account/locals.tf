locals {
  state_bucket_name = "freesecdev-tfstate-${var.account_id}-${var.aws_region}"
  state_key         = "account/terraform.tfstate"
  state_lock_key    = "account/terraform.tfstate.tflock"

  oidc_host = "token.actions.githubusercontent.com"

  plan_role_name = "freesecdev-gha-ansible-linux-compliance-plan"
  plan_role_arn  = "arn:aws:iam::${var.account_id}:role/${local.plan_role_name}"

  budget_name = "freesecdev-monthly"
  budget_arn  = "arn:aws:budgets::${var.account_id}:budget/${local.budget_name}"

  plan_subject = "repo:${var.github_repository}:ref:refs/heads/main"
  plan_workflow_refs = [
    for file in var.plan_workflow_files :
    "${var.github_repository}/.github/workflows/${file}@refs/heads/main"
  ]
}
