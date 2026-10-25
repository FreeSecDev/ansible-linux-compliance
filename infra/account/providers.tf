provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      project     = "freesecdev"
      repository  = var.github_repository
      managed-by  = "opentofu"
      owner       = var.owner
      cost-center = var.cost_center
    }
  }
}
