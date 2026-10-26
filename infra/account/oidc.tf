data "aws_iam_openid_connect_provider" "github" {
  arn = local.oidc_provider_arn

  lifecycle {
    postcondition {
      condition     = contains(self.client_id_list, "sts.amazonaws.com")
      error_message = "The existing GitHub OIDC provider must list the audience sts.amazonaws.com."
    }
  }
}
