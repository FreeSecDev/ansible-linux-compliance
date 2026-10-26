data "aws_iam_openid_connect_provider" "github" {
  url = "https://${local.oidc_host}"
}
