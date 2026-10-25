data "aws_iam_policy_document" "plan_trust" {
  statement {
    sid     = "GitHubActionsMainOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = [local.plan_subject]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:job_workflow_ref"
      values   = local.plan_workflow_refs
    }
  }
}

data "aws_iam_policy_document" "plan_permissions" {
  statement {
    sid       = "ReadOidcProvider"
    effect    = "Allow"
    actions   = ["iam:GetOpenIDConnectProvider", "iam:ListOpenIDConnectProviderTags"]
    resources = [aws_iam_openid_connect_provider.github.arn]
  }

  statement {
    sid    = "ReadPlanRole"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListRoleTags",
    ]
    resources = [local.plan_role_arn]
  }

  statement {
    sid       = "ReadBudget"
    effect    = "Allow"
    actions   = ["budgets:ViewBudget", "budgets:ListTagsForResource"]
    resources = [local.budget_arn]
  }

  statement {
    sid       = "ListStateBucketPrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${local.state_bucket_name}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["account/*", "env:/*"]
    }
  }

  statement {
    sid     = "ReadWriteStateAndLock"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = [
      "arn:aws:s3:::${local.state_bucket_name}/${local.state_key}",
      "arn:aws:s3:::${local.state_bucket_name}/${local.state_lock_key}",
    ]
  }
}

resource "aws_iam_role" "plan" {
  name                 = local.plan_role_name
  description          = "Read-only tofu plan of infra/account from ${var.github_repository} on main"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "plan" {
  name   = "plan-read-only"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_permissions.json
}
