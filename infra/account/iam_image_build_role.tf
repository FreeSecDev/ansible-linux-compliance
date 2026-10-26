locals {
  start_build_allowed_environment_variables = ["EXPECTED_COMMIT", "BUILD_DATE"]
  start_build_denied_override_keys = [
    "source",
    "source.buildspec",
    "source.location",
    "source.auth.type",
    "source.auth.resource",
    "source.insecureSsl",
    "source.buildStatusConfig.context",
    "source.buildStatusConfig.targetUrl",
    "secondarySources",
    "artifacts",
    "secondaryArtifacts",
    "cache",
    "logsConfig",
    "serviceRole",
    "encryptionKey",
    "autoRetryLimit",
    "environment.type",
    "environment.image",
    "environment.computeType",
    "environment.privilegedMode",
    "environment.certificate",
    "environment.imagePullCredentialsType",
    "environment.registryCredential",
    "environment.registryCredential.credential",
    "environment.registryCredential.credentialProvider",
    "environment.fleet.fleetArn",
  ]
}

data "aws_iam_policy_document" "image_build_trust" {
  statement {
    sid     = "RunnerImageBuildFromTheReleaseEnvironmentOnMain"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = [local.image_build_subject]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:repository_id"
      values   = [var.runner_repository_id]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:repository_owner_id"
      values   = [var.github_owner_id]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:job_workflow_ref"
      values   = [local.image_build_workflow]
    }
  }
}

data "aws_iam_policy_document" "image_build_permissions" {
  statement {
    sid       = "RunTheImageBuild"
    effect    = "Allow"
    actions   = ["codebuild:StartBuild", "codebuild:BatchGetBuilds", "codebuild:StopBuild"]
    resources = [aws_codebuild_project.runner_image.arn]
  }

  dynamic "statement" {
    for_each = local.start_build_denied_override_keys

    content {
      sid       = "DenyStartBuildOverride${statement.key}"
      effect    = "Deny"
      actions   = ["codebuild:StartBuild"]
      resources = ["*"]

      condition {
        test     = "Null"
        variable = "codebuild:${statement.value}"
        values   = ["false"]
      }
    }
  }

  statement {
    sid       = "DenyStartBuildEnvironmentVariablesOtherThanTheGateInputs"
    effect    = "Deny"
    actions   = ["codebuild:StartBuild"]
    resources = ["*"]

    condition {
      test     = "ForAnyValue:StringNotEquals"
      variable = "codebuild:environment.environmentVariables.name"
      values   = local.start_build_allowed_environment_variables
    }
  }

  statement {
    sid       = "ReadTheBuildLogs"
    effect    = "Allow"
    actions   = ["logs:GetLogEvents"]
    resources = ["${local.image_build_log_group_arn}:log-stream:*"]
  }

  statement {
    sid       = "GetRegistryToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "PullAndDescribeStagedImages"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.runner_staging.arn]
  }
}

resource "aws_iam_role" "image_build" {
  name                 = local.image_build_role_name
  description          = "Starts the runner image CodeBuild build and pulls the staged digest, from the ${var.image_build_environment} environment of ${var.runner_repository} on main"
  assume_role_policy   = data.aws_iam_policy_document.image_build_trust.json
  max_session_duration = 3600
  tags                 = local.image_build_tags
}

resource "aws_iam_role_policy" "image_build" {
  name   = "runner-image-build"
  role   = aws_iam_role.image_build.id
  policy = data.aws_iam_policy_document.image_build_permissions.json
}

data "aws_iam_policy_document" "plan_image_build_permissions" {
  statement {
    sid    = "ReadImageBuildRoles"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListRoleTags",
    ]
    resources = [local.image_build_role_arn, local.codebuild_service_role_arn]
  }

  statement {
    sid       = "ReadImageBuildProject"
    effect    = "Allow"
    actions   = ["codebuild:BatchGetProjects"]
    resources = [local.codebuild_project_arn]
  }

  statement {
    sid    = "ReadStagingRepository"
    effect = "Allow"
    actions = [
      "ecr:DescribeRepositories",
      "ecr:GetLifecyclePolicy",
      "ecr:GetRepositoryPolicy",
      "ecr:ListTagsForResource",
    ]
    resources = [local.staging_repository_arn]
  }

  statement {
    sid       = "DescribeLogGroupsInTheAccountRegion"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:*"]
  }

  statement {
    sid       = "ReadImageBuildLogGroupTags"
    effect    = "Allow"
    actions   = ["logs:ListTagsForResource"]
    resources = [local.image_build_log_group_arn]
  }

  statement {
    sid    = "ReadImageBuildKey"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
    ]
    resources = [aws_kms_key.image_build.arn]
  }
}

resource "aws_iam_role_policy" "plan_image_build" {
  name   = "plan-read-image-build"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_image_build_permissions.json
}
