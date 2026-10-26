locals {
  runner_owner_name      = split("/", var.runner_repository)[0]
  runner_repository_name = split("/", var.runner_repository)[1]

  image_build_role_name = "freesecdev-gha-linux-compliance-runner-build"
  image_build_role_arn  = "arn:aws:iam::${var.account_id}:role/${local.image_build_role_name}"
  image_build_subject   = "repo:${local.runner_owner_name}@${var.github_owner_id}/${local.runner_repository_name}@${var.runner_repository_id}:environment:${var.image_build_environment}"
  image_build_workflow  = "${var.runner_repository}/.github/workflows/${var.image_build_workflow_file}@refs/heads/main"

  codebuild_project_name      = "freesecdev-linux-compliance-runner"
  codebuild_project_arn       = "arn:aws:codebuild:${var.aws_region}:${var.account_id}:project/${local.codebuild_project_name}"
  codebuild_service_role_name = "freesecdev-codebuild-linux-compliance-runner"
  codebuild_service_role_arn  = "arn:aws:iam::${var.account_id}:role/${local.codebuild_service_role_name}"
  runner_clone_url            = "https://github.com/${var.runner_repository}.git"
  runner_source_dir           = "/tmp/runner-source"
  build_script_timeout        = var.image_build_timeout_minutes * 60 - 300
  codebuild_buildspec = yamlencode({
    version = 0.2
    env = {
      shell              = "bash"
      exported-variables = ["BUILT_COMMIT", "IMAGE_DIGEST", "IMAGE_TAG", "IMAGE_REFERENCE", "BUILDAH_VERSION"]
    }
    phases = {
      build = {
        on-failure = "ABORT"
        commands = [
          "[[ \"$EXPECTED_COMMIT\" =~ ^[0-9a-f]{40}$ ]] || { echo 'error: EXPECTED_COMMIT must be a full commit SHA' >&2; false; }",
          "[[ \"$BUILD_DATE\" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || { echo 'error: BUILD_DATE must be a UTC RFC 3339 time' >&2; false; }",
          "rm -rf ${local.runner_source_dir}",
          "GIT_TERMINAL_PROMPT=0 timeout 300 git -c credential.helper= clone --quiet --no-tags --single-branch --branch main ${local.runner_clone_url} ${local.runner_source_dir}",
          "git -C ${local.runner_source_dir} merge-base --is-ancestor \"$EXPECTED_COMMIT\" refs/remotes/origin/main || { echo 'error: EXPECTED_COMMIT is not a commit on main of ${var.runner_repository}' >&2; false; }",
          "git -C ${local.runner_source_dir} -c advice.detachedHead=false checkout --quiet --detach \"$EXPECTED_COMMIT\"",
          "export BUILT_COMMIT=\"$(git -C ${local.runner_source_dir} rev-parse HEAD)\" && test \"$BUILT_COMMIT\" = \"$EXPECTED_COMMIT\"",
          "cd ${local.runner_source_dir} && IMAGE_SOURCE_DIR=${local.runner_source_dir} timeout --kill-after=60 ${local.build_script_timeout} bash codebuild/build-image.sh",
          ". /tmp/image-build/result.env",
        ]
      }
    }
  })

  image_build_log_group_name = "/aws/codebuild/${local.codebuild_project_name}"
  image_build_log_group_arn  = "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:${local.image_build_log_group_name}"

  staging_repository_name = "linux-compliance-runner-staging"
  staging_repository_arn  = "arn:aws:ecr:${var.aws_region}:${var.account_id}:repository/${local.staging_repository_name}"

  image_build_tags = {
    component = "runner-image-build"
    consumer  = var.runner_repository
  }
}

resource "aws_kms_key" "image_build" {
  description             = "Encrypts the CodeBuild logs and build settings of the linux-compliance-runner image build"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministersTheKey"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsUsesTheKeyForTheBuildLogGroup"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = local.image_build_log_group_arn
          }
        }
      },
    ]
  })
  tags = local.image_build_tags
}

resource "aws_cloudwatch_log_group" "image_build" {
  name              = local.image_build_log_group_name
  retention_in_days = var.image_build_log_retention_days
  kms_key_id        = aws_kms_key.image_build.arn
  tags              = local.image_build_tags
}

resource "aws_ecr_repository" "runner_staging" {
  name                 = local.staging_repository_name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }

  tags = local.image_build_tags
}

resource "aws_ecr_lifecycle_policy" "runner_staging" {
  repository = aws_ecr_repository.runner_staging.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire staged images ${var.image_staging_retention_days} days after the push"
        selection = {
          tagStatus   = "any"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.image_staging_retention_days
        }
        action = { type = "expire" }
      },
    ]
  })
}

data "aws_iam_policy_document" "codebuild_trust" {
  statement {
    sid     = "CodeBuildForTheRunnerProjectOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.codebuild_project_arn]
    }
  }
}

data "aws_iam_policy_document" "codebuild_permissions" {
  statement {
    sid       = "WriteBuildLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${local.image_build_log_group_arn}:log-stream:*"]
  }

  statement {
    sid       = "GetRegistryToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "PushStagingImage"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
    ]
    resources = [local.staging_repository_arn]
  }

  statement {
    sid       = "UseBuildKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.image_build.arn]
  }
}

resource "aws_iam_role" "codebuild_service" {
  name                 = local.codebuild_service_role_name
  description          = "Service role of the ${local.codebuild_project_name} CodeBuild project: build logs and pushes to the ECR staging repository"
  assume_role_policy   = data.aws_iam_policy_document.codebuild_trust.json
  max_session_duration = 3600
  tags                 = local.image_build_tags
}

resource "aws_iam_role_policy" "codebuild_service" {
  name   = "runner-image-build"
  role   = aws_iam_role.codebuild_service.id
  policy = data.aws_iam_policy_document.codebuild_permissions.json
}

resource "aws_codebuild_project" "runner_image" {
  name                   = local.codebuild_project_name
  description            = "Builds a main commit of ${var.runner_repository} with rootless Buildah and pushes it to ECR staging"
  service_role           = aws_iam_role.codebuild_service.arn
  build_timeout          = var.image_build_timeout_minutes
  queued_timeout         = var.image_build_queued_timeout_minutes
  concurrent_build_limit = 1
  encryption_key         = aws_kms_key.image_build.arn
  badge_enabled          = false

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    type                        = "LINUX_CONTAINER"
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                       = var.image_builder_image
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true

    environment_variable {
      name  = "STAGING_REPOSITORY_URI"
      value = aws_ecr_repository.runner_staging.repository_url
      type  = "PLAINTEXT"
    }
  }

  logs_config {
    cloudwatch_logs {
      status     = "ENABLED"
      group_name = aws_cloudwatch_log_group.image_build.name
    }

    s3_logs {
      status = "DISABLED"
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = local.codebuild_buildspec
  }

  tags = local.image_build_tags

  depends_on = [aws_iam_role_policy.codebuild_service]
}
