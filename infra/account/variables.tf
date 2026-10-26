variable "account_id" {
  description = "The only AWS account this stack may be applied to."
  type        = string
  default     = "910736812072"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12 digit AWS account ID."
  }
}

variable "aws_region" {
  description = "Region for regional resources and the state bucket."
  type        = string
  default     = "eu-west-1"
}

variable "github_repository" {
  description = "GitHub repository (owner/name) whose workflows may assume the plan role."
  type        = string
  default     = "FreeSecDev/ansible-linux-compliance"
}

variable "github_owner_id" {
  description = "Numeric ID of the GitHub organization; immutable subjects embed it."
  type        = string
  default     = "347867179"

  validation {
    condition     = can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "github_owner_id must be numeric."
  }
}

variable "github_repository_id" {
  description = "Numeric ID of the GitHub repository; immutable subjects embed it."
  type        = string
  default     = "1433323044"

  validation {
    condition     = can(regex("^[0-9]+$", var.github_repository_id))
    error_message = "github_repository_id must be numeric."
  }
}

variable "plan_workflow_files" {
  description = "Workflow files on main that may assume the plan role; each is matched exactly through job_workflow_ref."
  type        = list(string)
  default     = ["oidc-check.yml"]

  validation {
    condition     = length(var.plan_workflow_files) > 0 && alltrue([for f in var.plan_workflow_files : can(regex("^[A-Za-z0-9._-]+\\.ya?ml$", f))])
    error_message = "plan_workflow_files must list plain workflow file names such as oidc-check.yml."
  }
}

variable "owner" {
  description = "Value of the owner tag."
  type        = string
  default     = "freesecdev"
}

variable "cost_center" {
  description = "Value of the cost-center tag."
  type        = string
  default     = "freesecdev"
}

variable "budget_limit_usd" {
  description = "Monthly cost budget in USD."
  type        = number
  default     = 50

  validation {
    condition     = var.budget_limit_usd > 0
    error_message = "budget_limit_usd must be positive."
  }
}

variable "budget_alert_email" {
  description = "Address that receives budget alerts. Supply it in a gitignored *.local.tfvars file."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.budget_alert_email))
    error_message = "budget_alert_email must be an email address."
  }
}

variable "runner_repository" {
  description = "GitHub repository (owner/name) that builds the CI runner image and may assume the image build role."
  type        = string
  default     = "FreeSecDev/linux-compliance-runner"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.runner_repository))
    error_message = "runner_repository must be owner/name."
  }
}

variable "runner_repository_id" {
  description = "Numeric ID of the runner repository; its immutable subjects embed it."
  type        = string
  default     = "1433323102"

  validation {
    condition     = can(regex("^[0-9]+$", var.runner_repository_id))
    error_message = "runner_repository_id must be numeric."
  }
}

variable "image_build_workflow_file" {
  description = "Workflow file on main of the runner repository that may assume the image build role, matched exactly through job_workflow_ref."
  type        = string
  default     = "image-build.yml"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+\\.ya?ml$", var.image_build_workflow_file))
    error_message = "image_build_workflow_file must be a plain workflow file name such as image-build.yml."
  }
}

variable "image_build_environment" {
  description = "Protected deployment environment of the runner repository whose jobs may assume the image build role; it accepts main only."
  type        = string
  default     = "release"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.image_build_environment))
    error_message = "image_build_environment must be a plain environment name."
  }
}

variable "image_builder_image" {
  description = "Digest-pinned build environment image of the CodeBuild project (Buildah, run rootless by the build script)."
  type        = string
  default     = "quay.io/buildah/stable@sha256:7c2b605262748ace2c5c57c5550942d0adad57aec82ede3070927722306c0ffb"

  validation {
    condition     = can(regex("^[a-z0-9.-]+(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$", var.image_builder_image))
    error_message = "image_builder_image must be pinned by digest (name@sha256:<64 hex>) without a tag."
  }
}

variable "image_build_timeout_minutes" {
  description = "Hard CodeBuild timeout for one image build, in minutes."
  type        = number
  default     = 45

  validation {
    condition     = var.image_build_timeout_minutes >= 10 && var.image_build_timeout_minutes <= 90
    error_message = "image_build_timeout_minutes must be between 10 and 90."
  }
}

variable "image_build_queued_timeout_minutes" {
  description = "Minutes a build may wait in the CodeBuild queue before it is stopped."
  type        = number
  default     = 15

  validation {
    condition     = var.image_build_queued_timeout_minutes >= 5 && var.image_build_queued_timeout_minutes <= 60
    error_message = "image_build_queued_timeout_minutes must be between 5 and 60."
  }
}

variable "image_staging_retention_days" {
  description = "Days an image stays in the private ECR staging repository before the lifecycle policy expires it (ADR 0007)."
  type        = number
  default     = 14

  validation {
    condition     = var.image_staging_retention_days >= 1 && var.image_staging_retention_days <= 30
    error_message = "image_staging_retention_days must be between 1 and 30."
  }
}

variable "image_build_log_retention_days" {
  description = "Retention of the CodeBuild log group in days; at least one year."
  type        = number
  default     = 365

  validation {
    condition     = contains([365, 400, 545, 731], var.image_build_log_retention_days)
    error_message = "image_build_log_retention_days must be 365, 400, 545 or 731."
  }
}
