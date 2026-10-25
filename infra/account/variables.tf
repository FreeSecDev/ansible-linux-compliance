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
