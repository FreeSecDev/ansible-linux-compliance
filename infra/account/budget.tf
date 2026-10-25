locals {
  budget_thresholds = [50, 80, 100]
  budget_notifications = flatten([
    for threshold in local.budget_thresholds : [
      { threshold = threshold, notification_type = "ACTUAL" },
      { threshold = threshold, notification_type = "FORECASTED" },
    ]
  ])
}

resource "aws_budgets_budget" "monthly" {
  name         = local.budget_name
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = local.budget_notifications

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.notification_type
      subscriber_email_addresses = [var.budget_alert_email]
    }
  }
}
