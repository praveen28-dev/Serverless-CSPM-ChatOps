# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — SNS Topic
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# -----------------------------------------------------------------
# SNS topic for security alert notifications
# -----------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-${var.sns_topic_name}"

  tags = {
    Name = "${local.name_prefix}-${var.sns_topic_name}"
  }
}

# -----------------------------------------------------------------
# Slack Webhook Subscription  (Phase 3 — ChatOps Integration)
# -----------------------------------------------------------------
# Uncomment this block when you have the Slack webhook relay set up.
# The HTTPS subscription will forward SNS messages to Slack via the
# Incoming Webhook URL.
#
# resource "aws_sns_topic_subscription" "slack_webhook" {
#   topic_arn = aws_sns_topic.alerts.arn
#   protocol  = "https"
#   endpoint  = var.slack_webhook_url
#
#   # Deliver raw JSON so the Lambda or API Gateway relay can parse it
#   raw_message_delivery = true
# }
