# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — Outputs
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# -----------------------------------------------------------------
# Lambda
# -----------------------------------------------------------------
output "lambda_function_arn" {
  description = "ARN of the CSPM scanner Lambda function"
  value       = aws_lambda_function.scanner.arn
}

output "lambda_function_name" {
  description = "Name of the CSPM scanner Lambda function"
  value       = aws_lambda_function.scanner.function_name
}

# -----------------------------------------------------------------
# DynamoDB
# -----------------------------------------------------------------
output "dynamodb_table_name" {
  description = "Name of the DynamoDB findings table"
  value       = local.dynamodb_table_name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB findings table"
  value       = local.dynamodb_table_arn
}

# -----------------------------------------------------------------
# SNS
# -----------------------------------------------------------------
output "sns_topic_arn" {
  description = "ARN of the SNS alerts topic"
  value       = local.sns_topic_arn
}

# -----------------------------------------------------------------
# EventBridge
# -----------------------------------------------------------------
output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge scheduled rule"
  value       = aws_cloudwatch_event_rule.scanner_schedule.arn
}

# -----------------------------------------------------------------
# IAM
# -----------------------------------------------------------------
output "scanner_role_arn" {
  description = "ARN of the IAM role assumed by the scanner Lambda"
  value       = aws_iam_role.scanner_lambda.arn
}

# -----------------------------------------------------------------
# Lambda Function URL
# -----------------------------------------------------------------
output "slack_action_endpoint" {
  description = "The HTTP endpoint for Slack interactive webhooks"
  value       = aws_lambda_function_url.remediation.function_url
}
