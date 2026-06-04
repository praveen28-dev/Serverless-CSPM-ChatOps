# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — Lambda Function
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# -----------------------------------------------------------------
# Package the scanner source code into a deployment ZIP
# -----------------------------------------------------------------
data "archive_file" "scanner" {
  type        = "zip"
  source_dir  = "${path.module}/../src/scanner"
  output_path = "${path.module}/../dist/scanner.zip"
}

# -----------------------------------------------------------------
# Scanner Lambda Function
# -----------------------------------------------------------------
resource "aws_lambda_function" "scanner" {
  function_name = "${local.name_prefix}-scanner"
  description   = "CSPM security scanner — audits S3, EC2, and RDS configurations"

  filename         = data.archive_file.scanner.output_path
  source_code_hash = data.archive_file.scanner.output_base64sha256
  handler          = "lambda_handler.lambda_handler"
  runtime          = "python3.12"

  role        = aws_iam_role.scanner_lambda.arn
  timeout     = var.lambda_timeout
  memory_size = var.lambda_memory

  environment {
    variables = {
      DYNAMODB_TABLE    = aws_dynamodb_table.findings.name
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
      SCAN_REGIONS      = join(",", var.scan_regions)
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }

  tags = {
    Name = "${local.name_prefix}-scanner"
  }

  depends_on = [
    aws_iam_role_policy.scanner_cloudwatch,
    aws_cloudwatch_log_group.scanner,
  ]
}

# -----------------------------------------------------------------
# Allow EventBridge to invoke the scanner Lambda
# -----------------------------------------------------------------
resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scanner_schedule.arn
}

# -----------------------------------------------------------------
# CloudWatch Log Group (created before the Lambda to control retention)
# -----------------------------------------------------------------
resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${local.name_prefix}-scanner"
  retention_in_days = 14

  tags = {
    Name = "${local.name_prefix}-scanner-logs"
  }
}
