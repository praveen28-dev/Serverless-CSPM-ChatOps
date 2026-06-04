# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — Lambda Function
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# -----------------------------------------------------------------
# Package the scanner source code into a deployment ZIP
# -----------------------------------------------------------------
data "archive_file" "scanner" {
  type        = "zip"
  source_dir  = "${path.module}/.."
  excludes    = [
    ".git", 
    "terraform", 
    "dist", 
    "venv", 
    ".venv",
    ".gemini",
    "__pycache__", 
    ".pytest_cache", 
    "mock_slack.log"
  ]
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
  handler          = "src.scanner.main.lambda_handler"
  runtime          = "python3.12"

  role        = aws_iam_role.scanner_lambda.arn
  timeout     = var.lambda_timeout
  memory_size = var.lambda_memory

  environment {
    variables = {
      DYNAMODB_TABLE    = local.dynamodb_table_name
      DYNAMODB_REGION   = var.aws_region
      SNS_TOPIC_ARN     = local.sns_topic_arn
      SCAN_REGIONS      = join(",", var.scan_regions)
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      SLACK_BOT_TOKEN   = var.slack_bot_token
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

# -----------------------------------------------------------------
# Remediation Lambda Function
# -----------------------------------------------------------------
resource "aws_lambda_function" "remediation" {
  function_name = "${local.name_prefix}-remediation"
  description   = "CSPM remediation handler for ChatOps interactivity"

  filename         = data.archive_file.scanner.output_path
  source_code_hash = data.archive_file.scanner.output_base64sha256
  handler          = "src.remediation.handler.lambda_handler"
  runtime          = "python3.12"

  role        = aws_iam_role.remediation_lambda.arn
  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      SLACK_SIGNING_SECRET = var.slack_signing_secret
      SLACK_BOT_TOKEN      = var.slack_bot_token
    }
  }

  tags = {
    Name = "${local.name_prefix}-remediation"
  }

  depends_on = [
    aws_iam_role_policy.remediation_cloudwatch,
    aws_cloudwatch_log_group.remediation,
  ]
}

# -----------------------------------------------------------------
# CloudWatch Log Group for Remediation Lambda
# -----------------------------------------------------------------
resource "aws_cloudwatch_log_group" "remediation" {
  name              = "/aws/lambda/${local.name_prefix}-remediation"
  retention_in_days = 14

  tags = {
    Name = "${local.name_prefix}-remediation-logs"
  }
}

# -----------------------------------------------------------------
# Lambda Function URL for Remediation
# -----------------------------------------------------------------
resource "aws_lambda_function_url" "remediation" {
  function_name      = aws_lambda_function.remediation.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "allow_public_invoke" {
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.remediation.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}
