# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — EventBridge Schedule
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# -----------------------------------------------------------------
# Scheduled rule that triggers the scanner on a recurring cadence
# -----------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "scanner_schedule" {
  name                = "${local.name_prefix}-scanner-schedule"
  description         = "Triggers the CSPM scanner Lambda on a recurring schedule"
  schedule_expression = var.scan_schedule

  tags = {
    Name = "${local.name_prefix}-scanner-schedule"
  }
}

# -----------------------------------------------------------------
# Target: invoke the scanner Lambda when the rule fires
# -----------------------------------------------------------------
resource "aws_cloudwatch_event_target" "scanner_lambda" {
  rule      = aws_cloudwatch_event_rule.scanner_schedule.name
  target_id = "${local.name_prefix}-scanner"
  arn       = aws_lambda_function.scanner.arn
}
