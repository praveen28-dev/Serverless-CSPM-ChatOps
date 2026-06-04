# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — DynamoDB Table (existing, pre-created)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The DynamoDB table was created manually in Phase 2. We reference it
# via locals to avoid needing Describe/Tag permissions on the Fin-App
# IAM user. The ARN is deterministic from account + region + table name.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

locals {
  dynamodb_table_name = var.dynamodb_table_name
  dynamodb_table_arn  = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.dynamodb_table_name}"
}
