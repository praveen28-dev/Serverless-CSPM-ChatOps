# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — DynamoDB Table
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

resource "aws_dynamodb_table" "findings" {
  name         = "${local.name_prefix}-${var.dynamodb_table_name}"
  billing_mode = "PAY_PER_REQUEST"

  # Partition key — unique identifier for each scanned resource
  hash_key = "ResourceID"

  attribute {
    name = "ResourceID"
    type = "S"
  }

  # Enable TTL so stale findings expire automatically
  ttl {
    attribute_name = "ExpiresAt"
    enabled        = true
  }

  tags = {
    Name = "${local.name_prefix}-${var.dynamodb_table_name}"
  }
}
