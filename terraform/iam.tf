# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — IAM Roles & Policies
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Principle of least privilege: each Lambda gets only the permissions
# it needs to do its job — nothing more.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# -----------------------------------------------------------------
# Data sources for ARN construction
# -----------------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# =================================================================
# Scanner Lambda Execution Role
# =================================================================
resource "aws_iam_role" "scanner_lambda" {
  name = "${local.name_prefix}-scanner-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-scanner-lambda-role"
  }
}

# -----------------------------------------------------------------
# Policy: Read-only access to AWS services being scanned
# -----------------------------------------------------------------
resource "aws_iam_role_policy" "scanner_readonly" {
  name = "${local.name_prefix}-scanner-readonly"
  role = aws_iam_role.scanner_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketAcl"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "RDSReadOnly"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------
# Policy: DynamoDB access for the findings table
# -----------------------------------------------------------------
resource "aws_iam_role_policy" "scanner_dynamodb" {
  name = "${local.name_prefix}-scanner-dynamodb"
  role = aws_iam_role.scanner_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBFindingsAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Scan"
        ]
        Resource = local.dynamodb_table_arn
      }
    ]
  })
}

# -----------------------------------------------------------------
# Policy: SNS publish for security alerts
# -----------------------------------------------------------------
resource "aws_iam_role_policy" "scanner_sns" {
  name = "${local.name_prefix}-scanner-sns"
  role = aws_iam_role.scanner_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SNSPublishAlerts"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = local.sns_topic_arn
      }
    ]
  })
}

# -----------------------------------------------------------------
# Policy: CloudWatch Logs for Lambda execution logs
# -----------------------------------------------------------------
resource "aws_iam_role_policy" "scanner_cloudwatch" {
  name = "${local.name_prefix}-scanner-cloudwatch"
  role = aws_iam_role.scanner_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.name_prefix}-scanner:*"
      }
    ]
  })
}

# =================================================================
# Remediation Lambda Execution Role  (Phase 6 — Auto-Remediation)
# =================================================================
# Uncomment this block when implementing Phase 6.
#
# resource "aws_iam_role" "remediation_lambda" {
#   name = "${local.name_prefix}-remediation-lambda-role"
#
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect = "Allow"
#         Principal = {
#           Service = "lambda.amazonaws.com"
#         }
#         Action = "sts:AssumeRole"
#       }
#     ]
#   })
#
#   tags = {
#     Name = "${local.name_prefix}-remediation-lambda-role"
#   }
# }
#
# resource "aws_iam_role_policy" "remediation_cloudwatch" {
#   name = "${local.name_prefix}-remediation-cloudwatch"
#   role = aws_iam_role.remediation_lambda.id
#
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Sid    = "CloudWatchLogs"
#         Effect = "Allow"
#         Action = [
#           "logs:CreateLogGroup",
#           "logs:CreateLogStream",
#           "logs:PutLogEvents"
#         ]
#         Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.name_prefix}-remediation:*"
#       }
#     ]
#   })
# }
#
# resource "aws_iam_role_policy" "remediation_actions" {
#   name = "${local.name_prefix}-remediation-actions"
#   role = aws_iam_role.remediation_lambda.id
#
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Sid    = "S3Remediation"
#         Effect = "Allow"
#         Action = [
#           "s3:PutBucketPublicAccessBlock"
#         ]
#         Resource = "*"
#       },
#       {
#         Sid    = "EC2Remediation"
#         Effect = "Allow"
#         Action = [
#           "ec2:RevokeSecurityGroupIngress"
#         ]
#         Resource = "*"
#       }
#     ]
#   })
# }
