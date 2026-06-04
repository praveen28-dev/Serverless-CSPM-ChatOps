# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — Input Variables
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# -----------------------------------------------------------------
# General
# -----------------------------------------------------------------
variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  description = "Short project identifier used in resource naming"
  type        = string
  default     = "cspm"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# -----------------------------------------------------------------
# Scanner Configuration
# -----------------------------------------------------------------
variable "scan_schedule" {
  description = "EventBridge schedule expression that triggers the scanner Lambda"
  type        = string
  default     = "rate(6 hours)"
}

variable "scan_regions" {
  description = "List of AWS regions the scanner will audit"
  type        = list(string)
  default     = ["ap-south-1", "us-east-1"]
}

# -----------------------------------------------------------------
# Integrations
# -----------------------------------------------------------------
variable "slack_webhook_url" {
  description = "Slack Incoming Webhook URL for ChatOps notifications (leave empty to disable)"
  type        = string
  default     = ""
  sensitive   = true
}

# -----------------------------------------------------------------
# DynamoDB
# -----------------------------------------------------------------
variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table that stores security findings"
  type        = string
  default     = "cspm-findings"
}

# -----------------------------------------------------------------
# SNS
# -----------------------------------------------------------------
variable "sns_topic_name" {
  description = "Name of the SNS topic used for security alerts"
  type        = string
  default     = "cspm-alerts"
}

# -----------------------------------------------------------------
# Lambda
# -----------------------------------------------------------------
variable "lambda_timeout" {
  description = "Timeout in seconds for the scanner Lambda function"
  type        = number
  default     = 120

  validation {
    condition     = var.lambda_timeout >= 30 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 30 and 900 seconds."
  }
}

variable "lambda_memory" {
  description = "Memory allocation in MB for the scanner Lambda function"
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory >= 128 && var.lambda_memory <= 3008
    error_message = "Lambda memory must be between 128 and 3008 MB."
  }
}
