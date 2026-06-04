# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — Main Terraform Configuration
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# This file wires up the AWS provider and sets project-wide defaults.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # ---------------------------------------------------------------
  # Uncomment the block below to enable remote state in S3.
  # Create the bucket and DynamoDB lock table first, then configure:
  #
  # backend "s3" {
  #   bucket         = "cspm-terraform-state-603542832679"
  #   key            = "cspm/terraform.tfstate"
  #   region         = "ap-south-1"
  #   dynamodb_table = "cspm-terraform-locks"
  #   encrypt        = true
  # }
  # ---------------------------------------------------------------
}

# -----------------------------------------------------------------
# AWS Provider
# -----------------------------------------------------------------
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "https://github.com/praveen28-dev/Serverless-CSPM-ChatOps.git"
    }
  }
}

# -----------------------------------------------------------------
# Local Values — common naming helpers
# -----------------------------------------------------------------
locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}
