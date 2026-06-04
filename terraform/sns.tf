# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Serverless CSPM Engine — SNS Topic (existing, pre-created)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The SNS topic was created manually in Phase 3. We reference it
# via locals to avoid needing ListTopics/TagResource permissions on
# the Fin-App IAM user. The ARN is deterministic.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

locals {
  sns_topic_name = var.sns_topic_name
  sns_topic_arn  = "arn:aws:sns:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.sns_topic_name}"
}
