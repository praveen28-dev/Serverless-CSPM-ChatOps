# 📖 Setup Guide — Serverless CSPM Engine

This guide walks you through setting up, configuring, and deploying the CSPM engine from scratch.

---

## 📋 Prerequisites

Before you begin, ensure the following tools are installed:

| Tool | Version | Installation |
|------|---------|-------------|
| Python | 3.12+ | [python.org](https://www.python.org/downloads/) |
| Terraform | ≥ 1.5 | [terraform.io](https://developer.hashicorp.com/terraform/downloads) |
| AWS CLI | v2 | [AWS Docs](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |
| Git | latest | [git-scm.com](https://git-scm.com/downloads) |

---

## 1️⃣ AWS Configuration

### 1.1 Create an IAM User (Recommended for Development)

1. Sign in to the [AWS Console](https://console.aws.amazon.com/).
2. Navigate to **IAM → Users → Create User**.
3. Assign the following managed policies:
   - `AmazonS3ReadOnlyAccess`
   - `AmazonEC2ReadOnlyAccess`
   - `AmazonRDSReadOnlyAccess`
   - `AmazonDynamoDBFullAccess`
   - `AmazonSNSFullAccess`
   - `AWSLambda_FullAccess`
   - `CloudWatchLogsFullAccess`
   - `AmazonEventBridgeFullAccess`
   - `IAMFullAccess` (for Terraform to create roles)
4. Create an access key under **Security credentials → Access keys**.

> **⚠️ Important:** For production, use IAM Identity Center (SSO) or assume-role instead of long-lived access keys.

### 1.2 Configure the AWS CLI

```bash
aws configure
```

Provide:
- **Access Key ID**: `<your-access-key>`
- **Secret Access Key**: `<your-secret-key>`
- **Default region**: `ap-south-1`
- **Output format**: `json`

### 1.3 Verify Access

```bash
aws sts get-caller-identity
```

Expected output:

```json
{
    "UserId": "AIDXXXXXXXXXXXXXXXX",
    "Account": "603542832679",
    "Arn": "arn:aws:iam::603542832679:user/<your-user>"
}
```

---

## 2️⃣ Local Testing

Before deploying to AWS, validate the scanner logic locally.

### 2.1 Set Up a Virtual Environment

```bash
cd src/scanner
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

### 2.2 Install Dependencies

```bash
pip install boto3
```

### 2.3 Run the Scanner Locally

```bash
python lambda_handler.py
```

The scanner will use your locally configured AWS credentials to audit resources. Review the console output for any findings.

### 2.4 Run Unit Tests

```bash
cd ../../tests
python -m pytest test_scanner.py -v
```

---

## 3️⃣ Terraform Deployment

### 3.1 Initialize Terraform

```bash
cd terraform
terraform init
```

This downloads the AWS provider and the archive provider.

### 3.2 Review the Plan

```bash
terraform plan
```

Inspect the plan to ensure the resources match your expectations. Key resources:
- 1 × Lambda function
- 1 × DynamoDB table
- 1 × SNS topic
- 1 × EventBridge rule
- 1 × IAM role with 4 inline policies
- 1 × CloudWatch Log Group

### 3.3 Apply

```bash
terraform apply
```

Type `yes` when prompted. Deployment typically takes 30–60 seconds.

### 3.4 Verify Deployment

```bash
# List the outputs
terraform output

# Test the Lambda manually
aws lambda invoke \
  --function-name cspm-dev-scanner \
  --region ap-south-1 \
  --cli-binary-format raw-in-base64-out \
  output.json

cat output.json
```

### 3.5 Tear Down (when needed)

```bash
terraform destroy
```

---

## 4️⃣ Slack Integration (Phase 3)

### 4.1 Create a Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App**.
2. Choose **From scratch**, name it `CSPM Alerts`, and select your workspace.
3. Navigate to **Incoming Webhooks** and toggle it **On**.
4. Click **Add New Webhook to Workspace** and select a channel (e.g., `#security-alerts`).
5. Copy the Webhook URL.

### 4.2 Configure the Webhook in Terraform

Option A — **terraform.tfvars** (not committed to git):

```hcl
# terraform/terraform.tfvars
slack_webhook_url = "<YOUR_SLACK_WEBHOOK_URL_HERE>"
```

Option B — **Environment variable**:

```bash
export TF_VAR_slack_webhook_url="<YOUR_SLACK_WEBHOOK_URL_HERE>"
```

### 4.3 Enable the SNS Subscription

In `terraform/sns.tf`, uncomment the `aws_sns_topic_subscription` block, then:

```bash
terraform plan
terraform apply
```

### 4.4 Test the Integration

```bash
aws sns publish \
  --topic-arn "$(terraform output -raw sns_topic_arn)" \
  --message '{"severity":"HIGH","resource":"test-bucket","check":"S3 Public Access"}' \
  --region ap-south-1
```

You should see a message in your `#security-alerts` channel within seconds.

---

## 🔧 Troubleshooting

| Issue | Solution |
|-------|---------|
| `terraform init` fails | Check internet connectivity and provider version constraints |
| Lambda timeout | Increase `lambda_timeout` variable (max 900s) |
| No findings in DynamoDB | Verify the Lambda has the correct IAM permissions and scan regions |
| Slack not receiving alerts | Confirm the webhook URL is correct and the SNS subscription is active |
| `AccessDenied` errors | Ensure the IAM user/role has the required permissions |

---

## 📚 Additional Resources

- [AWS Lambda Developer Guide](https://docs.aws.amazon.com/lambda/latest/dg/)
- [Terraform AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
- [AWS Free Tier](https://aws.amazon.com/free/)
