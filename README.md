<!-- markdownlint-disable MD033 MD041 -->
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Terraform-1.5+-7B42BC?style=for-the-badge&logo=terraform&logoColor=white" alt="Terraform" />
  <img src="https://img.shields.io/badge/AWS-Serverless-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white" alt="AWS" />
  <img src="https://img.shields.io/badge/Slack-ChatOps-4A154B?style=for-the-badge&logo=slack&logoColor=white" alt="Slack" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
</p>

# 🛡️ Serverless CSPM Engine with ChatOps & Auto-Remediation

> **A production-grade, event-driven Cloud Security Posture Management (CSPM) engine** that continuously monitors AWS resources, detects misconfigurations, delivers interactive Slack alerts with one-click auto-remediation buttons — all running 100% serverless within the AWS Free Tier.

---

## 💼 Business Impact

Cloud misconfigurations are the **#1 cause of data breaches** in modern organizations. Open S3 buckets, SSH ports exposed to the internet, and unencrypted databases cost companies millions in fines and reputation damage. This project delivers:

- **Automated, continuous scanning** — catches misconfigurations within minutes, not days
- **Mean-Time-to-Detect (MTTD)** reduced from weeks to **under 6 hours**
- **Mean-Time-to-Remediate (MTTR)** reduced to **under 30 seconds** via one-click Slack buttons
- **Zero operational cost** — runs entirely within AWS Free Tier
- **Zero maintenance** — fully serverless, event-driven architecture

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        Serverless CSPM Architecture                         │
│                                                                              │
│  ┌──────────────┐     ┌──────────────────┐     ┌──────────────────────┐      │
│  │  EventBridge  │────▶│  Scanner Lambda  │────▶│  DynamoDB (State)    │      │
│  │  (every 6h)   │     │  (Python 3.12)   │     │  (Deduplication)     │      │
│  └──────────────┘     └───────┬──────────┘     └──────────────────────┘      │
│                               │                                              │
│                    ┌──────────┼──────────┐                                   │
│                    ▼          ▼          ▼                                    │
│              ┌──────────┐ ┌──────┐ ┌──────┐                                  │
│              │ S3 Audit │ │ EC2  │ │ RDS  │  (Multi-Region Scanning)         │
│              └──────────┘ └──────┘ └──────┘                                  │
│                               │                                              │
│                    ┌──────────┴──────────┐                                   │
│                    ▼                     ▼                                    │
│              ┌──────────┐        ┌──────────────┐                            │
│              │   SNS    │        │    Slack      │                            │
│              │ (alerts) │        │ (Block Kit)   │                            │
│              └──────────┘        └──────┬───────┘                            │
│                                         │                                    │
│                                    Click "Fix it 🛠️"                        │
│                                         │                                    │
│                                         ▼                                    │
│                                  ┌──────────────┐     ┌──────────────────┐   │
│                                  │ Remediation  │────▶│ AWS EC2 API      │   │
│                                  │ Lambda (URL) │     │ (Revoke Rules)   │   │
│                                  └──────┬───────┘     └──────────────────┘   │
│                                         │                                    │
│                                         ▼                                    │
│                                  ┌──────────────┐                            │
│                                  │ Slack Reply  │                            │
│                                  │ "✅ Fixed!"   │                            │
│                                  └──────────────┘                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow (Step by Step)

1. **EventBridge** triggers the Scanner Lambda every 6 hours (configurable)
2. **Scanner Lambda** audits S3 buckets, EC2 Security Groups, and RDS instances across multiple AWS regions
3. **DynamoDB** tracks previously seen findings to avoid duplicate alerts (delta detection)
4. **Only new findings** are sent to Slack via an Incoming Webhook with rich Block Kit formatting
5. **Security Group findings** include a "Fix it 🛠️" button for one-click remediation
6. When clicked, Slack sends the action to the **Remediation Lambda** via its public Function URL
7. The Remediation Lambda **verifies the Slack signature** (HMAC-SHA256), then **asynchronously invokes itself** to stay within Slack's 3-second response timeout
8. The background Lambda instance **revokes the dangerous ingress rules** and posts a confirmation back to Slack

---

## ✅ Features — Phase-by-Phase Implementation

### Roadmap

- [x] **Phase 1** — Core Scanner Engine (S3, EC2 Security Groups, RDS)
- [x] **Phase 2** — DynamoDB State Tracking & Delta Detection
- [x] **Phase 3** — Slack ChatOps Integration (Block Kit Alerts)
- [x] **Phase 4** — Infrastructure as Code (Terraform)
- [x] **Phase 5** — Multi-Region Scanning
- [x] **Phase 6** — Auto-Remediation with ChatOps Fix-it Button

### Phase 1: Core Scanner Engine
Built three independent scanner modules using the **Strategy Pattern**:

| Scanner | Service | Checks Performed | Severity |
|---------|---------|-------------------|----------|
| `S3Scanner` | S3 Buckets | Public access block disabled or missing | CRITICAL |
| `SecurityGroupScanner` | EC2 Security Groups | SSH (port 22) open to 0.0.0.0/0 | CRITICAL |
| `SecurityGroupScanner` | EC2 Security Groups | MySQL (port 3306) open to 0.0.0.0/0 | HIGH |
| `RDSScanner` | RDS Instances | Storage encryption disabled | HIGH |

### Phase 2: State Management & Deduplication
- DynamoDB-backed state tracking with automatic local JSON fallback
- Delta detection: only alerts on **new** findings, suppresses known ones
- Automatic detection of **resolved** findings when resources are fixed
- State schema: `ResourceID` (PK) → finding details + status (open/resolved) + timestamps

### Phase 3: Slack ChatOps Integration
- Rich **Block Kit** message formatting with severity indicators and emoji
- Per-finding cards with resource name, type, region, issue description
- Interactive **"Fix it 🛠️"** buttons on remediable findings
- Alert deduplication — no spam for known issues
- Context footer with scanner branding

### Phase 4: Infrastructure as Code
- **100% Terraform-managed** infrastructure (17 resources)
- Least-privilege IAM roles — scanner gets read-only, remediation gets write access
- Environment-aware naming (`cspm-dev-*`, `cspm-prod-*`)
- Sensitive variable handling for tokens and secrets
- Default tags applied across all resources

### Phase 5: Multi-Region Scanning
- Configurable region list via `SCAN_REGIONS` environment variable
- S3 scanning is global; EC2 and RDS are per-region
- Handles cross-region API pagination gracefully

### Phase 6: Auto-Remediation with ChatOps
- **Lambda Function URL** as a public HTTPS endpoint for Slack interactivity
- **Slack Signature Verification** (HMAC-SHA256 with replay protection)
- **Async Self-Invocation Pattern** — Lambda invokes itself asynchronously to beat Slack's 3-second timeout
- Revokes dangerous `0.0.0.0/0` and `::/0` ingress rules for SSH and MySQL ports
- Posts remediation result back to Slack via `response_url`

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Compute** | AWS Lambda (Python 3.12) | Serverless execution for scanning and remediation |
| **State** | Amazon DynamoDB (on-demand) | Finding deduplication and tracking |
| **Messaging** | Amazon SNS | Alert distribution backbone |
| **Notifications** | Slack Incoming Webhooks + Block Kit | Interactive ChatOps alerts |
| **Scheduling** | Amazon EventBridge | Automated 6-hour scan cycles |
| **API** | Lambda Function URL | Public HTTPS endpoint for Slack buttons |
| **Security** | HMAC-SHA256 | Slack request signature verification |
| **IaC** | Terraform ~> 5.0 | Infrastructure provisioning and management |
| **Language** | Python 3.12 (stdlib only) | Zero external dependencies beyond boto3 |
| **VCS** | Git + GitHub | Source control and collaboration |

---

## 📁 Project Structure

```
cspm/
├── README.md                          # This file — comprehensive project documentation
├── .gitignore                         # Python, Terraform, IDE, and project-specific ignores
├── mock_slack.py                      # Local Slack webhook simulator for development
├── docs/
│   └── setup-guide.md                 # Step-by-step deployment guide
│
├── src/
│   ├── __init__.py                    # Root package marker
│   ├── scanner/
│   │   ├── __init__.py                # Re-exports Finding, Severity, Scanner classes
│   │   ├── main.py                    # Lambda handler + CLI entry point (491 lines)
│   │   ├── scanner.py                 # S3Scanner, SecurityGroupScanner, RDSScanner (519 lines)
│   │   ├── models.py                  # Finding, ScanResult, Severity data models (126 lines)
│   │   ├── notifier.py                # Console, Slack (Block Kit), SNS notifiers (437 lines)
│   │   ├── state_manager.py           # DynamoDB + local JSON state backends (308 lines)
│   │   └── requirements.txt           # boto3, botocore
│   └── remediation/
│       ├── handler.py                 # Slack interactivity handler with async pattern (131 lines)
│       └── remediators.py             # Security group remediation logic (78 lines)
│
└── terraform/
    ├── main.tf                        # Provider config, backend, locals
    ├── lambda.tf                      # Scanner + Remediation Lambdas, Function URL
    ├── iam.tf                         # Least-privilege IAM roles & policies
    ├── variables.tf                   # Input variables with validation
    ├── outputs.tf                     # Stack outputs (ARNs, URLs)
    ├── dynamodb.tf                    # DynamoDB table reference
    ├── eventbridge.tf                 # Scheduled scanning rule
    └── sns.tf                         # SNS topic reference
```

### Key Modules Explained

| Module | Lines | Purpose |
|--------|-------|---------|
| `main.py` | 491 | Dual entry point — `lambda_handler()` for AWS Lambda, `main()` for CLI. Orchestrates scan → deduplicate → notify pipeline |
| `scanner.py` | 519 | Three scanner classes using Strategy Pattern. S3 is global, EC2/RDS are per-region. Full pagination support |
| `models.py` | 126 | Frozen (immutable) dataclasses: `Finding`, `ScanResult`, `Severity` enum |
| `notifier.py` | 437 | Three notification backends (Console, Slack, SNS). Slack uses Block Kit with interactive buttons |
| `state_manager.py` | 308 | Dual-backend state manager — DynamoDB primary, local JSON fallback. Automatic probe + graceful degradation |
| `handler.py` | 131 | Slack interactive message handler with HMAC-SHA256 verification and async self-invocation |
| `remediators.py` | 78 | Revokes dangerous `0.0.0.0/0` ingress rules for SSH/MySQL ports on Security Groups |

---

## 🚀 Quick Start

### Prerequisites

- [Python 3.12+](https://www.python.org/downloads/)
- [Terraform ≥ 1.5](https://developer.hashicorp.com/terraform/downloads)
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) — configured with credentials
- An AWS account (Free Tier eligible)
- A Slack workspace with an [Incoming Webhook](https://api.slack.com/messaging/webhooks)

### 1. Clone the Repository

```bash
git clone https://github.com/praveen28-dev/Serverless-CSPM-ChatOps.git
cd Serverless-CSPM-ChatOps
```

### 2. Test Locally (Optional)

```bash
pip install boto3
python -m src.scanner.main --regions ap-south-1,us-east-1
```

### 3. Deploy with Terraform

```bash
cd terraform
terraform init
terraform plan -var="slack_webhook_url=YOUR_WEBHOOK_URL" \
               -var="slack_signing_secret=YOUR_SIGNING_SECRET" \
               -var="slack_bot_token=YOUR_BOT_TOKEN"
terraform apply -auto-approve
```

### 4. Configure Slack Interactivity

1. Go to [Slack API Dashboard](https://api.slack.com/apps) → Your App → **Interactivity & Shortcuts**
2. Toggle **Interactivity** to ON
3. Set **Request URL** to the `slack_action_endpoint` output from Terraform
4. Click **Save Changes**

### 5. Verify

```bash
# Trigger a manual scan
aws lambda invoke \
  --function-name cspm-dev-scanner \
  --region ap-south-1 \
  output.json

cat output.json
```

### 6. Cleanup

```bash
cd terraform
terraform destroy -auto-approve
```

---

## ⚙️ Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | `ap-south-1` | AWS region for infrastructure deployment |
| `scan_regions` | `["ap-south-1","us-east-1"]` | Regions the scanner audits |
| `scan_schedule` | `rate(6 hours)` | EventBridge schedule expression |
| `lambda_timeout` | `120` | Scanner Lambda timeout in seconds |
| `lambda_memory` | `256` | Scanner Lambda memory in MB |
| `slack_webhook_url` | — | Slack Incoming Webhook URL (sensitive) |
| `slack_signing_secret` | — | Slack app signing secret (sensitive) |
| `slack_bot_token` | — | Slack Bot User OAuth Token (sensitive) |

---

## 🧩 Design Patterns

| Pattern | Where Used | Why |
|---------|-----------|-----|
| **Strategy Pattern** | Scanners (`S3Scanner`, `SecurityGroupScanner`, `RDSScanner`) and Notifiers (`Console`, `Slack`, `SNS`) | Pluggable, extensible scanner/notifier framework — add new checks without modifying existing code |
| **Dual-Backend Fallback** | `StateManager` (DynamoDB → local JSON) | Graceful degradation — works locally for development and in Lambda for production |
| **Async Self-Invocation** | `handler.py` (Lambda invokes itself with `InvocationType='Event'`) | Beats Slack's 3-second response timeout while still performing multi-second AWS API operations |
| **Frozen Dataclasses** | `Finding` model | Immutability ensures findings can't be accidentally modified after creation |
| **Least-Privilege IAM** | `iam.tf` (separate roles per Lambda) | Scanner gets read-only access; Remediation gets write access only to specific APIs |
| **Delta Detection** | `_deduplicate()` in `main.py` | Only alerts on new findings — no duplicate spam for known issues |
| **HMAC-SHA256 Verification** | `handler.py` | Cryptographically verifies every incoming request is from Slack, with replay attack protection |

---

## 🏆 Challenges, Failures & Troubleshooting

This section documents the **real-world problems** encountered during development and how they were systematically resolved. These are the types of challenges that demonstrate hands-on cloud engineering skills.

### Challenge 1: API Gateway 403 Forbidden — IAM Permission Wall

**Problem**: The initial design used **API Gateway** to expose the Remediation Lambda. Every request returned `403 Forbidden`.

**Root Cause**: The IAM user (`Fin-App`) used for deployment lacked `apigateway:*` permissions, and the organization's IAM policy restricted creating API Gateway resources.

**Solution**: Pivoted the architecture from API Gateway to **Lambda Function URLs** — a newer AWS feature that provides a built-in HTTPS endpoint for Lambda functions without requiring API Gateway at all.

**Lesson Learned**: Always validate IAM permissions *before* designing the architecture. Lambda Function URLs are a simpler alternative to API Gateway for single-function endpoints.

---

### Challenge 2: Lambda Function URL 502 Bad Gateway

**Problem**: After switching to Lambda Function URLs, all requests returned `502 Bad Gateway`.

**Root Cause**: When using `AuthType: NONE` (public access), AWS requires a **resource-based policy** with `lambda:InvokeFunctionUrl` permission on the function. Without this policy, AWS returns 502 instead of routing the request.

**Diagnosis Steps**:
1. Checked CloudWatch Logs — no invocation logs appeared (request never reached the function)
2. Tested with `curl` — same 502
3. Investigated AWS documentation on Function URL permissions
4. Found that Terraform's `aws_lambda_permission` resource was needed

**Solution**: Added a `aws_lambda_permission` resource:
```hcl
resource "aws_lambda_permission" "allow_public_invoke" {
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.remediation.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}
```

**Lesson Learned**: Lambda Function URLs with `NONE` auth type are not truly "open" by default — they still require an explicit resource-based policy granting public invoke access.

---

### Challenge 3: Slack 3-Second Timeout ("operation_timeout")

**Problem**: Clicking the "Fix it 🛠️" button in Slack showed a ⚠️ warning icon and "This app's response timed out." The remediation *did* complete, but Slack flagged it as failed.

**Root Cause**: Slack requires all interactive message responses within **3.0 seconds**. Our Lambda function was taking ~4-6 seconds because:
- Cold start: ~350ms
- Slack signature verification: ~2ms
- `describe_security_groups` API call: ~1.5s
- `revoke_security_group_ingress` API call: ~1.5s
- `response_url` POST back to Slack: ~1s

**Solution**: Implemented the **Async Self-Invocation Pattern**:
1. The Lambda receives Slack's request, validates the signature
2. Immediately invokes **itself** asynchronously using `boto3.client('lambda').invoke(InvocationType='Event')`
3. Returns HTTP 200 OK to Slack within **200ms**
4. The second (background) Lambda instance performs the actual remediation and posts results back via Slack's `response_url`

```python
# Return 200 immediately, do work in background
lambda_client.invoke(
    FunctionName=context.function_name,
    InvocationType='Event',  # Asynchronous — fire and forget
    Payload=json.dumps({"async_action": "remediate", "payload": payload})
)
return {"statusCode": 200, "body": ""}
```

**IAM Requirement**: This pattern requires the Lambda to have `lambda:InvokeFunction` permission on itself:
```hcl
{
  Sid    = "LambdaSelfInvoke"
  Effect = "Allow"
  Action = ["lambda:InvokeFunction"]
  Resource = "arn:aws:lambda:REGION:ACCOUNT:function:cspm-dev-remediation"
}
```

**Lesson Learned**: Any webhook handler that calls external APIs should use async processing. The 3-second timeout is a hard limit in Slack's interactive message protocol.

---

### Challenge 4: Terraform State Drift After Manual AWS Console Changes

**Problem**: During debugging, a Lambda Function URL was manually recreated via the AWS Console. On the next `terraform apply`, Terraform attempted to create a duplicate, causing conflicts.

**Root Cause**: The manually-created resource existed in AWS but not in Terraform's state file, causing Terraform to treat it as a new resource.

**Solution**: Used `terraform import` to sync the state:
```bash
terraform import aws_lambda_function_url.remediation cspm-dev-remediation
terraform import aws_lambda_permission.allow_public_invoke "cspm-dev-remediation/FunctionURLAllowPublicAccess"
```

**Lesson Learned**: Never modify Terraform-managed resources manually. If you must, always `terraform import` to sync state before running `apply` again.

---

### Challenge 5: Cross-Region Security Group Lookup Failure

**Problem**: Clicking "Fix it" returned "Error: Failed to fetch Security Group sg-xxx details" even though the security group existed.

**Root Cause**: The Slack button's action value encoded the wrong AWS region. The security group existed in `ap-south-1`, but the button value contained `us-east-1`. The Lambda tried to call `describe_security_groups` in the wrong region, where the SG didn't exist.

**Solution**: Fixed the region encoding in the notification payload to always use the finding's actual region:
```python
action_value = json.dumps({
    "action": "remediate",
    "type": finding.resource_type,
    "id": finding.resource_id,
    "region": finding.region  # Must match the actual resource region
})
```

**Lesson Learned**: Always validate that the metadata embedded in interactive buttons matches the actual resource location. Cross-region lookups are a common source of "not found" errors.

---

### Challenge 6: Terraform `aws_lambda_permission` Infinite Hang

**Problem**: `terraform apply` would hang indefinitely on `aws_lambda_permission.allow_public_invoke: Still creating...` for 2+ minutes before timing out.

**Root Cause**: DNS resolution failure for `lambda.ap-south-1.amazonaws.com` — a transient network issue on the local machine.

**Solution**: The permission already existed from a previous manual creation. We imported it:
```bash
terraform import aws_lambda_permission.allow_public_invoke "cspm-dev-remediation/FunctionURLAllowPublicAccess"
```

**Lesson Learned**: Terraform `aws_lambda_permission` operations are idempotent but don't handle existing permissions gracefully. If a permission with the same `statement_id` already exists, the API may hang or error. Always check `aws lambda get-policy` before applying.

---

### Troubleshooting Quick Reference

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `403 Forbidden` on Function URL | Missing resource-based policy | Add `aws_lambda_permission` with `lambda:InvokeFunctionUrl` |
| `502 Bad Gateway` on Function URL | Lambda execution error or missing invoke permission | Check CloudWatch Logs; add `lambda:InvokeFunction` permission |
| Slack timeout warning ⚠️ | Lambda takes >3 seconds to respond | Use async self-invocation pattern (`InvocationType='Event'`) |
| "Failed to fetch Security Group" | Wrong region in button action value | Verify `finding.region` matches the resource's actual region |
| Terraform state drift | Manual AWS Console changes | Use `terraform import` to sync, then `terraform plan` to verify |
| Duplicate Slack alerts | DynamoDB state not clearing | Check `status` field in DynamoDB; run scan to trigger deduplication |
| Lambda "Module not found" error | Incorrect handler path in Terraform | Verify `handler = "src.scanner.main.lambda_handler"` matches package structure |
| `No open rules found` after Fix it | Security group already remediated | Expected behavior — the SG is now secure |

---

## 💰 Cost Analysis

This project runs entirely within the [AWS Free Tier](https://aws.amazon.com/free/):

| Service | Free Tier Allowance | Estimated Usage | Monthly Cost |
|---------|-------------------|-----------------|-------------|
| Lambda | 1M requests/month | ~120 invocations | $0.00 |
| DynamoDB | 25 GB + 25 WCU/RCU | < 1 MB | $0.00 |
| SNS | 1M publishes/month | < 100 publishes | $0.00 |
| EventBridge | All rules free | 1 rule | $0.00 |
| CloudWatch Logs | 5 GB/month | < 50 MB | $0.00 |
| **Total** | | | **$0.00** |

---

## 🔐 Security Considerations

- **Least Privilege**: Scanner Lambda has read-only access; Remediation Lambda only has write access to specific EC2/S3 APIs
- **No Hardcoded Secrets**: All tokens passed via Terraform variables and Lambda environment variables (marked as sensitive)
- **Slack Signature Verification**: Every incoming request is cryptographically verified using HMAC-SHA256 with replay attack protection (5-minute window)
- **Public Endpoint Protection**: The Function URL is public by design (required for Slack webhooks), but every request must pass signature verification before any action is taken
- **Immutable Findings**: The `Finding` dataclass uses `frozen=True` to prevent accidental modification
- **No External Dependencies**: The remediation handler uses only Python stdlib + boto3 — no third-party packages that could introduce supply chain vulnerabilities

---

## 📊 Skills Demonstrated

| Skill Area | Technologies & Concepts |
|-----------|------------------------|
| **Cloud Architecture** | Event-driven, serverless, multi-region, async processing patterns |
| **AWS Services** | Lambda, DynamoDB, EventBridge, SNS, IAM, EC2, S3, RDS, CloudWatch, Function URLs |
| **Infrastructure as Code** | Terraform (HCL), state management, resource import, least-privilege IAM policies |
| **Python Engineering** | Dataclasses, enums, strategy pattern, ABC, type hints, logging, stdlib HTTP |
| **Security Engineering** | CSPM scanning, HMAC-SHA256 verification, replay protection, security group auditing |
| **ChatOps / DevSecOps** | Slack Block Kit, interactive messages, webhook handlers, one-click remediation |
| **Debugging & Troubleshooting** | CloudWatch Logs analysis, Terraform state drift, IAM permission debugging, cross-region issues |
| **API Design** | Webhook handlers, async processing, HTTP status codes, form-encoded payload parsing |

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure all Terraform code passes `terraform validate` and `terraform fmt` before submitting.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with ❤️ for cloud security by <a href="https://github.com/praveen28-dev">@praveen28-dev</a>
</p>
