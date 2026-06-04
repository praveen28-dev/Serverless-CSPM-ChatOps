<!-- markdownlint-disable MD033 MD041 -->
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Terraform-1.5+-7B42BC?style=for-the-badge&logo=terraform&logoColor=white" alt="Terraform" />
  <img src="https://img.shields.io/badge/AWS-Serverless-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white" alt="AWS" />
  <img src="https://img.shields.io/badge/Slack-ChatOps-4A154B?style=for-the-badge&logo=slack&logoColor=white" alt="Slack" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
</p>

# 🛡️ Serverless CSPM Engine with ChatOps

> **A cloud-native, event-driven Cloud Security Posture Management engine** that continuously monitors your AWS resources, detects misconfigurations, and delivers actionable alerts through Slack — all running serverless within the AWS Free Tier.

---

## 💼 Business Impact

Organizations face an ever-growing attack surface as cloud adoption accelerates. Misconfigured S3 buckets, overly permissive security groups, and unencrypted databases are responsible for the majority of cloud breaches. This project delivers an automated, zero-maintenance security scanner that catches these misconfigurations within minutes — not days — reducing mean-time-to-detect (MTTD) from weeks to under an hour. By integrating directly with Slack, security findings reach the right people instantly, enabling rapid response without context-switching away from daily workflows.

---

## 🏗️ Architecture

<p align="center">
  <img src="docs/architecture.png" alt="CSPM Architecture Diagram" width="800" />
</p>

> _EventBridge triggers the scanner Lambda on a configurable schedule. The Lambda audits AWS resources across multiple regions, stores findings in DynamoDB, and publishes alerts via SNS to Slack._

---

## ✅ Features

### Roadmap

- [x] **Phase 1** — Core Scanner Engine (S3, EC2 Security Groups, RDS)
- [ ] **Phase 2** — DynamoDB State Tracking & Delta Detection
- [ ] **Phase 3** — Slack ChatOps Integration via SNS
- [ ] **Phase 4** — Security Dashboard & Reporting
- [ ] **Phase 5** — Multi-Region Scanning
- [ ] **Phase 6** — Auto-Remediation (with approval workflow)

### Current Capabilities

| Check | Service | Description |
|-------|---------|-------------|
| 🪣 | S3 | Detects publicly accessible buckets |
| 🔓 | EC2 | Flags security groups with `0.0.0.0/0` on sensitive ports |
| 🗄️ | RDS | Identifies unencrypted or publicly accessible databases |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Compute | AWS Lambda (Python 3.12) |
| Storage | DynamoDB (on-demand) |
| Messaging | SNS → Slack Incoming Webhook |
| Scheduling | Amazon EventBridge |
| IaC | Terraform ~> 5.0 |
| CI/CD | GitHub Actions (planned) |

---

## 📁 Project Structure

```
cspm/
├── README.md
├── .gitignore
├── docs/
│   ├── architecture.png          # Architecture diagram
│   └── setup-guide.md            # Detailed setup & deployment guide
├── src/
│   └── scanner/
│       ├── lambda_handler.py     # Lambda entry point
│       ├── checks/
│       │   ├── s3_checks.py      # S3 misconfiguration checks
│       │   ├── ec2_checks.py     # Security group checks
│       │   └── rds_checks.py     # RDS checks
│       └── utils/
│           ├── formatter.py      # Finding formatter
│           └── notifier.py       # SNS / Slack notifier
├── terraform/
│   ├── main.tf                   # Provider & backend config
│   ├── variables.tf              # Input variables
│   ├── outputs.tf                # Stack outputs
│   ├── iam.tf                    # IAM roles & policies
│   ├── lambda.tf                 # Lambda function
│   ├── dynamodb.tf               # DynamoDB table
│   ├── eventbridge.tf            # Scheduled trigger
│   └── sns.tf                    # SNS topic & subscriptions
└── tests/
    └── test_scanner.py           # Unit tests
```

---

## 🚀 Quick Start

### Prerequisites

- [Python 3.12+](https://www.python.org/downloads/)
- [Terraform ≥ 1.5](https://developer.hashicorp.com/terraform/downloads)
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) — configured with credentials
- An AWS account (Free Tier eligible)

### 1. Clone the repository

```bash
git clone https://github.com/praveen28-dev/Serverless-CSPM-ChatOps.git
cd Serverless-CSPM-ChatOps
```

### 2. Test locally (optional)

```bash
cd src/scanner
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install boto3
python lambda_handler.py
```

### 3. Deploy with Terraform

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### 4. Verify

```bash
# Invoke the Lambda manually
aws lambda invoke \
  --function-name cspm-dev-scanner \
  --region ap-south-1 \
  output.json

cat output.json
```

---

## ⚙️ How It Works

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│  EventBridge  │────▶│  Scanner Lambda  │────▶│   DynamoDB   │
│  (scheduled)  │     │  (Python 3.12)   │     │  (findings)  │
└──────────────┘     └───────┬──────────┘     └──────────────┘
                             │
                             ▼
                     ┌──────────────┐     ┌──────────────┐
                     │     SNS      │────▶│    Slack      │
                     │   (alerts)   │     │  (ChatOps)   │
                     └──────────────┘     └──────────────┘
```

1. **EventBridge** fires the scanner Lambda every 6 hours (configurable).
2. The **Lambda** uses read-only API calls to audit S3, EC2, and RDS across target regions.
3. Findings are persisted in **DynamoDB** with TTL-based expiry.
4. New or changed findings are published to **SNS**.
5. SNS delivers formatted alerts to **Slack** via an Incoming Webhook.

---

## 💰 Cost

This project is designed to run entirely within the [AWS Free Tier](https://aws.amazon.com/free/):

| Service | Free Tier Allowance | Estimated Usage |
|---------|-------------------|-----------------|
| Lambda | 1M requests/month | ~120 invocations/month |
| DynamoDB | 25 GB + 25 WCU/RCU | < 1 GB |
| SNS | 1M publishes/month | < 100/month |
| EventBridge | All rules free | 1 rule |
| CloudWatch Logs | 5 GB/month | < 100 MB |

> **Estimated monthly cost: $0.00** (within Free Tier limits)

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
  Built with ❤️ for cloud security
</p>
