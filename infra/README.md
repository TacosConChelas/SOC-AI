# SOC-AI Infrastructure as Code (Terraform)

This directory contains the complete AWS infrastructure provisioning for SOC-AI Phase 1, entirely managed by Terraform.

## Overview

See `../README.md` (root level) for the repository structure and the phases. The infrastructure is described in full in `.Knowledge/Infrastructure.md` and its design justification in `.Knowledge/ADRs/ADR-0007_AWS_Deployment.md`.

---

## Bootstrap: S3 state bucket (one-time manual task, 0.5.1)

**Before** running any Terraform command, the S3 bucket that holds Terraform state must exist. This is a classic chicken-and-egg problem: Terraform cannot create the bucket where it saves its own state.

### Why: Terraform State is the source of truth

- `terraform.tfstate` is the only record linking your code to live AWS resources.
- Losing the state file means losing the infrastructure map — Terraform would not know what you own.
- The state file contains sensitive data in plaintext (the contents of KMS keys, IAM policies, Parameter Store values, etc.).
- **Therefore, the state bucket must be:**
  - Versioned (restore accidentally-deleted state)
  - Encrypted at rest (SSE-S3, not KMS — the KMS key is provisioned by Terraform itself, circular dependency)
  - Locked down against accidental deletion (must survive `terraform destroy`)
  - Protected against unauthenticated access

### Manual one-time setup (task 0.5.1)

```bash
# Set the bucket name as an environment variable.
export BUCKET="soc-ai-tfstate-85ee5abb"
export REGION="us-east-2"
export OWNER_PROFILE="taco-soc-ai-user"

# Create the bucket in the chosen region.
aws s3api create-bucket \
  --bucket "$BUCKET" \
  --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION" \
  --profile "$OWNER_PROFILE"

# Enable versioning (recovery from accidental deletions).
aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled \
  --region "$REGION" \
  --profile "$OWNER_PROFILE"

# Block all public access (never expose state to the internet).
aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile "$OWNER_PROFILE"

# Enable server-side encryption with SSE-S3 (AWS-managed keys).
# Note: NOT KMS — the project's KMS key is provisioned by Terraform.
# SSE-S3 is simpler and free; once the project key is provisioned, you can upgrade in-place.
aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        }
      }
    ]
  }' \
  --profile "$OWNER_PROFILE"

# Require TLS for all access (reject insecure connections).
aws s3api put-bucket-policy \
  --bucket "$BUCKET" \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyUnencryptedObjectUploads",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::'"$BUCKET"'/*",
        "Condition": {
          "StringNotEquals": {
            "s3:x-amz-server-side-encryption": "AES256"
          }
        }
      },
      {
        "Sid": "DenyInsecureTransport",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::'"$BUCKET"'",
          "arn:aws:s3:::'"$BUCKET"'/*"
        ],
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        }
      }
    ]
  }' \
  --profile "$OWNER_PROFILE"

echo "✅ State bucket '$BUCKET' bootstrapped."
```

### Verification

```bash
# Confirm the bucket exists and has versioning/encryption.
aws s3api get-bucket-versioning --bucket "$BUCKET" --profile "$OWNER_PROFILE"
aws s3api get-bucket-encryption --bucket "$BUCKET" --profile "$OWNER_PROFILE"
aws s3api get-public-access-block --bucket "$BUCKET" --profile "$OWNER_PROFILE"
```

### ⚠️ DO NOT DELETE

The state bucket is the **production database** of your infrastructure. Deleting it is **catastrophic**:
- Terraform no longer knows what it created.
- Manual intervention required to reclaim resources (EC2, EBS, S3, KMS) — expensive and error-prone.
- **Never run `aws s3 rm s3://$BUCKET --recursive` or `aws s3api delete-bucket`** unless you are certain you understand the consequences.

---

## Operating the infrastructure

### Prerequisites

1. **AWS account** with a non-root IAM user (`taco-soc-ai-user`) with **MFA enabled**.
2. **AWS CLI** installed and configured: `aws configure --profile taco-soc-ai-user`.
3. **Terraform >= 1.11** installed (for native S3 lockfile support).
4. **State bucket** bootstrapped (see above, task 0.5.1).

### Workflow

```bash
# Set up the environment. The profile is passed via AWS_PROFILE so credentials
# come from your local AWS config, never from the code or .env.
export AWS_PROFILE=taco-soc-ai-user

# Initialize Terraform. This downloads provider plugins and validates the backend.
# The first init will acquire a lock in the S3 bucket, proving credentials work.
cd infra/terraform
terraform init

# Validate syntax (no AWS API calls yet).
terraform validate

# Plan changes (dry-run against live AWS).
terraform plan

# If plan looks correct, apply.
terraform apply
```

### Cleanup (if reverting)

```bash
# Destroy all managed resources (EXCEPT the data EBS volume, protected with prevent_destroy).
terraform destroy

# To fully delete, you must manually delete the data volume in the AWS console
# or use `aws ec2 delete-volume`, then remove the prevent_destroy lifecycle rule.
```

---

## File structure

```
infra/terraform/
  versions.tf          # Terraform >= 1.11, hashicorp/aws ~> 5.0
  backend.tf           # S3 backend pointing to soc-ai-tfstate-85ee5abb
  providers.tf         # AWS provider with default tags
  variables.tf         # Global knobs: region, and placeholders for domain-specific toggles
  outputs.tf           # (Currently empty; filled as resources are added)
  .gitignore           # State files ignored; .terraform.lock.hcl NOT ignored (committed)
  terraform.tfvars.example  # Template for future variable assignments

  (Future domain files, added in later phases)
  network.tf           # VPC, subnet, security group, IGW
  compute.tf           # EC2 g6.2xlarge, user_data, IMDSv2
  storage.tf           # EBS data volume (prevent_destroy), snapshots, S3 buckets
  iam.tf               # Instance role, least-privilege policies, Colab writer, Prowler
  secrets.tf           # KMS key, Parameter Store structure
  observability.tf     # CloudWatch Agent, logs, metrics, alarms, SNS
  cloudtrail.tf        # CloudTrail, VPC Flow Logs, Prowler identity
```

### Naming conventions

- **Resource names:** lowercase, hyphens, project-prefixed (e.g., `soc-ai-ec2`, `soc-ai-data-ebs`).
- **Output names:** self-documenting (e.g., `instance_id`, `data_volume_id`).
- **Variables:** snake_case (e.g., `aws_region`, `enable_wazuh_agent_ingress`).
- **Tags:** Applied via provider default_tags; individual resources inherit.

---

## Notes

- **Terraform does not start the stack.** It provisions where it runs; `docker compose up` is run manually by the owner over SSM.
- **Secrets never enter Terraform state.** Terraform creates the Parameter Store structure; secret *values* are loaded via CLI (`aws ssm put-parameter`).
- **The .terraform.lock.hcl is committed.** It pins exact provider versions and ensures reproducible deployments.
- **No SSH keys are created.** Access is entirely via AWS SSM Session Manager (port 443 outbound).

---

## References

- `.Knowledge/Infrastructure.md` — full resource inventory and design rationale
- `.Knowledge/ADRs/ADR-0007_AWS_Deployment.md` — deployment decision record
- `.Knowledge/decisions.md` — technical decisions (D-33: region, D-37: toggles)
- `.Knowledge/Diagram_L0_Infrastructure.md` — visual architecture
