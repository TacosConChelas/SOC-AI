# Ring 3 (ADR-0007 §3, Infrastructure.md §4.4): identities, least privilege, no
# permanent keys on the instance.
#
# Two identities in this pass (Colab writer, decided with the owner 2026-09):
#   1. Instance role  - auto-rotated temporary credentials, assumed by the EC2.
#   2. Colab writer   - IAM user, write-only to soc-ai-models/models/*, used from
#      Google Colab to upload the fine-tuned GGUF (ADR-0008). Its access key lands
#      in Terraform state in plaintext - an accepted trade-off for this identity
#      only (distinct from the "no secret values in state" rule, which governs
#      Parameter Store, secrets.tf).
#
# Prowler identity and the owner's own IAM user are out of scope for this pass:
# Prowler stays gated behind enable_prowler_identity (Infrastructure.md §4.4,
# "off until Prowler is actually adopted") and is not wired here; the owner's
# MFA user is a manual prerequisite (ADR-0007), not Terraform-managed.
#
# Permissions on resources created by later domains (storage.tf, cloudtrail.tf)
# are attached in those files, not here, to avoid forward references across
# domain files while keeping each commit independently valid.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# --- Instance role ---

data "aws_iam_policy_document" "instance_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "soc-ai-instance-role"
  assume_role_policy = data.aws_iam_policy_document.instance_assume_role.json
}

resource "aws_iam_instance_profile" "instance" {
  name = "soc-ai-instance-profile"
  role = aws_iam_role.instance.name
}

resource "aws_iam_role_policy_attachment" "instance_ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "instance_parameter_store" {
  statement {
    sid       = "ReadSocAiParameters"
    effect    = "Allow"
    actions   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = ["arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/soc-ai/*"]
  }
}

resource "aws_iam_role_policy" "instance_parameter_store" {
  name   = "soc-ai-instance-parameter-store-read"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance_parameter_store.json
}

data "aws_iam_policy_document" "instance_cloudwatch" {
  statement {
    sid    = "WriteSocAiLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/soc-ai/*",
      "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/soc-ai/*:*",
    ]
  }

  statement {
    sid       = "WriteSocAiMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "instance_cloudwatch" {
  name   = "soc-ai-instance-cloudwatch-write"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance_cloudwatch.json
}

# --- Colab writer (ADR-0008): write-only, no read, no other resource ---

resource "aws_iam_user" "colab_writer" {
  name = "soc-ai-colab-writer"
}

resource "aws_iam_access_key" "colab_writer" {
  user = aws_iam_user.colab_writer.name
}
