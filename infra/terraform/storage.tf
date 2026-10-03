# Storage: the sacred data volume (a pet, not cattle), its snapshots, the
# project KMS key (Ring 4), and the models bucket (ADR-0008 transport).
#
# Grants permissions on resources created here to identities from iam.tf,
# since attaching them there would have been a forward reference.

# CloudTrail needs an explicit grant in the key policy - a key with no policy
# falls back to the default (root-only) policy, which CloudTrail's service
# principal isn't part of, so CreateTrail fails with InsufficientEncryptionPolicyException.
data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid     = "AllowCloudTrailEncrypt"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*"]

    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "AllowCloudTrailDescribe"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "project" {
  description         = "SOC-AI project key (Ring 4): EBS data volume, snapshots, S3 buckets, Parameter Store"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms_key_policy.json

  tags = {
    Name = "soc-ai-kms"
  }
}

resource "aws_kms_alias" "project" {
  name          = "alias/soc-ai"
  target_key_id = aws_kms_key.project.key_id
}

# --- Data EBS: the pet. Principle 1 (Infrastructure.md §1): prevent_destroy so
# not even an accidental `terraform destroy` can take it. ---

resource "aws_ebs_volume" "data" {
  availability_zone = aws_subnet.public.availability_zone
  size              = var.data_volume_size_gb
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.project.arn

  tags = {
    Name          = "soc-ai-data-ebs"
    SocAiSnapshot = "true"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# --- DLM: automated incremental snapshots of the data volume ---

data "aws_iam_policy_document" "dlm_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["dlm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dlm" {
  name               = "soc-ai-dlm-role"
  assume_role_policy = data.aws_iam_policy_document.dlm_assume_role.json
}

data "aws_iam_policy_document" "dlm_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateSnapshot",
      "ec2:CreateSnapshots",
      "ec2:DeleteSnapshot",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
    ]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"]
  }
}

resource "aws_iam_role_policy" "dlm_permissions" {
  name   = "soc-ai-dlm-snapshot-policy"
  role   = aws_iam_role.dlm.id
  policy = data.aws_iam_policy_document.dlm_permissions.json
}

resource "aws_dlm_lifecycle_policy" "data_volume" {
  description        = "SOC-AI data volume incremental snapshots"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "daily snapshots"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["03:00"]
      }

      retain_rule {
        count = var.snapshot_retention_count
      }

      copy_tags = false
    }

    target_tags = {
      SocAiSnapshot = "true"
    }
  }
}

# --- S3 soc-ai-models: canonical home of the GGUF (ADR-0008) + DB backups ---

resource "aws_s3_bucket" "models" {
  bucket = "soc-ai-models-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "soc-ai-models"
  }
}

resource "aws_s3_bucket_versioning" "models" {
  bucket = aws_s3_bucket.models.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "models" {
  bucket = aws_s3_bucket.models.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.project.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "models" {
  bucket = aws_s3_bucket.models.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Grants on soc-ai-models, attached to identities from iam.tf ---

data "aws_iam_policy_document" "instance_models_bucket" {
  statement {
    sid       = "ReadModels"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.models.arn, "${aws_s3_bucket.models.arn}/*"]
  }

  statement {
    sid       = "WriteBackups"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.models.arn}/backups/*"]
  }

  statement {
    sid       = "UseProjectKmsKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.project.arn]
  }
}

resource "aws_iam_role_policy" "instance_models_bucket" {
  name   = "soc-ai-instance-models-bucket-access"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance_models_bucket.json
}

data "aws_iam_policy_document" "colab_writer_models_bucket" {
  statement {
    sid       = "WriteOnlyModels"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.models.arn}/models/*"]
  }

  statement {
    sid       = "UseProjectKmsKeyToEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.project.arn]
  }
}

resource "aws_iam_user_policy" "colab_writer_models_bucket" {
  name   = "soc-ai-colab-writer-write-only"
  user   = aws_iam_user.colab_writer.name
  policy = data.aws_iam_policy_document.colab_writer_models_bucket.json
}
