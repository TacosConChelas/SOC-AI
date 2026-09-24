# Cloud control-plane and network-layer telemetry (Infrastructure.md §4.7,
# ADR-0010). Closes the "nothing could observe abuse of the instance role"
# gap: the trail watches the account, VPC Flow Logs watch traffic that
# reaches the instance. Both keep recording while the instance is stopped.
#
# ponytail: enable_cloudtrail/enable_vpc_flow_logs are documented as knobs in
# Infrastructure.md §8, but this telemetry is adopted, not a pending/dormant
# feature like the Wazuh ports or auto-stop - it is built unconditionally
# here. Add an `enable_*` toggle with per-resource `count` if a future need
# to switch it off without deleting code shows up.

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "soc-ai-cloudtrail-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "soc-ai-cloudtrail-logs"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.project.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "expire-old-trail-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.cloudtrail_retention_days
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/soc-ai-trail"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/soc-ai-trail"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

resource "aws_cloudtrail" "main" {
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  name                          = "soc-ai-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.project.arn

  tags = {
    Name = "soc-ai-trail"
  }
}

# --- Grant: instance role reads the CloudTrail bucket (Wazuh aws-s3 wodle) ---

data "aws_iam_policy_document" "instance_cloudtrail_bucket" {
  statement {
    sid       = "ReadCloudTrailLogs"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn, "${aws_s3_bucket.cloudtrail_logs.arn}/*"]
  }
}

resource "aws_iam_role_policy" "instance_cloudtrail_bucket" {
  name   = "soc-ai-instance-cloudtrail-bucket-read"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance_cloudtrail_bucket.json
}

# --- VPC Flow Logs: network-layer visibility of traffic that reaches the instance ---

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/soc-ai/vpc-flow-logs"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "flow_logs_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "soc-ai-vpc-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role.json
}

data "aws_iam_policy_document" "flow_logs_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = [
      aws_cloudwatch_log_group.vpc_flow_logs.arn,
      "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "flow_logs_permissions" {
  name   = "soc-ai-vpc-flow-logs-write"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_permissions.json
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = {
    Name = "soc-ai-vpc-flow-logs"
  }
}
