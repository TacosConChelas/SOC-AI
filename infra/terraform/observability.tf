# Plane 3 (Observability.md §5): external alerting that survives the instance
# dying. All alarms notify the same SNS topic -> email; deliberately outside
# Slack, which is fed by the pipeline and can't speak when the pipeline can't.
#
# Only alarms 1-4 of Observability.md's "six alarms" are built here (owner
# decision, 2026-09-24). Alarms 5 (CloudTrail bucket growing unconsumed) and 6
# (soc_bus_boundary_rejects_total mirrored to CloudWatch) both depend on
# plumbing that Observability.md §5.1/§7 says does not exist yet: no
# Prometheus -> CloudWatch metric mirror for alarm 6, and no native CloudWatch
# metric for a "vs. last-consumed marker" comparison for alarm 5. Building
# them now would mean inventing metrics the design does not define. They stay
# open until that plumbing exists - tracked as a gap in the final report, not
# built here.

locals {
  soc_ai_docker_services = toset(["worker", "collector", "notifier", "ollama"])
}

resource "aws_cloudwatch_log_group" "docker" {
  for_each = local.soc_ai_docker_services

  name              = "/soc-ai/docker/${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "wazuh_manager" {
  name              = "/soc-ai/wazuh/manager"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "system_syslog" {
  name              = "/soc-ai/system/syslog"
  retention_in_days = var.log_retention_days
}

resource "aws_sns_topic" "alerts" {
  name = "soc-ai-alerts"
}

resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Alarm 1: instance down/unresponsive ---

resource "aws_cloudwatch_metric_alarm" "instance_status_check" {
  alarm_name          = "soc-ai-instance-status-check-failed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching" # an intentional `stop` must not email (§5.2)
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = aws_instance.main.id
  }
}

# --- Alarm 2: /data disk filling ---
# Dimensions assume a CW Agent config publishing `path` per Observability.md
# §4; the agent config JSON itself is not part of this Terraform pass.

resource "aws_cloudwatch_metric_alarm" "data_disk_used" {
  alarm_name          = "soc-ai-data-disk-used-percent"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "disk_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = aws_instance.main.id
    path       = "/data"
  }
}

# --- Alarm 3: GPU saturated sustained (util >= 95% OR VRAM >= ~22GB, 30min) ---
# Composite OR of two base alarms; only the composite notifies.

resource "aws_cloudwatch_metric_alarm" "gpu_util_high" {
  alarm_name          = "soc-ai-gpu-utilization-high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 6 # 6 x 5min = 30min sustained
  metric_name         = "nvidia_smi_utilization_gpu"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 95
  treat_missing_data  = "missing"
  actions_enabled     = false

  dimensions = {
    InstanceId = aws_instance.main.id
  }
}

resource "aws_cloudwatch_metric_alarm" "gpu_memory_high" {
  alarm_name          = "soc-ai-gpu-memory-high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 6
  metric_name         = "nvidia_smi_memory_used"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 22528 # ~22 GiB in MiB
  treat_missing_data  = "missing"
  actions_enabled     = false

  dimensions = {
    InstanceId = aws_instance.main.id
  }
}

resource "aws_cloudwatch_composite_alarm" "gpu_saturated" {
  alarm_name    = "soc-ai-gpu-saturated-sustained"
  alarm_rule    = "ALARM(${aws_cloudwatch_metric_alarm.gpu_util_high.alarm_name}) OR ALARM(${aws_cloudwatch_metric_alarm.gpu_memory_high.alarm_name})"
  alarm_actions = [aws_sns_topic.alerts.arn]
}

# --- Alarm 4 / EventBridge Scheduler: forgot-to-stop reminder (notify-only) ---

data "aws_iam_policy_document" "scheduler_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler_notify" {
  name               = "soc-ai-scheduler-notify-role"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume_role.json
}

data "aws_iam_policy_document" "scheduler_notify_publish" {
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "scheduler_notify_publish" {
  name   = "soc-ai-scheduler-sns-publish"
  role   = aws_iam_role.scheduler_notify.id
  policy = data.aws_iam_policy_document.scheduler_notify_publish.json
}

resource "aws_scheduler_schedule" "notify_still_running" {
  name       = "soc-ai-notify-still-running"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = var.notify_schedule

  target {
    arn      = "arn:${data.aws_partition.current.partition}:scheduler:::aws-sdk:sns:publish"
    role_arn = aws_iam_role.scheduler_notify.arn

    input = jsonencode({
      TopicArn = aws_sns_topic.alerts.arn
      Subject  = "SOC-AI: instance still running"
      Message  = "The SOC-AI EC2 instance is still running. Stop it manually with ./aws-stop.sh if the session is over."
    })
  }
}

# --- Auto-stop: implemented but dormant (enable_auto_stop = false by design) ---

resource "aws_iam_role" "scheduler_auto_stop" {
  count = var.enable_auto_stop ? 1 : 0

  name               = "soc-ai-scheduler-auto-stop-role"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume_role.json
}

data "aws_iam_policy_document" "scheduler_auto_stop_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["ec2:StopInstances"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/${aws_instance.main.id}"]
  }
}

resource "aws_iam_role_policy" "scheduler_auto_stop_permissions" {
  count = var.enable_auto_stop ? 1 : 0

  name   = "soc-ai-scheduler-ec2-stop"
  role   = aws_iam_role.scheduler_auto_stop[0].id
  policy = data.aws_iam_policy_document.scheduler_auto_stop_permissions.json
}

resource "aws_scheduler_schedule" "auto_stop" {
  count = var.enable_auto_stop ? 1 : 0

  name       = "soc-ai-auto-stop"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = var.notify_schedule

  target {
    arn      = "arn:${data.aws_partition.current.partition}:scheduler:::aws-sdk:ec2:stopInstances"
    role_arn = aws_iam_role.scheduler_auto_stop[0].arn

    input = jsonencode({
      InstanceIds = [aws_instance.main.id]
    })
  }
}
