# Transversal variables for the SOC-AI infrastructure skeleton.
# Domain-specific variables (toggles, networking, storage, IAM, secrets, observability)
# will be added as each domain is implemented.
# See Infrastructure.md §2 for the full list of knobs coming: network toggles (D-37),
# instance type, data volume size, alert email, Wazuh ingress toggles, snapshot retention, etc.

variable "aws_region" {
  description = "AWS region for SOC-AI infrastructure (D-33: us-east-2)"
  type        = string
  default     = "us-east-2"
}

# --- network.tf ---

variable "vpc_cidr" {
  description = "CIDR block for the SOC-AI VPC (minimal: single public subnet, no NAT)"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the single public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "enable_wazuh_agent_ingress" {
  description = "D-37: opens 1514/tcp (Wazuh agent session) to wazuh_agent_source_ip. Never 0.0.0.0/0."
  type        = bool
  default     = false
}

variable "enable_wazuh_enrollment_ingress" {
  description = "D-37: opens 1515/tcp (Wazuh agent enrollment) to wazuh_agent_source_ip. Enable only during a host's enrollment window, then close it."
  type        = bool
  default     = false
}

variable "wazuh_agent_source_ip" {
  description = "Owner's current public lab IP (no CIDR suffix). Refreshed per session. Required only when either Wazuh ingress toggle is true."
  type        = string
  default     = ""
}

# --- storage.tf ---

variable "data_volume_size_gb" {
  description = "Size of the data EBS volume (the pet) in GiB. Grow later, never shrink."
  type        = number
  default     = 100
}

variable "snapshot_retention_count" {
  description = "How many DLM snapshots of the data volume to retain"
  type        = number
  default     = 7
}

# --- compute.tf ---

variable "instance_type" {
  description = "EC2 instance type. Was g6.2xlarge (ADR-0007: 1x L4 24GB, 8 vCPU, 32GB RAM); lowered to g6.xlarge on 2026-09-24 (see new-cuota.md) - same L4 and same 24GB VRAM, but 4 vCPU / 16GB RAM, halving the G/VT quota ask AWS denied twice. Raise back to g6.2xlarge if benchmarks show 16GB system RAM starves the stack (ADR-0007 §1: RAM, not VRAM, is the contended resource)."
  type        = string
  default     = "g6.xlarge"
}

# --- observability.tf ---

variable "alert_email" {
  description = "SNS destination for Plane 3 alarms - what happens TO the SOC (instance dead, disk full, GPU saturated, forgot-to-stop)"
  type        = string
}

variable "notify_schedule" {
  description = "EventBridge Scheduler cron/rate expression for the 'instance still running' reminder. Also drives the auto-stop schedule when enable_auto_stop is true."
  type        = string
  default     = "cron(0 4 * * ? *)" # 04:00 UTC nightly
}

variable "enable_auto_stop" {
  description = "Hard cost cap: an EventBridge Scheduler stops the instance at notify_schedule instead of only notifying. Default flipped to true on 2026-09-24 (see new-cuota.md): AWS denied the G/VT vCPU quota twice citing unexpected-spike risk, so the cap is now deployed rather than dormant."
  type        = bool
  default     = true
}

variable "monthly_budget_usd" {
  description = "AWS Budgets monthly cost ceiling for the whole account. Default 80 = headroom over ADR-0007's recalculated $42-66/mo at ~7-10 h/wk of GPU runtime. Notifies alert_email at 80% actual and 100% forecasted; it warns, it does not stop anything (enable_auto_stop is what actually stops spend)."
  type        = number
  default     = 80
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for /soc-ai/* log groups (cost control)"
  type        = number
  default     = 14
}

# --- cloudtrail.tf ---

variable "cloudtrail_retention_days" {
  description = "S3 lifecycle expiration for the CloudTrail log bucket (cost control)"
  type        = number
  default     = 90
}
