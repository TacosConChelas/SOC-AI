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
