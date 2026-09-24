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
  description = "EC2 instance type (ADR-0007: g6.2xlarge - 1x NVIDIA L4 24GB, 8 vCPU, 32GB RAM)"
  type        = string
  default     = "g6.2xlarge"
}
