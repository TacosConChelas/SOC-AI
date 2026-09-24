# Structure without values (Infrastructure.md §1, Principle 3). Terraform
# declares the Parameter Store names and encrypts them with the project KMS
# key; the owner loads the real values once via CLI
# (`aws ssm put-parameter --type SecureString`). The placeholder value below
# is never the real secret and `ignore_changes` keeps Terraform from ever
# reverting a CLI-loaded value back to the placeholder or writing a real
# value into state.

locals {
  soc_ai_parameters = toset([
    "slack-token",
    "grafana-admin-pw",
    "postgres-pw",
    "redis-acl-pws",
    "wazuh-api-creds",
    "wazuh-authd-pass", # D-37: Wazuh agent enrollment password
  ])
}

resource "aws_ssm_parameter" "soc_ai" {
  for_each = local.soc_ai_parameters

  name        = "/soc-ai/${each.key}"
  description = "SOC-AI secret placeholder - real value loaded via CLI, never by Terraform"
  type        = "SecureString"
  key_id      = aws_kms_key.project.arn
  value       = "REPLACE_ME"

  lifecycle {
    ignore_changes = [value]
  }
}
