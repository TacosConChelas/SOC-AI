terraform {
  required_version = ">= 1.11"
  # Terraform 1.11 introduces native S3 lockfile support (use_lockfile).
  # This replaces the need for DynamoDB-based locking and is stable in >= 1.11.
  # See: https://developer.hashicorp.com/terraform/language/state/remote-state-data-sources#s3-backend

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
