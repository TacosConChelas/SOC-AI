provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "soc-ai"
      ManagedBy = "terraform"
      CreatedAt = timestamp()
    }
  }
}
