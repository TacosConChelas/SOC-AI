provider "aws" {
  region = var.aws_region

  # No timestamp() here. It is re-evaluated during apply, so tags_all stops
  # matching the plan ("Provider produced inconsistent final plan") and, even
  # when it does apply, every plan afterwards shows a tag change on every
  # taggable resource because the value moved. Creation time already lives in
  # CloudTrail (cloudtrail.tf) and in each resource's own metadata.
  default_tags {
    tags = {
      Project   = "soc-ai"
      ManagedBy = "terraform"
    }
  }
}
