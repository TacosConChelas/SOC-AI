terraform {
  backend "s3" {
    bucket       = "soc-ai-tfstate-85ee5abb"
    key          = "soc-ai/terraform.tfstate"
    region       = "us-east-2"
    encrypt      = true
    use_lockfile = true
    # AWS credentials are loaded from the environment (AWS_PROFILE=taco-soc-ai-user).
    # Never hardcode profile, access_key, or secret_key here.
  }
}
