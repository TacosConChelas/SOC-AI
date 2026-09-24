# Nothing sensitive: no secret ARNs, no parameter values (Infrastructure.md
# §1, Principle 3).

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.main.id
}

output "ssm_session_command" {
  description = "Open an SSM session to the instance (zero inbound ports)"
  value       = "aws ssm start-session --target ${aws_instance.main.id} --profile taco-soc-ai-user"
}

output "models_bucket_name" {
  description = "S3 bucket holding the GGUF (ADR-0008) and DB backups"
  value       = aws_s3_bucket.models.id
}

output "cloudtrail_bucket_name" {
  description = "S3 bucket holding CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}
