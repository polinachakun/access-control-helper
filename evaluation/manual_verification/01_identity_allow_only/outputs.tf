output "role_arn" {
  description = "IAM Role ARN — paste into Policy Simulator as the principal"
  value       = aws_iam_role.app_role.arn
}

output "bucket_name" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.my_bucket.bucket
}

output "validate_commands" {
  description = "AWS CLI commands to validate via IAM Policy Simulator"
  value       = <<-EOT
    # Scenario 01 – identity_allow_only
    # Expected: GetObject → allowed (L5 grants, no bucket policy)

    ROLE="${aws_iam_role.app_role.arn}"
    BUCKET="${aws_s3_bucket.my_bucket.bucket}"

    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected result: "EvalDecision": "allowed"
  EOT
}
