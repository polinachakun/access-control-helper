output "role_arn" {
  value = aws_iam_role.app_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.my_bucket.bucket
}

output "validate_commands" {
  description = "AWS CLI commands to validate via IAM Policy Simulator (include bucket policy via --resource-policy)"
  value       = <<-EOT
    # Scenario 02 – explicit_deny_wins
    # Bucket policy has explicit Deny on s3:DeleteObject.
    # Include it as --resource-policy so the simulator applies it.

    ROLE="${aws_iam_role.app_role.arn}"
    BUCKET="${aws_s3_bucket.my_bucket.bucket}"
    BUCKET_POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text)

    # DeleteObject → denied (L1 explicit deny from bucket policy)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:DeleteObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key" \
      --resource-policy "$BUCKET_POLICY"
    # Expected: "EvalDecision": "explicitDeny"

    # GetObject → allowed (identity + bucket policy both allow)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key" \
      --resource-policy "$BUCKET_POLICY"
    # Expected: "EvalDecision": "allowed"
  EOT
}
