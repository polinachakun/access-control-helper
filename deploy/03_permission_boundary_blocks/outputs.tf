output "role_arn" {
  value = aws_iam_role.restricted_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.secure_bucket.bucket
}

output "validate_commands" {
  description = "AWS CLI commands — Policy Simulator automatically includes the permission boundary when you use the role ARN as policy-source-arn"
  value       = <<-EOT
    # Scenario 03 – permission_boundary_blocks
    # The role has permissions_boundary set — Policy Simulator applies it automatically.

    ROLE="${aws_iam_role.restricted_role.arn}"
    BUCKET="${aws_s3_bucket.secure_bucket.bucket}"

    # GetObject → allowed (identity allows AND boundary allows)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected: "EvalDecision": "allowed"

    # PutObject → implicitDeny (identity allows but boundary does NOT allow)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:PutObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected: "EvalDecision": "implicitDeny"

    # DeleteObject → implicitDeny (same reason)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:DeleteObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected: "EvalDecision": "implicitDeny"
  EOT
}
