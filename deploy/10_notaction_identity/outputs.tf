output "role_arn" {
  value = aws_iam_role.app_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.my_bucket.bucket
}

output "validate_commands" {
  value = <<-EOT
    # Scenario 11 – notaction_identity
    # Identity policy uses NotAction to allow everything EXCEPT s3:DeleteObject.

    ROLE="${aws_iam_role.app_role.arn}"
    BUCKET="${aws_s3_bucket.my_bucket.bucket}"

    # GetObject → allowed (not in NotAction list)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected: "EvalDecision": "allowed"

    # PutObject → allowed (not in NotAction list)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:PutObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected: "EvalDecision": "allowed"

    # DeleteObject → implicitDeny (excluded by NotAction)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:DeleteObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected: "EvalDecision": "implicitDeny"
  EOT
}
