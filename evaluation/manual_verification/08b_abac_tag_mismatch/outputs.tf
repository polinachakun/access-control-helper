output "role_arn" {
  value = aws_iam_role.developer.arn
}

output "bucket_name" {
  value = aws_s3_bucket.data.bucket
}

output "validate_commands" {
  value = <<-EOT
    # Scenario 08b – abac_tag_mismatch
    # No VPCE restriction. Bucket policy has ABAC allow (env tag must match).
    # The developer role has env=dev but bucket requires env=prod → ABAC fails.
    # No explicit deny exists → result is implicitDeny (allow condition not met).

    ROLE="${aws_iam_role.developer.arn}"
    BUCKET="${aws_s3_bucket.data.bucket}"
    BUCKET_POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text)

    # GetObject → implicitDeny (ABAC condition not met: dev ≠ prod)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key" \
      --resource-policy "$BUCKET_POLICY"
    # Expected: "EvalDecision": "implicitDeny"
  EOT
}
