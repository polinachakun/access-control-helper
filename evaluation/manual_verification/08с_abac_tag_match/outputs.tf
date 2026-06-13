output "role_arn" {
  value = aws_iam_role.developer.arn
}

output "bucket_name" {
  value = aws_s3_bucket.data.bucket
}

output "validate_commands" {
  value = <<-EOT
    # Scenario 08c – abac_tag_match
    # No VPCE restriction. Bucket policy has ABAC allow (env tag must match).
    # The developer role has env=dev and bucket policy requires env=dev → ABAC passes.
    # No explicit deny exists → result is allowed.

    ROLE="${aws_iam_role.developer.arn}"
    BUCKET="${aws_s3_bucket.data.bucket}"
    BUCKET_POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text)

    # GetObject → allowed (ABAC condition met: dev == dev)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key" \
      --resource-policy "$BUCKET_POLICY"
    # Expected: "EvalDecision": "allowed"
  EOT
}
