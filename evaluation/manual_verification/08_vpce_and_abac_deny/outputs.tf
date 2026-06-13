output "role_arn" {
  value = aws_iam_role.developer.arn
}

output "bucket_name" {
  value = aws_s3_bucket.data.bucket
}

output "validate_commands" {
  value = <<-EOT
    # Scenario 08 – vpce_and_abac_deny
    # Bucket policy denies access without VPCE and has ABAC allow (env tag must match).
    # The developer role has env=dev but bucket requires env=prod → ABAC fails.
    # Additionally the VPCE deny fires for any request not from vpce-0a1b2c3d.

    ROLE="${aws_iam_role.developer.arn}"
    BUCKET="${aws_s3_bucket.data.bucket}"
    BUCKET_POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text)

    # GetObject → explicitDeny (VPCE condition fires for simulator; ABAC condition not met)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key" \
      --resource-policy "$BUCKET_POLICY"
    # Expected: "EvalDecision": "explicitDeny"

    # Real test: from an EC2 instance INSIDE the VPC (with the VPCE), assume the
    # developer role (env=dev) and try GetObject — still denied because ABAC fails
    # (principal tag env=dev ≠ bucket tag env=prod).
    # Only a role with env=prod tag from inside the VPC would be allowed.
  EOT
}
