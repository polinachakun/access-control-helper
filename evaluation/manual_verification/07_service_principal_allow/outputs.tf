output "role_arn" {
  value = aws_iam_role.app_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.logs_bucket.bucket
}

output "validate_commands" {
  value = <<-EOT
    # Scenario 07 – service_principal_allow
    # Bucket policy grants lambda.amazonaws.com GetObject + PutObject.
    # app-role only has GetObject in its identity policy.

    ROLE="${aws_iam_role.app_role.arn}"
    BUCKET="${aws_s3_bucket.logs_bucket.bucket}"
    BUCKET_POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text)

    # app-role / GetObject → allowed (identity allows)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key" \
      --resource-policy "$BUCKET_POLICY"
    # Expected: "EvalDecision": "allowed"

    # app-role / PutObject → implicitDeny (identity does not allow PutObject)
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:PutObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key" \
      --resource-policy "$BUCKET_POLICY"
    # Expected: "EvalDecision": "implicitDeny"

    # Note: lambda.amazonaws.com is a service principal and cannot be
    # simulated with simulate-principal-policy. Validate via a real
    # Lambda function invocation or aws lambda invoke.
  EOT
}
