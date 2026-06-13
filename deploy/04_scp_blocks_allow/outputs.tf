output "role_arn" {
  value = aws_iam_role.app_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.my_bucket.bucket
}

output "scp_policy_id" {
  description = "ID of the attached SCP — useful for verifying in Organizations console"
  value       = aws_organizations_policy.scp_no_delete.id
}

output "validate_commands" {
  description = <<-NOTE
    IMPORTANT: aws iam simulate-principal-policy does NOT simulate SCPs.
    Role and bucket are in the member account so the SCP actually applies.
    Steps:
      1. terraform apply (creates role + bucket in member account, attaches SCP)
      2. aws sts assume-role --role-arn <role_arn> --role-session-name test
         (assumes role IN member account — SCP applies to it)
      3. Export credentials, call s3:DeleteObject — expect AccessDenied
      4. Call s3:GetObject — expect success (SCP does not block it)
  NOTE
  value       = <<-EOT
    # Scenario 04 – scp_blocks_allow
    # Role and bucket are in member account (${var.target_id}) — SCP applies.

    ROLE="${aws_iam_role.app_role.arn}"
    BUCKET="${aws_s3_bucket.my_bucket.bucket}"

    # Step 1: assume the role from management account (trust policy allows it)
    CREDS=$(aws sts assume-role --role-arn "$ROLE" --role-session-name scp-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    # Step 2: upload a test object first
    aws s3api put-object --bucket "$BUCKET" --key "test-key" --body /dev/null

    # Step 3: test DeleteObject — SCP should block it (AccessDenied)
    aws s3api delete-object --bucket "$BUCKET" --key "test-key" 2>&1
    # Expected: An error occurred (AccessDenied)

    # Step 4: test GetObject — SCP should NOT block it
    aws s3api get-object --bucket "$BUCKET" --key "test-key" /tmp/out.txt
    # Expected: success (HTTP 200)

    # Unset credentials after testing
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  EOT
}
