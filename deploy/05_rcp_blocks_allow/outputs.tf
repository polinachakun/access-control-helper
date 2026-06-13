output "role_arn" {
  value = aws_iam_role.app_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.my_bucket.bucket
}

output "rcp_policy_id" {
  description = "ID of the attached RCP"
  value       = aws_organizations_policy.rcp_no_delete.id
}

output "validate_commands" {
  description = "IMPORTANT: simulators do not support RCPs — must test with real credentials. Bucket is in member account so RCP applies to it. Role is in management account; RCP restricts the resource, not the caller."
  value       = <<-EOT
    # Scenario 05 – rcp_blocks_allow
    # Bucket is in member account (${var.target_id}) — RCP applies to it.
    # Role is in management account — RCP still applies (resource-side restriction).

    ROLE="${aws_iam_role.app_role.arn}"
    BUCKET="${aws_s3_bucket.my_bucket.bucket}"

    # Step 1: assume the role
    CREDS=$(aws sts assume-role --role-arn "$ROLE" --role-session-name rcp-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    # Step 2: upload a test object
    echo "" > /tmp/test-file.txt
    aws s3api put-object --bucket "$BUCKET" --key "test-key" --body /tmp/test-file.txt

    # Step 3: test DeleteObject — RCP should block it (AccessDenied)
    aws s3api delete-object --bucket "$BUCKET" --key "test-key" 2>&1
    # Expected: An error occurred (AccessDenied)

    # Step 4: test GetObject — RCP should NOT block it
    aws s3api get-object --bucket "$BUCKET" --key "test-key" /tmp/out.txt
    # Expected: success (HTTP 200)

    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  EOT
}
