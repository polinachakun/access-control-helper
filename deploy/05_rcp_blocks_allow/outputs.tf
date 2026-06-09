output "role_arn" {
  value = aws_iam_role.app_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.my_bucket.bucket
}

output "rcp_policy_id" {
  value = aws_organizations_policy.rcp_no_delete.id
}

output "validate_commands" {
  value = <<-EOT
    # Scenario 05 – rcp_blocks_allow
    # RCP (Resource Control Policy) denies s3:DeleteObject.
    # Must test with real credentials — simulators do not support RCPs.

    ROLE="${aws_iam_role.app_role.arn}"
    BUCKET="${aws_s3_bucket.my_bucket.bucket}"

    CREDS=$(aws sts assume-role --role-arn "$ROLE" --role-session-name rcp-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    # DeleteObject → AccessDenied (RCP blocks it at resource level)
    aws s3api delete-object --bucket "$BUCKET" --key "test-key" 2>&1
    # Expected: AccessDenied

    # GetObject → success (RCP does not block it)
    aws s3api put-object --bucket "$BUCKET" --key "test-key" --body /dev/null
    aws s3api get-object --bucket "$BUCKET" --key "test-key" /tmp/out.txt
    # Expected: success

    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  EOT
}
