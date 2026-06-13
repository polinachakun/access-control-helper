output "developer_role_arn" {
  value = aws_iam_role.developer_role.arn
}

output "admin_role_arn" {
  value = aws_iam_role.admin_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.data_bucket.bucket
}

output "scp_policy_id" {
  value = aws_organizations_policy.scp_no_delete.id
}

output "validate_commands" {
  value = <<-EOT
    # Scenario 06 – scp_restricts_account_wide
    # SCP blocks s3:DeleteObject for BOTH developer-role AND admin-role.
    # Key point: even admin with s3:* cannot override an SCP.

    DEV_ROLE="${aws_iam_role.developer_role.arn}"
    ADMIN_ROLE="${aws_iam_role.admin_role.arn}"
    BUCKET="${aws_s3_bucket.data_bucket.bucket}"

    # Upload test object (management account has cross-account access via bucket policy)
    echo "" > /tmp/test-file.txt

    # --- developer-role ---
    CREDS=$(aws sts assume-role --role-arn "$DEV_ROLE" --role-session-name scp-dev-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    aws s3api delete-object --bucket "$BUCKET" --key "test-key" 2>&1
    # Expected: AccessDenied (SCP)

    aws s3api get-object --bucket "$BUCKET" --key "test-key" /tmp/out.txt
    # Expected: success

    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

    # --- admin-role ---
    CREDS=$(aws sts assume-role --role-arn "$ADMIN_ROLE" --role-session-name scp-admin-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    aws s3api delete-object --bucket "$BUCKET" --key "test-key" 2>&1
    # Expected: AccessDenied (SCP) — even admin is blocked

    aws s3api get-object --bucket "$BUCKET" --key "test-key" /tmp/out.txt
    # Expected: success

    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  EOT
}
