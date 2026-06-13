output "role_arn" {
  value = aws_iam_role.restricted_role.arn
}

output "bucket_name" {
  value = aws_s3_bucket.data_bucket.bucket
}

output "scp_policy_id" {
  value = aws_organizations_policy.scp_no_put.id
}

output "validate_commands" {
  value = <<-EOT
    # Scenario 09 – scp_and_boundary_combined
    # Role and bucket in member account (${var.target_id}) — SCP applies.
    # Permission boundary allows only s3:GetObject.
    # SCP denies s3:PutObject.

    ROLE="${aws_iam_role.restricted_role.arn}"
    BUCKET="${aws_s3_bucket.data_bucket.bucket}"

    CREDS=$(aws sts assume-role --role-arn "$ROLE" --role-session-name boundary-scp-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    # PutObject → AccessDenied (SCP blocks at L3, boundary also blocks at L6)
    echo "" > /tmp/test-file.txt
    aws s3api put-object --bucket "$BUCKET" --key "test-key" --body /tmp/test-file.txt 2>&1
    # Expected: AccessDenied

    # DeleteObject → AccessDenied (boundary blocks at L6, SCP does not block it)
    aws s3api delete-object --bucket "$BUCKET" --key "test-key" 2>&1
    # Expected: AccessDenied

    # GetObject — first upload via management account credentials, then test
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    aws s3api put-object --bucket "$BUCKET" --key "test-key" --body /tmp/test-file.txt

    CREDS=$(aws sts assume-role --role-arn "$ROLE" --role-session-name boundary-scp-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    aws s3api get-object --bucket "$BUCKET" --key "test-key" /tmp/out.txt
    # Expected: success (HTTP 200)

    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  EOT
}
