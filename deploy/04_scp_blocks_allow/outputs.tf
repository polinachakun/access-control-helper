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
    To validate SCP behavior you must make real API calls with the role's credentials.
    Steps:
      1. terraform apply (creates role + attaches SCP to your account)
      2. aws sts assume-role --role-arn <role_arn> --role-session-name test
      3. Export the temporary credentials, then call s3:DeleteObject — expect AccessDenied
      4. Call s3:GetObject — expect success (SCP does not block it)
  NOTE
  value       = <<-EOT
    # Scenario 04 – scp_blocks_allow
    # SCP denies s3:DeleteObject — must test with real credentials.

    ROLE="${aws_iam_role.app_role.arn}"
    BUCKET="${aws_s3_bucket.my_bucket.bucket}"

    # Step 1: assume the role
    CREDS=$(aws sts assume-role --role-arn "$ROLE" --role-session-name scp-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    # Step 2: test DeleteObject — SCP should block it (AccessDenied)
    aws s3api delete-object --bucket "$BUCKET" --key "test-key" 2>&1
    # Expected: An error occurred (AccessDenied)

    # Step 3: test GetObject — SCP should NOT block it
    aws s3api put-object --bucket "$BUCKET" --key "test-key" --body /dev/null
    aws s3api get-object --bucket "$BUCKET" --key "test-key" /tmp/out.txt
    # Expected: success (HTTP 200)

    # Unset credentials after testing
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  EOT
}
