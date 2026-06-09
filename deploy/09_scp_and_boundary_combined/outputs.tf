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
    # SCP denies PutObject (L3). Permission boundary allows only GetObject (L6).
    # Two independent blocking layers affect different actions.

    ROLE="${aws_iam_role.restricted_role.arn}"
    BUCKET="${aws_s3_bucket.data_bucket.bucket}"

    # GetObject → allowed (neither SCP nor boundary blocks it)
    # Test via Policy Simulator (boundary is auto-applied, SCP is not):
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:GetObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected: "EvalDecision": "allowed"

    # PutObject → implicitDeny in Policy Simulator (boundary blocks it)
    # Real test also blocked by SCP; Policy Simulator only shows boundary block.
    aws iam simulate-principal-policy \
      --policy-source-arn "$ROLE" \
      --action-names s3:PutObject \
      --resource-arns "arn:aws:s3:::$BUCKET/test-key"
    # Expected: "EvalDecision": "implicitDeny"

    # Real credentials test for SCP layer:
    CREDS=$(aws sts assume-role --role-arn "$ROLE" --role-session-name boundary-scp-test --query Credentials --output json)
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

    # PutObject → AccessDenied (SCP blocks before boundary is even reached)
    aws s3api put-object --bucket "$BUCKET" --key "test-key" --body /dev/null 2>&1
    # Expected: AccessDenied

    # DeleteObject → AccessDenied (boundary blocks, SCP does not)
    aws s3api delete-object --bucket "$BUCKET" --key "test-key" 2>&1
    # Expected: AccessDenied

    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  EOT
}
