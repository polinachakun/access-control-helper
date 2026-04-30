# scp_restricts_account_wide
#
# Key insight: SCPs are account-level guardrails — they apply to EVERY principal
# in the account, including fully-privileged admin roles. No identity policy or
# bucket policy can override an SCP deny.
#
# Setup:
#   - developer_role: identity policy allowing s3:GetObject only
#   - admin_role:     identity policy allowing s3:* (full S3 access)
#   - Bucket policy grants both roles full S3 access
#   - SCP (deny-only) denies s3:DeleteObject account-wide
#
# Expected for s3:DeleteObject:
#   - developer_role: DENY at Layer 3 (SCP blocks it; identity also doesn't grant it — L5 NOT GRANTED)
#   - admin_role:     DENY at Layer 3 (SCP blocks it despite admin having full identity permissions)
#
# Expected for s3:GetObject:
#   - developer_role: ALLOW (identity grants it, SCP does not block it)
#   - admin_role:     ALLOW
#
# Expected for s3:PutObject, s3:ListBucket:
#   - developer_role: ALLOW — L5 NOT GRANTED (identity has no PutObject/ListBucket), but L4 grants via
#                     bucket policy. Same-account semantics: resource policy OR identity policy suffices.
#   - admin_role:     ALLOW

resource "aws_iam_role" "developer_role" {
  name = "developer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    environment = "dev"
  }
}

resource "aws_iam_role" "admin_role" {
  name = "admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    environment = "dev"
  }
}

resource "aws_iam_policy" "developer_policy" {
  name = "developer-read-only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "admin_policy" {
  name = "admin-s3-full"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "developer_attach" {
  role       = aws_iam_role.developer_role.name
  policy_arn = aws_iam_policy.developer_policy.arn
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.admin_role.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "data-bucket"

  tags = {
    environment = "dev"
  }
}

resource "aws_s3_bucket_policy" "allow_both_roles" {
  bucket = aws_s3_bucket.data_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = [
          aws_iam_role.developer_role.arn,
          aws_iam_role.admin_role.arn
        ]
      }
      Action   = "s3:*"
      Resource = ["arn:aws:s3:::data-bucket", "arn:aws:s3:::data-bucket/*"]
    }]
  })
}

resource "aws_organizations_policy" "scp_no_delete" {
  name = "deny-s3-delete-account-wide"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "s3:DeleteObject"
      Resource = "*"
    }]
  })
}
