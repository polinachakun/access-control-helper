# rcp_and_scp_combined
#
# Setup:
#   - IAM Role "app_role" with identity policy allowing s3:*
#   - Bucket policy granting full access to app_role
#   - RCP (Resource Control Policy) denying s3:DeleteObject
#   - SCP (Service Control Policy) denying s3:PutObject
#
# Key insight: RCP (L2) and SCP (L3) are independent blocking layers. Each blocks
# a different action. The tool reports the earliest-failing layer.
#
# Expected:
#   - ALLOW  for s3:GetObject    (neither RCP nor SCP blocks it)
#   - ALLOW  for s3:ListBucket   (neither RCP nor SCP blocks it)
#   - DENY at Layer 2 for s3:DeleteObject (RCP blocks it before SCP is checked)
#   - DENY at Layer 3 for s3:PutObject    (RCP does not block, SCP blocks)

resource "aws_iam_role" "app_role" {
  name = "app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "s3_full" {
  name = "s3-full"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_full.arn
}

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_policy" "allow_role" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.app_role.arn }
      Action    = "s3:*"
      Resource  = ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
    }]
  })
}

resource "aws_organizations_policy" "rcp_no_delete" {
  name = "rcp-deny-delete"
  type = "RESOURCE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "s3:DeleteObject"
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy" "scp_no_put" {
  name = "scp-deny-put"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "s3:PutObject"
      Resource = "*"
    }]
  })
}
