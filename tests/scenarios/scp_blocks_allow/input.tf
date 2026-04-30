# scp_blocks_allow
#
# Setup:
#   - IAM role "app_role" with identity policy allowing s3:*
#   - Bucket policy granting full access to app_role
#   - SCP (deny-only) that denies s3:DeleteObject for all principals
#
# Expected:
#   - DENY at Layer 3 for s3:DeleteObject (SCP explicitly denies it)
#   - ALLOW for s3:GetObject, s3:PutObject, s3:ListBucket (SCP does not deny them)

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

  tags = {
    environment = "dev"
  }
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

  tags = {
    environment = "dev"
  }
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

resource "aws_organizations_policy" "scp_no_delete" {
  name = "deny-s3-delete"
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
