# permission_boundary_blocks
#
# Setup:
#   - IAM Role "restricted_role" with identity policy allowing s3:*
#   - Permission boundary on the role that allows ONLY s3:GetObject
#   - S3 bucket "secure_bucket" with NO bucket policy
#
# Expected:
#   - ALLOW for s3:GetObject  (identity allows AND boundary allows)
#   - DENY at Layer 6 for s3:PutObject, s3:ListBucket, s3:DeleteObject
#     (identity allows but boundary does NOT allow those actions)

resource "aws_iam_policy" "s3_get_only_boundary" {
  name = "s3-get-only-boundary"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "restricted_role" {
  name = "restricted-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  permissions_boundary = aws_iam_policy.s3_get_only_boundary.arn

  tags = {
    environment = "prod"
  }
}

resource "aws_iam_policy" "s3_full" {
  name = "s3-full-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_full" {
  role       = aws_iam_role.restricted_role.name
  policy_arn = aws_iam_policy.s3_full.arn
}

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-bucket"

  tags = {
    environment = "prod"
  }
}
