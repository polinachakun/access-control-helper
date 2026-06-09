# scp_and_boundary_combined
#
# Setup:
#   - IAM Role "restricted_role" with identity policy allowing s3:*
#   - Permission boundary on the role allowing ONLY s3:GetObject
#   - SCP denying s3:PutObject for all principals
#   - S3 bucket with NO bucket policy
#
# Expected:
#   - ALLOW for s3:GetObject   (identity allows, boundary allows, SCP does not block)
#   - DENY at Layer 3 for s3:PutObject   (SCP explicitly denies; boundary also blocks → L3 reported first)
#   - DENY at Layer 6 for s3:ListBucket  (SCP does not block, but boundary only allows GetObject)
#   - DENY at Layer 6 for s3:DeleteObject (same as ListBucket — boundary blocks)

resource "aws_iam_policy" "boundary_get_only" {
  name = "boundary-get-only"

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

  permissions_boundary = aws_iam_policy.boundary_get_only.arn
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

resource "aws_s3_bucket" "data_bucket" {
  bucket = "data-bucket"
}

resource "aws_organizations_policy" "scp_no_put" {
  name = "deny-s3-put"
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
