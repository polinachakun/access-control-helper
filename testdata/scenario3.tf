# Scenario 3 — Access Blocked by Missing Permission Boundary
#
# Setup:
#   - IAM Role "restricted-role" with identity policy allowing s3:*
#   - Permission boundary on the role that only allows s3:GetObject
#
# Expected:
#   - DENY for s3:PutObject  (blocked at Layer 4: boundary does not allow it)
#   - ALLOW for s3:GetObject (both identity policy AND boundary allow it)
#
# Key rule: identity policy alone is insufficient;
# both identity policy AND boundary must allow the action.

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

  # Permission boundary caps the maximum permissions:
  # even though the identity policy allows s3:*, the boundary limits it to s3:GetObject only.
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
