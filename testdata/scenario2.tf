# Scenario 2 — Explicit Deny in Bucket Policy overrides IAM Allow
#
# Setup:
#   - IAM Role "app-role" with identity policy allowing s3:*
#   - Bucket policy with explicit Deny on s3:DeleteObject for all principals
#
# Expected:
#   - DENY at Layer 1 for s3:DeleteObject  (explicit deny wins)
#   - ALLOW for s3:GetObject               (no explicit deny, identity policy allows)

resource "aws_iam_role" "app_role" {
  name = "user-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    environment = "prod"
  }
}

resource "aws_iam_policy" "s3_all" {
  name = "s3-full-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "s3:DeleteObject"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_all.arn
}

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"

  tags = {
    environment = "prod"
  }
}

resource "aws_s3_bucket_policy" "deny_delete" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyDeleteObject"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteObject"
        Resource  = "arn:aws:s3:::my-bucket/*"
      },
      {
        Sid    = "AllowGetObject"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.app_role.arn
        }
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
      }
    ]
  })
}
