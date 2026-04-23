# explicit_deny_wins
#
# Setup:
#   - IAM Role "app_role" with identity policy allowing s3:* (all S3 actions)
#   - Bucket policy with explicit Deny on s3:DeleteObject for all principals
#   - Bucket policy also allows s3:GetObject and s3:ListBucket for app_role
#
# Expected:
#   - DENY at Layer 1 for s3:DeleteObject  (explicit deny overrides all allows)
#   - ALLOW for s3:GetObject               (bucket policy grants, identity grants)
#   - ALLOW for s3:ListBucket              (bucket policy grants, identity grants)
#   - ALLOW for s3:PutObject               (no explicit deny, identity grants — same-account union)

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
        Sid    = "AllowGetAndList"
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
