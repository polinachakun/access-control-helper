# bucket_policy_grants_same_account
#
# Setup:
#   - IAM Role "app_role" with NO identity policy
#   - Bucket policy granting app_role s3:GetObject, s3:PutObject, s3:ListBucket
#   - Bucket policy also has an explicit Deny on s3:DeleteObject for all principals
#
# Key insight: for same-account access, either the resource policy (L4) OR the
# identity policy (L5) is sufficient to grant access. Here L4 grants and L5 is
# empty — access is still allowed.
#
# Expected:
#   - ALLOW for s3:GetObject   (bucket policy grants via L4; no identity policy)
#   - ALLOW for s3:PutObject   (bucket policy grants via L4; no identity policy)
#   - ALLOW for s3:ListBucket  (bucket policy grants via L4; no identity policy)
#   - DENY at Layer 1 for s3:DeleteObject (explicit deny in bucket policy wins)

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

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRoleReadWrite"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.app_role.arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::my-bucket",
          "arn:aws:s3:::my-bucket/*"
        ]
      },
      {
        Sid       = "DenyDeleteForEveryone"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteObject"
        Resource  = "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}
