# Simple test case: ABAC tag mismatch causes access denial
# Bucket has "prod" tag, but Role has "dev" tag

resource "aws_s3_bucket" "data" {
  bucket = "company-data-bucket"

  tags = {
    environment = "prod"
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyWithoutVPCE"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:sourceVpce" = "vpce-0a1b2c3d"
          }
        }
      },
      {
        Sid    = "AllowRoleAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.developer.arn
        }
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
        Condition = {
          StringEquals = {
            # ABAC: role tag must match bucket tag
            "aws:PrincipalTag/environment" = "prod"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "developer" {
  name = "developer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  # BUG: Role has "dev" but bucket policy requires "prod"
  # This will cause Step 4 (ABAC) to fail
  tags = {
    environment = "dev"
  }
}

# Role has identity policy attached (Step 5 passes)
resource "aws_iam_policy" "s3_read" {
  name = "s3-read-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "developer_s3" {
  role       = aws_iam_role.developer.name
  policy_arn = aws_iam_policy.s3_read.arn
}
