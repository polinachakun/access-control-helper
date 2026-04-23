resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket-9d6ce7da"

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
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce" = "vpce-0a1b2c3d"
          }
        }
      },
      {
        Sid    = "AllowRoleAccessIfTagsMatch"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.developer.arn
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/environment" = "prod"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "developer" {
  name = "developer"

  tags = {
    environment = "dev"
  }

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}