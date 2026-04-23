# identity_allow_only
#
# Setup:
#   - IAM Role "app_role" with identity policy allowing s3:GetObject
#   - S3 bucket "my_bucket" with NO bucket policy
#
# Expected:
#   - ALLOW for s3:GetObject (identity policy grants, no blocking layers)

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
    environment = "prod"
  }
}

resource "aws_iam_policy" "s3_read" {
  name = "s3-read-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_read.arn
}

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"

  tags = {
    environment = "prod"
  }
}
