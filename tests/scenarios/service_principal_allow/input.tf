# service_principal_allow
#
# Setup:
#   - IAM Role "app_role" with identity policy allowing s3:GetObject
#   - S3 bucket "logs_bucket"
#   - Bucket policy granting lambda.amazonaws.com s3:GetObject and s3:PutObject
#
# Expected:
#   - ALLOW for lambda.amazonaws.com/s3:GetObject  (bucket policy grants; L4 alone sufficient)
#   - ALLOW for lambda.amazonaws.com/s3:PutObject  (bucket policy grants; L4 alone sufficient)
#   - DENY  for lambda.amazonaws.com/s3:DeleteObject (not in bucket policy)
#   - ALLOW for app_role/s3:GetObject (identity policy grants)

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

resource "aws_iam_policy" "s3_read" {
  name = "s3-read"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_read.arn
}

resource "aws_s3_bucket" "logs_bucket" {
  bucket = "my-logs-bucket"
}

resource "aws_s3_bucket_policy" "allow_lambda" {
  bucket = aws_s3_bucket.logs_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowLambdaReadWrite"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = ["arn:aws:s3:::my-logs-bucket", "arn:aws:s3:::my-logs-bucket/*"]
      }
    ]
  })
}
