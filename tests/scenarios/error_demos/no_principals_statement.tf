# error_demo: no_principals_statement
#
# Pipeline behaviour:
#   Non-fatal warning on stderr:
#   "warning: bucket policy anon_policy statement 1 has no principals; statement skipped"
#
#   A bucket policy statement without a Principal field is invalid for resource
#   policies. The statement is skipped and the policy appears to have no effect
#   on Layer 4 (Resource Policy).
#
# Run:
#   go run . tests/scenarios/error_demos/no_principals_statement.tf /tmp/out.als

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
  name = "s3-read-policy"

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

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"

  tags = {
    environment = "prod"
  }
}

# This bucket policy has a statement with NO Principal field.
# Valid for identity-based policies but not for resource policies.
# The builder will skip the statement and emit a warning.
resource "aws_s3_bucket_policy" "anon_policy" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
      # No Principal field
    }]
  })
}
