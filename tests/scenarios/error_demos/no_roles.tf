# error_demo: no_roles
#
# Pipeline behaviour:
#   Fatal error before Alloy is invoked:
#   "configuration error: no IAM roles found in configuration; nothing to analyse"
#
# Run:
#   go run . tests/scenarios/error_demos/no_roles.tf /tmp/out.als

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"

  tags = {
    environment = "prod"
  }
}

resource "aws_s3_bucket_policy" "my_bucket" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:role/some-role" }
      Action    = ["s3:GetObject"]
      Resource  = "arn:aws:s3:::my-bucket/*"
    }]
  })
}
