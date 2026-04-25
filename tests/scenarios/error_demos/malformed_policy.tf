# error_demo: malformed_policy
#
# Pipeline behaviour:
#   Non-fatal warning on stderr (pipeline continues):
#   "warning: bucket policy "bad_policy": failed to parse policy document: ..."
#
#   The bucket policy is silently dropped from the analysis, but the pipeline
#   still runs. Layer 4 (Resource Policy) will show NOT GRANTED for all triples.
#
# Run:
#   go run . tests/scenarios/error_demos/malformed_policy.tf /tmp/out.als

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

# This bucket policy has intentionally broken JSON (missing closing brace).
# The pipeline will emit a warning and skip this policy.
resource "aws_s3_bucket_policy" "bad_policy" {
  bucket = aws_s3_bucket.my_bucket.id
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\""
}
