# user_managed_policy_attachment
#
# Setup:
#   - IAM User "alice" with a managed policy granting s3:GetObject
#     attached via aws_iam_user_policy_attachment
#   - S3 bucket "data_bucket" with no bucket policy
#
# Expected:
#   - ALLOW for s3:GetObject (identity policy via managed policy attachment grants access)

resource "aws_iam_user" "alice" {
  name = "alice"

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
      Resource = "arn:aws:s3:::data-bucket/*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "alice_attach" {
  user       = aws_iam_user.alice.name
  policy_arn = aws_iam_policy.s3_read.arn
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "data-bucket"

  tags = {
    environment = "prod"
  }
}
