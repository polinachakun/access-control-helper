# notaction_identity
#
# Setup:
#   - IAM Role "app_role" with identity policy using NotAction to allow all S3
#     actions EXCEPT s3:DeleteObject
#   - S3 bucket with NO bucket policy
#
# Key insight: Allow + NotAction means "allow everything in the supported action
# set except the listed actions". s3:DeleteObject is excluded from the grant.
#
# Expected:
#   - ALLOW for s3:GetObject    (not excluded by NotAction)
#   - ALLOW for s3:PutObject    (not excluded by NotAction)
#   - ALLOW for s3:ListBucket   (not excluded by NotAction)
#   - DENY at Layer 5 for s3:DeleteObject (identity policy does not grant Delete)

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

resource "aws_iam_policy" "s3_no_delete" {
  name = "s3-no-delete"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect     = "Allow"
      NotAction  = ["s3:DeleteObject"]
      Resource   = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_no_delete.arn
}

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
}
