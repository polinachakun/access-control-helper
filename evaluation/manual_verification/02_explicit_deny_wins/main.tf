terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  sfx = var.suffix != "" ? "-${var.suffix}" : ""
}

resource "aws_iam_role" "app_role" {
  name = "user-role${local.sfx}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "s3_all" {
  name = "s3-full-access${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "s3:DeleteObject"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_all.arn
}

resource "aws_s3_bucket" "my_bucket" {
  bucket        = "my-bucket${local.sfx}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "deny_delete" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyDeleteObject"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteObject"
        Resource  = "${aws_s3_bucket.my_bucket.arn}/*"
      },
      {
        Sid       = "AllowGetAndList"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.app_role.arn }
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource  = [aws_s3_bucket.my_bucket.arn, "${aws_s3_bucket.my_bucket.arn}/*"]
      }
    ]
  })
}
