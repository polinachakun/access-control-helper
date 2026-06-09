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
  # VPC endpoint ID used in the bucket policy condition.
  # Replace with a real vpce-* ID from your VPC before applying.
  vpce_id = "vpce-0a1b2c3d"
}

resource "aws_iam_role" "developer" {
  name = "developer${local.sfx}"

  tags = {
    environment = "dev"
  }

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_s3_bucket" "data" {
  bucket        = "my-data-bucket${local.sfx}"
  force_destroy = true

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
        Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce" = local.vpce_id
          }
        }
      },
      {
        Sid    = "AllowRoleAccessIfTagsMatch"
        Effect = "Allow"
        Principal = { AWS = aws_iam_role.developer.arn }
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/environment" = "prod"
          }
        }
      }
    ]
  })
}
