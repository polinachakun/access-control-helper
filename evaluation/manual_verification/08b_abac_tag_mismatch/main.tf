terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  sfx       = var.suffix != "" ? "-${var.suffix}" : ""
  admin_arn = "arn:aws:iam::184789577674:user/polina"
}

resource "aws_iam_role" "developer" {
  name = "developer-b${local.sfx}"

  tags = {
    environment = "dev"
  }

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "ec2.amazonaws.com" }
      },
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { AWS = local.admin_arn }
      }
    ]
  })
}

resource "aws_iam_role_policy" "minimal" {
  name = "allow-get-caller-identity${local.sfx}"
  role = aws_iam_role.developer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:GetCallerIdentity"
      Resource = "*"
    }]
  })
}

resource "aws_s3_bucket" "data" {
  bucket        = "my-data-bucket-b${local.sfx}"
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
        Sid       = "AllowRoleAccessIfTagsMatch"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.developer.arn }
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/environment" = "prod"
          }
        }
      }
    ]
  })
}
