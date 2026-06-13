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

resource "aws_iam_policy" "s3_get_only_boundary" {
  name = "s3-get-only-boundary${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "restricted_role" {
  name = "restricted-role${local.sfx}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  permissions_boundary = aws_iam_policy.s3_get_only_boundary.arn
}

resource "aws_iam_policy" "s3_full" {
  name = "s3-full-access${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_full" {
  role       = aws_iam_role.restricted_role.name
  policy_arn = aws_iam_policy.s3_full.arn
}

resource "aws_s3_bucket" "secure_bucket" {
  bucket        = "secure-bucket${local.sfx}"
  force_destroy = true
}
