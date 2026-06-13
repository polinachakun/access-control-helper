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
  name = "app-role${local.sfx}"

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
  name = "s3-read${local.sfx}"

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
  bucket        = "my-logs-bucket${local.sfx}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "allow_lambda" {
  bucket = aws_s3_bucket.logs_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowLambdaReadWrite"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = ["s3:GetObject", "s3:PutObject"]
      Resource  = [aws_s3_bucket.logs_bucket.arn, "${aws_s3_bucket.logs_bucket.arn}/*"]
    }]
  })
}
