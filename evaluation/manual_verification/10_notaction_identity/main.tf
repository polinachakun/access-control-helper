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

resource "aws_iam_policy" "s3_no_delete" {
  name = "s3-no-delete${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      NotAction = ["s3:DeleteObject"]
      Resource  = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_no_delete.arn
}

resource "aws_s3_bucket" "my_bucket" {
  bucket        = "my-bucket${local.sfx}"
  force_destroy = true
}
