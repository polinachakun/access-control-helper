terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  effective_target_id = var.target_id != "" ? var.target_id : data.aws_caller_identity.current.account_id
  sfx                 = var.suffix != "" ? "-${var.suffix}" : ""
}

# ── IAM Role ────────────────────────────────────────────────────────────────

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

resource "aws_iam_policy" "s3_full" {
  name = "s3-full${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_full.arn
}

# ── S3 Bucket ────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "my_bucket" {
  bucket        = "my-bucket${local.sfx}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "allow_role" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.app_role.arn }
      Action    = "s3:*"
      Resource  = [
        aws_s3_bucket.my_bucket.arn,
        "${aws_s3_bucket.my_bucket.arn}/*"
      ]
    }]
  })
}

# ── RCP: deny s3:DeleteObject ─────────────────────────────────────────────
# Resource Control Policies (RCPs) apply to resource-based access regardless
# of the calling identity. Requires AWS Organizations.

resource "aws_organizations_policy" "rcp_no_delete" {
  name = "deny-s3-delete${local.sfx}"
  type = "RESOURCE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "s3:DeleteObject"
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "rcp_attach" {
  policy_id = aws_organizations_policy.rcp_no_delete.id
  target_id = local.effective_target_id
}
