terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Management account — Organizations resources (RCP) only
provider "aws" {
  region = var.aws_region
}

# Member account — S3 bucket lives here so RCP actually applies to it.
# RCPs restrict resources in the attached account regardless of caller identity.
provider "aws" {
  alias  = "member"
  region = var.aws_region
  assume_role {
    role_arn = "arn:aws:iam::${var.target_id}:role/OrganizationAccountAccessRole"
  }
}

data "aws_caller_identity" "management" {}

locals {
  sfx = var.suffix != "" ? "-${var.suffix}" : ""
}

# ── IAM Role (management account) ───────────────────────────────────────────
# RCP applies to the resource (bucket), not the identity, so role can stay here.

resource "aws_iam_role" "app_role" {
  name = "app-role${local.sfx}"

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
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.management.account_id}:root" }
      }
    ]
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

# ── S3 Bucket (member account) ───────────────────────────────────────────────
# Bucket must be in member account so the RCP attached to it takes effect.

resource "aws_s3_bucket" "my_bucket" {
  provider      = aws.member
  bucket        = "my-bucket${local.sfx}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "allow_role" {
  provider = aws.member
  bucket   = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.app_role.arn }
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.my_bucket.arn,
        "${aws_s3_bucket.my_bucket.arn}/*"
      ]
    }]
  })
}

# ── RCP: deny s3:DeleteObject ─────────────────────────────────────────────────

resource "aws_organizations_policy" "rcp_no_delete" {
  name = "deny-s3-delete${local.sfx}"
  type = "RESOURCE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:DeleteObject"
      Resource  = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "rcp_attach" {
  policy_id = aws_organizations_policy.rcp_no_delete.id
  target_id = var.target_id
}
