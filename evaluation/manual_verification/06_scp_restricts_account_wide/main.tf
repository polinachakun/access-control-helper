terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Management account — Organizations resources (SCP) only
provider "aws" {
  region = var.aws_region
}

# Member account — all IAM and S3 resources live here so SCP applies
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

# ── IAM Roles (member account) ───────────────────────────────────────────────

resource "aws_iam_role" "developer_role" {
  provider = aws.member
  name     = "developer-role${local.sfx}"

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

resource "aws_iam_policy" "developer_s3" {
  provider = aws.member
  name     = "developer-s3${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "developer_attach" {
  provider   = aws.member
  role       = aws_iam_role.developer_role.name
  policy_arn = aws_iam_policy.developer_s3.arn
}

resource "aws_iam_role" "admin_role" {
  provider = aws.member
  name     = "admin-role${local.sfx}"

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

resource "aws_iam_policy" "admin_s3_full" {
  provider = aws.member
  name     = "admin-s3-full${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  provider   = aws.member
  role       = aws_iam_role.admin_role.name
  policy_arn = aws_iam_policy.admin_s3_full.arn
}

# ── S3 Bucket (member account) ───────────────────────────────────────────────

resource "aws_s3_bucket" "data_bucket" {
  provider      = aws.member
  bucket        = "data-bucket${local.sfx}"
  force_destroy = true
}

# ── SCP: deny s3:DeleteObject account-wide ───────────────────────────────────
# Blocks DeleteObject even for the admin role — SCPs are guardrails that
# no identity policy or bucket policy can override.

resource "aws_organizations_policy" "scp_no_delete" {
  name = "deny-s3-delete-account-wide${local.sfx}"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "s3:DeleteObject"
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "scp_attach" {
  policy_id = aws_organizations_policy.scp_no_delete.id
  target_id = var.target_id
}
