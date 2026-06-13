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

# Member account — IAM role and S3 bucket live here so SCP actually applies.
# SCPs do NOT apply to the management account, so resources must be in a member account.
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

# ── IAM Role (member account) ────────────────────────────────────────────────

resource "aws_iam_role" "app_role" {
  provider = aws.member
  name     = "app-role${local.sfx}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "ec2.amazonaws.com" }
      },
      {
        # Allow management account to assume this role for manual testing
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.management.account_id}:root" }
      }
    ]
  })
}

resource "aws_iam_policy" "s3_full" {
  provider = aws.member
  name     = "s3-full${local.sfx}"

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
  provider   = aws.member
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_full.arn
}

# ── S3 Bucket (member account) ───────────────────────────────────────────────

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

# ── SCP: deny s3:DeleteObject ─────────────────────────────────────────────────

resource "aws_organizations_policy" "scp_no_delete" {
  name = "deny-s3-delete${local.sfx}"
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
