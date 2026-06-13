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

# Member account — IAM role, boundary, and S3 bucket live here so SCP applies
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

# ── Permission Boundary (member account) ──────────────────────────────────────

resource "aws_iam_policy" "boundary_get_only" {
  provider = aws.member
  name     = "boundary-get-only${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}

# ── IAM Role (member account) ────────────────────────────────────────────────

resource "aws_iam_role" "restricted_role" {
  provider             = aws.member
  name                 = "restricted-role${local.sfx}"
  permissions_boundary = aws_iam_policy.boundary_get_only.arn

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
  provider = aws.member
  name     = "s3-full-access${local.sfx}"

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
  provider   = aws.member
  role       = aws_iam_role.restricted_role.name
  policy_arn = aws_iam_policy.s3_full.arn
}

# ── S3 Bucket (member account) ───────────────────────────────────────────────

resource "aws_s3_bucket" "data_bucket" {
  provider      = aws.member
  bucket        = "data-bucket${local.sfx}"
  force_destroy = true
}

# ── SCP: deny s3:PutObject ────────────────────────────────────────────────────
# Combined with the permission boundary, this creates two independent blocking
# layers: SCP (L3) blocks PutObject, boundary (L6) blocks everything but GetObject.

resource "aws_organizations_policy" "scp_no_put" {
  name = "deny-s3-put${local.sfx}"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "s3:PutObject"
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "scp_attach" {
  policy_id = aws_organizations_policy.scp_no_put.id
  target_id = var.target_id
}
