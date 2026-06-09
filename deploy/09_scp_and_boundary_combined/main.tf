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

# ── Permission Boundary ───────────────────────────────────────────────────────

resource "aws_iam_policy" "boundary_get_only" {
  name = "boundary-get-only${local.sfx}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}

# ── IAM Role (boundary + full identity policy) ────────────────────────────────

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

  permissions_boundary = aws_iam_policy.boundary_get_only.arn
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

# ── S3 Bucket ────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "data_bucket" {
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
  target_id = local.effective_target_id
}
