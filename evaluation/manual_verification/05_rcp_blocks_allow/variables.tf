variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"
}

variable "target_id" {
  description = "Member account ID (12 digits) to deploy S3 bucket in and attach RCP to. Required — RCP must be on the account that owns the resource."
  type        = string

  validation {
    condition     = var.target_id != ""
    error_message = "target_id must be set to a member account ID."
  }
}

variable "suffix" {
  description = "Optional suffix appended to resource names to avoid global naming conflicts"
  type        = string
  default     = ""
}
