variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"
}

variable "target_id" {
  description = "Member account ID (12 digits) to deploy resources in and attach SCP to. Required — management account is exempt from SCPs."
  type        = string

  validation {
    condition     = var.target_id != ""
    error_message = "target_id must be set to a member account ID. Management account is exempt from SCPs."
  }
}

variable "suffix" {
  description = "Optional suffix appended to resource names to avoid global naming conflicts (e.g. 'abc123')"
  type        = string
  default     = ""
}
