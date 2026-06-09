variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"
}

variable "target_id" {
  description = "Organizations target for RCP attachment: account ID (12 digits) or OU ID (ou-xxxx-xxxxxxxx). Defaults to the current account."
  type        = string
  default     = ""
}

variable "suffix" {
  description = "Optional suffix appended to resource names to avoid global naming conflicts"
  type        = string
  default     = ""
}
