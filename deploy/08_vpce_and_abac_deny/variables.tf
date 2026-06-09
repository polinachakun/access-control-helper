variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"
}

variable "suffix" {
  description = "Optional suffix appended to resource names to avoid global naming conflicts (e.g. 'abc123')"
  type        = string
  default     = ""
}
