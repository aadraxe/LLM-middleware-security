variable "aws_region" {
  description = "Region for every resource. The account's organization SCP allows only us-east-2 (same Fargate/ECR/S3 prices as us-east-1)."
  type        = string
  default     = "us-east-2"
}

variable "aws_profile" {
  description = "Local AWS CLI profile (from `aws configure sso`). Credentials are never stored in Terraform."
  type        = string
  default     = null
}

variable "project" {
  description = "Name prefix for all resources."
  type        = string
  default     = "aegisflow-gateway"
}

variable "github_repository" {
  description = "The only GitHub repository (owner/name) whose workflows may assume the CI roles."
  type        = string
  default     = "aadraxe/LLM-middleware-security"
}

variable "create_github_oidc_provider" {
  description = "Set false if this account already has the token.actions.githubusercontent.com provider (only one is allowed per account)."
  type        = bool
  default     = true
}
