terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Bootstrap state stays local (it creates the remote state bucket itself).
  # It holds resource IDs only, no secrets; terraform.tfstate is gitignored.
  # Optional: after the first apply, migrate it into the new bucket (see README).
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Stack     = "bootstrap"
    }
  }
}
