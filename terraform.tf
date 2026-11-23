terraform {
  # The vulnerable image cleanup runs as terraform-aws-lambda-monitored, which needs Terraform 1.9, AWS 5.31 and the
  # null and time providers. Terraform installs a module's providers whether its count is 0 or not, so this floor
  # applies to every caller, with the cleanup on or off.
  required_version = "~> 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31, < 7.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}
