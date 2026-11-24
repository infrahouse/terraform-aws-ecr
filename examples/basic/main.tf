terraform {
  required_version = "~> 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "ecr" {
  source  = "registry.infrahouse.com/infrahouse/ecr/aws"
  version = "1.0.1"

  repo_name    = var.repo_name
  environment  = var.environment
  service_name = var.service_name

  # The module needs at least one lifecycle rule: with none set, terraform plan fails.

  # A tagged image whose tag starts with "v" expires 365 days after it was pushed.
  expire_days_tagged = 365
  tag_prefix_list    = ["v"]

  # Keep the 5 newest untagged images and expire the rest.
  expire_count_untagged = 5
}
