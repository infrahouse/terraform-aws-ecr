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

  # The images something runs by tag outside the service's deployments, such as a migration task's image.
  # No lifecycle rule expires an image while it carries one of these tags.
  retain_tags = var.retain_tags

  # Rollback candidates: the images the ECS module tagged deployed-at-<timestamp> after a successful deployment.
  # Keep the 5 newest, however old they are.
  rollback_candidate_retain_count = 5

  # Every tagged image: keep the 30 newest. The retained images and the rollback candidates match "*" too, so ECR
  # counts them among the 30, but this rule can't expire them: higher-priority rules select them.
  expire_count_tagged = 30
  tag_pattern_list    = ["*"]

  # Untagged images, such as an image a tag moved away from, expire 7 days after they were pushed.
  expire_days_untagged = 7
}
