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
  version = "1.0.2"

  repo_name    = var.repo_name
  environment  = var.environment
  service_name = var.service_name

  # The lifecycle policy. The cleanup protects the retained images and the rollback candidates the policy keeps;
  # the expire_* rules protect nothing from it.
  retain_tags                     = var.retain_tags
  rollback_candidate_retain_count = 5
  expire_count_tagged             = 30
  tag_pattern_list                = ["*"]
  expire_days_untagged            = 7

  # A daily job that deletes the images Amazon Inspector reports vulnerable and that nothing protects.
  # A failed run alarms by email.
  vulnerable_image_cleanup_enabled      = true
  vulnerable_image_cleanup_alarm_emails = var.alarm_emails

  # It runs dry: it logs what it would delete, and its role has no ecr:BatchDeleteImage. Read the dry runs' lines in
  # the function's log group. Once they name only images you can do without, uncomment the next line and apply.
  # A deletion can't be undone.
  # vulnerable_image_cleanup_dry_run = false
}
