module "ecr" {
  source       = "../../"
  repo_name    = "test-cleanup-e2e"
  environment  = "development"
  service_name = "foo"
  force_delete = true

  retain_tags = ["pinned"]

  vulnerable_image_cleanup_enabled      = true
  vulnerable_image_cleanup_dry_run      = false
  vulnerable_image_cleanup_alarm_emails = ["devnull@infrahouse.com"]
}
