module "ecr" {
  source       = "../../"
  repo_name    = "test-cleanup-dry-run"
  environment  = "development"
  service_name = "foo"
  force_delete = true

  rollback_candidate_retain_count = 3
  retain_tags                     = ["pinned"]

  vulnerable_image_cleanup_enabled      = true
  vulnerable_image_cleanup_alarm_emails = ["devnull@infrahouse.com"]
}
