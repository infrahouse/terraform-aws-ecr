module "ecr" {
  source       = "../../"
  repo_name    = "test_repo"
  environment  = "development"
  service_name = "foo"
  # expire_count_tagged = 10
  expire_days_tagged = 365
  tag_prefix_list    = ["v"]
  # expire_days_untagged  = 30
  expire_count_untagged = 5

  rollback_candidate_retain_count = 3
  retain_tags                     = ["pinned-1", "pinned-2"]
}
