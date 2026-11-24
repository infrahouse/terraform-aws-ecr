# Examples

Common uses of the module. Each section matches a complete root module in
[examples/](https://github.com/infrahouse/terraform-aws-ecr/tree/main/examples) in the repository, with its
`variables.tf`, `outputs.tf` and a README on how to apply it. The test suite runs `terraform init` and
`terraform validate` on every example.

## Basic Repository

A repository whose tagged releases expire after a year, and that keeps only the newest untagged images.
Directory: [examples/basic](https://github.com/infrahouse/terraform-aws-ecr/tree/main/examples/basic).

```hcl
module "ecr" {
  source  = "registry.infrahouse.com/infrahouse/ecr/aws"
  version = "1.0.1"

  repo_name    = "my-service"
  environment  = "production"
  service_name = "my-service"

  expire_days_tagged = 365
  tag_prefix_list    = ["v"]

  expire_count_untagged = 5
}
```

- A tagged image with a tag that starts with `v` expires 365 days after it was pushed.
- Of the untagged images, the 5 newest stay.
- A tagged image without a `v` tag matches no rule, and stays.

The module needs at least one lifecycle rule; this is about the smallest useful policy.

## Rollback Candidates and Retained Tags

A repository for a service that deploys to ECS: CI pushes an image per commit, the last deployments stay for
rollbacks, and the images something pins by tag never expire. Directory:
[examples/rollback-and-retained-tags](https://github.com/infrahouse/terraform-aws-ecr/tree/main/examples/rollback-and-retained-tags).

```hcl
module "ecr" {
  source  = "registry.infrahouse.com/infrahouse/ecr/aws"
  version = "1.0.1"

  repo_name    = "my-service"
  environment  = "production"
  service_name = "my-service"

  # The image the migrator task's task definition pins.
  retain_tags = ["migrator-3f9c2e1"]

  rollback_candidate_retain_count = 5

  expire_count_tagged = 30
  tag_pattern_list    = ["*"]

  expire_days_untagged = 7
}
```

The rules, in the order ECR applies them:

| Priority | Rule | What it does |
|----------|------|--------------|
| 1 | `retain_tags` | Never expires the image tagged `migrator-3f9c2e1` |
| 2 | `rollback_candidate_retain_count` | Keeps the 5 newest `deployed-at-*` images, expires the rest |
| 4 | `expire_count_tagged` | Keeps the 30 newest tagged images, expires the rest |
| 7 | `expire_days_untagged` | Expires untagged images pushed more than 7 days ago |

The retained image and the 5 rollback candidates are safe from the tagged-image rule, however old they are. They still
take places among its 30: its pattern, `*`, matches them too.

The `deployed-at-*` tags come from the InfraHouse [ECS module](https://github.com/infrahouse/terraform-aws-ecs), with
`enable_ecr_image_tagging = true`. When the migrator moves to another image, put the new tag in `retain_tags`; the old
image then falls to the other rules.

## Vulnerable Image Cleanup

The rollback configuration above, plus the daily job that deletes the images Amazon Inspector reports vulnerable and
that nothing protects. Directory:
[examples/vulnerable-image-cleanup](https://github.com/infrahouse/terraform-aws-ecr/tree/main/examples/vulnerable-image-cleanup).

```hcl
module "ecr" {
  source  = "registry.infrahouse.com/infrahouse/ecr/aws"
  version = "1.0.1"

  repo_name    = "my-service"
  environment  = "production"
  service_name = "my-service"

  retain_tags                     = ["migrator-3f9c2e1"]
  rollback_candidate_retain_count = 5
  expire_count_tagged             = 30
  tag_pattern_list                = ["*"]
  expire_days_untagged            = 7

  vulnerable_image_cleanup_enabled      = true
  vulnerable_image_cleanup_alarm_emails = ["ops@example.com"]

  # It runs dry. Uncomment once the dry runs' would_delete lines name only images you can do without.
  # vulnerable_image_cleanup_dry_run = false
}
```

It protects the retained image and the 5 newest rollback candidates, as the lifecycle policy keeps them. The
tagged-image rule protects nothing from it: a vulnerable image among the 30 newest tagged images is deleted unless
something else protects it. It also keeps an image in use or used within 2 days, an image pushed within 7 days, and an
image whose use it can't judge. Each run deletes at most 10 images, the oldest first, once deletion is on.

It needs Amazon Inspector's ECR scanning in the account and Region, and `python3`, `pip3`, the AWS CLI and `jq` where
Terraform runs. The example's README shows how to run it now and read its log lines. A deletion can't be undone: before
you turn deletion on, put every tag that something pins in `retain_tags`.

## See Also

- [Getting Started](getting-started.md): prerequisites and a first deployment
- [Configuration](configuration.md): every input, and when to change it
- [Architecture](architecture.md): how the rules and the cleanup work
- [Troubleshooting](troubleshooting.md)
