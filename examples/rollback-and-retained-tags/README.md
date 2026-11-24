# Rollback Candidates and Retained Tags Example

An ECR repository for a service that deploys to ECS: CI pushes a tagged image on every commit, the deployed images are
kept as rollback candidates, and the images that something runs by tag are never expired.

## What This Example Creates

- An ECR repository, tagged with `environment`, `service`, `created_by_module` and `module_version`
- A lifecycle policy. With `retain_tags = ["migrator-3f9c2e1"]`, its rules are, in the order ECR applies them:

| Priority | Rule | What it does |
|----------|------|--------------|
| 1 | `retain_tags` | Selects the image tagged `migrator-3f9c2e1` and never expires it |
| 2 | `rollback_candidate_retain_count` | Keeps the 5 newest images with a `deployed-at-` tag, expires the rest |
| 4 | `expire_count_tagged` | Keeps the 30 newest tagged images, expires the rest |
| 7 | `expire_days_untagged` | Expires untagged images pushed more than 7 days ago |

A rule can't expire an image that a higher-priority rule selects. So the retained image survives every other rule,
and a rollback candidate survives the tagged-image rule, even when it is older than the 30 newest tagged images.

A lower-priority rule still counts the images that higher rules select. The tagged-image rule's pattern, `*`, matches
the retained image and every `deployed-at-` image too, so each of them among the 30 newest tagged images takes one of
the 30 places. The more often the service deploys, the fewer of the other tagged images the rule keeps.

## Prerequisites

Something must tag the deployed images with `deployed-at-<timestamp>`. The InfraHouse
[ECS module](https://github.com/infrahouse/terraform-aws-ecs) does it when `enable_ecr_image_tagging` is true; its
`deployed_image_tag_prefix` must match this module's `rollback_candidate_tag_prefix` (both default to `deployed-at-`).

## Usage

Create a `terraform.tfvars`:

```hcl
region       = "us-west-2"
repo_name    = "my-service"
environment  = "production"
service_name = "my-service"

# The image the migrator task's task definition pins, by its git SHA.
retain_tags = ["migrator-3f9c2e1"]
```

Then apply it:

```bash
terraform init
terraform apply
```

The protection follows the tag: when the migrator task moves to another image, put its new tag in `retain_tags`. The
old image then falls to the other rules again.

Lifecycle rules can't tell whether an image runs. Keep in `retain_tags` every tag that something pins outside the
service's deployments: a scheduled task, a one-off task, or a production pin.

## Outputs

| Name | Description |
|------|-------------|
| `repository_url` | URL of the repository, to tag and push images to |
| `repository_arn` | ARN of the repository, to grant access to it |
