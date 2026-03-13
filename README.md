# terraform-aws-ecr

Creates an AWS ECR repository with configurable lifecycle policies
for automatic image expiration, including support for rollback
candidate retention.

## Lifecycle Policy

The module supports up to six lifecycle rules, each activated by
setting the corresponding variable. All are optional and default
to `null` (disabled).

### Regular image expiry

| Variable | What it does |
|----------|--------------|
| `expire_count_tagged` | Keep at most N tagged images (by count) |
| `expire_days_tagged` | Expire tagged images older than N days |
| `expire_count_untagged` | Keep at most N untagged images (by count) |
| `expire_days_untagged` | Expire untagged images older than N days |

When using `expire_count_tagged` or `expire_days_tagged`, you must
also set `tag_prefix_list` or `tag_pattern_list` to specify which
tagged images the rule applies to.

### Rollback candidate retention

Rollback candidates are images that were successfully deployed to
an ECS service. After a successful deployment, the ECS module tags
the image with a prefix (default `deployed-at-`), e.g.,
`deployed-at-2026-03-13T17-30-00Z`. The ECR module can then apply
separate, typically more generous, retention rules to these images.

| Variable | What it does |
|----------|--------------|
| `rollback_candidate_tag_prefix` | Tag prefix for rollback candidates (default: `deployed-at-`) |
| `rollback_candidate_retain_count` | Keep at most N rollback candidates |
| `rollback_candidate_retain_days` | Keep rollback candidates for N days |

### How rules interact — example

Suppose your CI builds an image on every commit to `main` and tags
it with the git SHA. You deploy some of those images to ECS, and
after a successful deployment, the ECS module adds a
`deployed-at-<timestamp>` tag.

```hcl
module "my_service_ecr" {
    source  = "registry.infrahouse.com/infrahouse/ecr/aws"
    version = "0.5.0"

    repo_name    = "my-service-repo"
    environment  = "production"
    service_name = "my-service"

    # Keep the 3 most recent CI-built images
    expire_count_tagged = 3
    tag_prefix_list     = ["v"]

    # Keep the 5 most recent rollback candidates
    rollback_candidate_retain_count = 5

    # Clean up untagged images after 7 days
    expire_days_untagged = 7
}
```

With this configuration, your ECR repo might look like:

```
IMAGE    TAGS                               AGE   KEPT BY RULE
img-A    v-abc1234, deployed-at-...T17-00Z  1d    rollback_candidate (1 of 5)
img-F    v-pqr1234                          2d    expire_count_tagged (1 of 3)
img-B    v-def5678, deployed-at-...T09-00Z  4d    rollback_candidate (2 of 5)
img-G    v-stu5678                          6d    expire_count_tagged (2 of 3)
img-H    v-vwx9012                          9d    expire_count_tagged (3 of 3)
img-I    v-yza3456                          12d   EXPIRED
img-C    v-ghi9012, deployed-at-...T12-00Z  13d   rollback_candidate (3 of 5)
img-D    v-jkl3456, deployed-at-...T08-00Z  27d   rollback_candidate (4 of 5)
img-E    v-mno7890, deployed-at-...T14-00Z  53d   rollback_candidate (5 of 5)
         <untagged manifests>               <7d   expire_days_untagged
```

Note that deployed images carry **both** their original CI tag
(`v-*`) and the rollback candidate tag (`deployed-at-*`). Each
image is matched by exactly **one** lifecycle rule — the
highest-priority rule whose tag filter matches. Rollback candidate
rules have higher priority than general tagged rules, so a
deployed image is protected by the rollback rule even if the
general tagged rule would expire it.

The key insight: rollback candidates are retained independently
from regular CI images. Even if a service hasn't been deployed in
months, its last 5 successful deployment images are preserved —
preventing the kind of outage where an old but still-active image
gets pruned.

## Basic usage

```hcl
module "foo_ecr" {
    source  = "registry.infrahouse.com/infrahouse/ecr/aws"
    version = "0.5.0"

    repo_name             = "test_repo"
    environment           = "development"
    service_name          = "foo"
    expire_days_tagged    = 365
    tag_prefix_list       = ["v"]
    expire_count_untagged = 5
}
```
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.5 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.11, < 7.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.11, < 7.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_ecr_lifecycle_policy.repo](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_lifecycle_policy) | resource |
| [aws_ecr_repository.repo](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository) | resource |
| [aws_ecr_lifecycle_policy_document.repo](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ecr_lifecycle_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_environment"></a> [environment](#input\_environment) | Name of environment. | `string` | n/a | yes |
| <a name="input_expire_count_tagged"></a> [expire\_count\_tagged](#input\_expire\_count\_tagged) | Keep no more tagged images that this. | `number` | `null` | no |
| <a name="input_expire_count_untagged"></a> [expire\_count\_untagged](#input\_expire\_count\_untagged) | Keep no more tagged images that this. You can only specify `expire_days_untagged` or `expire_count_untagged`. | `number` | `null` | no |
| <a name="input_expire_days_tagged"></a> [expire\_days\_tagged](#input\_expire\_days\_tagged) | The amount of days after which a tagged image is deleted from the repository. | `number` | `null` | no |
| <a name="input_expire_days_untagged"></a> [expire\_days\_untagged](#input\_expire\_days\_untagged) | The amount of days after which an untagged image is deleted from the repository. You can only specify `expire_days_untagged` or `expire_count_untagged`. | `number` | `null` | no |
| <a name="input_force_delete"></a> [force\_delete](#input\_force\_delete) | If true, will delete the repository even if it contains images. | `bool` | `false` | no |
| <a name="input_repo_name"></a> [repo\_name](#input\_repo\_name) | Name of the repository. | `string` | n/a | yes |
| <a name="input_service_name"></a> [service\_name](#input\_service\_name) | Service name. | `string` | n/a | yes |
| <a name="input_tag_pattern_list"></a> [tag\_pattern\_list](#input\_tag\_pattern\_list) | If the lifecycle expires tagged images, specify list of tag patterns. | `list(string)` | `null` | no |
| <a name="input_tag_prefix_list"></a> [tag\_prefix\_list](#input\_tag\_prefix\_list) | If the lifecycle expires tagged images, specify list of tag prefixes. | `list(string)` | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_repository_arn"></a> [repository\_arn](#output\_repository\_arn) | ECR repository ARN. |
| <a name="output_repository_url"></a> [repository\_url](#output\_repository\_url) | ECR repository URL. |
