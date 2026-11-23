# terraform-aws-ecr

[![Need Help?](https://img.shields.io/badge/Need%20Help%3F-Contact%20Us-0066CC)](https://infrahouse.com/contact)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://infrahouse.github.io/terraform-aws-ecr/)
[![Registry](https://img.shields.io/badge/Terraform-Registry-purple?logo=terraform)](https://registry.terraform.io/modules/infrahouse/ecr/aws/latest)
[![Release](https://img.shields.io/github/release/infrahouse/terraform-aws-ecr.svg)](https://github.com/infrahouse/terraform-aws-ecr/releases/latest)
[![AWS ECR](https://img.shields.io/badge/AWS-ECR-orange?logo=amazonaws)](https://aws.amazon.com/ecr/)
[![Security](https://img.shields.io/github/actions/workflow/status/infrahouse/terraform-aws-ecr/vuln-scanner-pr.yml?label=Security)](https://github.com/infrahouse/terraform-aws-ecr/actions/workflows/vuln-scanner-pr.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Creates an AWS ECR repository with configurable lifecycle policies
for automatic image expiration, including support for rollback
candidate retention.

## Features

- ECR repository with configurable lifecycle policies
- Count-based and age-based expiry for tagged and untagged images
- Rollback candidate retention: protect deployed images from
  being pruned by lifecycle policies
- Retained tags: protect images that something pins by tag, such as a
  scheduled task's image, from every other rule
- Vulnerable image cleanup: an opt-in scheduled job that deletes the
  images Amazon Inspector reports vulnerable and that nothing protects
- Rollback candidates, retained tags and the cleanup are opt-in

## Requirements

- Terraform 1.9 or later
- AWS provider 6.0 or later, below 7.0
- The `null` and `time` providers

The vulnerable image cleanup runs as
[terraform-aws-lambda-monitored](https://github.com/infrahouse/terraform-aws-lambda-monitored),
which needs this floor: its S3 bucket comes from
[terraform-aws-s3-bucket](https://github.com/infrahouse/terraform-aws-s3-bucket),
which needs AWS provider 6.0. Terraform installs a module's providers
whether the module is used or not, so the floor applies to every caller,
with the cleanup on or off: a caller on AWS provider 5 upgrades to 6
before taking this release. Earlier releases of this module needed
Terraform 1.5 and AWS provider 5.11.

## Quick Start

```hcl
module "foo_ecr" {
    source  = "registry.infrahouse.com/infrahouse/ecr/aws"
    version = "1.0.0"

    repo_name             = "test_repo"
    environment           = "development"
    service_name          = "foo"
    expire_days_tagged    = 365
    tag_prefix_list       = ["v"]
    expire_count_untagged = 5
}
```

## Lifecycle Policy

The module supports up to six lifecycle rules, each activated by
setting the corresponding variable, plus one rule per retained tag.
All are optional and default to `null` (disabled), or `[]` for
`retain_tags`.

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

### Retained tags

`retain_tags` lists image tags whose images are never expired. Use it
for an image that something runs by tag outside the ECS service's
deployments, such as the image a scheduled or one-off task's task
definition pins: the rollback candidate rules don't protect it, since
it isn't the one deployed, and once it was deployed it carries a
`deployed-at-*` tag, so they expire it after enough newer deployments.

```hcl
module "my_service_ecr" {
    source  = "registry.infrahouse.com/infrahouse/ecr/aws"
    version = "1.0.0"

    repo_name    = "my-service-repo"
    environment  = "production"
    service_name = "my-service"

    rollback_candidate_retain_count = 3
    expire_count_tagged             = 30
    tag_pattern_list                = ["*"]

    # The image the migrator task runs, pinned by its git SHA.
    retain_tags = [var.migrator_image_tag]
}
```

Each tag gets a rule of its own, at the highest priorities (1, 2, …),
that selects the one image carrying the tag and keeps it. ECR never
lets a lower-priority rule expire an image a higher-priority rule
selects, so neither the rollback candidate rules nor the tagged-image
rules can expire it; every other rule keeps its order after them. The
protection follows the tag: retain another tag, and the old one's
image falls to the other rules again.

A retained image that is also a rollback candidate still counts toward
`rollback_candidate_retain_count`, as ECR counts every image a rule's
filter matches. While it is among the newest rollback candidates, it
takes one of those places.

Tags are exact: no wildcards. `retain_tags` defaults to `[]`, which
leaves the policy as it was.

### How rules interact — example

Suppose your CI builds an image on every commit to `main` and tags
it with the git SHA. You deploy some of those images to ECS, and
after a successful deployment, the ECS module adds a
`deployed-at-<timestamp>` tag.

```hcl
module "my_service_ecr" {
    source  = "registry.infrahouse.com/infrahouse/ecr/aws"
    version = "1.0.0"

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

### Security note: mutable image tags

This module does **not** enable ECR immutable tags because the
rollback candidate feature requires adding tags to existing images
after deployment (via `PutImage`). This means a principal with
`ecr:PutImage` permission could retag a malicious image to look
like a known-good deployment. Mitigate this by restricting
`ecr:PutImage` to the deployment Lambda role only.

## Vulnerable image cleanup

Amazon Inspector reports a vulnerability in every image it still
monitors, used or not. A repository that keeps an image per commit
carries one report per old image long after a fixed image runs, until
the lifecycle policy expires it. The cleanup is a scheduled Lambda that
deletes those images sooner.

It is off by default, and creates nothing until
`vulnerable_image_cleanup_enabled` is true. Turned on, it runs dry until
`vulnerable_image_cleanup_dry_run` is false.

```hcl
module "my_service_ecr" {
    source  = "registry.infrahouse.com/infrahouse/ecr/aws"
    version = "..." # the first release with the cleanup, or later

    repo_name    = "my-service-repo"
    environment  = "production"
    service_name = "my-service"

    rollback_candidate_retain_count = 3
    expire_count_tagged             = 30
    tag_pattern_list                = ["*"]
    retain_tags                     = [var.migrator_image_tag, var.docker_image_tag]

    vulnerable_image_cleanup_enabled      = true
    vulnerable_image_cleanup_alarm_emails = ["ops@example.com"]
    # Delete only once the dry runs' logs show the right images:
    # vulnerable_image_cleanup_dry_run = false
}
```

### What it deletes

An image that Inspector reports vulnerable, with an ACTIVE finding at or
above `vulnerable_image_cleanup_min_severity` (default `HIGH`) that has a
fix available, when nothing protects it. An image index is deleted with
the manifests it references, its platform images and its attestation,
and counts as one image.

### What it keeps

An image is protected, and kept, when any of these hold:

- It carries a tag in `retain_tags`.
- It is a rollback candidate the lifecycle policy keeps: the newest
  `rollback_candidate_retain_count` images with a tag that starts with
  `rollback_candidate_tag_prefix`, counting retained images, or those
  pushed within `rollback_candidate_retain_days`. Only while
  `vulnerable_image_cleanup_protect_rollback_candidates` is true (the
  default), and only when one of the two is set, as the lifecycle policy
  has no rollback candidate rule otherwise.
- It is in use: Inspector counts a running ECS task or EKS pod that uses
  it (`inUseCount`), or saw it in use within
  `vulnerable_image_cleanup_soak_days` (default 2, `lastInUseAt`). Or
  ECR recorded a pull of its platform image, or of a single-manifest
  image, within the soak (`lastRecordedPullTime`).
- It was pushed within `vulnerable_image_cleanup_min_age_days` (default
  7), so an image waiting for its pin isn't deleted.
- It isn't ACTIVE: an archived image.
- The job can't tell whether it is in use. That is a platform image, or
  a single-manifest image, that Inspector gives no in-use data on and
  that ECR recorded a pull of before the soak: a long-running task that
  pulled it then may still run it. Or one that Inspector gives only part
  of its in-use data on. Or one pushed before 2022-03-03, when ECR began
  recording pulls, which may have been pulled without a record.

A reason that holds for any manifest of an index protects the whole
index, and an index that is kept keeps every manifest it references:
when two indexes share a platform image and one is kept, the other is
deleted and the shared image stays.

### How it judges use

From Inspector's in-use data, `inUseCount` and `lastInUseAt`, when
Inspector gives it. Inspector leaves both out for an image it has never
seen in use, and some accounts get them for no image at all.

Otherwise from ECR's pull record. A container runtime pulls an image to
run it, and ECR records the pull on the platform image it fetched. So an
image none of whose platform images ECR ever recorded a pull of (or, for
a single-manifest image, the manifest) was never run: the job judges it
not in use, and deletes it if nothing else protects it. Inspector's
scans record no pull, and the job's own reads record one on the indexes
only.

Which pulls count: a fetch of a platform image or a single manifest.
An index's own pull time doesn't count: the job reads every index each
run, and ECR records that read as a pull. An attestation's doesn't
either: a runtime doesn't fetch one to run the image. A client that
already has the platform image, such as an EKS node or a host that ran
the image before, may fetch only the index; the pull that brought the
platform image to it is on record, and keeps the image.

What ECR's pull record doesn't show, so put every tag something pins in
`retain_tags` rather than rely on a pull:

- A first pull within the last day. ECR refreshes the pull time "at
  least once every 24 hours", so an old image deployed for the first
  time within the last day, say for a rollback, may not show its pull
  yet.
- A pull from elsewhere. ECR records a pull on the image in the
  repository that served it: a replica in another Region or account, or
  the same image pulled from another repository and cached on a host,
  runs without a pull recorded here.
- A pull by a principal in the registry's pull-time update exclusions.

When the job can't judge, it deletes nothing: an API error, throttling
that outlasts the retries, or a page or manifest it can't read fails the
run before any deletion, and the Lambda's alarm emails
`vulnerable_image_cleanup_alarm_emails`.

### Dry run, and turning deletion on

In a dry run the function logs what it would delete and deletes nothing;
its role has no `ecr:BatchDeleteImage` at all. Each run logs, as JSON:

- one line per image deleted, or that would be (`"action": "deleted"` or
  `"would_delete"`), with its digests, tags, push time, last use and
  pull, how its use was judged (`use_judged_by`: `inspector`,
  `ecr_pull_record` or `unknown`; and `never_pulled`), and the CVE ids;
- one line per vulnerable image kept, with the same facts and its
  `reasons`, and one per image the cap leaves for a later run
  (`"left_by_cap"`);
- one summary line: images seen, vulnerable, protected by each reason,
  vulnerable images judged never pulled (`judged_never_pulled`), deleted,
  and left by the cap.

If a deletion fails part way, say ECR refuses a manifest or throttles
past the retries, the run logs one `"delete_failed"` line naming the
image, the digests ECR did delete (`deleted_digests`) and the error, and
then fails, so the alarm fires with the trail in the log.

Read the dry runs' lines in the function's log group. When they name
only images you can do without, set `vulnerable_image_cleanup_dry_run =
false`. Each run then deletes at most
`vulnerable_image_cleanup_max_deletions` images (default 10), the oldest
first; the schedule is `vulnerable_image_cleanup_schedule` (default
daily).

**A deletion can't be undone.** An image a service still needs and that
nothing protects is gone: that service's next task can't start. Put every
tag an environment pins, such as a scheduled task's image or a
production pin, in `retain_tags`.

### What it needs

- Inspector's ECR scanning, in the repository's account and Region.
- One alarm email at least, in `vulnerable_image_cleanup_alarm_emails`:
  AWS sends each address a confirmation to accept.
- Where Terraform runs: `python3`, `pip3`, the AWS CLI and `jq`.
  terraform-aws-lambda-monitored builds the function's package there.

## Documentation

- [GitHub Pages](https://infrahouse.github.io/terraform-aws-ecr/)
- [Examples](examples/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE)

<!-- BEGIN_TF_DOCS -->

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.9 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0, < 7.0 |
| <a name="requirement_null"></a> [null](#requirement\_null) | ~> 3.0 |
| <a name="requirement_time"></a> [time](#requirement\_time) | ~> 0.9 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0, < 7.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_vulnerable_image_cleanup"></a> [vulnerable\_image\_cleanup](#module\_vulnerable\_image\_cleanup) | registry.infrahouse.com/infrahouse/lambda-monitored/aws | 2.2.1 |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_event_rule.vulnerable_image_cleanup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.vulnerable_image_cleanup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_ecr_lifecycle_policy.repo](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_lifecycle_policy) | resource |
| [aws_ecr_repository.repo](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository) | resource |
| [aws_iam_policy.vulnerable_image_cleanup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_lambda_permission.vulnerable_image_cleanup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_ecr_lifecycle_policy_document.repo](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ecr_lifecycle_policy_document) | data source |
| [aws_iam_policy_document.vulnerable_image_cleanup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_environment"></a> [environment](#input\_environment) | Name of environment. | `string` | n/a | yes |
| <a name="input_expire_count_tagged"></a> [expire\_count\_tagged](#input\_expire\_count\_tagged) | Keep no more tagged images than this. | `number` | `null` | no |
| <a name="input_expire_count_untagged"></a> [expire\_count\_untagged](#input\_expire\_count\_untagged) | Keep no more untagged images than this. You can only specify `expire_days_untagged` or `expire_count_untagged`. | `number` | `null` | no |
| <a name="input_expire_days_tagged"></a> [expire\_days\_tagged](#input\_expire\_days\_tagged) | The amount of days after which a tagged image is deleted from the repository. | `number` | `null` | no |
| <a name="input_expire_days_untagged"></a> [expire\_days\_untagged](#input\_expire\_days\_untagged) | The amount of days after which an untagged image is deleted from the repository. You can only specify `expire_days_untagged` or `expire_count_untagged`. | `number` | `null` | no |
| <a name="input_force_delete"></a> [force\_delete](#input\_force\_delete) | If true, will delete the repository even if it contains images. | `bool` | `false` | no |
| <a name="input_repo_name"></a> [repo\_name](#input\_repo\_name) | Name of the repository. | `string` | n/a | yes |
| <a name="input_retain_tags"></a> [retain\_tags](#input\_retain\_tags) | Image tags whose images the lifecycle policy never expires: for an image<br/>that something runs by tag outside the ECS service's deployments, such as<br/>the image a scheduled or one-off task pins. Each tag gets a rule of its<br/>own, at the highest priorities, that selects the one image carrying it, so<br/>no lower rule can expire that image: not the rollback candidate rules,<br/>even if the image was deployed once and carries a rollback candidate tag,<br/>nor the tagged-image rules. Exact tags, without wildcards.<br/><br/>The protection follows the tag: retain another tag, and the image of the<br/>old one falls to the other rules again. A retained image that is also a<br/>rollback candidate still counts toward rollback\_candidate\_retain\_count,<br/>so it takes one of those places while it is among the newest. | `list(string)` | `[]` | no |
| <a name="input_rollback_candidate_retain_count"></a> [rollback\_candidate\_retain\_count](#input\_rollback\_candidate\_retain\_count) | Maximum number of rollback candidate images to keep. Only images<br/>tagged with the rollback\_candidate\_tag\_prefix are affected.<br/>Set to null (default) to disable count-based rollback candidate<br/>expiry.<br/><br/>When both rollback\_candidate\_retain\_count and<br/>rollback\_candidate\_retain\_days are set, each image is expired by<br/>at most one rule — the count-based rule (higher priority) takes<br/>precedence. For example, retain\_count=5 and retain\_days=90 means:<br/>keep the 5 most recent, AND expire any beyond that which are also<br/>older than 90 days.<br/>See: https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html | `number` | `null` | no |
| <a name="input_rollback_candidate_retain_days"></a> [rollback\_candidate\_retain\_days](#input\_rollback\_candidate\_retain\_days) | Number of days to keep rollback candidate images. Only images<br/>tagged with the rollback\_candidate\_tag\_prefix are affected.<br/>Set to null (default) to disable age-based rollback candidate<br/>expiry.<br/><br/>This rule has lower priority than rollback\_candidate\_retain\_count.<br/>ECR lifecycle rules are evaluated simultaneously but each image<br/>is expired by at most one rule, with higher-priority rules taking<br/>precedence.<br/>See: https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html | `number` | `null` | no |
| <a name="input_rollback_candidate_tag_prefix"></a> [rollback\_candidate\_tag\_prefix](#input\_rollback\_candidate\_tag\_prefix) | Tag prefix identifying rollback candidate images. Images tagged<br/>with this prefix (e.g., "deployed-at-2026-03-13T17-30-00Z") are<br/>treated as rollback candidates with separate retention rules.<br/>Used by the ECS module to tag images after successful deployment. | `string` | `"deployed-at-"` | no |
| <a name="input_service_name"></a> [service\_name](#input\_service\_name) | Service name. | `string` | n/a | yes |
| <a name="input_tag_pattern_list"></a> [tag\_pattern\_list](#input\_tag\_pattern\_list) | List of tag wildcard patterns for tagged image lifecycle rules.<br/>Only tagged images matching at least one pattern will be expired.<br/>Supports wildcards, e.g. ["v*", "prod-*"] matches "v1.0", "prod-abc".<br/>At least one of tag\_pattern\_list or tag\_prefix\_list is required<br/>when expire\_days\_tagged or expire\_count\_tagged is set. | `list(string)` | `null` | no |
| <a name="input_tag_prefix_list"></a> [tag\_prefix\_list](#input\_tag\_prefix\_list) | List of tag prefixes for tagged image lifecycle rules.<br/>Only tagged images whose tag starts with one of these prefixes<br/>will be expired, e.g. ["v", "release-"] matches "v1.0", "release-2026".<br/>At least one of tag\_pattern\_list or tag\_prefix\_list is required<br/>when expire\_days\_tagged or expire\_count\_tagged is set. | `list(string)` | `null` | no |
| <a name="input_vulnerable_image_cleanup_alarm_emails"></a> [vulnerable\_image\_cleanup\_alarm\_emails](#input\_vulnerable\_image\_cleanup\_alarm\_emails) | Email addresses that get the cleanup Lambda's alarms, through terraform-aws-lambda-monitored. Required<br/>when the cleanup is on: a failed run alarms. AWS sends each address a confirmation email to accept. | `list(string)` | `[]` | no |
| <a name="input_vulnerable_image_cleanup_dry_run"></a> [vulnerable\_image\_cleanup\_dry\_run](#input\_vulnerable\_image\_cleanup\_dry\_run) | The cleanup only logs what it would delete, and its role has no ecr:BatchDeleteImage. Set to false to<br/>delete: a deletion can't be undone. | `bool` | `true` | no |
| <a name="input_vulnerable_image_cleanup_enabled"></a> [vulnerable\_image\_cleanup\_enabled](#input\_vulnerable\_image\_cleanup\_enabled) | Turns on the vulnerable image cleanup: a scheduled Lambda that deletes the images Amazon Inspector<br/>reports vulnerable, at or above vulnerable\_image\_cleanup\_min\_severity with a fix available, that nothing<br/>protects. An image is protected when it carries a tag in retain\_tags, is a rollback candidate the<br/>lifecycle policy keeps, is in use or was within the soak, was pushed within the least age, or when the<br/>job can't tell whether it is in use. It judges use from Inspector's in-use data and from ECR's pull<br/>record: an image whose platform images ECR never recorded a pull of was never run, so it isn't in use.<br/>ECR refreshes the pull time at least once every 24 hours, and records a pull only in the repository that<br/>served it: put every tag something pins in retain\_tags. An image index is deleted with the manifests it<br/>references.<br/>Turned on, it runs dry until vulnerable\_image\_cleanup\_dry\_run is false. A deletion can't be undone.<br/>Off by default: false creates nothing. | `bool` | `false` | no |
| <a name="input_vulnerable_image_cleanup_max_deletions"></a> [vulnerable\_image\_cleanup\_max\_deletions](#input\_vulnerable\_image\_cleanup\_max\_deletions) | The most images the cleanup deletes in a run. An image index with the manifests it references counts as<br/>one image. The oldest go first; the rest wait for the next run. | `number` | `10` | no |
| <a name="input_vulnerable_image_cleanup_min_age_days"></a> [vulnerable\_image\_cleanup\_min\_age\_days](#input\_vulnerable\_image\_cleanup\_min\_age\_days) | An image pushed within this many days is protected, so an image waiting for its pin isn't deleted. | `number` | `7` | no |
| <a name="input_vulnerable_image_cleanup_min_severity"></a> [vulnerable\_image\_cleanup\_min\_severity](#input\_vulnerable\_image\_cleanup\_min\_severity) | The least Inspector severity that makes an image vulnerable: CRITICAL, HIGH, MEDIUM or LOW. Only ACTIVE<br/>findings with a fix available count. | `string` | `"HIGH"` | no |
| <a name="input_vulnerable_image_cleanup_protect_rollback_candidates"></a> [vulnerable\_image\_cleanup\_protect\_rollback\_candidates](#input\_vulnerable\_image\_cleanup\_protect\_rollback\_candidates) | Protects the rollback candidates the lifecycle policy keeps (rollback\_candidate\_retain\_count and<br/>rollback\_candidate\_retain\_days) even when they are vulnerable, so a rollback can go to them until they<br/>rotate out. Set to false to delete a vulnerable rollback candidate once nothing else protects it, so a<br/>rollback can only go to an image without such findings. | `bool` | `true` | no |
| <a name="input_vulnerable_image_cleanup_schedule"></a> [vulnerable\_image\_cleanup\_schedule](#input\_vulnerable\_image\_cleanup\_schedule) | When the cleanup runs: an EventBridge schedule expression, rate(...) or cron(...).<br/>See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html | `string` | `"rate(1 day)"` | no |
| <a name="input_vulnerable_image_cleanup_soak_days"></a> [vulnerable\_image\_cleanup\_soak\_days](#input\_vulnerable\_image\_cleanup\_soak\_days) | An image in use, or used within this many days by Inspector's lastInUseAt, is protected, and so is one whose<br/>platform image or single manifest ECR's lastRecordedPullTime says was pulled within this many days. Without<br/>Inspector's in-use data, one pulled earlier is kept too, as a task that pulled it then may still run it,<br/>while one never pulled was never run, and isn't in use. An index's own pull time doesn't count, as ECR records<br/>the job's own read of each index as a pull. ECR refreshes the pull time at least once every 24 hours, so a first<br/>pull within the last day may not show yet: put a tag something pins in retain\_tags rather than rely on a pull. | `number` | `2` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_repository_arn"></a> [repository\_arn](#output\_repository\_arn) | ECR repository ARN. |
| <a name="output_repository_url"></a> [repository\_url](#output\_repository\_url) | ECR repository URL. |
| <a name="output_vulnerable_image_cleanup_function_arn"></a> [vulnerable\_image\_cleanup\_function\_arn](#output\_vulnerable\_image\_cleanup\_function\_arn) | ARN of the vulnerable image cleanup's Lambda function; null when the cleanup is off. |
| <a name="output_vulnerable_image_cleanup_function_name"></a> [vulnerable\_image\_cleanup\_function\_name](#output\_vulnerable\_image\_cleanup\_function\_name) | Name of the vulnerable image cleanup's Lambda function; null when the cleanup is off. |
<!-- END_TF_DOCS -->
