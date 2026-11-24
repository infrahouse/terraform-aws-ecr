# Configuration

This page explains every input of the module, grouped by what it configures: what it does, its default, and when to
change it. The README's [Inputs](https://github.com/infrahouse/terraform-aws-ecr#inputs) table lists their types
and descriptions. See [Architecture](architecture.md) for how the pieces work together.

## Repository

| Variable | Default |
|----------|---------|
| `repo_name` | required |
| `environment` | required |
| `service_name` | required |
| `force_delete` | `false` |

**`repo_name`** names the repository. Changing it replaces the repository, so plan the move of its images first. The
vulnerable image cleanup's function name is derived from it.

**`environment`** and **`service_name`** become the repository's `environment` and `service` tags. They have no
defaults on purpose: every repository says where it belongs. The module adds `created_by_module` and
`module_version`.

**`force_delete`** lets `terraform destroy` delete the repository while it still holds images, and the images with
it. Keep it `false` for a repository whose images something runs; set it to `true` for a test or throwaway
repository.

## Lifecycle: Regular Expiry

| Variable | Default |
|----------|---------|
| `expire_count_tagged` | `null` |
| `expire_days_tagged` | `null` |
| `tag_prefix_list` | `null` |
| `tag_pattern_list` | `null` |
| `expire_count_untagged` | `null` |
| `expire_days_untagged` | `null` |

Each of the four `expire_*` inputs adds a rule when it is set; `null` leaves the rule out. The module needs at least
one lifecycle rule from this group, the rollback group or `retain_tags`: with none, `terraform plan` fails.

### Tagged images

**`expire_count_tagged`** keeps the N newest tagged images that match the tag filter, and expires the rest.
**`expire_days_tagged`** expires the tagged images that match the filter and were pushed more than N days ago. Set one
of the two: ECR refuses a policy with two rules on the same tag filter.

The filter is **`tag_prefix_list`** or **`tag_pattern_list`**; a tagged rule needs one of them, and `terraform plan`
fails without it. Set one, not both: ECR refuses a rule with both.

- `tag_prefix_list = ["v"]` selects the images with a tag that starts with `v`.
- `tag_pattern_list = ["*"]` selects every tagged image; `["prod-*"]` the images with a tag that matches `prod-*`.
  A pattern takes up to four `*` wildcards.

With more than one value in the list, ECR selects only the images that have a matching tag for **every** value:
`tag_prefix_list = ["v", "release-"]` selects an image tagged both `v2` and `release-2`, not one tagged only `v1`. To
expire two kinds of tags, use a single value that covers both, such as a pattern.

The tagged rules count every image the filter matches, the retained images and rollback candidates included. A rule
can't expire those, but each one among the newest takes one of `expire_count_tagged`'s places (see
[How ECR Applies the Rules](architecture.md#how-ecr-applies-the-rules)).

When to change: set `expire_count_tagged` when the repository grows by an image per commit and only the recent ones
matter; `expire_days_tagged` when age is what matters, such as release images kept for a year.

### Untagged images

**`expire_count_untagged`** keeps the N newest untagged images and expires the rest. **`expire_days_untagged`** expires
the untagged images pushed more than N days ago. Set one of the two: ECR allows one rule for untagged images.

An image becomes untagged when its tags move to another image. The platform images of a multi-architecture image are
untagged too, but ECR doesn't expire them while their index is in the repository.

## Lifecycle: Rollback Candidates

| Variable | Default |
|----------|---------|
| `rollback_candidate_tag_prefix` | `"deployed-at-"` |
| `rollback_candidate_retain_count` | `null` |
| `rollback_candidate_retain_days` | `null` |

A rollback candidate is an image that was deployed successfully. The InfraHouse
[ECS module](https://github.com/infrahouse/terraform-aws-ecs), with `enable_ecr_image_tagging = true`, tags it
`deployed-at-<timestamp>` once the service reaches a steady state. The rollback rules come before the tagged-image
rules, so those can't expire a deployed image, however old it is or however many images CI pushes after it.

**`rollback_candidate_tag_prefix`** is the tag prefix that marks a candidate. Change it only together with the ECS
module's `deployed_image_tag_prefix`: the two must match.

**`rollback_candidate_retain_count`** keeps the N newest candidates and expires the rest. It must be at least 2, so the
image that runs and the one before it stay. **`rollback_candidate_retain_days`** expires the candidates pushed more than
N days ago; at least 1. Set one of the two: both are rules on the same tag prefix, and ECR refuses the policy.

When to change: set `rollback_candidate_retain_count` for any repository an ECS service deploys from, so the images a
rollback needs survive a burst of CI pushes. Prefer the count: the last N deployments stay however long ago they were.
The days rule goes by the images' push time, so when the service hasn't deployed for N days, it expires every
candidate, the image that runs among them.

## Lifecycle: Retained Tags

| Variable | Default |
|----------|---------|
| `retain_tags` | `[]` |

**`retain_tags`** lists exact image tags whose images no lifecycle rule expires, and the vulnerable image cleanup
never deletes. Each tag gets a rule of its own at the first priorities, which selects the one image carrying the tag
and keeps it.

Use it for an image that something runs by tag outside the service's deployments: the image a scheduled or one-off
task's task definition pins, or a production pin. The rollback rules don't protect such an image, since it isn't the
one the service deployed, and once it was deployed it carries a `deployed-at-*` tag too, so they expire it after
enough newer deployments.

Tags are exact, without wildcards: a letter, digit or underscore, then up to 127 letters, digits, `_`, `.` or `-`. Each
tag appears once. The protection follows the tag: retain another tag, and the old one's image falls to the other rules
again. A retained image that is also a rollback candidate still counts toward `rollback_candidate_retain_count`.

When to change: every time something starts to pin an image by tag. The default, `[]`, adds no rule.

## Vulnerable Image Cleanup

| Variable | Default |
|----------|---------|
| `vulnerable_image_cleanup_enabled` | `false` |
| `vulnerable_image_cleanup_alarm_emails` | `[]` |
| `vulnerable_image_cleanup_dry_run` | `true` |
| `vulnerable_image_cleanup_min_severity` | `"HIGH"` |
| `vulnerable_image_cleanup_min_age_days` | `7` |
| `vulnerable_image_cleanup_soak_days` | `2` |
| `vulnerable_image_cleanup_protect_rollback_candidates` | `true` |
| `vulnerable_image_cleanup_max_deletions` | `10` |
| `vulnerable_image_cleanup_schedule` | `"rate(1 day)"` |

[Architecture](architecture.md#the-vulnerable-image-cleanup) explains what a run reads, decides and deletes.

**`vulnerable_image_cleanup_enabled`** turns the cleanup on. Off, the module creates nothing for it. On, it needs
Amazon Inspector's ECR scanning in the repository's account and Region, and `python3`, `pip3`, the AWS CLI and `jq`
where Terraform runs, to build the function's package.

**`vulnerable_image_cleanup_alarm_emails`** gets the function's alarms, a failed run among them. At least one address
is required when the cleanup is on. AWS sends each address a confirmation email to accept.

**`vulnerable_image_cleanup_dry_run`** keeps the cleanup from deleting: it logs what it would delete, and its role has
no `ecr:BatchDeleteImage`. Leave it `true` until the dry runs' `would_delete` lines name only images you can do
without, then set it to `false`. A deletion can't be undone.

**`vulnerable_image_cleanup_min_severity`** is the least Inspector severity that makes an image vulnerable:
`CRITICAL`, `HIGH`, `MEDIUM` or `LOW`, in capitals. Only ACTIVE findings with a fix available count. Lower it to
delete more images; raise it to `CRITICAL` to delete only the worst.

**`vulnerable_image_cleanup_min_age_days`** protects an image pushed within this many days, at least 1, so an image
waiting for its deployment or its pin isn't deleted. Raise it when images wait longer than a week between push and
use.

**`vulnerable_image_cleanup_soak_days`** protects an image in use, or used within this many days by Inspector's
`lastInUseAt`, at least 1. Without Inspector's in-use data, an image ECR recorded a pull of within this many days is
protected too, and one pulled before is kept as unknown. Raise it when a service can run an image for days without
pulling it again.

**`vulnerable_image_cleanup_protect_rollback_candidates`** protects the rollback candidates the lifecycle policy keeps,
vulnerable or not, so a rollback can go to them until they rotate out. Set it to `false` to delete a vulnerable
rollback candidate once nothing else protects it: a rollback can then only go to an image without such findings.

**`vulnerable_image_cleanup_max_deletions`** caps the images a run deletes, a whole number of at least 1. An index with
the manifests it references counts as one image. The oldest go first, and the rest wait for the next run. Keep it low
when you first turn deletion on.

**`vulnerable_image_cleanup_schedule`** is an EventBridge
[schedule expression](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html),
`rate(...)` or `cron(...)`. The default runs it once a day.

The cleanup also reads `retain_tags`, `rollback_candidate_tag_prefix`, `rollback_candidate_retain_count` and
`rollback_candidate_retain_days`, so it protects what the lifecycle policy keeps.

## Outputs

| Output | Value |
|--------|-------|
| `repository_url` | The repository's URL, to tag and push images to |
| `repository_arn` | The repository's ARN, to grant access to it |
| `vulnerable_image_cleanup_function_name` | The cleanup's Lambda function name; `null` when the cleanup is off |
| `vulnerable_image_cleanup_function_arn` | The cleanup's Lambda function ARN; `null` when the cleanup is off |
