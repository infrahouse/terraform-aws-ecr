# Troubleshooting

Problems you may meet, what causes them, and what to do.

## Terraform

### `terraform init` Finds No AWS Provider Version

```
Error: Failed to query available provider packages

Could not retrieve the list of available versions for provider hashicorp/aws:
no available releases match the given constraints ~> 5.0, >= 5.31.0, >=
6.0.0, < 7.0.0
```

The module needs AWS provider 6.0 or later, below 7.0, and your root module pins provider 5. The floor holds whether
the vulnerable image cleanup is on or off: Terraform installs a module's providers either way, and the cleanup's
dependencies need AWS provider 6.0.

Upgrade the root module to AWS provider 6 (`version = "~> 6.0"`), then run `terraform init -upgrade`. The module
also needs Terraform 1.9 or later, below 2.0: another version stops with `Unsupported Terraform Core version`.

### `terraform plan` Fails with `Invalid Block`

```
Error: Invalid Block

  with module.ecr.data.aws_ecr_lifecycle_policy_document.repo,
  on .terraform/modules/ecr/policy.tf line 6, in data "aws_ecr_lifecycle_policy_document" "repo":
   6: data "aws_ecr_lifecycle_policy_document" "repo" {

Block rule must have a configuration value as the provider has marked it as
required
```

No lifecycle input is set, so the policy has no rule. `terraform validate` passes; `terraform plan` doesn't. Set at
least one of `expire_count_tagged`, `expire_days_tagged`, `expire_count_untagged`, `expire_days_untagged`,
`rollback_candidate_retain_count`, `rollback_candidate_retain_days`, or a tag in `retain_tags`.

### `terraform plan` Fails: `tag_prefix_list or tag_pattern_list is required`

`expire_count_tagged` or `expire_days_tagged` is set without a tag filter. Set `tag_prefix_list` or
`tag_pattern_list`; `tag_pattern_list = ["*"]` selects every tagged image.

### `terraform apply` Fails: `Rules must contain unique sets of tags per storage class`

```
InvalidParameterException: Invalid parameter at 'LifecyclePolicyText' failed to satisfy constraint:
'Lifecycle policy validation failure: Rules must contain unique sets of tags per storage class.'
```

ECR refuses a policy with two rules on the same tag filter. That happens when both inputs of a pair are set:

- `rollback_candidate_retain_count` and `rollback_candidate_retain_days`;
- `expire_count_tagged` and `expire_days_tagged`.

`terraform plan` doesn't catch it; ECR refuses the policy at apply, after the repository is created. Keep one input of
each pair. For the rollback candidates, prefer the count (see
[Configuration](configuration.md#lifecycle-rollback-candidates)).

### `terraform apply` Fails: `Only one rule can select Untagged images per storage class`

Both `expire_count_untagged` and `expire_days_untagged` are set. ECR allows one rule for untagged images: keep one.

### `terraform apply` Fails: `only one of tagPrefixList or tagPatternList can be populated`

```
Lifecycle policy validation failure: If policy has a tagged rule only one of tagPrefixList or tagPatternList can
be populated. Both can't be populated at same time
```

Both `tag_prefix_list` and `tag_pattern_list` are set. Keep one. A prefix `v` is the pattern `v*`.

### An Input Fails Validation

The module checks its inputs at plan, and its error says what is wrong. The ones you are most likely to meet:

- `rollback_candidate_retain_count must be >= 2`: a lower count risks expiring the image that runs.
- `retain_tags holds exact image tags`: a tag with a wildcard or a character ECR tags can't hold.
- `vulnerable_image_cleanup_alarm_emails needs at least one address`: the cleanup is on without an alarm email.
- `vulnerable_image_cleanup_min_severity must be CRITICAL, HIGH, MEDIUM or LOW, in capitals`.

### `terraform apply` Fails While Building the Cleanup's Package

```
ERROR: Required command 'python3' not found
```

or `ERROR: jq is required but not installed`. With the cleanup on, terraform-aws-lambda-monitored builds the
function's package on the host that runs Terraform: `python3` and `pip3` build it, and its scripts call the AWS CLI
and `jq`. Install the missing one there, or run Terraform where they are.

## The Vulnerable Image Cleanup

Everything below reads the function's log group, `/aws/lambda/<function name>`. Get the name from the module's
`vulnerable_image_cleanup_function_name` output, then:

```bash
aws logs tail "/aws/lambda/$FUNCTION" --since 1d --format short
```

Each run logs JSON lines, one per image, with `"action"`: `would_delete` or `deleted`, `kept`, `left_by_cap`,
`recheck` or `delete_failed`, and a `summary` line.

### A Dry Run Would Delete Nothing

Read the `summary` line:

```json
{"summary": {"candidates": 0, "deleted": 0, "dropped_on_recheck": 0, "dry_run": true,
 "images_in_use_by": {"ecr_pull_record": 1, "ecs": 3, "inspector": 0, "lambda": 0}, "images_seen": 42,
 "judged_never_pulled": 0, "left_by_cap": 0, "manifests_seen": 120, "protected": {"in_use": 3,
 "in_use_unknown": 9, "not_active": 0, "recent": 2, "retained_tag": 1, "rollback_candidate": 5},
 "pulled_on_recheck": 0, "repository": "my-service",
 "view": {"complete": false, "ecs_clusters": 2, "ecs_running_tasks": 6, "ecs_service_revisions": 3,
 "ecs_services": 3, "ecs_task_definitions": 4, "incomplete_because": ["repository policy allows account 111122223333"],
 "lambda_image_versions": 0}, "vulnerable": 14, "would_delete": 0}}
```

- **`vulnerable` is 0.** No ACTIVE Inspector finding at or above `vulnerable_image_cleanup_min_severity` with a fix
  available names an image in this repository. Check that Inspector scans ECR images in the repository's account and
  Region, and that its findings have a fix (`fixAvailable` YES): the cleanup counts no other finding.
- **Every vulnerable image is protected.** `protected` counts the vulnerable images by reason, and each `kept` line
  gives an image's `reasons`. An image may have several. This is the cleanup working as meant: it deletes only what
  nothing protects. The reason you are most likely to see is `in_use_unknown`, below.

### An Image Is Kept as `in_use_unknown`

The cleanup can't tell whether something runs the image, so it keeps it. Its `kept` line says
`"use_judged_by": "unknown"`. Nothing in ECS or Lambda runs it, and one of its platform images, or the image itself if
it is a single manifest, is in one of these cases:

- **Inspector gives no in-use data on it, ECR recorded a pull before the soak, and the view isn't complete.**
  `last_pulled_at` is older than `vulnerable_image_cleanup_soak_days`, and the summary's `view` says
  `"complete": false`. `incomplete_because` says why: who outside the account the repository's or the registry's
  policy lets pull, such as `"repository policy allows account 111122223333"`, where a long-running task that pulled
  it then may still run it; or an ECS service that shows no revision, so not the digest its tag resolved to. Once
  neither holds, such an image is deleted, if nothing else protects it.
- **Inspector gives part of its in-use data:** one of `inUseCount` and `lastInUseAt` without the other, one coverage
  record with both and another without, or in-use data on its findings without a coverage record.
- **Inspector gives no in-use data, ECR has no pull record, and it was pushed before 2022-03-03.** AWS released ECR's
  pull time on 2022-03-02, so such an image may have been pulled without a record.

Nothing in the module overrides this. The image stays until the lifecycle policy expires it, until Inspector
reports its use, or, for the first case, until the view is complete. If you
have made sure that nothing runs it, you can delete it yourself: the index first, then its platform images and
attestation, with their digests from its `kept` line.

```bash
aws ecr batch-delete-image --repository-name my-service --image-ids imageDigest=sha256:<index digest>
```

### An Image Something Runs Is `would_delete`

The cleanup judged it not in use. Look at its line: `use_judged_by` and `never_pulled` say how, and `in_use_by` is
empty: nothing in ECS or Lambda in the repository's account and Region runs it.

The cleanup doesn't see:

- EKS;
- Docker run directly on EC2;
- an ECS task started by a schedule or by hand, outside a service, unless it runs at the time;
- CodeBuild and App Runner;
- other Regions;
- anything else in the account that pulls from ECR, such as AWS Batch or SageMaker;
- something outside the account that pulls with a role of this account.

ECR's pull record misses some pulls:

- **A first pull within the last day.** ECR refreshes the pull time at least once every 24 hours, so an old image
  deployed for the first time today may not show its pull yet.
- **A pull from elsewhere.** ECR records a pull in the repository that served it. A replica in another Region or
  account, or a copy of the image in another repository, runs without a pull recorded here.
- **A pull by a principal in the registry's pull-time update exclusions.**

Put the tag that the running service or task uses in `retain_tags`. Do it before you turn deletion on: a deletion
can't be undone. Before it decides, the cleanup reads the pull records of every candidate's platform images again, 13
times over two minutes, then the running ECS tasks; the `recheck` line shows what it read, the newer pulls it found and
the candidates it dropped, and `pulled_on_recheck` and `dropped_on_recheck` count them.

### A Run Deletes Fewer Images Than It Could

`vulnerable_image_cleanup_max_deletions` (10 by default) caps each run. An image index with its manifests counts as
one. The oldest go first, and each image the cap leaves gets a `left_by_cap` line; the next run takes them.

### The Alarm Fired: A Run Failed

The function fails closed: when it can't read or judge, it fails before it deletes anything, and lambda-monitored's
error alarm, `<function name>-errors-immediate`, emails `vulnerable_image_cleanup_alarm_emails`. The log has the
exception and its message:

- **An AWS error, such as `AccessDeniedException` or `ThrottlingException`.** A call failed after botocore's retries
  (standard mode, 10 attempts). Throttling clears by itself; the next run tries again.
- **`ImageNotFoundException`, or `ECR didn't return the images [...]`.** An image it read again was deleted during
  the run, by the lifecycle policy or by hand. The next run reads the repository afresh.
- **`ECR didn't return these manifests`, or `ECR didn't return the manifests of [...]`.** It couldn't read an index's
  manifest, so it doesn't know what the index references.
- **`AccessDeniedException` from ECS or Lambda.** The function's role reads ECS and Lambda in the repository's account
  and Region; a service control policy or a permissions boundary may deny it. Without those reads, what runs would go
  unseen.
- **`ECS didn't describe these tasks`, `ECS didn't describe the services [...]`, or the same of service deployments
  or service revisions.** Something ECS listed was gone when the function asked about it. The next run reads ECS
  afresh.
- **`The manifest of ... wasn't read`, or `The index ... lists no manifests`.** It couldn't map an index to its
  manifests.
- **`botocore ... models ... without [...]: the package's boto3 is too old to judge.`** The function's package has a
  boto3 older than 1.41, which its `requirements.txt` asks for (`boto3 ~= 1.41`).
- **`ECR refused to delete`, or `BatchDeleteImage failed`.** A deletion failed part way. See below.

### `ImageReferencedByManifestList`

```text
{"action": "delete_failed", "deleted_digests": ["sha256:..."], "error": "ECR refused to delete: [{...
 'failureCode': 'ImageReferencedByManifestList', 'failureReason': 'Requested image referenced by manifest list:
 [sha256:...]'}]", ...}
```

ECR refuses to delete a manifest that an index in the repository still references. The cleanup deletes an index
before its manifests, and keeps a manifest that another index still references, so this means an index it didn't read
references the manifest: one pushed during the run, for instance.

The `delete_failed` line names the image, the digests ECR did delete (`deleted_digests`) and the error, and the run
fails. A deletion can't be undone, so check `deleted_digests`: an index may be gone while its platform images stay,
untagged. The next run reads the repository afresh and judges what is left.

You get the same refusal when you delete a platform image by hand before its index. Delete the index first.

### The Alarm Email Never Arrives

AWS sends each address in `vulnerable_image_cleanup_alarm_emails` a confirmation email from SNS. Alarms reach an
address only after the link in it is followed. Look for the email, or check the subscriptions of the function's SNS
topic in the SNS console.

## Getting Help

[Open an issue](https://github.com/infrahouse/terraform-aws-ecr/issues/new) with:

- the module's version;
- the `terraform plan` or `terraform apply` output;
- for the cleanup, the `summary` line and the lines of the images in question.
