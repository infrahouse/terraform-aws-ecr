# terraform-aws-ecr

Module that creates a container registry (AWS ECR service).

It needs Terraform 1.9 or later, AWS provider 6.0 or later (below 7.0), and the `null` and `time` providers.
The vulnerable image cleanup below runs as
[terraform-aws-lambda-monitored](https://github.com/infrahouse/terraform-aws-lambda-monitored), which needs this
floor (its S3 bucket comes from terraform-aws-s3-bucket, which needs AWS provider 6.0), and Terraform installs a
module's providers whether the module is used or not: the floor applies to every caller, with the cleanup on or off.
A caller on AWS provider 5 upgrades to 6 before taking this release.

## Vulnerable image cleanup

Amazon Inspector reports a vulnerability in every image it still monitors, used or not. The cleanup is an opt-in
scheduled Lambda that deletes the images Inspector reports vulnerable, so old images stop carrying reports long after
a fixed image runs.

It is off by default: with `vulnerable_image_cleanup_enabled = false` it creates nothing.

### What it deletes

An image with an ACTIVE Inspector finding at or above `vulnerable_image_cleanup_min_severity` (default `HIGH`) that
has a fix available, when nothing protects it. An image index goes with the manifests it references (its platform
images and its attestation) and counts as one image: the index first, then the manifests no other index references.

### What it keeps

An image is protected when any of these hold:

- it carries a tag in `retain_tags`;
- it is a rollback candidate the lifecycle policy keeps (the same tag prefix, count and days as its rules; a retained
  image counts toward the count), while `vulnerable_image_cleanup_protect_rollback_candidates` is true;
- it is in use, or was used within `vulnerable_image_cleanup_soak_days`, by Inspector's `inUseCount` and
  `lastInUseAt`; or ECR's `lastRecordedPullTime` says its platform image, or a single-manifest image, was pulled within
  the soak. Only a fetch of a platform image or single manifest counts as a pull. An index's own pull time doesn't
  count, since ECR records the job's read of each index as a pull, so a pull that fetches only the index isn't seen. A
  fresh `docker pull` fetches the platform image too; a client that already has it, such as an EKS node or a host that
  ran the image before, may fetch only the index, and then only Inspector's in-use data protects the image. Put every
  tag something pins in `retain_tags` rather than rely on a recent pull;
- it was pushed within `vulnerable_image_cleanup_min_age_days`;
- it is archived;
- the job can't tell whether it is in use: no Inspector coverage record, or one without `inUseCount` and
  `lastInUseAt`. Inspector leaves both out for an image it has never seen in use, so such an image is kept.

A protected index protects every manifest it references. When the job can't judge, it deletes nothing: an API error,
throttling that outlasts the retries, or a page it can't read fails the run, and the Lambda's alarm emails
`vulnerable_image_cleanup_alarm_emails`.

### Dry run, and turning deletion on

Turned on, it runs dry: it logs a JSON line per image it would delete, with its digests, tags, push time, last use
and pull, and CVE ids, a line per vulnerable image it keeps, with the reasons, and a summary line. Its role has no
`ecr:BatchDeleteImage`. Read the dry runs' lines in the function's log group, and once they name only images you can
do without, set `vulnerable_image_cleanup_dry_run = false`. A run then deletes at most
`vulnerable_image_cleanup_max_deletions` images (default 10), the oldest first. A deletion that fails part way logs
a `delete_failed` line naming the image, the digests ECR did delete and the error, and then the run fails.

**A deletion can't be undone.** An image a service still needs and that nothing protects is gone, and that service's
next task can't start. Put every tag an environment pins in `retain_tags`.

```hcl
module "my_service_ecr" {
  source  = "registry.infrahouse.com/infrahouse/ecr/aws"
  version = "..." # the first release with the cleanup, or later

  repo_name    = "my-service-repo"
  environment  = "production"
  service_name = "my-service"

  rollback_candidate_retain_count = 3
  retain_tags                     = [var.migrator_image_tag, var.docker_image_tag]

  vulnerable_image_cleanup_enabled      = true
  vulnerable_image_cleanup_alarm_emails = ["ops@example.com"]
  # vulnerable_image_cleanup_dry_run    = false
}
```

Turning it on needs `python3`, `pip3`, the AWS CLI and `jq` where Terraform runs: terraform-aws-lambda-monitored
builds the function's package there.
