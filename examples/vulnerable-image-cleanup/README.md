# Vulnerable Image Cleanup Example

An ECR repository with the vulnerable image cleanup turned on: a daily job that deletes the images Amazon Inspector
reports vulnerable and that nothing protects. It runs dry, as the module does by default: it logs what it would delete
and deletes nothing.

## What This Example Creates

- An ECR repository and its lifecycle policy: the retained images, the 5 newest rollback candidates, and the 30 newest
  tagged images are kept, and untagged images expire after 7 days. The cleanup protects the retained images and the
  rollback candidates; a vulnerable image among the 30 newest tagged images is deleted unless something else protects
  it
- A Lambda function, `<repo_name>-<hash>-vuln-cleanup`, built and monitored by
  [terraform-aws-lambda-monitored](https://github.com/infrahouse/terraform-aws-lambda-monitored): its log group,
  `/aws/lambda/<function name>`, kept 365 days, and error and throttle alarms that email `alarm_emails`
- An IAM policy for the function: `ecr:DescribeImages` and `ecr:BatchGetImage` on this repository,
  `inspector2:ListFindings` and `inspector2:ListCoverage`. No `ecr:BatchDeleteImage` while it runs dry
- An EventBridge rule that runs the function once a day

## Prerequisites

- Amazon Inspector scans ECR images in the repository's account and Region. Without it there are no findings, and the
  job deletes nothing.
- `python3`, `pip3`, the AWS CLI and `jq` where Terraform runs: terraform-aws-lambda-monitored builds the function's
  package there.

## Usage

Create a `terraform.tfvars`:

```hcl
region       = "us-west-2"
repo_name    = "my-service"
environment  = "production"
service_name = "my-service"
retain_tags  = ["migrator-3f9c2e1"]
alarm_emails = ["ops@example.com"]
```

Then apply it:

```bash
terraform init
terraform apply
```

Every address in `alarm_emails` gets a confirmation email from SNS. Alarms reach it only after the link in it is
followed.

## Read a Dry Run

The function runs once a day. To run it now and read what it decided:

```bash
FUNCTION=$(terraform output -raw vulnerable_image_cleanup_function_name)
aws lambda invoke --function-name "$FUNCTION" --invocation-type Event /dev/null
aws logs tail "/aws/lambda/$FUNCTION" --since 15m --format short
```

A run with images to read again takes about two minutes. Each run logs JSON lines:

- `"action": "would_delete"`: an image it would delete, with its digests, tags, push time, last use and pull, how its
  use was judged, and its CVE ids;
- `"action": "kept"`: a vulnerable image something protects, with its `reasons`;
- `"action": "left_by_cap"`: an image the cap leaves for a later run;
- `"action": "recheck"`: the images judged never pulled that it read again, and any pull it found;
- `"summary"`: the counts, `would_delete` among them.

## Turn Deletion On

When the dry runs' `would_delete` lines name only images you can do without, set
`vulnerable_image_cleanup_dry_run = false` in `main.tf` and apply. The function's role gets `ecr:BatchDeleteImage` on
this repository, and each run deletes at most 10 images, the oldest first.

**A deletion can't be undone.** Before you turn it on, put every tag that something pins in `retain_tags`.

## Outputs

| Name | Description |
|------|-------------|
| `repository_url` | URL of the repository, to tag and push images to |
| `repository_arn` | ARN of the repository, to grant access to it |
| `vulnerable_image_cleanup_function_name` | Name of the cleanup's Lambda function |
| `vulnerable_image_cleanup_function_arn` | ARN of the cleanup's Lambda function |
