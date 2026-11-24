# Getting Started

This guide takes you from nothing to an ECR repository with a lifecycle policy, and then to turning on the vulnerable
image cleanup.

## Prerequisites

### Terraform and Providers

- **Terraform 1.9 or later**, below 2.0.
- **AWS provider 6.0 or later, below 7.0.** AWS provider 5 isn't supported.
- **The `null` and `time` providers.** `terraform init` installs them; you don't configure them.

The module installs from the InfraHouse registry, `registry.infrahouse.com`, so `terraform init` needs to reach it.

The floor comes from the vulnerable image cleanup: it runs as
[terraform-aws-lambda-monitored](https://github.com/infrahouse/terraform-aws-lambda-monitored), which needs Terraform
1.9 and the `null` and `time` providers, and whose S3 bucket needs AWS provider 6.0. Terraform installs a module's
providers whether the module is used or not, so the floor applies to every caller, with the cleanup on or off. A root
module that pins AWS provider 5 fails at `terraform init`; see
[Troubleshooting](troubleshooting.md#terraform-init-finds-no-aws-provider-version).

### AWS Permissions

Whoever runs Terraform needs to manage ECR repositories and their lifecycle policies. With the cleanup on, they also
need to manage S3 buckets and objects (the function's package goes to a bucket that terraform-aws-lambda-monitored
creates), IAM roles and policies, Lambda functions, CloudWatch log groups and alarms, SNS topics and EventBridge rules.

### For the Vulnerable Image Cleanup

Only if you turn it on:

- **Amazon Inspector scans ECR images** in the repository's account and Region. Without Inspector there are no
  findings, and the cleanup deletes nothing.
- **`python3`, `pip3`, the AWS CLI and `jq` where Terraform runs.** terraform-aws-lambda-monitored builds the
  function's package on that host, during `terraform apply`.
- **An email address** for its alarms. AWS sends it a confirmation email to accept.

## First Deployment

### Step 1: Write the Configuration

```hcl
terraform {
  required_version = "~> 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

module "ecr" {
  source  = "registry.infrahouse.com/infrahouse/ecr/aws"
  version = "1.1.1"

  repo_name    = "my-service"
  environment  = "production"
  service_name = "my-service"

  # A tagged image whose tag starts with "v" expires 365 days after it was pushed.
  expire_days_tagged = 365
  tag_prefix_list    = ["v"]

  # Keep the 5 newest untagged images.
  expire_count_untagged = 5
}

output "repository_url" {
  value = module.ecr.repository_url
}
```

The module needs at least one lifecycle rule. See [Configuration](configuration.md) for every input.

### Step 2: Apply

```bash
terraform init
terraform plan
terraform apply
```

### Step 3: Verify

The repository and its tags:

```bash
aws ecr describe-repositories --repository-names my-service
```

The lifecycle policy, one rule per lifecycle input:

```bash
aws ecr get-lifecycle-policy --repository-name my-service \
  --query lifecyclePolicyText --output text | jq .
```

To see which images the policy would expire before ECR expires them, run a lifecycle policy preview in the ECR
console; see [Lifecycle policies](https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html).

### Step 4: Push an Image

```bash
REPOSITORY_URL=$(terraform output -raw repository_url)
aws ecr get-login-password --region us-west-2 \
  | docker login --username AWS --password-stdin "${REPOSITORY_URL%%/*}"
docker tag my-service:latest "$REPOSITORY_URL:v1.0.0"
docker push "$REPOSITORY_URL:v1.0.0"
```

## Next Steps

### Keep Deployed Images for Rollbacks

If an ECS service deploys from the repository, keep its last deployments as rollback candidates, and protect the
images that something pins by tag:

```hcl
module "ecr" {
  source  = "registry.infrahouse.com/infrahouse/ecr/aws"
  version = "1.1.1"

  repo_name    = "my-service"
  environment  = "production"
  service_name = "my-service"

  rollback_candidate_retain_count = 5
  expire_count_tagged             = 30
  tag_pattern_list                = ["*"]
  retain_tags                     = ["migrator-3f9c2e1"]
}
```

The ECS module tags the deployed images when its `enable_ecr_image_tagging` is true. See
[Architecture](architecture.md#rollback-candidates-and-retained-tags) for how the rules interact.

### Turn On the Vulnerable Image Cleanup

Add two inputs to the module call, and an output for the function's name:

```hcl
  vulnerable_image_cleanup_enabled      = true
  vulnerable_image_cleanup_alarm_emails = ["ops@example.com"]
```

```hcl
output "vulnerable_image_cleanup_function_name" {
  value = module.ecr.vulnerable_image_cleanup_function_name
}
```

It runs dry: once a day it logs what it would delete, and deletes nothing. Run it now and read its lines:

```bash
FUNCTION=$(terraform output -raw vulnerable_image_cleanup_function_name)
aws lambda invoke --function-name "$FUNCTION" --invocation-type Event /dev/null
aws logs tail "/aws/lambda/$FUNCTION" --since 15m --format short
```

When the `would_delete` lines name only images you can do without, set `vulnerable_image_cleanup_dry_run = false`.
A deletion can't be undone, so first put every tag that something pins in `retain_tags`. The
[vulnerable-image-cleanup example](https://github.com/infrahouse/terraform-aws-ecr/tree/main/examples/vulnerable-image-cleanup)
is a complete configuration.

- [Examples](examples.md): complete configurations for common cases
- [Configuration](configuration.md): every input, and when to change it
- [Troubleshooting](troubleshooting.md): what can go wrong, and what to do
