# Basic Example

An ECR repository with a simple lifecycle policy: tagged releases expire after a year, and only the newest untagged
images are kept.

## What This Example Creates

- An ECR repository, tagged with `environment`, `service`, `created_by_module` and `module_version`
- A lifecycle policy with two rules:
    - a tagged image whose tag starts with `v` expires 365 days after it was pushed;
    - of the untagged images, the 5 newest are kept and the rest expire.

A tagged image without a tag that starts with `v` matches neither rule, and the policy never expires it.

The module needs at least one lifecycle rule. With no lifecycle input set, `terraform plan` fails with
`Block rule must have a configuration value`.

## Usage

Create a `terraform.tfvars`:

```hcl
region       = "us-west-2"
repo_name    = "my-service"
environment  = "production"
service_name = "my-service"
```

Then apply it:

```bash
terraform init
terraform apply
```

Push an image, with Docker and the AWS CLI:

```bash
REPOSITORY_URL=$(terraform output -raw repository_url)
aws ecr get-login-password --region us-west-2 \
  | docker login --username AWS --password-stdin "${REPOSITORY_URL%%/*}"
docker tag my-service:latest "$REPOSITORY_URL:v1.0.0"
docker push "$REPOSITORY_URL:v1.0.0"
```

## Outputs

| Name | Description |
|------|-------------|
| `repository_url` | URL of the repository, to tag and push images to |
| `repository_arn` | ARN of the repository, to grant access to it |
