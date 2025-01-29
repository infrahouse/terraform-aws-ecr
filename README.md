# terraform-aws-ecr
For usage see how the module is used in the using tests in `test_data/test_module`.

```hcl
module "foo_ecr" {
    source  = "infrahouse/ecr/aws"
    version = "0.2.0"

    repo_name               = "test_repo"
    environment             = "development"
    service_name            = "foo"
    expire_days_tagged      = 365
    tag_prefix_list         = ["v"]
    expire_count_untagged = 5
}
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.5 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 5.11 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 5.11 |

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
| <a name="input_repo_name"></a> [repo\_name](#input\_repo\_name) | Name of the repository. | `string` | n/a | yes |
| <a name="input_service_name"></a> [service\_name](#input\_service\_name) | Service name. | `string` | n/a | yes |
| <a name="input_tag_pattern_list"></a> [tag\_pattern\_list](#input\_tag\_pattern\_list) | If the lifecycle expires tagged images, specify list of tag patterns. | `list(string)` | `null` | no |
| <a name="input_tag_prefix_list"></a> [tag\_prefix\_list](#input\_tag\_prefix\_list) | If the lifecycle expires tagged images, specify list of tag prefixes. | `list(string)` | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_repository_arn"></a> [repository\_arn](#output\_repository\_arn) | ECR repository ARN. |
