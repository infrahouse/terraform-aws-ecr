locals {
  module_version = "0.1.0"

  module_name = "infrahouse/ecr/aws"
  default_module_tags = {
    environment : var.environment
    service : var.service_name
    created_by_module : local.module_name
    module_version = local.module_version
  }
}

