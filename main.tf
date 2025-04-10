resource "aws_ecr_repository" "repo" {
  name         = var.repo_name
  force_delete = var.force_delete
  tags = merge(
    local.default_module_tags
  )
}
