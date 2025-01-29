resource "aws_ecr_repository" "repo" {
  name = var.repo_name
  tags = merge(
    local.default_module_tags
  )
}
