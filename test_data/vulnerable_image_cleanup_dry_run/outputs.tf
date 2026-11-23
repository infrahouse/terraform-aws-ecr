output "repository_arn" {
  value = module.ecr.repository_arn
}

output "repository_url" {
  value = module.ecr.repository_url
}

output "function_name" {
  value = module.ecr.vulnerable_image_cleanup_function_name
}

output "function_arn" {
  value = module.ecr.vulnerable_image_cleanup_function_arn
}
