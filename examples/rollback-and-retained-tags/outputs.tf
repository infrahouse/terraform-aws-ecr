output "repository_url" {
  description = "URL of the repository, to tag and push images to."
  value       = module.ecr.repository_url
}

output "repository_arn" {
  description = "ARN of the repository, to grant access to it."
  value       = module.ecr.repository_arn
}
