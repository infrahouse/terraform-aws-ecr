output "repository_url" {
  description = "URL of the repository, to tag and push images to."
  value       = module.ecr.repository_url
}

output "repository_arn" {
  description = "ARN of the repository, to grant access to it."
  value       = module.ecr.repository_arn
}

output "vulnerable_image_cleanup_function_name" {
  description = "Name of the cleanup's Lambda function. Its logs are in the /aws/lambda/<name> log group."
  value       = module.ecr.vulnerable_image_cleanup_function_name
}

output "vulnerable_image_cleanup_function_arn" {
  description = "ARN of the cleanup's Lambda function."
  value       = module.ecr.vulnerable_image_cleanup_function_arn
}
