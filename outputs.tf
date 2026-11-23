output "repository_arn" {
  description = "ECR repository ARN."
  value       = aws_ecr_repository.repo.arn
}

output "repository_url" {
  description = "ECR repository URL."
  value       = aws_ecr_repository.repo.repository_url
}

output "vulnerable_image_cleanup_function_name" {
  description = "Name of the vulnerable image cleanup's Lambda function; null when the cleanup is off."
  value       = one(module.vulnerable_image_cleanup[*].lambda_function_name)
}

output "vulnerable_image_cleanup_function_arn" {
  description = "ARN of the vulnerable image cleanup's Lambda function; null when the cleanup is off."
  value       = one(module.vulnerable_image_cleanup[*].lambda_function_arn)
}
