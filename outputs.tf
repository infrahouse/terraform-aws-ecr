output "repository_arn" {
  description = "ECR repository ARN."
  value       = aws_ecr_repository.repo.arn
}
