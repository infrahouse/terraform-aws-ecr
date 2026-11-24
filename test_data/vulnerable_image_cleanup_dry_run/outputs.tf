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

output "cluster_name" {
  value = aws_ecs_cluster.test.name
}

output "service_name" {
  value = aws_ecs_service.web.name
}

output "task_definition" {
  value = "${aws_ecs_task_definition.web.family}:${aws_ecs_task_definition.web.revision}"
}

output "worker_service_name" {
  value = aws_ecs_service.worker.name
}

output "worker_task_definition" {
  value = "${aws_ecs_task_definition.worker.family}:${aws_ecs_task_definition.worker.revision}"
}

output "function_role_arn" {
  value = aws_iam_role.function.arn
}
