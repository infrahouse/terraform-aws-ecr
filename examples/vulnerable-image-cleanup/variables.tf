variable "region" {
  description = "AWS Region to create the repository in. Amazon Inspector must scan ECR images in this Region."
  type        = string
}

variable "repo_name" {
  description = "Name of the ECR repository."
  type        = string
}

variable "environment" {
  description = "Environment name, e.g. production. The module tags the repository with it."
  type        = string
}

variable "service_name" {
  description = "Name of the service whose images the repository holds. The module tags the repository with it."
  type        = string
}

variable "retain_tags" {
  description = <<-EOT
    Exact tags of the images that something runs by tag outside the service's deployments, such as the image a
    scheduled or one-off task's task definition pins. Neither the lifecycle policy nor the cleanup deletes them.
    Pass [] if nothing does.
  EOT
  type        = list(string)
}

variable "alarm_emails" {
  description = <<-EOT
    Email addresses that get the cleanup's alarms, such as a failed run. AWS sends each one a confirmation email to
    accept.
  EOT
  type        = list(string)
}
