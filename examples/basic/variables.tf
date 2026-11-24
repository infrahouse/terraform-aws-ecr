variable "region" {
  description = "AWS Region to create the repository in."
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
