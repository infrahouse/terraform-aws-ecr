variable "environment" {
  description = "Name of environment."
  type        = string
}

variable "force_delete" {
  description = "If true, will delete the repository even if it contains images."
  type        = bool
  default     = false
}

variable "repo_name" {
  description = "Name of the repository."
  type        = string
}

variable "service_name" {
  description = "Service name."
  type        = string
}

variable "tag_pattern_list" {
  description = "If the lifecycle expires tagged images, specify list of tag patterns."
  type        = list(string)
  default     = null
}

variable "tag_prefix_list" {
  description = "If the lifecycle expires tagged images, specify list of tag prefixes."
  type        = list(string)
  default     = null
}
variable "expire_days_tagged" {
  description = "The amount of days after which a tagged image is deleted from the repository."
  type        = number
  default     = null
}

variable "expire_count_tagged" {
  description = "Keep no more tagged images that this."
  type        = number
  default     = null
}

variable "expire_days_untagged" {
  description = "The amount of days after which an untagged image is deleted from the repository. You can only specify `expire_days_untagged` or `expire_count_untagged`."
  type        = number
  default     = null
}

variable "expire_count_untagged" {
  description = "Keep no more tagged images that this. You can only specify `expire_days_untagged` or `expire_count_untagged`."
  type        = number
  default     = null
}
