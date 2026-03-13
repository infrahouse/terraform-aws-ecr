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
  description = <<-EOT
    List of tag wildcard patterns for tagged image lifecycle rules.
    Only tagged images matching at least one pattern will be expired.
    Supports wildcards, e.g. ["v*", "prod-*"] matches "v1.0", "prod-abc".
    At least one of tag_pattern_list or tag_prefix_list is required
    when expire_days_tagged or expire_count_tagged is set.
  EOT
  type        = list(string)
  default     = null
}

variable "tag_prefix_list" {
  description = <<-EOT
    List of tag prefixes for tagged image lifecycle rules.
    Only tagged images whose tag starts with one of these prefixes
    will be expired, e.g. ["v", "release-"] matches "v1.0", "release-2026".
    At least one of tag_pattern_list or tag_prefix_list is required
    when expire_days_tagged or expire_count_tagged is set.
  EOT
  type        = list(string)
  default     = null
}
variable "rollback_candidate_tag_prefix" {
  description = <<-EOT
    Tag prefix identifying rollback candidate images. Images tagged
    with this prefix (e.g., "deployed-at-2026-03-13T17-30-00Z") are
    treated as rollback candidates with separate retention rules.
    Used by the ECS module to tag images after successful deployment.
  EOT
  type        = string
  default     = "deployed-at-"
}

variable "rollback_candidate_retain_count" {
  description = <<-EOT
    Maximum number of rollback candidate images to keep. Only images
    tagged with the rollback_candidate_tag_prefix are affected.
    Set to null (default) to disable count-based rollback candidate
    expiry. At least one of rollback_candidate_retain_count or
    rollback_candidate_retain_days must be set to enable rollback
    candidate lifecycle rules.
  EOT
  type        = number
  default     = null
}

variable "rollback_candidate_retain_days" {
  description = <<-EOT
    Number of days to keep rollback candidate images. Only images
    tagged with the rollback_candidate_tag_prefix are affected.
    Set to null (default) to disable age-based rollback candidate
    expiry. At least one of rollback_candidate_retain_count or
    rollback_candidate_retain_days must be set to enable rollback
    candidate lifecycle rules.
  EOT
  type        = number
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
