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
    expiry.

    When both rollback_candidate_retain_count and
    rollback_candidate_retain_days are set, each image is expired by
    at most one rule — the count-based rule (higher priority) takes
    precedence. For example, retain_count=5 and retain_days=90 means:
    keep the 5 most recent, AND expire any beyond that which are also
    older than 90 days.
    See: https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.rollback_candidate_retain_count == null ? true : var.rollback_candidate_retain_count >= 2
    error_message = "rollback_candidate_retain_count must be >= 2 (or null to disable). A value of 1 is dangerous: it keeps only the current deployment, so the previous (possibly still active) image would be pruned."
  }
}

variable "rollback_candidate_retain_days" {
  description = <<-EOT
    Number of days to keep rollback candidate images. Only images
    tagged with the rollback_candidate_tag_prefix are affected.
    Set to null (default) to disable age-based rollback candidate
    expiry.

    This rule has lower priority than rollback_candidate_retain_count.
    ECR lifecycle rules are evaluated simultaneously but each image
    is expired by at most one rule, with higher-priority rules taking
    precedence.
    See: https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html
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
  description = "Keep no more tagged images than this."
  type        = number
  default     = null
}

variable "expire_days_untagged" {
  description = "The amount of days after which an untagged image is deleted from the repository. You can only specify `expire_days_untagged` or `expire_count_untagged`."
  type        = number
  default     = null
}

variable "expire_count_untagged" {
  description = "Keep no more untagged images than this. You can only specify `expire_days_untagged` or `expire_count_untagged`."
  type        = number
  default     = null
}
