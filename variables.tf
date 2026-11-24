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
    error_message = "rollback_candidate_retain_count must be >= 2 (or null to disable). Values below 2 risk pruning the currently active image."
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

  validation {
    condition     = var.rollback_candidate_retain_days == null ? true : var.rollback_candidate_retain_days >= 1
    error_message = "rollback_candidate_retain_days must be >= 1 (or null to disable)."
  }
}

variable "retain_tags" {
  description = <<-EOT
    Image tags whose images the lifecycle policy never expires: for an image
    that something runs by tag outside the ECS service's deployments, such as
    the image a scheduled or one-off task pins. Each tag gets a rule of its
    own, at the highest priorities, that selects the one image carrying it, so
    no lower rule can expire that image: not the rollback candidate rules,
    even if the image was deployed once and carries a rollback candidate tag,
    nor the tagged-image rules. Exact tags, without wildcards.

    The protection follows the tag: retain another tag, and the image of the
    old one falls to the other rules again. A retained image that is also a
    rollback candidate still counts toward rollback_candidate_retain_count,
    so it takes one of those places while it is among the newest.
  EOT
  type        = list(string)
  default     = []
  nullable    = false

  validation {
    condition     = alltrue([for tag in var.retain_tags : can(regex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", tag))])
    error_message = <<-EOT
      retain_tags holds exact image tags: a letter, digit or underscore, then up to 127 letters, digits, '_', '.' or
      '-', without wildcards. Got: ${jsonencode(var.retain_tags)}
    EOT
  }

  validation {
    condition     = length(distinct(var.retain_tags)) == length(var.retain_tags)
    error_message = "retain_tags names each tag once. Got: ${jsonencode(var.retain_tags)}"
  }
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

variable "vulnerable_image_cleanup_enabled" {
  description = <<-EOT
    Turns on the vulnerable image cleanup: a scheduled Lambda that deletes the images Amazon Inspector
    reports vulnerable, at or above vulnerable_image_cleanup_min_severity with a fix available, that nothing
    protects. An image is protected when it carries a tag in retain_tags, is a rollback candidate the
    lifecycle policy keeps, is in use or was within the soak, was pushed within the least age, or when the
    job can't tell whether it is in use. It judges use from what ECS (running tasks, services' deployments)
    and Lambda (every function version) run in the repository's account and Region, from Inspector's in-use
    data and, without it, from ECR's pull record: an image pushed from 2022-03-03 whose platform images ECR
    never recorded a pull of was never run, so it isn't in use; an older one without a pull record is kept.
    One last pulled before the soak that nothing in ECS or Lambda runs isn't in use when neither the
    repository's nor the registry's policy lets anyone outside the account pull, and is kept otherwise. It
    doesn't see EKS, Docker run on EC2, an ECS task outside a service unless it is running, CodeBuild, App
    Runner, AWS Batch, SageMaker or other Regions, and ECR refreshes the pull time at least once every 24
    hours: put every tag something pins in retain_tags. An image index is deleted with the manifests it
    references.
    Turned on, it runs dry until vulnerable_image_cleanup_dry_run is false. A deletion can't be undone.
    Off by default: false creates nothing.
  EOT
  type        = bool
  default     = false
  nullable    = false
}

variable "vulnerable_image_cleanup_dry_run" {
  description = <<-EOT
    The cleanup only logs what it would delete, and its role has no ecr:BatchDeleteImage. Set to false to
    delete: a deletion can't be undone.
  EOT
  type        = bool
  default     = true
  nullable    = false
}

variable "vulnerable_image_cleanup_alarm_emails" {
  description = <<-EOT
    Email addresses that get the cleanup Lambda's alarms, through terraform-aws-lambda-monitored. Required
    when the cleanup is on: a failed run alarms. AWS sends each address a confirmation email to accept.
  EOT
  type        = list(string)
  default     = []
  nullable    = false

  validation {
    condition     = var.vulnerable_image_cleanup_enabled ? length(var.vulnerable_image_cleanup_alarm_emails) > 0 : true
    error_message = <<-EOT
      vulnerable_image_cleanup_alarm_emails needs at least one address when vulnerable_image_cleanup_enabled is
      true: a failed run alarms by email.
    EOT
  }

  validation {
    condition = alltrue([
      for email in var.vulnerable_image_cleanup_alarm_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", email))
    ])
    error_message = <<-EOT
      vulnerable_image_cleanup_alarm_emails holds email addresses, e.g. "ops@example.com".
      Got: ${jsonencode(var.vulnerable_image_cleanup_alarm_emails)}
    EOT
  }
}

variable "vulnerable_image_cleanup_min_severity" {
  description = <<-EOT
    The least Inspector severity that makes an image vulnerable: CRITICAL, HIGH, MEDIUM or LOW. Only ACTIVE
    findings with a fix available count.
  EOT
  type        = string
  default     = "HIGH"
  nullable    = false

  validation {
    condition     = contains(["CRITICAL", "HIGH", "MEDIUM", "LOW"], var.vulnerable_image_cleanup_min_severity)
    error_message = <<-EOT
      vulnerable_image_cleanup_min_severity must be CRITICAL, HIGH, MEDIUM or LOW, in capitals.
      Got: ${var.vulnerable_image_cleanup_min_severity}
    EOT
  }
}

variable "vulnerable_image_cleanup_min_age_days" {
  description = <<-EOT
    An image pushed within this many days is protected, so an image waiting for its pin isn't deleted.
  EOT
  type        = number
  default     = 7
  nullable    = false

  validation {
    condition     = var.vulnerable_image_cleanup_min_age_days >= 1
    error_message = <<-EOT
      vulnerable_image_cleanup_min_age_days must be at least 1. Got: ${var.vulnerable_image_cleanup_min_age_days}
    EOT
  }
}

variable "vulnerable_image_cleanup_soak_days" {
  description = <<-EOT
    An image in use, or used within this many days by Inspector's lastInUseAt, is protected, and so is one whose
    platform image or single manifest ECR's lastRecordedPullTime says was pulled within this many days. Without
    Inspector's in-use data, one pulled earlier that nothing in ECS or Lambda runs isn't in use when neither the
    repository's nor the registry's policy lets anyone outside the account pull; otherwise it is kept, as a task in
    another account that pulled it then may still run it. One never pulled was never run, and isn't in use. An
    index's own pull time doesn't count, as ECR records the job's own read of each index as a pull. ECR refreshes
    the pull time at least once every 24 hours, so a first pull within the last day may not show yet: put a tag
    something pins in retain_tags rather than rely on a pull.
  EOT
  type        = number
  default     = 2
  nullable    = false

  validation {
    condition     = var.vulnerable_image_cleanup_soak_days >= 1
    error_message = <<-EOT
      vulnerable_image_cleanup_soak_days must be at least 1. Got: ${var.vulnerable_image_cleanup_soak_days}
    EOT
  }
}

variable "vulnerable_image_cleanup_protect_rollback_candidates" {
  description = <<-EOT
    Protects the rollback candidates the lifecycle policy keeps (rollback_candidate_retain_count and
    rollback_candidate_retain_days) even when they are vulnerable, so a rollback can go to them until they
    rotate out. Set to false to delete a vulnerable rollback candidate once nothing else protects it, so a
    rollback can only go to an image without such findings.
  EOT
  type        = bool
  default     = true
  nullable    = false
}

variable "vulnerable_image_cleanup_max_deletions" {
  description = <<-EOT
    The most images the cleanup deletes in a run. An image index with the manifests it references counts as
    one image. The oldest go first; the rest wait for the next run.
  EOT
  type        = number
  default     = 10
  nullable    = false

  validation {
    condition = (
      var.vulnerable_image_cleanup_max_deletions >= 1
      && floor(var.vulnerable_image_cleanup_max_deletions) == var.vulnerable_image_cleanup_max_deletions
    )
    error_message = <<-EOT
      vulnerable_image_cleanup_max_deletions must be a whole number, at least 1.
      Got: ${var.vulnerable_image_cleanup_max_deletions}
    EOT
  }
}

variable "vulnerable_image_cleanup_schedule" {
  description = <<-EOT
    When the cleanup runs: an EventBridge schedule expression, rate(...) or cron(...).
    See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html
  EOT
  type        = string
  default     = "rate(1 day)"
  nullable    = false

  validation {
    condition     = can(regex("^(rate|cron)\\(.+\\)$", var.vulnerable_image_cleanup_schedule))
    error_message = <<-EOT
      vulnerable_image_cleanup_schedule must be an EventBridge rate(...) or cron(...) expression, e.g. "rate(1 day)".
      Got: ${var.vulnerable_image_cleanup_schedule}
    EOT
  }
}
