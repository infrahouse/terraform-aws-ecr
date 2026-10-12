locals {
  # The retained tags' rules take the first priorities; every other rule follows them, in its usual order.
  retained_rules = length(var.retain_tags)
}

data "aws_ecr_lifecycle_policy_document" "repo" {
  # Each retained tag's rule selects the one image that carries the tag, and never expires it (it keeps one image,
  # and only one can carry the tag). An image a rule selects can't be expired by a lower-priority rule, so these come
  # first: a pinned image that was deployed once, and so carries a "deployed-at-*" tag, is safe from the rollback
  # rule too.
  dynamic "rule" {
    for_each = var.retain_tags
    content {
      priority    = rule.key + 1
      description = "Keep the image tagged ${rule.value}."
      selection {
        tag_status       = "tagged"
        tag_pattern_list = [rule.value]
        count_type       = "imageCountMoreThan"
        count_number     = 1
      }
    }
  }
  # Rollback candidate rules come next (1-2 without retained tags) so they
  # match deployed images before general tagged rules can expire them.
  # An image with both a "v-*" tag and a "deployed-at-*" tag will be
  # matched by the rollback rule and protected from the general rule.
  dynamic "rule" {
    for_each = var.rollback_candidate_retain_count != null ? [1] : []
    content {
      priority    = local.retained_rules + 1
      description = "Keep not more than ${var.rollback_candidate_retain_count} rollback candidate images."
      selection {
        tag_status      = "tagged"
        tag_prefix_list = [var.rollback_candidate_tag_prefix]
        count_type      = "imageCountMoreThan"
        count_number    = var.rollback_candidate_retain_count
      }
    }
  }
  dynamic "rule" {
    for_each = var.rollback_candidate_retain_days != null ? [1] : []
    content {
      priority    = local.retained_rules + 2
      description = "Keep rollback candidate images not older than ${var.rollback_candidate_retain_days} days."
      selection {
        tag_status      = "tagged"
        tag_prefix_list = [var.rollback_candidate_tag_prefix]
        count_type      = "sinceImagePushed"
        count_unit      = "days"
        count_number    = var.rollback_candidate_retain_days
      }
    }
  }
  dynamic "rule" {
    for_each = var.expire_count_tagged != null ? [1] : []
    content {
      priority    = local.retained_rules + 3
      description = "Keep not more than ${var.expire_count_tagged} tagged images."
      selection {
        tag_status       = "tagged"
        tag_prefix_list  = var.tag_prefix_list
        tag_pattern_list = var.tag_pattern_list
        count_type       = "imageCountMoreThan"
        count_number     = var.expire_count_tagged
      }
    }
  }
  dynamic "rule" {
    for_each = var.expire_days_tagged != null ? [1] : []
    content {
      priority    = local.retained_rules + 4
      description = "Keep tagged images not older than ${var.expire_days_tagged} days."
      selection {
        tag_status       = "tagged"
        tag_prefix_list  = var.tag_prefix_list
        tag_pattern_list = var.tag_pattern_list
        count_type       = "sinceImagePushed"
        count_unit       = "days"
        count_number     = var.expire_days_tagged
      }
    }
  }
  dynamic "rule" {
    for_each = var.expire_count_untagged != null ? [1] : []
    content {
      priority    = local.retained_rules + 5
      description = "Keep not more than ${var.expire_count_untagged} untagged images."
      selection {
        tag_status   = "untagged"
        count_type   = "imageCountMoreThan"
        count_number = var.expire_count_untagged
      }
    }
  }
  dynamic "rule" {
    for_each = var.expire_days_untagged != null ? [1] : []
    content {
      priority    = local.retained_rules + 6
      description = "Keep untagged images not older than ${var.expire_days_untagged} days."
      selection {
        tag_status   = "untagged"
        count_type   = "sinceImagePushed"
        count_unit   = "days"
        count_number = var.expire_days_untagged
      }
    }
  }
}

resource "aws_ecr_lifecycle_policy" "repo" {
  repository = aws_ecr_repository.repo.name
  policy     = data.aws_ecr_lifecycle_policy_document.repo.json

  lifecycle {
    precondition {
      condition = (
        var.expire_days_tagged == null && var.expire_count_tagged == null
        ) ? true : (
        var.tag_prefix_list != null || var.tag_pattern_list != null
      )
      error_message = "tag_prefix_list or tag_pattern_list is required when expire_days_tagged or expire_count_tagged is set."
    }
  }
}
