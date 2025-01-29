data "aws_ecr_lifecycle_policy_document" "repo" {
  dynamic "rule" {
    for_each = var.expire_count_tagged != null ? [1] : []
    content {
      priority    = 1
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
      priority    = 2
      description = "Keep tagged images not older than  ${var.expire_days_tagged} days."
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
      priority    = 3
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
      priority    = 4
      description = "Keep untagged images not older than  ${var.expire_days_untagged} days."
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
}
