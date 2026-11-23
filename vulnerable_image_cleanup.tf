# The vulnerable image cleanup: a scheduled Lambda that deletes the images Inspector reports vulnerable and that
# nothing protects. Off by default; with vulnerable_image_cleanup_enabled false, nothing here is created.
# The rules live in vulnerable_image_cleanup/selection.py.

locals {
  cleanup_enabled = var.vulnerable_image_cleanup_enabled
  # Lambda function names allow letters, digits, "-" and "_"; ECR repository names may also hold "/" and ".". The hash
  # keeps two repositories whose names sanitize alike apart. At most 40 + 1 + 6 + 13 = 60 of the 64 characters.
  cleanup_function_name = join("-", [
    substr(replace(var.repo_name, "/[^a-zA-Z0-9_-]/", "-"), 0, 40),
    substr(md5(var.repo_name), 0, 6),
    "vuln-cleanup",
  ])
  # The repository's Region, from its ARN: the function reads ECR and Inspector there.
  repository_region = split(":", aws_ecr_repository.repo.arn)[3]
  cleanup_tags = {
    environment : var.environment
    service : var.service_name
    created_by_module : local.module_name
  }
}

data "aws_iam_policy_document" "vulnerable_image_cleanup" {
  count = local.cleanup_enabled ? 1 : 0

  statement {
    sid       = "ReadRepository"
    actions   = ["ecr:DescribeImages", "ecr:BatchGetImage"]
    resources = [aws_ecr_repository.repo.arn]
  }
  # A dry run gets no delete permission at all.
  dynamic "statement" {
    for_each = var.vulnerable_image_cleanup_dry_run ? [] : [1]
    content {
      sid       = "DeleteImages"
      actions   = ["ecr:BatchDeleteImage"]
      resources = [aws_ecr_repository.repo.arn]
    }
  }
  # These take no resource ARN.
  statement {
    sid       = "ReadInspector"
    actions   = ["inspector2:ListFindings", "inspector2:ListCoverage"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "vulnerable_image_cleanup" {
  count       = local.cleanup_enabled ? 1 : 0
  name_prefix = "${local.cleanup_function_name}-"
  description = "The vulnerable image cleanup of the ECR repository ${var.repo_name}."
  policy      = data.aws_iam_policy_document.vulnerable_image_cleanup[0].json
  tags        = local.cleanup_tags
}

module "vulnerable_image_cleanup" {
  count   = local.cleanup_enabled ? 1 : 0
  source  = "registry.infrahouse.com/infrahouse/lambda-monitored/aws"
  version = "2.2.1"

  function_name              = local.cleanup_function_name
  description                = "Deletes the ECR images Inspector reports vulnerable that nothing protects."
  lambda_source_dir          = "${path.module}/vulnerable_image_cleanup"
  source_code_files          = ["*.py"]
  handler                    = "cleanup.lambda_handler"
  timeout                    = 300
  memory_size                = 256
  alarm_emails               = var.vulnerable_image_cleanup_alarm_emails
  additional_iam_policy_arns = [aws_iam_policy.vulnerable_image_cleanup[0].arn]

  environment_variables = {
    REPOSITORY_NAME                 = aws_ecr_repository.repo.name
    REGISTRY_ID                     = aws_ecr_repository.repo.registry_id
    REPOSITORY_REGION               = local.repository_region
    DRY_RUN                         = tostring(var.vulnerable_image_cleanup_dry_run)
    MIN_SEVERITY                    = var.vulnerable_image_cleanup_min_severity
    MIN_AGE_DAYS                    = tostring(var.vulnerable_image_cleanup_min_age_days)
    SOAK_DAYS                       = tostring(var.vulnerable_image_cleanup_soak_days)
    MAX_DELETIONS                   = tostring(var.vulnerable_image_cleanup_max_deletions)
    RETAIN_TAGS                     = jsonencode(var.retain_tags)
    PROTECT_ROLLBACK_CANDIDATES     = tostring(var.vulnerable_image_cleanup_protect_rollback_candidates)
    ROLLBACK_CANDIDATE_TAG_PREFIX   = var.rollback_candidate_tag_prefix
    ROLLBACK_CANDIDATE_RETAIN_COUNT = jsonencode(var.rollback_candidate_retain_count)
    ROLLBACK_CANDIDATE_RETAIN_DAYS  = jsonencode(var.rollback_candidate_retain_days)
  }

  tags = local.cleanup_tags
}

resource "aws_cloudwatch_event_rule" "vulnerable_image_cleanup" {
  count               = local.cleanup_enabled ? 1 : 0
  name_prefix         = substr("${local.cleanup_function_name}-", 0, 38)
  description         = "Runs ${module.vulnerable_image_cleanup[0].lambda_function_name} on its schedule."
  schedule_expression = var.vulnerable_image_cleanup_schedule
  tags                = local.cleanup_tags
}

resource "aws_cloudwatch_event_target" "vulnerable_image_cleanup" {
  count     = local.cleanup_enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.vulnerable_image_cleanup[0].name
  target_id = "vulnerable-image-cleanup"
  arn       = module.vulnerable_image_cleanup[0].lambda_function_arn
}

resource "aws_lambda_permission" "vulnerable_image_cleanup" {
  count         = local.cleanup_enabled ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = module.vulnerable_image_cleanup[0].lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.vulnerable_image_cleanup[0].arn
}
