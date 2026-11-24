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
  # The repository's partition and Region, from its ARN (arn:<partition>:ecr:<region>:<account>:repository/<name>):
  # the function reads ECR, Inspector, ECS and Lambda there, in the repository's account.
  repository_partition = split(":", aws_ecr_repository.repo.arn)[1]
  repository_region    = split(":", aws_ecr_repository.repo.arn)[3]
  # ECS's and Lambda's ARNs in the repository's account and Region.
  repository_account = aws_ecr_repository.repo.registry_id
  ecs_arn_prefix     = "arn:${local.repository_partition}:ecs:${local.repository_region}:${local.repository_account}"
  lambda_arn_prefix  = "arn:${local.repository_partition}:lambda:${local.repository_region}:${local.repository_account}"
  cleanup_tags = {
    environment : var.environment
    service : var.service_name
    created_by_module : local.module_name
  }
}

data "aws_iam_policy_document" "vulnerable_image_cleanup" {
  count = local.cleanup_enabled ? 1 : 0

  statement {
    sid = "ReadRepository"
    # GetRepositoryPolicy: whether anyone outside the account may pull, and run images the function can't see.
    actions   = ["ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetRepositoryPolicy"]
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
  # The registry's policy may let another account pull from this repository too. It takes no resource ARN.
  statement {
    sid       = "ReadRegistryPolicy"
    actions   = ["ecr:GetRegistryPolicy"]
    resources = ["*"]
  }

  # What ECS and Lambda run, in the repository's account and Region: every cluster's running tasks, every service's
  # deployed task definitions, every version of every container image function. Read-only.
  # ListClusters and DescribeTaskDefinition take no resource ARN.
  statement {
    sid       = "ListEcsClustersAndTaskDefinitions"
    actions   = ["ecs:ListClusters", "ecs:DescribeTaskDefinition"]
    resources = ["*"]
  }
  # ListTasks names the container-instance resource type and ListServices none; both take the ecs:cluster key, which
  # holds them to this account's and Region's clusters.
  statement {
    sid       = "ListEcsTasksAndServices"
    actions   = ["ecs:ListTasks", "ecs:ListServices"]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "ecs:cluster"
      values   = ["${local.ecs_arn_prefix}:cluster/*"]
    }
  }
  statement {
    sid       = "DescribeEcsTasks"
    actions   = ["ecs:DescribeTasks"]
    resources = ["${local.ecs_arn_prefix}:task/*"]
  }
  statement {
    sid       = "DescribeEcsServices"
    actions   = ["ecs:DescribeServices"]
    resources = ["${local.ecs_arn_prefix}:service/*"]
  }
  # The digests a service's deployments resolved its tags to: its current deployment, and its revisions. Each action
  # names two resource types: the service, and its deployment or its revision.
  statement {
    sid     = "DescribeEcsServiceDeployments"
    actions = ["ecs:DescribeServiceDeployments"]
    resources = [
      "${local.ecs_arn_prefix}:service/*",
      "${local.ecs_arn_prefix}:service-deployment/*",
    ]
  }
  statement {
    sid     = "DescribeEcsServiceRevisions"
    actions = ["ecs:DescribeServiceRevisions"]
    resources = [
      "${local.ecs_arn_prefix}:service/*",
      "${local.ecs_arn_prefix}:service-revision/*",
    ]
  }
  # ListFunctions takes no resource ARN.
  statement {
    sid       = "ListLambdaFunctions"
    actions   = ["lambda:ListFunctions"]
    resources = ["*"]
  }
  # A function's ARN, and a version's (function:<name>:<version>), which the wildcard covers.
  statement {
    sid       = "GetLambdaFunctions"
    actions   = ["lambda:GetFunction"]
    resources = ["${local.lambda_arn_prefix}:function:*"]
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
    REPOSITORY_ARN                  = aws_ecr_repository.repo.arn
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
