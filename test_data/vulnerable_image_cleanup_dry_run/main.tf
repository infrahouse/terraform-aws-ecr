module "ecr" {
  source       = "../../"
  repo_name    = "test-cleanup-dry-run"
  environment  = "development"
  service_name = "foo"
  force_delete = true

  rollback_candidate_retain_count = 3
  retain_tags                     = ["pinned"]

  vulnerable_image_cleanup_enabled      = true
  vulnerable_image_cleanup_alarm_emails = ["devnull@infrahouse.com"]
}

# What the cleanup reads in ECS: a cluster with a service scaled to zero, whose task definition names an image of the
# repository by tag. With no task to run, it needs no capacity and no network.
resource "aws_ecs_cluster" "test" {
  name = "test-cleanup-dry-run"
}

resource "aws_ecs_task_definition" "web" {
  family                   = "test-cleanup-dry-run-web"
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  container_definitions = jsonencode([
    {
      name      = "web"
      image     = "${module.ecr.repository_url}:abc1234"
      memory    = 64
      essential = true
    }
  ])
}

resource "aws_ecs_service" "web" {
  name            = "web"
  cluster         = aws_ecs_cluster.test.arn
  task_definition = aws_ecs_task_definition.web.arn
  launch_type     = "EC2"
  desired_count   = 0
}

# The role of the container image function the test makes from a pushed image. The function is never invoked, so
# the role needs no permissions.
data "aws_iam_policy_document" "function_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "function" {
  name_prefix        = "test-cleanup-fn-"
  assume_role_policy = data.aws_iam_policy_document.function_trust.json
}
