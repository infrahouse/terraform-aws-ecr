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

# What the cleanup reads in ECS: a cluster with two services scaled to zero, whose task definitions each name an image
# of the repository by tag. ECS refuses a DescribeServiceRevisions request whose revisions belong to more than one
# service: two services make the function describe each one's on their own. With no task to run, they need no capacity
# and no network.
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

resource "aws_ecs_task_definition" "worker" {
  family                   = "test-cleanup-dry-run-worker"
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = "${module.ecr.repository_url}:alias"
      memory    = 64
      essential = true
    }
  ])
}

resource "aws_ecs_service" "worker" {
  name            = "worker"
  cluster         = aws_ecs_cluster.test.arn
  task_definition = aws_ecs_task_definition.worker.arn
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
