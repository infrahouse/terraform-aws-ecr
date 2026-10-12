import json
from os import path as osp, remove
from shutil import rmtree
from textwrap import dedent

import pytest
from pytest_infrahouse import terraform_apply

from tests.conftest import (
    LOG,
    TERRAFORM_ROOT_DIR,
)


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 5.31", "~> 6.0"], ids=["aws-5", "aws-6"]
)
def test_module(
    test_role_arn,
    keep_after,
    aws_region,
    aws_provider_version,
    boto3_session,
):
    terraform_dir = osp.join(TERRAFORM_ROOT_DIR, "test_module")
    state_files = [
        osp.join(terraform_dir, ".terraform"),
        osp.join(terraform_dir, ".terraform.lock.hcl"),
    ]

    for state_file in state_files:
        try:
            if osp.isdir(state_file):
                rmtree(state_file)
            elif osp.isfile(state_file):
                remove(state_file)
        except FileNotFoundError:
            # File was already removed by another process
            pass

    # Write terraform.tfvars
    with open(osp.join(terraform_dir, "terraform.tfvars"), "w") as fp:
        fp.write(dedent(f"""
                region          = "{aws_region}"
                """))
        if test_role_arn:
            fp.write(dedent(f"""
                    role_arn      = "{test_role_arn}"
                    """))

    # Update terraform.tf with the specific AWS provider version
    with open(osp.join(terraform_dir, "terraform.tf"), "w") as fp:
        fp.write(dedent(f"""
                terraform {{
                  required_providers {{
                    aws = {{
                      source  = "hashicorp/aws"
                      version = "{aws_provider_version}"
                    }}
                  }}
                }}
                """))
    with terraform_apply(
        terraform_dir,
        destroy_after=not keep_after,
        json_output=True,
    ) as tf_output:
        LOG.info(json.dumps(tf_output, indent=4))
        ecr = boto3_session.client("ecr", region_name=aws_region)
        policy = json.loads(
            ecr.get_lifecycle_policy(repositoryName="test_repo")["lifecyclePolicyText"]
        )
        rules = sorted(policy["rules"], key=lambda rule: rule["rulePriority"])
        LOG.info(json.dumps(rules, indent=4))
        # The retained tags' rules come first, one per tag, each keeping the one image with the tag; every other rule
        # follows them, in its usual order.
        assert [(rule["rulePriority"], rule["selection"]) for rule in rules[:2]] == [
            (
                priority,
                {
                    "tagStatus": "tagged",
                    "tagPatternList": [tag],
                    "countType": "imageCountMoreThan",
                    "countNumber": 1,
                },
            )
            for priority, tag in ((1, "pinned-1"), (2, "pinned-2"))
        ]
        assert [(rule["rulePriority"], rule["description"]) for rule in rules[2:]] == [
            (3, "Keep not more than 3 rollback candidate images."),
            (6, "Keep tagged images not older than 365 days."),
            (7, "Keep not more than 5 untagged images."),
        ]
