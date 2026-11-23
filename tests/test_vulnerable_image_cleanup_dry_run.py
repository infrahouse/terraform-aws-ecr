"""
The vulnerable image cleanup, on and dry, in a repository with nothing vulnerable: the function runs, selects nothing,
and its role can't delete.
"""

import base64
import json
from fnmatch import fnmatch
from os import path as osp
from typing import Any, List

import pytest
from pytest_infrahouse import terraform_apply

from tests.conftest import LOG, TERRAFORM_ROOT_DIR, prepare_terraform_root
from tests.ecr_images import list_digests, push_index, push_synthetic_index

REPOSITORY = "test-cleanup-dry-run"


def allowed_actions(iam: Any, role_name: str) -> List[str]:
    """
    :return: The actions every policy of the role allows, inline and attached.
    """
    documents = [
        iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name)
        for name in page["PolicyNames"]
    ]
    for page in iam.get_paginator("list_attached_role_policies").paginate(
        RoleName=role_name
    ):
        for attached in page["AttachedPolicies"]:
            version = iam.get_policy(PolicyArn=attached["PolicyArn"])["Policy"][
                "DefaultVersionId"
            ]
            documents.append(
                iam.get_policy_version(
                    PolicyArn=attached["PolicyArn"], VersionId=version
                )["PolicyVersion"]["Document"]
            )
    actions = []
    for document in documents:
        LOG.info(json.dumps(document, indent=2))
        statements = document["Statement"]
        for statement in statements if isinstance(statements, list) else [statements]:
            if statement["Effect"] == "Allow":
                listed = statement.get("Action", [])
                actions.extend(listed if isinstance(listed, list) else [listed])
    return actions


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_dry_run_in_a_clean_repository(
    test_role_arn, keep_after, aws_region, aws_provider_version, boto3_session
):
    terraform_dir = osp.join(TERRAFORM_ROOT_DIR, "vulnerable_image_cleanup_dry_run")
    prepare_terraform_root(
        terraform_dir, aws_region, test_role_arn, aws_provider_version
    )
    with terraform_apply(
        terraform_dir, destroy_after=not keep_after, json_output=True
    ) as tf_output:
        LOG.info(json.dumps(tf_output, indent=4))
        ecr = boto3_session.client("ecr", region_name=aws_region)
        lambda_client = boto3_session.client("lambda", region_name=aws_region)
        function_name = tf_output["function_name"]["value"]

        # Indexes as BuildKit pushes them, one retained, and one that shares a platform image with another index.
        push_synthetic_index(ecr, REPOSITORY, "pinned", "pinned")
        other = push_synthetic_index(ecr, REPOSITORY, "other", "abc1234")
        push_index(ecr, REPOSITORY, "alias", platforms=[other["platform_descriptor"]])
        before = list_digests(ecr, REPOSITORY)

        lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)
        response = lambda_client.invoke(
            FunctionName=function_name, InvocationType="RequestResponse", LogType="Tail"
        )
        LOG.info(base64.b64decode(response["LogResult"]).decode())
        payload = json.loads(response["Payload"].read())
        assert "FunctionError" not in response, payload
        LOG.info(json.dumps(payload, indent=4))
        assert payload["dry_run"] is True
        assert payload["images_seen"] == 3
        assert payload["manifests_seen"] == 7
        assert payload["vulnerable"] == 0
        assert payload["candidates"] == 0
        assert payload["deleted"] == 0
        assert payload["would_delete"] == 0
        assert list_digests(ecr, REPOSITORY) == before

        # A dry run's role can't delete.
        iam = boto3_session.client("iam")
        role_name = lambda_client.get_function_configuration(
            FunctionName=function_name
        )["Role"].split("/")[-1]
        actions = allowed_actions(iam, role_name)
        assert not [
            action
            for action in actions
            if fnmatch("ecr:batchdeleteimage", action.lower())
        ], actions
        assert {
            "ecr:DescribeImages",
            "ecr:BatchGetImage",
            "inspector2:ListFindings",
            "inspector2:ListCoverage",
        } <= set(actions)
