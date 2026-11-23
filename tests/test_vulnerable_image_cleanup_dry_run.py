"""
The vulnerable image cleanup, on and dry, in a repository with nothing vulnerable: the function runs, selects nothing,
and its role can't delete. Its reads record a pull of each index it reads, and of nothing else: the cleanup judges an
image whose platform image or single manifest ECR never recorded a pull of as never run, so its own reads mustn't
record one there.
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from os import path as osp
from typing import Any, List

import pytest
from pytest_infrahouse import terraform_apply

from tests.conftest import LOG, TERRAFORM_ROOT_DIR, prepare_terraform_root
from tests.ecr_images import (
    list_digests,
    pull_times,
    push_index,
    push_synthetic_index,
    push_synthetic_platform,
    wait_for_pull_time,
)

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

        # Indexes as BuildKit pushes them, one retained, and one that shares a platform image with another index; and
        # a single manifest. Pushes record no pull, and nothing but the function reads an image.
        pinned = push_synthetic_index(ecr, REPOSITORY, "pinned", "pinned")
        other = push_synthetic_index(ecr, REPOSITORY, "other", "abc1234")
        alias = push_index(
            ecr, REPOSITORY, "alias", platforms=[other["platform_descriptor"]]
        )
        single = push_synthetic_platform(ecr, REPOSITORY, "single", "single")["digest"]
        names = {
            pinned["index"]: "pinned index",
            pinned["platform"]: "pinned platform image",
            pinned["attestation"]: "pinned attestation",
            other["index"]: "other index",
            other["platform"]: "other platform image, which alias shares",
            other["attestation"]: "other attestation",
            alias: "alias index",
            single: "single manifest",
        }
        before = list_digests(ecr, REPOSITORY)
        assert not any(pull_times(ecr, REPOSITORY).values())

        lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)
        invoked_at = datetime.now(timezone.utc)
        response = lambda_client.invoke(
            FunctionName=function_name, InvocationType="RequestResponse", LogType="Tail"
        )
        LOG.info(base64.b64decode(response["LogResult"]).decode())
        payload = json.loads(response["Payload"].read())
        assert "FunctionError" not in response, payload
        LOG.info(json.dumps(payload, indent=4))
        assert payload["dry_run"] is True
        assert payload["images_seen"] == 4
        assert payload["manifests_seen"] == 8
        assert payload["vulnerable"] == 0
        assert payload["candidates"] == 0
        assert payload["deleted"] == 0
        assert payload["would_delete"] == 0
        assert list_digests(ecr, REPOSITORY) == before

        # The function read each index with BatchGetImage, and ECR records that as a pull of the index. Once it shows
        # on one index, the platform images, the single manifest and the attestations, which the function didn't
        # read, still have none.
        pulled = wait_for_pull_time(ecr, REPOSITORY, pinned["index"], timeout=1200)
        times = pull_times(ecr, REPOSITORY)
        LOG.info(
            "Pull times after the function's run at %s: %s",
            invoked_at.isoformat(),
            json.dumps(
                {names[digest]: times[digest] for digest in names},
                default=str,
                indent=4,
            ),
        )
        if pulled is None:
            LOG.warning(
                "ECR recorded no pull of the index the function read within 20 minutes: the pull times say nothing."
            )
        else:
            # The pull is the function's: nothing read the index before it ran.
            assert pulled >= invoked_at - timedelta(minutes=1)
            unread = [
                pinned["platform"],
                other["platform"],
                single,
                pinned["attestation"],
                other["attestation"],
            ]
            assert [times[digest] for digest in unread] == [None] * len(unread), times

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
