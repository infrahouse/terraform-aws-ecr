"""
The vulnerable image cleanup, on and dry, in a repository with nothing vulnerable: the function runs, selects nothing,
and its role can't delete. Its reads record a pull of each index it reads, and of nothing else: the cleanup judges an
image whose platform image or single manifest ECR never recorded a pull of as never run, so its own reads mustn't
record one there.

It reads what ECS and Lambda run, under its own role: two ECS services scaled to zero whose task definitions each name
an image by tag, with their service revisions, and a container image function whose version 1 runs one pushed image
and whose $LATEST runs another. ECS refuses a DescribeServiceRevisions or DescribeServiceDeployments request whose ARNs
belong to more than one service, as 1.1.0 sent here for revisions: each service's are described on their own. The
services show no current deployment, so the test reads their deployments with the function's code itself. Then a
repository policy that lets another account pull makes its view incomplete. The test account has no registry policy,
which is account-wide, so the test sets none: the unit tests judge one.
"""

import base64
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from os import path as osp
from typing import Any, Dict, List

import pytest
from pytest_infrahouse import terraform_apply

import cleanup
import selection
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
# Another account, InfraHouse's, that the repository policy lets pull: nothing in it changes.
OTHER_ACCOUNT = "289256138624"
PULL_ACTIONS = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
# What the function's role must be allowed, and no more: it reads.
READS = {
    "ecr:DescribeImages",
    "ecr:BatchGetImage",
    "ecr:GetRepositoryPolicy",
    "ecr:GetRegistryPolicy",
    "inspector2:ListFindings",
    "inspector2:ListCoverage",
    "ecs:ListClusters",
    "ecs:ListTasks",
    "ecs:DescribeTasks",
    "ecs:ListServices",
    "ecs:DescribeServices",
    "ecs:DescribeServiceDeployments",
    "ecs:DescribeServiceRevisions",
    "ecs:DescribeTaskDefinition",
    "lambda:ListFunctions",
    "lambda:GetFunction",
}


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


def invoke(lambda_client: Any, function_name: str) -> Dict[str, Any]:
    """
    :return: The function's summary of a run.
    """
    response = lambda_client.invoke(
        FunctionName=function_name, InvocationType="RequestResponse", LogType="Tail"
    )
    LOG.info(base64.b64decode(response["LogResult"]).decode())
    payload = json.loads(response["Payload"].read())
    assert "FunctionError" not in response, payload
    LOG.info(json.dumps(payload, indent=4))
    return payload


def make_function(lambda_client: Any, name: str, role_arn: str, image_uri: str) -> None:
    """
    Make a container image function, retrying while Lambda can't assume its new role yet.
    """
    deadline = time.time() + 180
    while True:
        try:
            lambda_client.create_function(
                FunctionName=name,
                Role=role_arn,
                PackageType="Image",
                Code={"ImageUri": image_uri},
                Description="The vulnerable image cleanup's test: a function the cleanup must see.",
                Tags={"created_by": "infrahouse/terraform-aws-ecr"},
            )
            break
        except lambda_client.exceptions.InvalidParameterValueException as error:
            if "assumed" not in str(error) or time.time() > deadline:
                raise
            LOG.info("Lambda can't assume the role yet: %s", error)
            time.sleep(10)
    lambda_client.get_waiter("function_active_v2").wait(FunctionName=name)


def let_another_account_pull(ecr: Any) -> str:
    """
    Add a statement to the repository's policy, to whatever Lambda put there, that lets another account pull.

    :return: The policy before the change, for the log.
    """
    try:
        before = ecr.get_repository_policy(repositoryName=REPOSITORY)["policyText"]
        document = json.loads(before)
    except ecr.exceptions.RepositoryPolicyNotFoundException:
        before = "none"
        document = {"Version": "2012-10-17", "Statement": []}
    statements = document["Statement"]
    document["Statement"] = statements if isinstance(statements, list) else [statements]
    document["Statement"].append(
        {
            "Sid": "PullFromAnotherAccount",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:root"},
            "Action": PULL_ACTIONS,
        }
    )
    ecr.set_repository_policy(
        repositoryName=REPOSITORY, policyText=json.dumps(document)
    )
    return before


def simulated(
    iam: Any, role_arn: str, action: str, resource: str, **context: str
) -> str:
    """
    :return: IAM's decision on the role's policies for one action on one resource, with the context keys given.
    """
    entries = [
        {"ContextKeyName": key, "ContextKeyValues": [value], "ContextKeyType": "string"}
        for key, value in context.items()
    ]
    (result,) = iam.simulate_principal_policy(
        PolicySourceArn=role_arn,
        ActionNames=[action],
        ResourceArns=[resource],
        ContextEntries=entries,
    )["EvaluationResults"]
    return result["EvalDecision"]


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
        iam = boto3_session.client("iam")
        function_name = tf_output["function_name"]["value"]
        repository_url = tf_output["repository_url"]["value"]
        registry_id = tf_output["repository_arn"]["value"].split(":")[4]

        # Indexes as BuildKit pushes them, one retained, and one that shares a platform image with another index; and
        # two single manifests, for the test's function. Pushes record no pull, and nothing but the function and
        # Lambda reads an image.
        pinned = push_synthetic_index(ecr, REPOSITORY, "pinned", "pinned")
        other = push_synthetic_index(ecr, REPOSITORY, "other", "abc1234")
        alias = push_index(
            ecr, REPOSITORY, "alias", platforms=[other["platform_descriptor"]]
        )
        single = push_synthetic_platform(ecr, REPOSITORY, "single", "single")["digest"]
        later = push_synthetic_platform(ecr, REPOSITORY, "later", "later")["digest"]
        names = {
            pinned["index"]: "pinned index",
            pinned["platform"]: "pinned platform image",
            pinned["attestation"]: "pinned attestation",
            other["index"]: "other index, which the ECS service names by tag",
            other["platform"]: "other platform image, which alias shares",
            other["attestation"]: "other attestation",
            alias: "alias index, which the second ECS service names by tag",
            single: "single manifest, which the function's version 1 runs",
            later: "later single manifest, which the function's $LATEST runs",
        }
        before = list_digests(ecr, REPOSITORY)
        assert not any(pull_times(ecr, REPOSITORY).values())

        # A container image function: version 1 runs "single", and $LATEST has moved on to "later".
        test_function = f"test-cleanup-dry-run-{uuid.uuid4().hex[:8]}"
        try:
            make_function(
                lambda_client,
                test_function,
                tf_output["function_role_arn"]["value"],
                f"{repository_url}:single",
            )
            version = lambda_client.publish_version(FunctionName=test_function)[
                "Version"
            ]
            lambda_client.update_function_code(
                FunctionName=test_function, ImageUri=f"{repository_url}:later"
            )
            lambda_client.get_waiter("function_updated_v2").wait(
                FunctionName=test_function
            )
            LOG.info("The test's function %s: version %s", test_function, version)

            # 1. The deployed function, under its own role, reads ECS and Lambda without an error, and sees what they
            # run. The test account may hold other clusters and functions, so the counts are at least.
            lambda_client.get_waiter("function_active_v2").wait(
                FunctionName=function_name
            )
            invoked_at = datetime.now(timezone.utc)
            payload = invoke(lambda_client, function_name)
            assert payload["dry_run"] is True
            assert payload["images_seen"] == 5
            assert payload["manifests_seen"] == 9
            assert payload["vulnerable"] == 0
            assert payload["candidates"] == 0
            assert payload["deleted"] == 0
            assert payload["would_delete"] == 0
            assert payload["images_in_use_by"]["ecs"] == 2
            assert payload["images_in_use_by"]["lambda"] == 2
            view = payload["view"]
            # Lambda may have added a statement for this account's functions to the repository's policy.
            assert view["complete"] is True, view
            assert view["incomplete_because"] == []
            assert view["ecs_clusters"] >= 1
            assert view["ecs_services"] >= 2
            # Each service's revision: read, under the function's role, as a service shows it before it starts a task.
            assert view["ecs_service_revisions"] >= 2
            assert view["ecs_task_definitions"] >= 1
            assert view["lambda_image_versions"] >= 2
            assert list_digests(ecr, REPOSITORY) == before

            # 2. The function's code, from the test, names what runs each image, and reads the services' deployments.
            # The function describes each service's current deployment in a DescribeServiceDeployments request of its
            # own: ECS refuses a request across services, as it does DescribeServiceRevisions. These services show no
            # current deployment, so the function makes no such request here: the test reads a deployment of each
            # service with the function's code.
            ecs = boto3_session.client("ecs", region_name=aws_region)
            cluster = tf_output["cluster_name"]["value"]
            services = ecs.describe_services(
                cluster=cluster,
                services=[
                    tf_output["service_name"]["value"],
                    tf_output["worker_service_name"]["value"],
                ],
            )["services"]
            deployment_arns = {
                service["serviceArn"]: [
                    ecs.list_service_deployments(
                        cluster=cluster, service=service["serviceName"]
                    )["serviceDeployments"][0]["serviceDeploymentArn"]
                ]
                for service in services
            }
            deployments = cleanup.describe_by_service(
                ecs.describe_service_deployments,
                "serviceDeploymentArns",
                "serviceDeployments",
                "serviceDeploymentArn",
                deployment_arns,
                "service deployments",
            )
            LOG.info(
                "Both services' deployments, as ECS describes them: %s",
                json.dumps(deployments, default=str, indent=4),
            )
            assert sorted(deployments) == sorted(
                arn for arns in deployment_arns.values() for arn in arns
            )

            settings = selection.Settings(
                repository_name=REPOSITORY,
                registry_id=registry_id,
                region=aws_region,
                repository_arn=tf_output["repository_arn"]["value"],
                dry_run=True,
                min_severity="HIGH",
                min_age=timedelta(days=7),
                soak=timedelta(days=2),
                max_deletions=10,
                retain_tags=frozenset({"pinned"}),
                protect_rollback_candidates=True,
                rollback_candidate_tag_prefix="deployed-at-",
                rollback_candidate_retain_count=3,
                rollback_candidate_retain_days=None,
            )
            clients = cleanup.Clients(
                ecr=ecr,
                inspector=boto3_session.client("inspector2", region_name=aws_region),
                ecs=ecs,
                lambda_=lambda_client,
            )
            for service in services:
                revisions = [
                    item["arn"] for item in service.get("currentServiceRevisions", [])
                ]
                LOG.info(
                    "The revisions of %s, as ECS shows them: %s",
                    service["serviceName"],
                    json.dumps(
                        (
                            clients.ecs.describe_service_revisions(
                                serviceRevisionArns=revisions
                            )["serviceRevisions"]
                            if revisions
                            else []
                        ),
                        default=str,
                        indent=4,
                    ),
                )
            plan = cleanup.decide(settings, clients, datetime.now(timezone.utc))
            verdicts = {verdict.unit.root: verdict for verdict in plan.verdicts}
            for root, verdict in verdicts.items():
                LOG.info(
                    "%s: %s", names.get(root, root), json.dumps(verdict.describe())
                )
            ecs_uses = {
                root: [use.describe() for use in verdicts[root].in_use_by]
                for root in (other["index"], alias)
            }
            assert ecs_uses == {
                root: [
                    {
                        "source": "ecs",
                        "via": "deployment",
                        "cluster": cluster,
                        "service": tf_output[f"{prefix}service_name"]["value"],
                        "task_definition": tf_output[f"{prefix}task_definition"][
                            "value"
                        ],
                    }
                ]
                for root, prefix in ((other["index"], ""), (alias, "worker_"))
            }
            lambda_uses = {
                root: [use.describe() for use in verdicts[root].in_use_by]
                for root in (single, later)
            }
            assert lambda_uses == {
                single: [
                    {
                        "source": "lambda",
                        "via": "function_version",
                        "function": test_function,
                        "version": version,
                    }
                ],
                later: [
                    {
                        "source": "lambda",
                        "via": "function_version",
                        "function": test_function,
                        "version": "$LATEST",
                    }
                ],
            }
            assert verdicts[pinned["index"]].in_use_by == ()

            # 3. A repository policy that lets another account pull: the view isn't complete.
            LOG.info(
                "The repository's policy before: %s", let_another_account_pull(ecr)
            )
            payload = invoke(lambda_client, function_name)
            assert payload["view"]["complete"] is False
            assert payload["view"]["incomplete_because"] == [
                f"repository policy allows account {OTHER_ACCOUNT}"
            ]
            assert payload["deleted"] == 0
        finally:
            if not keep_after:
                lambda_client.delete_function(FunctionName=test_function)

        # The function read each index with BatchGetImage, and ECR records that as a pull of the index. Once it shows
        # on one index, the platform images and the attestations, which the function didn't read, still have none.
        # Lambda pulled the two single manifests to run them.
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
                pinned["attestation"],
                other["attestation"],
            ]
            assert [times[digest] for digest in unread] == [None] * len(unread), times

        # A dry run's role can't delete, and reads only.
        role_arn = lambda_client.get_function_configuration(FunctionName=function_name)[
            "Role"
        ]
        actions = allowed_actions(iam, role_arn.split("/")[-1])
        assert not [
            action
            for action in actions
            if fnmatch("ecr:batchdeleteimage", action.lower())
        ], actions
        assert READS <= set(actions)
        assert not [
            action
            for action in actions
            if action.startswith(("ecr:", "inspector2:", "ecs:", "lambda:"))
            and action not in READS
        ], actions
        # No task runs in the test account, so the function never described one: ask IAM. Its grants hold to this
        # account's and Region's tasks and clusters.
        here = f"arn:aws:ecs:{aws_region}:{registry_id}"
        elsewhere = f"arn:aws:ecs:eu-north-1:{registry_id}"
        assert (
            simulated(iam, role_arn, "ecs:DescribeTasks", f"{here}:task/c/0123")
            == "allowed"
        )
        assert (
            simulated(iam, role_arn, "ecs:DescribeTasks", f"{elsewhere}:task/c/0123")
            == "implicitDeny"
        )
        assert (
            simulated(
                iam,
                role_arn,
                "ecs:ListTasks",
                "*",
                **{"ecs:cluster": f"{elsewhere}:cluster/c"},
            )
            == "implicitDeny"
        )
