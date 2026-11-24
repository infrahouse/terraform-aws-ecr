"""
Deletes the images of one ECR repository that Inspector reports vulnerable and that nothing protects.

A run reads the repository, Inspector, the repository's policy, and what ECS and Lambda run in the repository's account
and Region; decides (see ``selection``); reads again the candidates' pull records and the running ECS tasks; then
deletes up to the cap, or in a dry run, only logs what it would delete. Any error from AWS, throttling that outlasts
the retries, or a page it can't read fails the run before it deletes anything: the monitored Lambda alarms.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

import selection
from selection import Evidence, Plan, Repository, Runtime, RuntimeBuilder, Settings

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

# Throttling and transient errors are retried; once the retries run out, the error fails the run.
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
# BatchGetImage and BatchDeleteImage take at most 100 image ids; ECS's DescribeTasks 100 tasks, DescribeServices 10
# services.
BATCH_SIZE = 100
TASKS_BATCH_SIZE = 100
SERVICES_BATCH_SIZE = 10
ACCEPTED_MEDIA_TYPES = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
]
# Botocore drops the fields its model doesn't know. Without these, every image would look unused or never pulled, the
# archived ones would stay hidden, or what ECS and Lambda run would go unseen.
REQUIRED_MODEL_FIELDS = {
    ("inspector2", "EcrContainerImageMetadata"): ("inUseCount", "lastInUseAt"),
    ("ecr", "DescribeImagesFilter"): ("imageStatus",),
    ("ecr", "ImageDetail"): ("imageStatus", "lastRecordedPullTime"),
    ("ecs", "Container"): ("image", "imageDigest"),
    ("ecs", "Service"): ("deployments", "taskSets", "taskDefinition"),
    ("lambda", "FunctionConfiguration"): ("PackageType", "Version"),
    ("lambda", "FunctionCodeLocation"): ("ImageUri", "ResolvedImageUri"),
}
# For about five minutes after an image's first pull shows, DescribeImages answers flap: in the test account, 22% to 60%
# of reads lost the pull time, in runs of up to 18 s. So the images judged never pulled are read again before the job
# deletes: 13 reads, 10 s apart, a span of 2 minutes. Replayed against the reads that measured the flapping, that
# schedule lost the pull in none of about 15,000 start times. It fits the function's 300 s timeout.
RECHECK_READS = 13
RECHECK_INTERVAL = 10.0


class CleanupError(RuntimeError):
    """The run can't go on safely."""


class DeletionError(CleanupError):
    """
    A deletion that failed part way.

    :param message: What failed.
    :param deleted: The digests ECR deleted before it failed.
    """

    def __init__(self, message: str, deleted: Sequence[str]) -> None:
        super().__init__(message)
        self.deleted = list(deleted)


@dataclass(frozen=True)
class Clients:
    """
    The AWS clients a run uses, all in the repository's account and Region.

    :param ecr: ECR.
    :param inspector: Inspector2.
    :param ecs: ECS.
    :param lambda_: Lambda.
    """

    ecr: Any
    inspector: Any
    ecs: Any
    lambda_: Any

    @classmethod
    def in_region(cls, region: str) -> "Clients":
        """
        :param region: The repository's Region.
        :return: The clients, with the retries of ``BOTO_CONFIG``.
        """
        return cls(
            **{
                name: boto3.client(service, region_name=region, config=BOTO_CONFIG)
                for name, service in (
                    ("ecr", "ecr"),
                    ("inspector", "inspector2"),
                    ("ecs", "ecs"),
                    ("lambda_", "lambda"),
                )
            }
        )


def lambda_handler(event: Mapping[str, Any], context: Any) -> Dict[str, Any]:
    """
    The Lambda's entry point. The event is ignored: the schedule only triggers a run.

    :param event: The EventBridge event.
    :param context: The Lambda context.
    :return: The run's summary.
    """
    settings = Settings.from_environment(os.environ)
    return run(settings, Clients.in_region(settings.region), datetime.now(timezone.utc))


def run(settings: Settings, clients: Clients, now: datetime) -> Dict[str, Any]:
    """
    Read, decide, act.

    :param settings: The job's settings.
    :param clients: The clients, in the repository's Region.
    :param now: The time of the run.
    :return: The run's summary.
    :raise CleanupError: if the run can't read what it needs, or ECR refuses a deletion.
    """
    check_models(clients)
    plan = decide(settings, clients, now)
    return execute(settings, clients.ecr, plan)


def check_models(clients: Clients) -> None:
    """
    Fail unless botocore's models have the fields the rules read.

    :param clients: The clients.
    :raise CleanupError: if a field is missing.
    """
    by_service = {
        "ecr": clients.ecr,
        "inspector2": clients.inspector,
        "ecs": clients.ecs,
        "lambda": clients.lambda_,
    }
    for (service, shape), fields in REQUIRED_MODEL_FIELDS.items():
        members = by_service[service].meta.service_model.shape_for(shape).members
        missing = [name for name in fields if name not in members]
        if missing:
            raise CleanupError(
                f"botocore {service} models {shape} without {missing}: the package's boto3 is too old to judge."
            )


def decide(settings: Settings, clients: Clients, now: datetime) -> Plan:
    """
    Read the repository, Inspector, the repository's policy, ECS and Lambda, and decide.

    :param settings: The job's settings.
    :param clients: The clients.
    :param now: The time of the run.
    :return: The plan.
    """
    details = read_images(settings, clients.ecr)
    repository = Repository.build(
        details, read_manifests(settings, clients.ecr, details)
    )
    evidence = Evidence.build(
        read_findings(settings, clients.inspector),
        read_coverage(settings, clients.inspector),
        settings,
    )
    view = read_view(settings, clients)
    plan = selection.plan(repository, evidence, view, settings, now)
    # One answer isn't enough to delete: read again the pull records of every candidate's runnable manifests, then the
    # running ECS tasks, right before deleting, to catch a pull or a task that started during the run. What a read
    # shows can only protect more, so judging again with it needs no further read.
    digests = plan.recheck_digests
    if not digests:
        return plan
    pulls, tasks = recheck(settings, clients, digests)
    # Only a pull newer than the first read's says something new.
    newer = {
        digest: moment
        for digest, moment in pulls.items()
        if repository.images[digest].last_pulled_at is None
        or moment > repository.images[digest].last_pulled_at
    }
    rejudged = selection.plan(
        repository.with_pulls(newer), evidence, view.merged(tasks), settings, now
    )
    still = {verdict.unit.root for verdict in rejudged.candidates}
    dropped = tuple(
        verdict.unit.root
        for verdict in plan.candidates
        if verdict.unit.root not in still
    )
    _log(
        "recheck",
        settings,
        {
            "read_again": digests,
            "pulled": {digest: moment.isoformat() for digest, moment in newer.items()},
            "dropped": list(dropped),
        },
    )
    return replace(rejudged, pulled_on_recheck=tuple(newer), dropped_on_recheck=dropped)


def recheck(
    settings: Settings, clients: Clients, digests: Sequence[str]
) -> Tuple[Dict[str, datetime], Runtime]:
    """
    Read again, right before deleting: the pull records of the candidates' runnable manifests, then the running ECS
    tasks.

    :param settings: The job's settings.
    :param clients: The clients.
    :param digests: The candidates' runnable manifests.
    :return: The latest pull time any read showed, by digest, and what the running tasks name.
    """
    pulls = recheck_pulls(settings, clients.ecr, digests)
    builder = RuntimeBuilder(settings)
    read_ecs(clients.ecs, builder, services=False)
    return pulls, builder.build()


def read_view(settings: Settings, clients: Clients) -> Runtime:
    """
    Read what can run the repository's images: the repository's policy, ECS and Lambda.

    :param settings: The job's settings.
    :param clients: The clients.
    :return: The view.
    """
    builder = RuntimeBuilder(settings)
    builder.add_repository_policy(read_repository_policy(settings, clients.ecr))
    read_ecs(clients.ecs, builder, services=True)
    read_lambda(clients.lambda_, builder)
    return builder.build()


def read_repository_policy(settings: Settings, ecr: Any) -> Optional[str]:
    """
    :param settings: The job's settings.
    :param ecr: An ECR client.
    :return: The repository's policy, or None if it has none.
    """
    try:
        return ecr.get_repository_policy(
            registryId=settings.registry_id, repositoryName=settings.repository_name
        )["policyText"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == (
            "RepositoryPolicyNotFoundException"
        ):
            return None
        raise


def read_ecs(ecs: Any, builder: RuntimeBuilder, services: bool) -> None:
    """
    Read every cluster's running tasks, and if asked, every service's deployed task definitions.

    :param ecs: An ECS client.
    :param builder: Where the uses go.
    :param services: Read the services too.
    :raise CleanupError: if ECS doesn't describe a task or service it listed.
    """
    deployed: Dict[str, List[Tuple[str, Mapping[str, Any]]]] = {}
    for cluster in _paginate(ecs, "list_clusters", "clusterArns"):
        builder.add_cluster()
        task_arns = _paginate(
            ecs, "list_tasks", "taskArns", cluster=cluster, desiredStatus="RUNNING"
        )
        for chunk in _chunks(task_arns, TASKS_BATCH_SIZE):
            response = ecs.describe_tasks(cluster=cluster, tasks=list(chunk))
            for task in _described(response, "tasks", "taskArn", chunk, "tasks"):
                builder.add_task(cluster, task)
        if not services:
            continue
        service_arns = _paginate(ecs, "list_services", "serviceArns", cluster=cluster)
        for chunk in _chunks(service_arns, SERVICES_BATCH_SIZE):
            response = ecs.describe_services(cluster=cluster, services=list(chunk))
            for service in _described(
                response, "services", "serviceArn", chunk, "services"
            ):
                builder.add_service()
                for arn in selection.deployed_task_definitions(service):
                    deployed.setdefault(arn, []).append((cluster, service))
    for arn in sorted(deployed):
        task_definition = ecs.describe_task_definition(taskDefinition=arn)[
            "taskDefinition"
        ]
        builder.add_task_definition()
        for cluster, service in deployed[arn]:
            builder.add_deployment(cluster, service, task_definition)


def read_lambda(lambda_: Any, builder: RuntimeBuilder) -> None:
    """
    Read the image of every version of every container image function: a rollback to a version runs its image.

    :param lambda_: A Lambda client.
    :param builder: Where the uses go.
    """
    for function in _paginate(
        lambda_, "list_functions", "Functions", FunctionVersion="ALL"
    ):
        if function.get("PackageType") != "Image":
            continue
        code = lambda_.get_function(
            FunctionName=function["FunctionName"], Qualifier=function["Version"]
        )["Code"]
        builder.add_function_version(function, code)


def recheck_pulls(
    settings: Settings, ecr: Any, digests: Sequence[str]
) -> Dict[str, datetime]:
    """
    Read images again with DescribeImages, ``RECHECK_READS`` times, ``RECHECK_INTERVAL`` seconds apart.

    :param settings: The job's settings.
    :param ecr: An ECR client.
    :param digests: The images.
    :return: For each image any read showed a pull of, the latest pull time a read gave.
    :raise CleanupError: if ECR doesn't return one of them.
    """
    pulls: Dict[str, datetime] = {}
    for number in range(RECHECK_READS):
        if number:
            time.sleep(RECHECK_INTERVAL)
        for chunk in _chunks(digests, BATCH_SIZE):
            details = ecr.describe_images(
                registryId=settings.registry_id,
                repositoryName=settings.repository_name,
                imageIds=[{"imageDigest": digest} for digest in chunk],
            )["imageDetails"]
            missing = sorted(set(chunk) - {detail["imageDigest"] for detail in details})
            if missing:
                raise CleanupError(f"ECR didn't return the images {missing}")
            for detail in details:
                moment = detail.get("lastRecordedPullTime")
                digest = detail["imageDigest"]
                if moment is not None and (
                    digest not in pulls or moment > pulls[digest]
                ):
                    pulls[digest] = moment
    return pulls


def read_images(settings: Settings, ecr: Any) -> List[Dict[str, Any]]:
    """
    :param settings: The job's settings.
    :param ecr: An ECR client.
    :return: Every image in the repository, archived ones included.
    """
    details: List[Dict[str, Any]] = []
    pages = ecr.get_paginator("describe_images").paginate(
        registryId=settings.registry_id,
        repositoryName=settings.repository_name,
        filter={"tagStatus": "ANY", "imageStatus": "ANY"},
        PaginationConfig={"PageSize": 1000},
    )
    for page in pages:
        details.extend(page["imageDetails"])
    return details


def read_manifests(
    settings: Settings, ecr: Any, details: Sequence[Mapping[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """
    Read the manifest of every index, and of every image whose media type ECR didn't give.

    :param settings: The job's settings.
    :param ecr: An ECR client.
    :param details: The repository's images.
    :return: The parsed manifests, by digest.
    :raise CleanupError: if ECR doesn't return one of them.
    """
    wanted = [
        detail["imageDigest"]
        for detail in details
        if selection.needs_manifest(detail.get("imageManifestMediaType"))
    ]
    manifests: Dict[str, Dict[str, Any]] = {}
    for chunk in _chunks(wanted, BATCH_SIZE):
        response = ecr.batch_get_image(
            registryId=settings.registry_id,
            repositoryName=settings.repository_name,
            imageIds=[{"imageDigest": digest} for digest in chunk],
            acceptedMediaTypes=ACCEPTED_MEDIA_TYPES,
        )
        if response.get("failures"):
            raise CleanupError(
                f"ECR didn't return these manifests: {response['failures']}"
            )
        for image in response["images"]:
            manifests[image["imageId"]["imageDigest"]] = selection.parse_manifest(
                image["imageManifest"]
            )
    missing = sorted(set(wanted) - set(manifests))
    if missing:
        raise CleanupError(f"ECR didn't return the manifests of {missing}")
    return manifests


def read_findings(settings: Settings, inspector: Any) -> List[Dict[str, Any]]:
    """
    :param settings: The job's settings.
    :param inspector: An Inspector2 client.
    :return: The ACTIVE findings on the repository's images, at or above the least severity, with a fix available.
    """
    findings: List[Dict[str, Any]] = []
    pages = inspector.get_paginator("list_findings").paginate(
        filterCriteria={
            "awsAccountId": [_equals(settings.registry_id)],
            "ecrImageRepositoryName": [_equals(settings.repository_name)],
            "resourceType": [_equals("AWS_ECR_CONTAINER_IMAGE")],
            "findingStatus": [_equals("ACTIVE")],
            # Values of one filter are OR'ed.
            "severity": [_equals(severity) for severity in settings.severities],
            "fixAvailable": [_equals("YES")],
        },
        PaginationConfig={"PageSize": 100},
    )
    for page in pages:
        findings.extend(page["findings"])
    return findings


def read_coverage(settings: Settings, inspector: Any) -> List[Dict[str, Any]]:
    """
    :param settings: The job's settings.
    :param inspector: An Inspector2 client.
    :return: The coverage records of the repository's images.
    """
    records: List[Dict[str, Any]] = []
    pages = inspector.get_paginator("list_coverage").paginate(
        filterCriteria={
            "accountId": [_equals(settings.registry_id)],
            "ecrRepositoryName": [_equals(settings.repository_name)],
            "resourceType": [_equals("AWS_ECR_CONTAINER_IMAGE")],
        },
        PaginationConfig={"PageSize": 200},
    )
    for page in pages:
        records.extend(page["coveredResources"])
    return records


def execute(settings: Settings, ecr: Any, plan: Plan) -> Dict[str, Any]:
    """
    Delete what the plan says, or in a dry run, only log it. Log one line per image, and one summary line.

    :param settings: The job's settings.
    :param ecr: An ECR client.
    :param plan: The plan.
    :return: The run's summary.
    :raise DeletionError: if a deletion fails. A ``delete_failed`` line names the image and the digests ECR deleted
        before the failure, as a deletion can't be undone.
    """
    for verdict in plan.kept_vulnerable:
        _log(
            "kept", settings, dict(verdict.describe(), reasons=sorted(verdict.reasons))
        )
    for deletion in plan.deletions:
        if settings.dry_run:
            _log("would_delete", settings, deletion.describe())
            continue
        deleted: List[str] = []
        try:
            for batch in deletion.batches:
                deleted.extend(delete_images(settings, ecr, batch))
        except DeletionError as error:
            _log(
                "delete_failed",
                settings,
                dict(
                    deletion.describe(),
                    deleted_digests=deleted + error.deleted,
                    error=str(error),
                ),
            )
            raise
        _log("deleted", settings, deletion.describe())
    for verdict in plan.left_by_cap:
        _log("left_by_cap", settings, verdict.describe())
    summary = plan.summary(settings)
    LOG.info(json.dumps({"summary": summary}, sort_keys=True))
    return summary


def delete_images(settings: Settings, ecr: Any, digests: Sequence[str]) -> List[str]:
    """
    Delete images by digest. An image already gone counts as deleted.

    :param settings: The job's settings.
    :param ecr: An ECR client.
    :param digests: The digests.
    :return: The digests ECR deleted, as its answers name them.
    :raise DeletionError: if ECR refuses to delete one, e.g. ImageReferencedByManifestList, or a call fails. It holds
        the digests ECR deleted before: BatchDeleteImage deletes the rest of a batch when it refuses some.
    """
    deleted: List[str] = []
    for chunk in _chunks(digests, BATCH_SIZE):
        try:
            response = ecr.batch_delete_image(
                registryId=settings.registry_id,
                repositoryName=settings.repository_name,
                imageIds=[{"imageDigest": digest} for digest in chunk],
            )
        except (BotoCoreError, ClientError) as error:
            raise DeletionError(f"BatchDeleteImage failed: {error}", deleted) from error
        for image_id in response.get("imageIds", []):
            digest = image_id.get("imageDigest")
            if digest is not None and digest not in deleted:
                deleted.append(digest)
        refused = [
            failure
            for failure in response.get("failures", [])
            if failure.get("failureCode") != "ImageNotFound"
        ]
        if refused:
            raise DeletionError(f"ECR refused to delete: {refused}", deleted)
    return deleted


def _chunks(items: Sequence[str], size: int) -> Iterator[Sequence[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _paginate(client: Any, operation: str, key: str, **params: Any) -> List[Any]:
    """
    :return: Every item of every page. A page that fails fails the read.
    """
    items: List[Any] = []
    for page in client.get_paginator(operation).paginate(**params):
        items.extend(page[key])
    return items


def _described(
    response: Mapping[str, Any],
    key: str,
    arn_key: str,
    asked: Sequence[str],
    what: str,
) -> List[Mapping[str, Any]]:
    """
    :param response: A DescribeTasks or DescribeServices answer.
    :param key: Where its items are.
    :param arn_key: Each item's ARN.
    :param asked: The ARNs asked for.
    :param what: What they are, for the error.
    :return: The items.
    :raise CleanupError: if ECS gives a failure, or leaves one out: what it runs would go unseen.
    """
    if response.get("failures"):
        raise CleanupError(f"ECS didn't describe these {what}: {response['failures']}")
    items = response[key]
    missing = sorted(set(asked) - {item.get(arn_key) for item in items})
    if missing:
        raise CleanupError(f"ECS didn't describe the {what} {missing}")
    return items


def _equals(value: str) -> Dict[str, str]:
    return {"comparison": "EQUALS", "value": value}


def _log(action: str, settings: Settings, facts: Mapping[str, Any]) -> None:
    LOG.info(
        json.dumps(
            dict(facts, action=action, repository=settings.repository_name),
            sort_keys=True,
        )
    )
