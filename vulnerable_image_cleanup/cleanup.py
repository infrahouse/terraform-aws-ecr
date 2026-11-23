"""
Deletes the images of one ECR repository that Inspector reports vulnerable and that nothing protects.

A run reads the repository and Inspector, decides (see ``selection``), then deletes up to the cap, or in a dry run, only
logs what it would delete. Any error from AWS, throttling that outlasts the retries, or a page it can't read fails the
run before it deletes anything: the monitored Lambda alarms.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Mapping, Sequence

import boto3
from botocore.config import Config

import selection
from selection import Evidence, Plan, Repository, Settings

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

# Throttling and transient errors are retried; once the retries run out, the error fails the run.
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
# BatchGetImage and BatchDeleteImage take at most 100 image ids.
BATCH_SIZE = 100
ACCEPTED_MEDIA_TYPES = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
]
# Botocore drops the fields its model doesn't know. Without these, every image would look unused, or the archived
# ones would stay hidden.
REQUIRED_MODEL_FIELDS = {
    ("inspector2", "EcrContainerImageMetadata"): ("inUseCount", "lastInUseAt"),
    ("ecr", "DescribeImagesFilter"): ("imageStatus",),
    ("ecr", "ImageDetail"): ("imageStatus", "lastRecordedPullTime"),
}


class CleanupError(RuntimeError):
    """The run can't go on safely."""


def lambda_handler(event: Mapping[str, Any], context: Any) -> Dict[str, Any]:
    """
    The Lambda's entry point. The event is ignored: the schedule only triggers a run.

    :param event: The EventBridge event.
    :param context: The Lambda context.
    :return: The run's summary.
    """
    settings = Settings.from_environment(os.environ)
    region = os.environ["REPOSITORY_REGION"]
    return run(
        settings,
        boto3.client("ecr", region_name=region, config=BOTO_CONFIG),
        boto3.client("inspector2", region_name=region, config=BOTO_CONFIG),
        datetime.now(timezone.utc),
    )


def run(settings: Settings, ecr: Any, inspector: Any, now: datetime) -> Dict[str, Any]:
    """
    Read, decide, act.

    :param settings: The job's settings.
    :param ecr: An ECR client in the repository's Region.
    :param inspector: An Inspector2 client in the repository's Region.
    :param now: The time of the run.
    :return: The run's summary.
    :raise CleanupError: if the run can't read what it needs, or ECR refuses a deletion.
    """
    check_models(ecr, inspector)
    plan = decide(settings, ecr, inspector, now)
    return execute(settings, ecr, plan)


def check_models(ecr: Any, inspector: Any) -> None:
    """
    Fail unless botocore's models have the fields the rules read.

    :param ecr: An ECR client.
    :param inspector: An Inspector2 client.
    :raise CleanupError: if a field is missing.
    """
    clients = {"ecr": ecr, "inspector2": inspector}
    for (service, shape), fields in REQUIRED_MODEL_FIELDS.items():
        members = clients[service].meta.service_model.shape_for(shape).members
        missing = [name for name in fields if name not in members]
        if missing:
            raise CleanupError(
                f"botocore {service} models {shape} without {missing}: the package's boto3 is too old to judge."
            )


def decide(settings: Settings, ecr: Any, inspector: Any, now: datetime) -> Plan:
    """
    Read the repository and Inspector, and decide.

    :param settings: The job's settings.
    :param ecr: An ECR client.
    :param inspector: An Inspector2 client.
    :param now: The time of the run.
    :return: The plan.
    """
    details = read_images(settings, ecr)
    repository = Repository.build(details, read_manifests(settings, ecr, details))
    evidence = Evidence.build(
        read_findings(settings, inspector), read_coverage(settings, inspector), settings
    )
    return selection.plan(repository, evidence, settings, now)


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
    :raise CleanupError: if ECR refuses a deletion.
    """
    for verdict in plan.kept_vulnerable:
        _log(
            "kept", settings, dict(verdict.describe(), reasons=sorted(verdict.reasons))
        )
    for deletion in plan.deletions:
        if not settings.dry_run:
            for batch in deletion.batches:
                delete_images(settings, ecr, batch)
        _log(
            "would_delete" if settings.dry_run else "deleted",
            settings,
            deletion.describe(),
        )
    for verdict in plan.left_by_cap:
        _log("left_by_cap", settings, verdict.describe())
    summary = plan.summary(settings)
    LOG.info(json.dumps({"summary": summary}, sort_keys=True))
    return summary


def delete_images(settings: Settings, ecr: Any, digests: Sequence[str]) -> None:
    """
    Delete images by digest. An image already gone counts as deleted.

    :param settings: The job's settings.
    :param ecr: An ECR client.
    :param digests: The digests.
    :raise CleanupError: if ECR refuses to delete one, e.g. ImageReferencedByManifestList.
    """
    for chunk in _chunks(digests, BATCH_SIZE):
        response = ecr.batch_delete_image(
            registryId=settings.registry_id,
            repositoryName=settings.repository_name,
            imageIds=[{"imageDigest": digest} for digest in chunk],
        )
        refused = [
            failure
            for failure in response.get("failures", [])
            if failure.get("failureCode") != "ImageNotFound"
        ]
        if refused:
            raise CleanupError(f"ECR refused to delete: {refused}")


def _chunks(items: Sequence[str], size: int) -> Iterator[Sequence[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _equals(value: str) -> Dict[str, str]:
    return {"comparison": "EQUALS", "value": value}


def _log(action: str, settings: Settings, facts: Mapping[str, Any]) -> None:
    LOG.info(
        json.dumps(
            dict(facts, action=action, repository=settings.repository_name),
            sort_keys=True,
        )
    )
