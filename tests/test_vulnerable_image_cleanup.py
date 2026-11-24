"""
Unit tests of the vulnerable image cleanup: no AWS.

Each test describes a repository, what Inspector says about it, and what ECS and Lambda run, then runs the Lambda's
code against boto3 clients whose answers botocore's Stubber serves. The Stubber checks every answer against botocore's
model, so they are shaped as botocore gives them, and fails a test on any call it wasn't given an answer for: a delete
in a dry run, or one in the wrong order.
"""

import contextlib
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from unittest import mock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import cleanup
import selection

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
# The function's own schedule of reads again, before the quick_recheck fixture shortens it.
REAL_RECHECK = (cleanup.RECHECK_READS, cleanup.RECHECK_INTERVAL)
REGISTRY = "111122223333"
OTHER_ACCOUNT = "444455556666"
REPOSITORY = "test-repo"
REGION = "us-west-2"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
PULL_ACTIONS = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]


def digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def days_ago(days: Optional[float]) -> Optional[datetime]:
    return None if days is None else NOW - timedelta(days=days)


def uri(
    tag: Optional[str] = None,
    image_digest: Optional[str] = None,
    repository: str = REPOSITORY,
    account: str = REGISTRY,
    region: str = REGION,
) -> str:
    """An image reference in ECR, as a task definition or a function names it."""
    reference = f"{account}.dkr.ecr.{region}.amazonaws.com/{repository}"
    if tag:
        reference += f":{tag}"
    if image_digest:
        reference += f"@{image_digest}"
    return reference


def ecs_arn(kind: str, name: str) -> str:
    return f"arn:aws:ecs:{REGION}:{REGISTRY}:{kind}/{name}"


def policy(*statements: Dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def pull_statement(principal: Any, **extra: Any) -> Dict[str, Any]:
    """A statement that lets ``principal`` pull."""
    return dict(
        {"Sid": "Pull", "Effect": "Allow", "Principal": principal},
        Action=PULL_ACTIONS,
        **extra,
    )


# The statement Lambda adds to a repository for this account's functions, as it added it in the test account.
LAMBDA_STATEMENT = {
    "Sid": "LambdaECRImageRetrievalPolicy",
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": PULL_ACTIONS
    + [
        "ecr:SetRepositoryPolicy",
        "ecr:DeleteRepositoryPolicy",
        "ecr:GetRepositoryPolicy",
    ],
    "Condition": {
        "StringLike": {
            "aws:sourceArn": f"arn:aws:lambda:{REGION}:{REGISTRY}:function:*"
        }
    },
}


def settings(**overrides: Any) -> selection.Settings:
    values = dict(
        repository_name=REPOSITORY,
        registry_id=REGISTRY,
        region=REGION,
        dry_run=False,
        min_severity="HIGH",
        min_age=timedelta(days=7),
        soak=timedelta(days=2),
        max_deletions=10,
        retain_tags=frozenset(),
        protect_rollback_candidates=True,
        rollback_candidate_tag_prefix="deployed-at-",
        rollback_candidate_retain_count=None,
        rollback_candidate_retain_days=None,
    )
    values.update(overrides)
    return selection.Settings(**values)


class Stubs:
    """The run's four clients, each with its Stubber active."""

    def __init__(self) -> None:
        self.clients = make_clients()
        self.ecr = Stubber(self.clients.ecr)
        self.inspector = Stubber(self.clients.inspector)
        self.ecs = Stubber(self.clients.ecs)
        self.lambda_ = Stubber(self.clients.lambda_)
        self._all = (self.ecr, self.inspector, self.ecs, self.lambda_)

    def __enter__(self) -> "Stubs":
        for stub in self._all:
            stub.activate()
        return self

    def __exit__(self, *exc: Any) -> None:
        for stub in self._all:
            stub.deactivate()

    def assert_no_pending_responses(self) -> None:
        for stub in self._all:
            stub.assert_no_pending_responses()


class Repo:
    """A repository, what Inspector says about it, and what ECS and Lambda run, as the AWS APIs answer."""

    def __init__(self) -> None:
        self.details: List[Dict[str, Any]] = []
        self.manifests: Dict[str, str] = {}
        self.findings: List[Dict[str, Any]] = []
        self.coverage: List[Dict[str, Any]] = []
        # The repository's policy; None for none.
        self.policy: Optional[str] = None
        # ECS: each cluster's running tasks and services, by the cluster's ARN, and the task definitions by ARN.
        self.tasks: Dict[str, List[Dict[str, Any]]] = {}
        self.services: Dict[str, List[Dict[str, Any]]] = {}
        self.task_definitions: Dict[str, Dict[str, Any]] = {}
        # The running tasks the read before deleting shows; None for the same as the first read.
        self.tasks_on_recheck: Optional[Dict[str, List[Dict[str, Any]]]] = None
        # Lambda: every function version, with its code.
        self.functions: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]] = []

    # --- What ECS and Lambda run ---

    def cluster(self, name: str = "prod") -> str:
        arn = ecs_arn("cluster", name)
        self.tasks.setdefault(arn, [])
        self.services.setdefault(arn, [])
        return arn

    def task(
        self,
        image: Optional[str],
        image_digest: Optional[str] = None,
        cluster: str = "prod",
        service: Optional[str] = "api",
        family: str = "api:3",
        on_recheck: bool = False,
    ) -> Dict[str, Any]:
        """
        Add a running task of one container. ``service`` None makes it a task outside a service. ``on_recheck`` adds
        it to the read before deleting only: a task that started during the run.
        """
        arn = self.cluster(cluster)
        container: Dict[str, Any] = {"name": "app", "lastStatus": "RUNNING"}
        if image is not None:
            container["image"] = image
        if image_digest is not None:
            container["imageDigest"] = image_digest
        number = sum(len(tasks) for tasks in self.tasks.values()) + (
            sum(len(tasks) for tasks in self.tasks_on_recheck.values())
            if self.tasks_on_recheck
            else 0
        )
        task = {
            "taskArn": ecs_arn("task", f"{cluster}/{number:032x}"),
            "clusterArn": arn,
            "taskDefinitionArn": ecs_arn("task-definition", family),
            "group": f"service:{service}" if service else f"family:{family}",
            "lastStatus": "RUNNING",
            "desiredStatus": "RUNNING",
            "containers": [container],
        }
        if on_recheck:
            if self.tasks_on_recheck is None:
                self.tasks_on_recheck = {
                    cluster_arn: list(tasks)
                    for cluster_arn, tasks in self.tasks.items()
                }
            self.tasks_on_recheck.setdefault(arn, []).append(task)
        else:
            self.tasks[arn].append(task)
            if self.tasks_on_recheck is not None:
                self.tasks_on_recheck.setdefault(arn, []).append(task)
        return task

    def task_definition(self, family: str, *images: str) -> str:
        arn = ecs_arn("task-definition", family)
        self.task_definitions[arn] = {
            "taskDefinitionArn": arn,
            "family": family.split(":")[0],
            "revision": int(family.split(":")[1]),
            "containerDefinitions": [
                {"name": f"container-{number}", "image": image}
                for number, image in enumerate(images)
            ],
        }
        return arn

    def service(
        self,
        name: str,
        deployments: Sequence[Tuple[str, str]],
        cluster: str = "prod",
        desired: int = 0,
        task_sets: Sequence[Tuple[str, str]] = (),
    ) -> Dict[str, Any]:
        """
        Add a service. ``deployments`` and ``task_sets`` are (status, task definition ARN) pairs; the first deployment
        is the service's own task definition.
        """
        arn = self.cluster(cluster)
        service: Dict[str, Any] = {
            "serviceArn": ecs_arn("service", f"{cluster}/{name}"),
            "serviceName": name,
            "clusterArn": arn,
            "status": "ACTIVE",
            "desiredCount": desired,
            "runningCount": 0,
            "deployments": [
                {
                    "id": f"ecs-svc/{number}",
                    "status": status,
                    "taskDefinition": task_definition,
                    "desiredCount": desired,
                }
                for number, (status, task_definition) in enumerate(deployments)
            ],
        }
        if deployments:
            service["taskDefinition"] = deployments[0][1]
        if task_sets:
            service["taskSets"] = [
                {
                    "id": f"ecs-svc/set-{number}",
                    "status": status,
                    "taskDefinition": task_definition,
                }
                for number, (status, task_definition) in enumerate(task_sets)
            ]
        self.services[arn].append(service)
        return service

    def function(
        self,
        name: str,
        version: str,
        resolved: Optional[str] = None,
        image_uri: Optional[str] = None,
        package: str = "Image",
    ) -> None:
        """Add a function version. A Zip function has no image, and the job doesn't read its code."""
        configuration = {
            "FunctionName": name,
            "FunctionArn": f"arn:aws:lambda:{REGION}:{REGISTRY}:function:{name}:{version}",
            "Version": version,
            "PackageType": package,
        }
        code = None
        if package == "Image":
            code = {"RepositoryType": "ECR", "ImageUri": image_uri or resolved}
            if resolved:
                code["ResolvedImageUri"] = resolved
        self.functions.append((configuration, code))

    def allow(self, *statements: Dict[str, Any]) -> None:
        """Give the repository a policy with these statements."""
        self.policy = policy(*statements)

    def manifest(
        self,
        name: str,
        tags: Sequence[str] = (),
        pushed: float = 30,
        pulled: Optional[float] = None,
        media_type: Optional[str] = OCI_MANIFEST,
        artifact: Optional[str] = "application/vnd.oci.image.config.v1+json",
        status: Optional[str] = "ACTIVE",
    ) -> str:
        """Add one manifest. Times are in days before NOW."""
        image_digest = digest(name)
        detail: Dict[str, Any] = {
            "registryId": REGISTRY,
            "repositoryName": REPOSITORY,
            "imageDigest": image_digest,
            "imagePushedAt": days_ago(pushed),
        }
        if tags:
            detail["imageTags"] = list(tags)
        if pulled is not None:
            detail["lastRecordedPullTime"] = days_ago(pulled)
        if media_type is not None:
            detail["imageManifestMediaType"] = media_type
        if artifact is not None:
            detail["artifactMediaType"] = artifact
        if status is not None:
            detail["imageStatus"] = status
        self.details.append(detail)
        return image_digest

    def index(
        self,
        name: str,
        tags: Sequence[str] = (),
        pushed: float = 30,
        pulled: Optional[float] = None,
        attestation: bool = True,
        platforms: Sequence[str] = (),
        status: str = "ACTIVE",
        media_type: Optional[str] = OCI_INDEX,
        platform_pulled: Optional[float] = None,
        attestation_pulled: Optional[float] = None,
    ) -> Dict[str, str]:
        """
        Add an index as BuildKit pushes it: a platform image, and an attestation. ``platforms`` names manifests
        already in the repository that it references instead of its own platform image. ``pulled`` is the index's own
        pull time; ``platform_pulled`` and ``attestation_pulled`` are those of its platform image and attestation.
        """
        entries = []
        made = {}
        if platforms:
            entries += [
                {"mediaType": OCI_MANIFEST, "digest": platform, "size": 1}
                for platform in platforms
            ]
        else:
            made["platform"] = self.manifest(
                f"{name}/platform",
                pushed=pushed,
                pulled=platform_pulled,
                status=status,
            )
            entries.append(
                {"mediaType": OCI_MANIFEST, "digest": made["platform"], "size": 1}
            )
        if attestation:
            made["attestation"] = self.manifest(
                f"{name}/attestation",
                pushed=pushed,
                pulled=attestation_pulled,
                artifact=selection.ATTESTATION_ARTIFACT_MEDIA_TYPE,
                status=status,
            )
            entries.append(
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": made["attestation"],
                    "size": 1,
                    "annotations": {
                        "vnd.docker.reference.digest": entries[0]["digest"],
                        "vnd.docker.reference.type": "attestation-manifest",
                    },
                }
            )
        made["index"] = self.manifest(
            name,
            tags=tags,
            pushed=pushed,
            pulled=pulled,
            media_type=media_type,
            artifact=None,
            status=status,
        )
        self.manifests[made["index"]] = json.dumps(
            {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries}
        )
        return made

    def vulnerable(
        self,
        image_digest: str,
        vulnerability: str = "CVE-2026-0001",
        severity: str = "HIGH",
        fix: str = "YES",
        status: str = "ACTIVE",
        repository: str = REPOSITORY,
        in_use_count: Optional[int] = None,
        last_in_use: Optional[float] = None,
    ) -> None:
        """Add a finding on a scanned image."""
        image = {
            "repositoryName": repository,
            "imageTags": [],
            "pushedAt": days_ago(30),
            "architecture": "amd64",
            "imageHash": image_digest,
            "registry": REGISTRY,
            "platform": "DEBIAN_12",
        }
        if in_use_count is not None:
            image["inUseCount"] = in_use_count
        if last_in_use is not None:
            image["lastInUseAt"] = days_ago(last_in_use)
        self.findings.append(
            {
                "findingArn": f"arn:aws:inspector2:{REGION}:{REGISTRY}:finding/{len(self.findings)}",
                "awsAccountId": REGISTRY,
                "type": "PACKAGE_VULNERABILITY",
                "description": "A vulnerability.",
                "title": f"{vulnerability} - zlib",
                "remediation": {"recommendation": {"text": "None Provided"}},
                "severity": severity,
                "firstObservedAt": days_ago(10),
                "lastObservedAt": days_ago(1),
                "status": status,
                "fixAvailable": fix,
                "resources": [
                    {
                        "type": "AWS_ECR_CONTAINER_IMAGE",
                        "id": f"arn:aws:ecr:{REGION}:{REGISTRY}:repository/{repository}/{image_digest}",
                        "partition": "aws",
                        "region": REGION,
                        "details": {"awsEcrContainerImage": image},
                    }
                ],
                "packageVulnerabilityDetails": {
                    "vulnerabilityId": vulnerability,
                    "source": "NVD",
                    "vulnerablePackages": [{"name": "zlib", "version": "1.3"}],
                },
            }
        )

    def covered(
        self,
        image_digest: str,
        in_use_count: Optional[int] = 0,
        last_in_use: Optional[float] = 30,
        repository: str = REPOSITORY,
    ) -> None:
        """Add a coverage record. None leaves the field out, as Inspector does for an image never seen in use."""
        metadata: Dict[str, Any] = {"tags": []}
        if in_use_count is not None:
            metadata["inUseCount"] = in_use_count
        if last_in_use is not None:
            metadata["lastInUseAt"] = days_ago(last_in_use)
        self.coverage.append(
            {
                "resourceType": "AWS_ECR_CONTAINER_IMAGE",
                "resourceId": f"arn:aws:ecr:{REGION}:{REGISTRY}:repository/{repository}/{image_digest}",
                "accountId": REGISTRY,
                "scanType": "PACKAGE",
                "scanStatus": {"statusCode": "ACTIVE", "reason": "SUCCESSFUL"},
                "resourceMetadata": {
                    "ecrRepository": {
                        "name": repository,
                        "scanFrequency": "CONTINUOUS_SCAN",
                    },
                    "ecrImage": metadata,
                },
            }
        )

    def unused(self, *digests: str) -> None:
        """Coverage that says each image was last in use 30 days ago and isn't now."""
        for image_digest in digests:
            self.covered(image_digest)

    def run(
        self,
        deletions: Iterable[Sequence[str]] = (),
        refused: Optional[Dict[str, str]] = None,
        throttled: Optional[int] = None,
        recheck: Optional[Sequence[str]] = None,
        recheck_pulls: Sequence[Dict[str, float]] = (),
        **overrides: Any,
    ) -> Dict[str, Any]:
        """
        Run the cleanup. ``deletions`` are the BatchDeleteImage calls the run must make, in order; any other delete
        fails the test. ECR refuses the images in ``refused`` with their failure codes, and the call numbered
        ``throttled`` (from 0) fails with ThrottlingException.

        ``recheck`` are the images the run must read again, in order, before it deletes, followed by its read of the
        running tasks (``tasks_on_recheck``); ``recheck_pulls`` gives, for each of those reads, the pull times (days
        before NOW) it shows. An empty ``recheck`` says the run reads nothing again. None, for a test about something
        else, stands in for the reads again: they find nothing new, and the run must make them exactly when it has
        candidates.
        """
        rechecked: List[List[str]] = []

        def found_nothing_new(
            _settings: selection.Settings, _clients: cleanup.Clients, digests: Any
        ) -> Tuple[Dict[str, datetime], selection.Runtime]:
            rechecked.append(list(digests))
            return {}, selection.Runtime()

        with Stubs() as stubs:
            self.stub_reads(stubs)
            if recheck is None:
                stand_in = mock.patch.object(cleanup, "recheck", found_nothing_new)
            else:
                stand_in = contextlib.nullcontext()
                if recheck:
                    self.stub_recheck(stubs.ecr, recheck, recheck_pulls)
                    self.stub_tasks(stubs.ecs, self.tasks_on_recheck or self.tasks)
            ecr_stub = stubs.ecr
            for number, batch in enumerate(deletions):
                if number == throttled:
                    ecr_stub.add_client_error(
                        "batch_delete_image",
                        service_error_code="ThrottlingException",
                        expected_params={
                            "registryId": REGISTRY,
                            "repositoryName": REPOSITORY,
                            "imageIds": [{"imageDigest": image} for image in batch],
                        },
                    )
                    continue
                failures = [
                    {
                        "imageId": {"imageDigest": image},
                        "failureCode": code,
                        "failureReason": code,
                    }
                    for image, code in (refused or {}).items()
                    if image in batch
                ]
                ecr_stub.add_response(
                    "batch_delete_image",
                    {
                        "imageIds": [
                            {"imageDigest": image}
                            for image in batch
                            if image not in (refused or {})
                        ],
                        "failures": failures,
                    },
                    {
                        "registryId": REGISTRY,
                        "repositoryName": REPOSITORY,
                        "imageIds": [{"imageDigest": image} for image in batch],
                    },
                )
            with stand_in:
                summary = cleanup.run(settings(**overrides), stubs.clients, NOW)
            stubs.assert_no_pending_responses()
        if recheck is None:
            assert len(rechecked) == int(summary["candidates"] > 0), rechecked
        return summary

    def stub_recheck(
        self,
        ecr_stub: Stubber,
        digests: Sequence[str],
        pulls_per_read: Sequence[Dict[str, float]] = (),
    ) -> None:
        """Answer the run's reads again of ``digests``: ``cleanup.RECHECK_READS`` DescribeImages calls."""
        details = {detail["imageDigest"]: detail for detail in self.details}
        for number in range(cleanup.RECHECK_READS):
            pulls = pulls_per_read[number] if number < len(pulls_per_read) else {}
            answers = []
            for image_digest in digests:
                answer = dict(details[image_digest])
                if image_digest in pulls:
                    answer["lastRecordedPullTime"] = days_ago(pulls[image_digest])
                answers.append(answer)
            ecr_stub.add_response(
                "describe_images",
                {"imageDetails": answers},
                {
                    "registryId": REGISTRY,
                    "repositoryName": REPOSITORY,
                    "imageIds": [{"imageDigest": image} for image in digests],
                },
            )

    def stub_reads(self, stubs: Stubs) -> None:
        """Answer the run's reads before it decides, in order, for each client."""
        self.stub_ecr_reads(stubs.ecr)
        stubs.inspector.add_response("list_findings", {"findings": self.findings})
        stubs.inspector.add_response(
            "list_coverage", {"coveredResources": self.coverage}
        )
        self.stub_policy(stubs.ecr)
        self.stub_tasks(stubs.ecs, self.tasks, services=True)
        self.stub_task_definitions(stubs.ecs)
        self.stub_functions(stubs.lambda_)

    def stub_policy(self, ecr_stub: Stubber) -> None:
        expected = {"registryId": REGISTRY, "repositoryName": REPOSITORY}
        if self.policy is None:
            ecr_stub.add_client_error(
                "get_repository_policy",
                service_error_code="RepositoryPolicyNotFoundException",
                http_status_code=400,
                expected_params=expected,
            )
        else:
            ecr_stub.add_response(
                "get_repository_policy",
                {
                    "registryId": REGISTRY,
                    "repositoryName": REPOSITORY,
                    "policyText": self.policy,
                },
                expected,
            )

    def stub_tasks(
        self,
        ecs_stub: Stubber,
        tasks: Dict[str, List[Dict[str, Any]]],
        services: bool = False,
    ) -> None:
        """Answer ListClusters, then each cluster's ListTasks and DescribeTasks, and if asked, its services."""
        clusters = sorted(set(tasks) | (set(self.services) if services else set()))
        ecs_stub.add_response("list_clusters", {"clusterArns": clusters}, {})
        for cluster in clusters:
            arns = [task["taskArn"] for task in tasks.get(cluster, [])]
            ecs_stub.add_response(
                "list_tasks",
                {"taskArns": arns},
                {"cluster": cluster, "desiredStatus": "RUNNING"},
            )
            if arns:
                ecs_stub.add_response(
                    "describe_tasks",
                    {"tasks": tasks[cluster], "failures": []},
                    {"cluster": cluster, "tasks": arns},
                )
            if not services:
                continue
            arns = [service["serviceArn"] for service in self.services.get(cluster, [])]
            ecs_stub.add_response(
                "list_services", {"serviceArns": arns}, {"cluster": cluster}
            )
            for start in range(0, len(arns), cleanup.SERVICES_BATCH_SIZE):
                chunk = arns[start : start + cleanup.SERVICES_BATCH_SIZE]
                ecs_stub.add_response(
                    "describe_services",
                    {
                        "services": [
                            service
                            for service in self.services[cluster]
                            if service["serviceArn"] in chunk
                        ],
                        "failures": [],
                    },
                    {"cluster": cluster, "services": chunk},
                )

    def stub_task_definitions(self, ecs_stub: Stubber) -> None:
        """Answer DescribeTaskDefinition, once for each task definition a service deploys, in ARN order."""
        deployed = {
            arn
            for services in self.services.values()
            for service in services
            for arn in selection.deployed_task_definitions(service)
        }
        for arn in sorted(deployed):
            ecs_stub.add_response(
                "describe_task_definition",
                {"taskDefinition": self.task_definitions[arn]},
                {"taskDefinition": arn},
            )

    def stub_functions(self, lambda_stub: Stubber) -> None:
        lambda_stub.add_response(
            "list_functions",
            {"Functions": [configuration for configuration, _ in self.functions]},
            {"FunctionVersion": "ALL"},
        )
        for configuration, code in self.functions:
            if code is None:
                continue
            lambda_stub.add_response(
                "get_function",
                {"Configuration": configuration, "Code": code},
                {
                    "FunctionName": configuration["FunctionName"],
                    "Qualifier": configuration["Version"],
                },
            )

    def stub_ecr_reads(self, ecr_stub: Stubber) -> None:
        ecr_stub.add_response("describe_images", {"imageDetails": self.details})
        wanted = [
            d["imageDigest"]
            for d in self.details
            if selection.needs_manifest(d.get("imageManifestMediaType"))
        ]
        if wanted:
            ecr_stub.add_response(
                "batch_get_image",
                {
                    "images": [
                        {
                            "registryId": REGISTRY,
                            "repositoryName": REPOSITORY,
                            "imageId": {"imageDigest": image},
                            "imageManifest": self.manifests.get(
                                image,
                                json.dumps(
                                    {"schemaVersion": 2, "mediaType": DOCKER_MANIFEST}
                                ),
                            ),
                        }
                        for image in wanted
                    ],
                    "failures": [],
                },
            )


@pytest.fixture(autouse=True)
def quick_recheck(monkeypatch):
    """Three reads again, without the wait between them; one test checks the real schedule."""
    monkeypatch.setattr(cleanup, "RECHECK_READS", 3)
    monkeypatch.setattr(cleanup, "RECHECK_INTERVAL", 0)


def make_clients() -> cleanup.Clients:
    session = boto3.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name=REGION
    )
    return cleanup.Clients(
        ecr=session.client("ecr"),
        inspector=session.client("inspector2"),
        ecs=session.client("ecs"),
        lambda_=session.client("lambda"),
    )


def vulnerable_index(
    repo: Repo, name: str, tags: Sequence[str] = (), **kwargs: Any
) -> Dict[str, str]:
    """An index whose platform image Inspector reports vulnerable, unused for 30 days."""
    made = repo.index(name, tags=tags, **kwargs)
    platform = made.get("platform") or kwargs["platforms"][0]
    repo.vulnerable(platform)
    repo.unused(platform)
    return made


def deletes(made: Dict[str, str]) -> List[List[str]]:
    """The deletions of a whole BuildKit index: the index, then its platform image and attestation."""
    return [[made["index"]], [made["platform"], made["attestation"]]]


# --- What it deletes ---


def test_deletes_a_vulnerable_index_with_its_manifests():
    repo = Repo()
    made = vulnerable_index(repo, "old", tags=["abc1234"])
    summary = repo.run(deletions=deletes(made))
    assert summary["deleted"] == 1
    assert summary["vulnerable"] == 1
    assert summary["images_seen"] == 1
    assert summary["manifests_seen"] == 3


def test_leaves_an_image_without_a_qualifying_finding():
    repo = Repo()
    made = repo.index("clean", tags=["abc"])
    repo.unused(made["platform"])
    low = repo.index("low", tags=["low"])
    repo.vulnerable(low["platform"], severity="MEDIUM")
    no_fix = repo.index("no-fix", tags=["no-fix"])
    repo.vulnerable(no_fix["platform"], fix="NO")
    closed = repo.index("closed", tags=["closed"])
    repo.vulnerable(closed["platform"], status="CLOSED")
    other = repo.index("other", tags=["other"])
    repo.vulnerable(other["platform"], repository="another-repo")
    repo.unused(
        low["platform"], no_fix["platform"], closed["platform"], other["platform"]
    )
    summary = repo.run()
    assert summary["vulnerable"] == 0
    assert summary["candidates"] == 0


def test_the_least_severity_is_inclusive():
    repo = Repo()
    made = vulnerable_index(repo, "old")
    repo.vulnerable(made["platform"], vulnerability="CVE-2026-0002", severity="MEDIUM")
    assert repo.run(deletions=deletes(made), min_severity="MEDIUM")["deleted"] == 1


def test_deletes_a_single_manifest_without_an_index():
    repo = Repo()
    image = repo.manifest("single", tags=["v1"], media_type=DOCKER_MANIFEST)
    repo.vulnerable(image)
    repo.unused(image)
    assert repo.run(deletions=[[image]])["deleted"] == 1


def test_deletes_an_index_without_attestation():
    repo = Repo()
    made = vulnerable_index(repo, "old", attestation=False)
    assert repo.run(deletions=[[made["index"]], [made["platform"]]])["deleted"] == 1


def test_reads_a_manifest_whose_media_type_ecr_did_not_give():
    repo = Repo()
    made = vulnerable_index(repo, "old", media_type=None)
    assert repo.run(deletions=deletes(made))["deleted"] == 1


# --- Protection reasons ---


def test_retained_tag_protects_the_whole_index():
    repo = Repo()
    vulnerable_index(repo, "pinned", tags=["abc1234", "migrator"])
    summary = repo.run(retain_tags=frozenset({"migrator"}))
    assert summary["deleted"] == 0
    assert summary["protected"]["retained_tag"] == 1


def test_in_use_count_protects():
    repo = Repo()
    made = repo.index("running", tags=["abc"])
    repo.vulnerable(made["platform"])
    repo.covered(made["platform"], in_use_count=2, last_in_use=10)
    summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 1


@pytest.mark.parametrize(
    "last_in_use, protected", [(1.5, True), (2.5, False)], ids=["within", "beyond"]
)
def test_last_in_use_within_the_soak_protects(last_in_use, protected):
    repo = Repo()
    made = repo.index("recently-used", tags=["abc"])
    repo.vulnerable(made["platform"])
    repo.covered(made["platform"], in_use_count=0, last_in_use=last_in_use)
    summary = repo.run(deletions=[] if protected else deletes(made))
    assert summary["protected"]["in_use"] == int(protected)


def test_a_finding_that_says_in_use_protects():
    repo = Repo()
    made = repo.index("used", tags=["abc"])
    repo.vulnerable(made["platform"], in_use_count=1, last_in_use=0.1)
    repo.unused(made["platform"])
    assert repo.run()["protected"]["in_use"] == 1


def test_a_pull_within_the_soak_protects():
    # A real pull of an index records its platform image's pull.
    repo = Repo()
    vulnerable_index(repo, "pulled", tags=["abc"], pulled=1, platform_pulled=1)
    summary = repo.run()
    assert summary["protected"]["in_use"] == 1


def test_a_pull_of_a_single_manifest_within_the_soak_protects():
    repo = Repo()
    image = repo.manifest("single", tags=["v1"], media_type=DOCKER_MANIFEST, pulled=1)
    repo.vulnerable(image)
    repo.unused(image)
    assert repo.run()["protected"]["in_use"] == 1


def test_the_pull_time_of_an_index_alone_does_not_count():
    # The job's own BatchGetImage of an index each run is recorded as a pull of the index, and of nothing else.
    repo = Repo()
    made = vulnerable_index(repo, "read", tags=["abc"], pulled=1)
    summary = repo.run(deletions=deletes(made))
    assert summary["protected"]["in_use"] == 0
    assert summary["deleted"] == 1


def test_a_pull_before_the_soak_does_not_protect():
    # Inspector says it isn't in use, so a pull before the soak doesn't protect it.
    repo = Repo()
    made = vulnerable_index(repo, "pulled", tags=["abc"], pulled=3, platform_pulled=3)
    assert repo.run(deletions=deletes(made))["deleted"] == 1


def test_recent_push_protects():
    repo = Repo()
    vulnerable_index(repo, "new", tags=["abc"], pushed=6.9)
    summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["recent"] == 1


def test_an_archived_image_is_kept():
    repo = Repo()
    vulnerable_index(repo, "archived", tags=["abc"], status="ARCHIVED")
    summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["not_active"] == 1


# --- Rollback candidates: the rules policy.tf writes ---


def rollback_repo(retained_newest: bool = False) -> Dict[str, Dict[str, str]]:
    """Five deployed images, pushed 50, 40, 30, 20 and 10 days ago, all vulnerable and unused."""
    repo = Repo()
    made = {}
    for age in (50, 40, 30, 20, 10):
        tags = [f"sha-{age}", f"deployed-at-{age}"]
        if retained_newest and age == 10:
            tags.append("pinned")
        made[age] = vulnerable_index(repo, f"deploy-{age}", tags=tags, pushed=age)
    made["repo"] = repo
    return made


def test_rollback_count_keeps_the_newest():
    made = rollback_repo()
    summary = made["repo"].run(
        deletions=deletes(made[50]) + deletes(made[40]) + deletes(made[30]),
        rollback_candidate_retain_count=2,
    )
    assert summary["protected"]["rollback_candidate"] == 2
    assert summary["deleted"] == 3


def test_a_retained_image_takes_a_rollback_place():
    # As the lifecycle counts it: the retained image is among the newest two, so only one other place is left.
    made = rollback_repo(retained_newest=True)
    summary = made["repo"].run(
        deletions=deletes(made[50]) + deletes(made[40]) + deletes(made[30]),
        rollback_candidate_retain_count=2,
        retain_tags=frozenset({"pinned"}),
    )
    assert summary["protected"]["retained_tag"] == 1
    assert summary["protected"]["rollback_candidate"] == 2
    assert summary["deleted"] == 3


def test_rollback_days_keep_those_pushed_within():
    made = rollback_repo()
    summary = made["repo"].run(
        deletions=deletes(made[50]) + deletes(made[40]),
        rollback_candidate_retain_days=35,
    )
    assert summary["protected"]["rollback_candidate"] == 3


def test_rollback_count_and_days_keep_what_either_keeps():
    made = rollback_repo()
    summary = made["repo"].run(
        deletions=deletes(made[50]),
        rollback_candidate_retain_count=2,
        rollback_candidate_retain_days=45,
    )
    assert summary["protected"]["rollback_candidate"] == 4


def test_rollback_count_and_days_null_protect_none():
    made = rollback_repo()
    summary = made["repo"].run(
        deletions=[d for age in (50, 40, 30, 20, 10) for d in deletes(made[age])]
    )
    assert summary["protected"]["rollback_candidate"] == 0


def test_rollback_protection_off_protects_none():
    made = rollback_repo()
    summary = made["repo"].run(
        deletions=[d for age in (50, 40, 30, 20, 10) for d in deletes(made[age])],
        rollback_candidate_retain_count=2,
        rollback_candidate_retain_days=45,
        protect_rollback_candidates=False,
    )
    assert summary["protected"]["rollback_candidate"] == 0
    assert summary["deleted"] == 5


def test_rollback_count_ignores_other_prefixes_and_archived_images():
    repo = Repo()
    newest_archived = vulnerable_index(
        repo, "archived", tags=["deployed-at-a"], pushed=5, status="ARCHIVED"
    )
    other_prefix = vulnerable_index(repo, "other", tags=["v-deployed-at-b"], pushed=8)
    older = vulnerable_index(repo, "older", tags=["deployed-at-c"], pushed=20)
    summary = repo.run(
        deletions=deletes(other_prefix), rollback_candidate_retain_count=1
    )
    # The archived image is kept as not ACTIVE; it takes no place, so the place goes to the older deployed image.
    assert summary["protected"] == dict.fromkeys(selection.REASONS, 0) | {
        "not_active": 1,
        "recent": 1,
        "rollback_candidate": 1,
    }
    assert newest_archived and older


def test_rollback_count_keeps_ties_at_the_edge():
    repo = Repo()
    made = [
        vulnerable_index(repo, f"tie-{n}", tags=[f"deployed-at-{n}"], pushed=20)
        for n in range(3)
    ]
    summary = repo.run(rollback_candidate_retain_count=1)
    assert summary["protected"]["rollback_candidate"] == 3
    assert made


# --- Fail closed ---


@pytest.mark.parametrize("in_use_count, last_in_use", [(0, None), (None, 30)])
def test_coverage_with_one_in_use_field_keeps_the_image(in_use_count, last_in_use):
    # Some of Inspector's in-use data is judged as Inspector's, not as none: ECR's pull record doesn't make up for
    # what it leaves out, though the image was never pulled.
    repo = Repo()
    made = repo.index("old", tags=["abc"])
    repo.vulnerable(made["platform"])
    repo.covered(made["platform"], in_use_count=in_use_count, last_in_use=last_in_use)
    summary = repo.run()
    assert summary["protected"]["in_use_unknown"] == 1
    assert summary["judged_never_pulled"] == 0


def test_in_use_data_on_a_finding_alone_keeps_the_image():
    repo = Repo()
    made = repo.index("old", tags=["abc"])
    repo.vulnerable(made["platform"], in_use_count=0, last_in_use=30)
    summary = repo.run()
    assert summary["protected"]["in_use_unknown"] == 1
    assert summary["judged_never_pulled"] == 0


def multi_platform(repo: Repo, arm_pulled: Optional[float] = None) -> List[str]:
    """
    An index of two platform images. Inspector reports the amd64 one vulnerable and says it isn't in use; it gives
    nothing on the arm64 one.

    :return: The digests of the index, the amd64 image and the arm64 image.
    """
    arm = repo.manifest("multi/arm64", pulled=arm_pulled)
    amd = repo.manifest("multi/amd64")
    index = repo.manifest("multi", tags=["abc"], media_type=OCI_INDEX, artifact=None)
    repo.manifests[index] = json.dumps(
        {"manifests": [{"digest": amd}, {"digest": arm}]}
    )
    repo.vulnerable(amd)
    repo.unused(amd)
    return [index, amd, arm]


def test_every_platform_image_needs_its_use_judged():
    # A task pulled the arm64 image a month ago and, with another account allowed to pull, may still run it.
    repo = Repo()
    multi_platform(repo, arm_pulled=30)
    repo.allow(pull_statement({"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:root"}))
    assert repo.run()["protected"]["in_use_unknown"] == 1


def test_platform_images_judged_by_inspector_and_by_ecr_pull_record(caplog):
    repo = Repo()
    index, amd, arm = multi_platform(repo)
    with caplog.at_level("INFO"):
        summary = repo.run(deletions=[[index], [amd, arm]], recheck=[amd, arm])
    assert summary["deleted"] == 1
    (line,) = image_lines(caplog)
    assert line["use_judged_by"] == "ecr_pull_record"
    assert line["never_pulled"] is True


# --- Without Inspector's in-use data: ECR's pull record ---

# What Inspector gives for every image in InfraHouse's accounts: no coverage record, or one without inUseCount and
# lastInUseAt. The latter is also what a record looks like to a botocore whose model lacks the fields.
NO_IN_USE_DATA = ["no-coverage-record", "record-without-in-use-data"]


def without_in_use_data(
    repo: Repo, name: str, coverage: str, **kwargs: Any
) -> Dict[str, str]:
    """An index whose platform image Inspector reports vulnerable, and gives no in-use data on."""
    made = repo.index(name, **kwargs)
    platform = made.get("platform") or kwargs["platforms"][0]
    repo.vulnerable(platform)
    if coverage == "record-without-in-use-data":
        repo.covered(platform, in_use_count=None, last_in_use=None)
    return made


@pytest.mark.parametrize("coverage", NO_IN_USE_DATA)
def test_never_pulled_is_not_in_use(coverage, caplog):
    repo = Repo()
    made = without_in_use_data(repo, "old", coverage, tags=["abc"])
    with caplog.at_level("INFO"):
        summary = repo.run(deletions=deletes(made), recheck=[made["platform"]])
    assert summary["deleted"] == 1
    assert summary["protected"] == dict.fromkeys(selection.REASONS, 0)
    assert summary["judged_never_pulled"] == 1
    (line,) = image_lines(caplog)
    assert line["action"] == "deleted"
    assert line["use_judged_by"] == "ecr_pull_record"
    assert line["never_pulled"] is True
    assert line["last_pulled_at"] is None


@pytest.mark.parametrize("coverage", NO_IN_USE_DATA)
def test_pulled_within_the_soak_is_in_use(coverage, caplog):
    repo = Repo()
    without_in_use_data(repo, "running", coverage, tags=["abc"], platform_pulled=1)
    with caplog.at_level("INFO"):
        summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 1
    assert summary["protected"]["in_use_unknown"] == 0
    assert summary["judged_never_pulled"] == 0
    (line,) = image_lines(caplog)
    assert line["action"] == "kept"
    assert line["reasons"] == ["in_use"]
    assert line["use_judged_by"] == "ecr_pull_record"
    assert line["never_pulled"] is False


@pytest.mark.parametrize("coverage", NO_IN_USE_DATA)
def test_pulled_before_the_soak_with_a_complete_view_is_deleted(coverage, caplog):
    # Pulled weeks ago, and nothing runs it now: no ECS task or deployment, no Lambda version, and no other account
    # may pull it.
    repo = Repo()
    made = without_in_use_data(
        repo, "old", coverage, tags=["abc"], pulled=30, platform_pulled=30
    )
    repo.allow(LAMBDA_STATEMENT)
    with caplog.at_level("INFO"):
        summary = repo.run(deletions=deletes(made), recheck=[made["platform"]])
    assert summary["deleted"] == 1
    assert summary["protected"] == dict.fromkeys(selection.REASONS, 0)
    assert summary["judged_never_pulled"] == 0
    assert summary["view"]["complete"] is True
    assert summary["view"]["incomplete_because"] == []
    (line,) = image_lines(caplog)
    assert line["action"] == "deleted"
    assert line["use_judged_by"] == "ecr_pull_record"
    assert line["never_pulled"] is False
    assert line["last_pulled_at"] == days_ago(30).isoformat()
    assert line["in_use_by"] == []


# Repository policies that let someone outside the account pull, and what the summary says of each.
INCOMPLETE_VIEWS = {
    "another-account": (
        [pull_statement({"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:root"})],
        f"repository policy allows account {OTHER_ACCOUNT}",
    ),
    "star": ([pull_statement("*")], "repository policy allows *"),
    "organization": (
        [
            pull_statement(
                {"AWS": "*"},
                Condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
            )
        ],
        "repository policy allows an organization (aws:PrincipalOrgID in statement 'Pull')",
    ),
}


@pytest.mark.parametrize("view", INCOMPLETE_VIEWS)
@pytest.mark.parametrize("coverage", NO_IN_USE_DATA)
def test_pulled_before_the_soak_with_an_incomplete_view_is_unknown(
    coverage, view, caplog
):
    # Another account may run it, and the job can't see what runs there: a long-running task that pulled it weeks
    # ago may still run it.
    repo = Repo()
    without_in_use_data(
        repo, "long-running", coverage, tags=["abc"], pulled=30, platform_pulled=30
    )
    statements, why = INCOMPLETE_VIEWS[view]
    repo.allow(LAMBDA_STATEMENT, *statements)
    with caplog.at_level("INFO"):
        summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 0
    assert summary["protected"]["in_use_unknown"] == 1
    assert summary["judged_never_pulled"] == 0
    assert summary["view"]["complete"] is False
    assert why in summary["view"]["incomplete_because"]
    (line,) = image_lines(caplog)
    assert line["action"] == "kept"
    assert line["reasons"] == ["in_use_unknown"]
    assert line["use_judged_by"] == "unknown"
    assert line["never_pulled"] is False


@pytest.mark.parametrize("view", INCOMPLETE_VIEWS)
def test_never_pulled_is_deleted_with_an_incomplete_view_too(view):
    # Never pulled, so never run, here or in another account: a pull from another account is recorded here too.
    repo = Repo()
    made = never_pulled_index(repo, "old", tags=["abc"])
    repo.allow(*INCOMPLETE_VIEWS[view][0])
    summary = repo.run(deletions=deletes(made), recheck=[made["platform"]])
    assert summary["deleted"] == 1
    assert summary["view"]["complete"] is False


def test_an_index_pulled_recently_whose_platform_image_was_never_pulled_is_not_in_use():
    # The job's own BatchGetImage of the index each run records a pull of the index, and of nothing else.
    repo = Repo()
    made = without_in_use_data(
        repo, "read", "no-coverage-record", tags=["abc"], pulled=0.1
    )
    summary = repo.run(deletions=deletes(made), recheck=[made["platform"]])
    assert summary["deleted"] == 1
    assert summary["judged_never_pulled"] == 1


@pytest.mark.parametrize(
    "pulled, reason",
    [(1, "in_use"), (30, "in_use_unknown")],
    ids=["within-the-soak", "before-the-soak"],
)
def test_indexes_sharing_a_platform_image_one_of_them_pulled(pulled, reason):
    # A pull through the first index records the shared platform image's pull: one record, which counts for both.
    repo = Repo()
    repo.allow(*INCOMPLETE_VIEWS["another-account"][0])
    first = without_in_use_data(
        repo,
        "first",
        "no-coverage-record",
        tags=["a"],
        pushed=40,
        pulled=pulled,
        platform_pulled=pulled,
    )
    repo.index("second", tags=["b"], pushed=30, platforms=[first["platform"]])
    summary = repo.run()
    assert summary["vulnerable"] == 2
    assert summary["deleted"] == 0
    assert summary["judged_never_pulled"] == 0
    assert summary["protected"][reason] == 2


@pytest.mark.parametrize("coverage", ["no-coverage-record", "unused"])
def test_an_attestations_pull_changes_nothing(coverage):
    # A scanner may fetch an attestation alone; a pull that fetches it fetches the platform image too. Its pull
    # protects nothing, by ECR's pull record or by Inspector's data.
    repo = Repo()
    made = repo.index("old", tags=["abc"], attestation_pulled=0.1)
    repo.vulnerable(made["platform"])
    if coverage == "unused":
        repo.unused(made["platform"])
    summary = repo.run(deletions=deletes(made), recheck=[made["platform"]])
    assert summary["deleted"] == 1
    assert summary["protected"]["in_use"] == 0
    assert summary["judged_never_pulled"] == int(coverage == "no-coverage-record")


@pytest.mark.parametrize(
    "offset, deleted",
    [(timedelta(seconds=-1), False), (timedelta(seconds=1), True)],
    ids=["a-second-before", "a-second-after"],
)
def test_an_image_pushed_before_ecr_recorded_pulls_is_unknown(offset, deleted):
    # Pushed before AWS released ECR's pull time, it may have been pulled without a record.
    repo = Repo()
    pushed = (NOW - selection.PULL_RECORD_START - offset) / timedelta(days=1)
    made = without_in_use_data(
        repo, "ancient", "no-coverage-record", tags=["abc"], pushed=pushed
    )
    summary = repo.run(
        deletions=deletes(made) if deleted else [],
        recheck=[made["platform"]] if deleted else [],
    )
    assert summary["deleted"] == int(deleted)
    assert summary["protected"]["in_use_unknown"] == int(not deleted)
    assert summary["judged_never_pulled"] == int(deleted)


# --- Reading again before deleting ---


def never_pulled_index(repo: Repo, name: str, **kwargs: Any) -> Dict[str, str]:
    """An index Inspector reports vulnerable and gives no in-use data on, which the first read shows never pulled."""
    return without_in_use_data(repo, name, "no-coverage-record", **kwargs)


@pytest.mark.parametrize("read", [0, 2], ids=["first-read", "last-read"])
def test_a_pull_one_read_again_shows_keeps_the_image(read, caplog):
    # For a few minutes after a first pull, ECR's answers flap: one read shows the pull, the next doesn't.
    repo = Repo()
    made = never_pulled_index(repo, "deployed", tags=["abc"])
    pulls: List[Dict[str, float]] = [{}, {}, {}]
    pulls[read] = {made["platform"]: 0.001}
    with caplog.at_level("INFO"):
        summary = repo.run(recheck=[made["platform"]], recheck_pulls=pulls)
    assert summary["deleted"] == 0
    assert summary["pulled_on_recheck"] == 1
    assert summary["protected"]["in_use"] == 1
    assert summary["judged_never_pulled"] == 0
    (recheck,) = [line for line in logged(caplog) if line.get("action") == "recheck"]
    assert recheck["read_again"] == [made["platform"]]
    assert list(recheck["pulled"]) == [made["platform"]]
    assert recheck["dropped"] == [made["index"]]
    assert summary["dropped_on_recheck"] == 1


@pytest.mark.parametrize("view", ["complete", "incomplete"])
def test_an_old_pull_a_read_again_shows_is_judged_as_one(view):
    # Judged as an image pulled before the soak: deleted with a complete view, kept as unknown without.
    repo = Repo()
    made = never_pulled_index(repo, "old", tags=["abc"])
    if view == "incomplete":
        repo.allow(*INCOMPLETE_VIEWS["another-account"][0])
    summary = repo.run(
        deletions=deletes(made) if view == "complete" else [],
        recheck=[made["platform"]],
        recheck_pulls=[{made["platform"]: 30}],
    )
    assert summary["deleted"] == int(view == "complete")
    assert summary["protected"]["in_use_unknown"] == int(view == "incomplete")
    assert summary["pulled_on_recheck"] == 1


def test_a_newer_pull_a_read_again_shows_keeps_an_image_pulled_before_the_soak(
    caplog,
):
    repo = Repo()
    made = without_in_use_data(
        repo, "old", "no-coverage-record", tags=["abc"], platform_pulled=30
    )
    with caplog.at_level("INFO"):
        summary = repo.run(
            recheck=[made["platform"]], recheck_pulls=[{}, {made["platform"]: 0.001}]
        )
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 1
    assert summary["pulled_on_recheck"] == 1
    assert summary["dropped_on_recheck"] == 1


def test_the_same_old_pull_on_a_read_again_is_nothing_new(caplog):
    repo = Repo()
    made = without_in_use_data(
        repo, "old", "no-coverage-record", tags=["abc"], platform_pulled=30
    )
    with caplog.at_level("INFO"):
        summary = repo.run(deletions=deletes(made), recheck=[made["platform"]])
    assert summary["deleted"] == 1
    assert summary["pulled_on_recheck"] == 0
    (recheck,) = [line for line in logged(caplog) if line.get("action") == "recheck"]
    assert recheck["pulled"] == {}
    assert recheck["dropped"] == []


def test_the_reads_again_cover_the_candidates_the_cap_leaves():
    # A pull found on the oldest candidate frees its place under the cap for the next, which was read again too.
    repo = Repo()
    older = never_pulled_index(repo, "older", tags=["a"], pushed=40)
    newer = never_pulled_index(repo, "newer", tags=["b"], pushed=30)
    summary = repo.run(
        deletions=deletes(newer),
        recheck=[older["platform"], newer["platform"]],
        recheck_pulls=[{older["platform"]: 0.001}],
        max_deletions=1,
    )
    assert summary["deleted"] == 1
    assert summary["left_by_cap"] == 0
    assert summary["pulled_on_recheck"] == 1


@pytest.mark.parametrize("pulled", [False, True], ids=["never-pulled", "pulled"])
def test_a_shared_platform_image_is_read_again_once(pulled):
    repo = Repo()
    first = never_pulled_index(repo, "first", tags=["a"], pushed=40)
    second = repo.index("second", tags=["b"], pushed=30, platforms=[first["platform"]])
    both = [
        [first["index"]],
        [first["attestation"]],
        [second["index"]],
        [first["platform"], second["attestation"]],
    ]
    summary = repo.run(
        deletions=[] if pulled else both,
        recheck=[first["platform"]],
        recheck_pulls=[{first["platform"]: 0.001}] if pulled else [],
    )
    assert summary["deleted"] == (0 if pulled else 2)
    assert summary["protected"]["in_use"] == (2 if pulled else 0)


def test_a_dry_run_reads_again_too():
    repo = Repo()
    made = never_pulled_index(repo, "old", tags=["abc"])
    summary = repo.run(recheck=[made["platform"]], dry_run=True)
    assert summary["would_delete"] == 1
    assert summary["deleted"] == 0


def test_a_read_again_that_fails_deletes_nothing():
    # No delete is stubbed, so a delete would fail the test with another error than the ClientError.
    repo = Repo()
    never_pulled_index(repo, "old", tags=["abc"])
    with Stubs() as stubs:
        repo.stub_reads(stubs)
        stubs.ecr.add_client_error(
            "describe_images",
            service_error_code="ThrottlingException",
            http_status_code=400,
        )
        with pytest.raises(ClientError, match="ThrottlingException"):
            cleanup.run(settings(), stubs.clients, NOW)


def test_an_image_a_read_again_does_not_return_fails_the_run():
    repo = Repo()
    made = never_pulled_index(repo, "old", tags=["abc"])
    with Stubs() as stubs:
        repo.stub_reads(stubs)
        stubs.ecr.add_response(
            "describe_images",
            {"imageDetails": []},
            {
                "registryId": REGISTRY,
                "repositoryName": REPOSITORY,
                "imageIds": [{"imageDigest": made["platform"]}],
            },
        )
        with pytest.raises(cleanup.CleanupError, match="didn't return the images"):
            cleanup.run(settings(), stubs.clients, NOW)


def test_the_reads_again_span_two_minutes(monkeypatch):
    # The schedule chosen by replaying it against the reads that measured ECR's flapping answers.
    reads, interval = REAL_RECHECK
    assert (reads, interval) == (13, 10.0)
    monkeypatch.setattr(cleanup, "RECHECK_READS", reads)
    monkeypatch.setattr(cleanup, "RECHECK_INTERVAL", interval)
    slept: List[float] = []
    monkeypatch.setattr(cleanup.time, "sleep", slept.append)
    repo = Repo()
    made = never_pulled_index(repo, "old", tags=["abc"])
    assert repo.run(deletions=deletes(made), recheck=[made["platform"]])["deleted"] == 1
    assert slept == [10.0] * 12


# --- Fail closed: errors ---


@pytest.mark.parametrize(
    "operation", ["describe_images", "list_findings", "list_coverage"]
)
def test_an_error_mid_pagination_deletes_nothing(operation):
    # The first page holds everything a deletion needs; the second fails, as throttling that outlasts the retries
    # does. No delete is stubbed, so a delete would fail the test with another error than the ClientError.
    repo = Repo()
    vulnerable_index(repo, "old", tags=["abc"])
    with Stubs() as stubs:
        if operation == "describe_images":
            stubs.ecr.add_response(
                operation, {"imageDetails": repo.details, "nextToken": "page-2"}
            )
            stubs.ecr.add_client_error(
                operation,
                service_error_code="ThrottlingException",
                http_status_code=400,
            )
        else:
            repo.stub_ecr_reads(stubs.ecr)
            pages = {
                "list_findings": {"findings": repo.findings},
                "list_coverage": {"coveredResources": repo.coverage},
            }
            if operation == "list_coverage":
                stubs.inspector.add_response("list_findings", pages["list_findings"])
            stubs.inspector.add_response(
                operation, dict(pages[operation], nextToken="page-2")
            )
            stubs.inspector.add_client_error(
                operation,
                service_error_code="ThrottlingException",
                http_status_code=400,
            )
        with pytest.raises(ClientError, match="ThrottlingException"):
            cleanup.run(settings(), stubs.clients, NOW)


def test_a_manifest_ecr_does_not_return_deletes_nothing():
    repo = Repo()
    made = vulnerable_index(repo, "old", tags=["abc"])
    with Stubs() as stubs:
        stubs.ecr.add_response("describe_images", {"imageDetails": repo.details})
        stubs.ecr.add_response(
            "batch_get_image",
            {
                "images": [],
                "failures": [
                    {
                        "imageId": {"imageDigest": made["index"]},
                        "failureCode": "ImageNotFound",
                        "failureReason": "gone",
                    }
                ],
            },
        )
        with pytest.raises(cleanup.CleanupError):
            cleanup.run(settings(), stubs.clients, NOW)


def test_a_refused_deletion_fails_the_run():
    repo = Repo()
    made = vulnerable_index(repo, "old", tags=["abc"])
    with pytest.raises(cleanup.CleanupError, match="ImageReferencedByManifestList"):
        repo.run(
            deletions=deletes(made)[:2],
            refused={made["platform"]: "ImageReferencedByManifestList"},
        )


def logged(caplog: pytest.LogCaptureFixture) -> List[Dict[str, Any]]:
    """The run's JSON log lines."""
    return [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.getMessage().startswith("{")
    ]


def image_lines(caplog: pytest.LogCaptureFixture) -> List[Dict[str, Any]]:
    """The run's JSON log lines about an image: neither the recheck's nor the summary."""
    return [
        line for line in logged(caplog) if line.get("action") not in (None, "recheck")
    ]


def test_a_refused_child_logs_the_index_ecr_deleted(caplog):
    repo = Repo()
    made = vulnerable_index(repo, "old", tags=["abc"])
    with caplog.at_level("INFO"), pytest.raises(
        cleanup.DeletionError, match="ImageReferencedByManifestList"
    ):
        repo.run(
            deletions=deletes(made),
            refused={made["platform"]: "ImageReferencedByManifestList"},
        )
    (line,) = image_lines(caplog)
    assert line["action"] == "delete_failed"
    assert line["digests"] == [made["index"], made["platform"], made["attestation"]]
    # ECR deleted the index, and the attestation in the batch it refused the platform image of.
    assert line["deleted_digests"] == [made["index"], made["attestation"]]
    assert "ImageReferencedByManifestList" in line["error"]
    assert line["tags"] == ["abc"]


def test_a_failed_call_logs_what_ecr_deleted_before(caplog):
    repo = Repo()
    first = vulnerable_index(repo, "first", tags=["first"], pushed=40)
    second = vulnerable_index(repo, "second", tags=["second"])
    with caplog.at_level("INFO"), pytest.raises(
        cleanup.DeletionError, match="ThrottlingException"
    ):
        repo.run(deletions=deletes(first) + deletes(second), throttled=3)
    deleted, failed = image_lines(caplog)
    assert deleted["action"] == "deleted"
    assert deleted["tags"] == ["first"]
    assert failed["action"] == "delete_failed"
    assert failed["tags"] == ["second"]
    assert failed["deleted_digests"] == [second["index"]]


def test_an_image_already_gone_counts_as_deleted():
    repo = Repo()
    made = vulnerable_index(repo, "old", tags=["abc"])
    assert (
        repo.run(
            deletions=deletes(made), refused={made["attestation"]: "ImageNotFound"}
        )["deleted"]
        == 1
    )


def test_an_old_botocore_model_fails_the_run():
    class Shape:
        members = {"tags": None, "imagePulledAt": None}

    class Model:
        @staticmethod
        def shape_for(name):
            return Shape

    class Meta:
        service_model = Model

    class OldInspector:
        meta = Meta

    with pytest.raises(cleanup.CleanupError, match="inUseCount"):
        cleanup.check_models(replace(make_clients(), inspector=OldInspector))


def test_an_ecr_model_without_the_pull_time_fails_the_run_before_any_call():
    # A botocore that drops lastRecordedPullTime would make every image without Inspector's in-use data look never
    # pulled.
    real = make_clients()
    model = real.ecr.meta.service_model

    class Shape:
        members = {
            name: None
            for name in model.shape_for("ImageDetail").members
            if name != "lastRecordedPullTime"
        }

    class Model:
        @staticmethod
        def shape_for(name):
            return Shape if name == "ImageDetail" else model.shape_for(name)

    class Meta:
        service_model = Model

    class OldEcr:
        meta = Meta

        def __getattr__(self, name):
            raise AssertionError(f"The run called ECR's {name}.")

    # The other Stubbers have no answers: a call to Inspector, ECS or Lambda fails the test too.
    with Stubs() as stubs, pytest.raises(
        cleanup.CleanupError, match="lastRecordedPullTime"
    ):
        cleanup.run(settings(), replace(stubs.clients, ecr=OldEcr()), NOW)


@pytest.mark.parametrize(
    "service, shape, field",
    [
        ("ecs", "Container", "imageDigest"),
        ("ecs", "Service", "taskSets"),
        ("lambda", "FunctionCodeLocation", "ResolvedImageUri"),
    ],
)
def test_a_model_without_what_ecs_or_lambda_run_fails_the_run(service, shape, field):
    # Without these, what ECS and Lambda run would go unseen, and the view look complete.
    real = make_clients()
    client = real.ecs if service == "ecs" else real.lambda_
    model = client.meta.service_model

    class Shape:
        members = {
            name: None for name in model.shape_for(shape).members if name != field
        }

    class Model:
        @staticmethod
        def shape_for(name):
            return Shape if name == shape else model.shape_for(name)

    class Meta:
        service_model = Model

    class Old:
        meta = Meta

    old = replace(real, **{"ecs" if service == "ecs" else "lambda_": Old})
    with pytest.raises(cleanup.CleanupError, match=field):
        cleanup.check_models(old)


def test_the_installed_botocore_models_the_fields():
    cleanup.check_models(make_clients())


# --- Indexes that share manifests ---


def test_a_manifest_a_kept_index_references_is_never_deleted():
    repo = Repo()
    kept = repo.index("kept", tags=["migrator"])
    repo.vulnerable(kept["platform"])
    repo.unused(kept["platform"])
    other = repo.index("other", tags=["abc"], platforms=[kept["platform"]])
    summary = repo.run(
        deletions=[[other["index"]], [other["attestation"]]],
        retain_tags=frozenset({"migrator"}),
    )
    assert summary["deleted"] == 1
    assert summary["protected"]["retained_tag"] == 1


def test_a_shared_manifest_goes_with_the_last_index_that_references_it():
    repo = Repo()
    first = vulnerable_index(repo, "first", tags=["a"], pushed=40)
    second = repo.index("second", tags=["b"], pushed=30, platforms=[first["platform"]])
    summary = repo.run(
        deletions=[
            [first["index"]],
            [first["attestation"]],
            [second["index"]],
            [first["platform"], second["attestation"]],
        ]
    )
    assert summary["deleted"] == 2


def test_a_shared_manifest_stays_while_the_cap_leaves_its_other_index():
    repo = Repo()
    first = vulnerable_index(repo, "first", tags=["a"], pushed=40)
    second = repo.index("second", tags=["b"], pushed=30, platforms=[first["platform"]])
    summary = repo.run(
        deletions=[[first["index"]], [first["attestation"]]], max_deletions=1
    )
    assert summary["deleted"] == 1
    assert summary["left_by_cap"] == 1
    assert second


def test_a_protected_index_protects_the_index_that_shares_its_running_image():
    repo = Repo()
    running = repo.index("running", tags=["prod"])
    repo.vulnerable(running["platform"])
    repo.covered(running["platform"], in_use_count=1, last_in_use=0)
    repo.index("alias", tags=["alias"], platforms=[running["platform"]])
    summary = repo.run()
    assert summary["vulnerable"] == 2
    assert summary["protected"]["in_use"] == 2


# --- The cap ---


def test_the_cap_counts_an_index_with_its_manifests_as_one_and_takes_the_oldest_first():
    repo = Repo()
    made = {
        age: vulnerable_index(repo, f"img-{age}", tags=[f"t{age}"], pushed=age)
        for age in (20, 40, 30)
    }
    summary = repo.run(deletions=deletes(made[40]) + deletes(made[30]), max_deletions=2)
    assert summary["deleted"] == 2
    assert summary["left_by_cap"] == 1
    assert summary["candidates"] == 3


# --- Dry run ---


def test_dry_run_calls_no_delete(caplog):
    repo = Repo()
    vulnerable_index(repo, "old", tags=["abc"])
    vulnerable_index(repo, "older", tags=["def"], pushed=40)
    with caplog.at_level("INFO"):
        summary = repo.run(deletions=[], dry_run=True, max_deletions=1)
    assert summary["deleted"] == 0
    assert summary["would_delete"] == 1
    assert summary["left_by_cap"] == 1
    lines = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.getMessage().startswith("{")
    ]
    assert [line["action"] for line in lines if "action" in line] == [
        "recheck",
        "would_delete",
        "left_by_cap",
    ]


# --- Logs ---


def test_one_line_per_deleted_image_and_one_summary(caplog):
    repo = Repo()
    made = vulnerable_index(repo, "old", tags=["abc1234"], platform_pulled=10)
    repo.vulnerable(
        made["platform"], vulnerability="CVE-2026-0002", severity="CRITICAL"
    )
    with caplog.at_level("INFO"):
        repo.run(deletions=deletes(made))
    lines = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.getMessage().startswith("{")
    ]
    assert len(lines) == 3
    recheck, line, summary = lines
    assert recheck["action"] == "recheck"
    assert line["action"] == "deleted"
    assert line["digests"] == [made["index"], made["platform"], made["attestation"]]
    assert line["tags"] == ["abc1234"]
    assert line["vulnerabilities"] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert line["pushed_at"] == days_ago(30).isoformat()
    assert line["last_in_use_at"] == days_ago(30).isoformat()
    assert line["last_pulled_at"] == days_ago(10).isoformat()
    assert line["use_judged_by"] == "inspector"
    assert line["never_pulled"] is False
    assert summary["summary"]["deleted"] == 1
    assert summary["summary"]["judged_never_pulled"] == 0


# --- Settings ---


def environment(**overrides: str) -> Dict[str, str]:
    values = {
        "REPOSITORY_NAME": REPOSITORY,
        "REGISTRY_ID": REGISTRY,
        "REPOSITORY_REGION": REGION,
        "DRY_RUN": "true",
        "MIN_SEVERITY": "HIGH",
        "MIN_AGE_DAYS": "7",
        "SOAK_DAYS": "2",
        "MAX_DELETIONS": "10",
        "RETAIN_TAGS": '["migrator"]',
        "PROTECT_ROLLBACK_CANDIDATES": "true",
        "ROLLBACK_CANDIDATE_TAG_PREFIX": "deployed-at-",
        "ROLLBACK_CANDIDATE_RETAIN_COUNT": "3",
        "ROLLBACK_CANDIDATE_RETAIN_DAYS": "null",
    }
    values.update(overrides)
    return values


def test_settings_from_the_environment():
    parsed = selection.Settings.from_environment(environment())
    assert parsed.dry_run is True
    assert parsed.severities == ["HIGH", "CRITICAL"]
    assert parsed.retain_tags == frozenset({"migrator"})
    assert parsed.rollback_candidate_retain_count == 3
    assert parsed.rollback_candidate_retain_days is None
    assert parsed.min_age == timedelta(days=7)


@pytest.mark.parametrize(
    "overrides",
    [
        {"DRY_RUN": "False"},
        {"DRY_RUN": ""},
        {"MIN_SEVERITY": "INFORMATIONAL"},
        {"MAX_DELETIONS": "0"},
        {"SOAK_DAYS": "-1"},
        {"RETAIN_TAGS": "migrator"},
        {"ROLLBACK_CANDIDATE_RETAIN_COUNT": '"3"'},
        {"REGISTRY_ID": "12345"},
        {"REPOSITORY_REGION": "Oregon"},
    ],
)
def test_wrong_settings_fail_the_run(overrides):
    with pytest.raises(selection.SettingsError):
        selection.Settings.from_environment(environment(**overrides))


def test_a_missing_setting_fails_the_run():
    values = environment()
    del values["DRY_RUN"]
    with pytest.raises(selection.SettingsError, match="DRY_RUN"):
        selection.Settings.from_environment(values)


def test_the_handler_reads_in_the_repository_region(monkeypatch):
    seen = {}

    def run(parsed, clients, now):
        seen.update(
            ecr=clients.ecr.meta.region_name,
            inspector=clients.inspector.meta.region_name,
            ecs=clients.ecs.meta.region_name,
            lambda_=clients.lambda_.meta.region_name,
            dry_run=parsed.dry_run,
        )
        return {}

    monkeypatch.setattr(cleanup, "run", run)
    for name, value in environment(REPOSITORY_REGION="eu-central-1").items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    cleanup.lambda_handler({}, None)
    assert seen == {
        "ecr": "eu-central-1",
        "inspector": "eu-central-1",
        "ecs": "eu-central-1",
        "lambda_": "eu-central-1",
        "dry_run": True,
    }


def test_the_findings_filter():
    inspector = make_clients().inspector
    with Stubber(inspector) as stub:
        stub.add_response(
            "list_findings",
            {"findings": []},
            {
                "filterCriteria": {
                    "awsAccountId": [{"comparison": "EQUALS", "value": REGISTRY}],
                    "ecrImageRepositoryName": [
                        {"comparison": "EQUALS", "value": REPOSITORY}
                    ],
                    "resourceType": [
                        {"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}
                    ],
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                    "severity": [
                        {"comparison": "EQUALS", "value": "MEDIUM"},
                        {"comparison": "EQUALS", "value": "HIGH"},
                        {"comparison": "EQUALS", "value": "CRITICAL"},
                    ],
                    "fixAvailable": [{"comparison": "EQUALS", "value": "YES"}],
                },
                "maxResults": 100,
            },
        )
        assert cleanup.read_findings(settings(min_severity="MEDIUM"), inspector) == []


# --- What ECS and Lambda run ---


def pulled_long_ago(repo: Repo, name: str, **kwargs: Any) -> Dict[str, str]:
    """
    An index Inspector reports vulnerable and gives no in-use data on, whose platform image ECR last recorded a pull
    of 30 days ago: with a complete view and nothing running it, it is deleted.
    """
    return without_in_use_data(
        repo, name, "no-coverage-record", pulled=30, platform_pulled=30, **kwargs
    )


def kept_line(caplog: pytest.LogCaptureFixture) -> Dict[str, Any]:
    (line,) = image_lines(caplog)
    assert line["action"] == "kept"
    return line


@pytest.mark.parametrize("member", ["index", "platform"])
def test_a_running_task_keeps_the_image_it_runs(member, caplog):
    # ECS reports the index's digest in production; whichever digest of the unit it gives, the whole unit is kept.
    # The task names a tag that has since moved: only the digest matches.
    repo = Repo()
    made = pulled_long_ago(repo, "running", tags=["abc"])
    repo.task(uri("moved-on"), made[member])
    with caplog.at_level("INFO"):
        summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 1
    assert summary["protected"]["in_use_unknown"] == 0
    assert summary["images_in_use_by"]["ecs"] == 1
    line = kept_line(caplog)
    assert line["reasons"] == ["in_use"]
    assert line["use_judged_by"] == "ecs"
    assert line["in_use_by"] == [
        {
            "source": "ecs",
            "via": "running_task",
            "cluster": "prod",
            "service": "api",
            "task_definition": "api:3",
        }
    ]


def test_a_task_outside_a_service_is_named_by_its_arn(caplog):
    repo = Repo()
    made = pulled_long_ago(repo, "migrator", tags=["abc"])
    task = repo.task(None, made["index"], service=None, family="migrator:7")
    with caplog.at_level("INFO"):
        repo.run()
    assert kept_line(caplog)["in_use_by"] == [
        {
            "source": "ecs",
            "via": "running_task",
            "cluster": "prod",
            "task": task["taskArn"],
            "task_definition": "migrator:7",
        }
    ]


def test_a_pending_task_without_a_digest_keeps_the_image_its_tag_names():
    # A container still pending may have no digest yet: it will pull the image the tag names.
    repo = Repo()
    pulled_long_ago(repo, "pending", tags=["abc"])
    repo.task(uri("abc"))
    summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 1


@pytest.mark.parametrize(
    "reference",
    [
        uri("abc", repository="other-repo"),
        uri("abc", account=OTHER_ACCOUNT),
        uri("abc", region="us-east-1"),
        "docker.io/library/test-repo:abc",
        "test-repo:abc",
    ],
    ids=["other-repository", "other-account", "other-region", "docker-hub", "no-host"],
)
def test_a_tag_of_another_repository_keeps_nothing(reference):
    repo = Repo()
    made = pulled_long_ago(repo, "old", tags=["abc"])
    repo.task(reference)
    repo.task_definition("web:1", reference)
    repo.service("web", [("PRIMARY", ecs_arn("task-definition", "web:1"))])
    summary = repo.run(deletions=deletes(made), recheck=[made["platform"]])
    assert summary["deleted"] == 1
    assert summary["images_in_use_by"]["ecs"] == 0


@pytest.mark.parametrize(
    "host",
    [
        f"{REGISTRY}.dkr.ecr-fips.{REGION}.amazonaws.com",
        f"{REGISTRY}.dkr-ecr.{REGION}.on.aws",
        f"{REGISTRY}.DKR.ECR.{REGION.upper()}.AMAZONAWS.COM",
    ],
    ids=["fips", "dual-stack", "upper-case"],
)
def test_a_tag_through_another_endpoint_of_this_repository_keeps_its_image(host):
    repo = Repo()
    pulled_long_ago(repo, "old", tags=["abc"])
    repo.task_definition("web:1", f"{host}/{REPOSITORY}:abc")
    repo.service("web", [("PRIMARY", ecs_arn("task-definition", "web:1"))])
    assert repo.run()["protected"]["in_use"] == 1


@pytest.mark.parametrize(
    "reference, member",
    [
        (uri("abc"), None),
        (uri(image_digest="index"), "index"),
        (uri(image_digest="platform"), "platform"),
        (uri("moved-on", image_digest="index"), "index"),
    ],
    ids=["by-tag", "by-index-digest", "by-platform-digest", "by-tag-and-digest"],
)
def test_a_service_scaled_to_zero_keeps_the_image_its_task_definition_names(
    reference, member, caplog
):
    # No task runs, but the service starts its task definition's image when it scales up.
    repo = Repo()
    made = pulled_long_ago(repo, "deployed", tags=["abc"])
    if member:
        reference = reference.replace(member, made[member])
    repo.task_definition("web:4", reference)
    repo.service("web", [("PRIMARY", ecs_arn("task-definition", "web:4"))], desired=0)
    with caplog.at_level("INFO"):
        summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["view"]["ecs_services"] == 1
    assert summary["view"]["ecs_task_definitions"] == 1
    line = kept_line(caplog)
    assert line["use_judged_by"] == "ecs"
    assert line["in_use_by"] == [
        {
            "source": "ecs",
            "via": "deployment",
            "cluster": "prod",
            "service": "web",
            "task_definition": "web:4",
        }
    ]


@pytest.mark.parametrize(
    "deployments, task_sets, kept",
    [
        ([("PRIMARY", "new"), ("ACTIVE", "old")], [], True),
        ([("PRIMARY", "new"), ("INACTIVE", "old")], [], False),
        ([("PRIMARY", "new")], [("ACTIVE", "old")], True),
        ([("PRIMARY", "new")], [("DRAINING", "old")], False),
    ],
    ids=[
        "mid-deployment",
        "inactive-deployment",
        "blue-green-task-set",
        "draining-task-set",
    ],
)
def test_a_service_keeps_the_images_of_the_deployments_it_may_go_back_to(
    deployments, task_sets, kept
):
    # An ACTIVE deployment is the one being replaced: a rollback goes back to it. An INACTIVE one is done with, and
    # a DRAINING task set's tasks are stopping (running tasks are read on their own).
    repo = Repo()
    old = pulled_long_ago(repo, "old", tags=["old"], pushed=40)
    pulled_long_ago(repo, "new", tags=["new"])
    arns = {
        "old": repo.task_definition("web:1", uri("old")),
        "new": repo.task_definition("web:2", uri("new")),
    }
    repo.service(
        "web",
        [(status, arns[name]) for status, name in deployments],
        task_sets=[(status, arns[name]) for status, name in task_sets],
    )
    summary = repo.run(
        deletions=[] if kept else deletes(old),
        recheck=None if kept else [old["platform"]],
    )
    assert summary["protected"]["in_use"] == (2 if kept else 1)
    assert summary["deleted"] == int(not kept)


def test_a_task_definition_two_services_deploy_is_read_once(caplog):
    repo = Repo()
    pulled_long_ago(repo, "shared", tags=["abc"])
    arn = repo.task_definition("web:1", "public.ecr.aws/nginx:1", uri("abc"))
    repo.service("web", [("PRIMARY", arn)])
    repo.service("web-canary", [("PRIMARY", arn)], cluster="canary")
    with caplog.at_level("INFO"):
        summary = repo.run()
    assert summary["view"]["ecs_clusters"] == 2
    assert summary["view"]["ecs_services"] == 2
    assert summary["view"]["ecs_task_definitions"] == 1
    assert [use["service"] for use in kept_line(caplog)["in_use_by"]] == [
        "web-canary",
        "web",
    ]


def test_every_page_of_ecs_and_every_batch_of_services_is_read():
    # Services are described 10 at a time; the image is named by the last service of the second batch.
    repo = Repo()
    made = pulled_long_ago(repo, "old", tags=["abc"])
    for number in range(11):
        image = uri("abc") if number == 10 else uri("other")
        repo.service(
            f"web-{number:02}",
            [("PRIMARY", repo.task_definition(f"web-{number:02}:1", image))],
        )
    assert repo.run()["protected"]["in_use"] == 1
    assert made


@pytest.mark.parametrize("member", ["index", "platform"])
def test_a_lambda_version_that_is_not_latest_keeps_its_image(member, caplog):
    # A rollback to version 3 runs its image, though $LATEST has moved on.
    repo = Repo()
    old = pulled_long_ago(repo, "old", tags=["v1"], pushed=40)
    new = pulled_long_ago(repo, "new", tags=["v2"])
    repo.function("fn", "$LATEST", resolved=uri(image_digest=new[member]))
    repo.function(
        "fn", "3", resolved=uri(image_digest=old[member]), image_uri=uri("v1")
    )
    repo.function("zip-fn", "$LATEST", package="Zip")
    with caplog.at_level("INFO"):
        summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 2
    assert summary["images_in_use_by"]["lambda"] == 2
    assert summary["view"]["lambda_image_versions"] == 2
    lines = {line["tags"][0]: line for line in image_lines(caplog)}
    assert lines["v1"]["use_judged_by"] == "lambda"
    assert lines["v1"]["in_use_by"] == [
        {
            "source": "lambda",
            "via": "function_version",
            "function": "fn",
            "version": "3",
        }
    ]
    assert lines["v2"]["in_use_by"][0]["version"] == "$LATEST"


def test_an_image_ecs_and_lambda_both_run_names_both(caplog):
    repo = Repo()
    made = pulled_long_ago(repo, "both", tags=["abc"])
    repo.task(None, made["index"])
    repo.function("fn", "1", resolved=uri(image_digest=made["platform"]))
    with caplog.at_level("INFO"):
        summary = repo.run()
    line = kept_line(caplog)
    assert line["use_judged_by"] == "ecs"
    assert [use["source"] for use in line["in_use_by"]] == ["ecs", "lambda"]
    assert summary["images_in_use_by"] == {
        "ecs": 1,
        "lambda": 1,
        "inspector": 0,
        "ecr_pull_record": 0,
    }


def test_what_runs_overrules_inspectors_in_use_data():
    # Inspector says it isn't in use, and hasn't been for 30 days; ECS runs it.
    repo = Repo()
    made = vulnerable_index(repo, "running", tags=["abc"])
    repo.task(None, made["index"])
    summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 1


def test_what_runs_overrules_an_unknown_judgement():
    # Without the whole view the pull record leaves it unknown; ECS runs it, so it is in use, and known to be.
    repo = Repo()
    made = pulled_long_ago(repo, "running", tags=["abc"])
    repo.allow(*INCOMPLETE_VIEWS["star"][0])
    repo.task(None, made["index"])
    summary = repo.run()
    assert summary["protected"]["in_use"] == 1
    assert summary["protected"]["in_use_unknown"] == 0


def test_the_summary_counts_what_each_source_shows_in_use():
    repo = Repo()
    by_ecs = pulled_long_ago(repo, "ecs", tags=["a"])
    by_lambda = pulled_long_ago(repo, "lambda", tags=["b"])
    by_inspector = repo.index("inspector", tags=["c"])
    repo.covered(by_inspector["platform"], in_use_count=1, last_in_use=0)
    without_in_use_data(
        repo, "pulled", "no-coverage-record", tags=["d"], platform_pulled=1
    )
    # Not vulnerable, but in use: it counts too.
    clean = repo.index("clean", tags=["e"])
    repo.task(None, by_ecs["index"])
    repo.task(None, clean["index"], service="worker")
    repo.function("fn", "1", resolved=uri(image_digest=by_lambda["platform"]))
    summary = repo.run()
    assert summary["images_in_use_by"] == {
        "ecs": 2,
        "lambda": 1,
        "inspector": 1,
        "ecr_pull_record": 1,
    }
    assert summary["view"] == {
        "complete": True,
        "incomplete_because": [],
        "ecs_clusters": 1,
        "ecs_running_tasks": 2,
        "ecs_services": 0,
        "ecs_task_definitions": 0,
        "lambda_image_versions": 1,
    }


# --- The repository's policy ---


@pytest.mark.parametrize(
    "statements",
    [
        [],
        [LAMBDA_STATEMENT],
        [pull_statement({"AWS": f"arn:aws:iam::{REGISTRY}:root"})],
        [pull_statement({"AWS": REGISTRY})],
        [pull_statement({"AWS": [f"arn:aws:iam::{REGISTRY}:role/deployer"]})],
        [pull_statement({"AWS": f"arn:aws:sts::{REGISTRY}:assumed-role/ci/x"})],
        [
            dict(
                LAMBDA_STATEMENT,
                Condition={"StringEquals": {"aws:SourceAccount": REGISTRY}},
            )
        ],
        [
            dict(
                LAMBDA_STATEMENT,
                Condition={
                    "ArnLike": {
                        "AWS:SourceArn": [
                            f"arn:aws:lambda:{REGION}:{REGISTRY}:function:a",
                            f"arn:aws:lambda:{REGION}:{REGISTRY}:function:b-*",
                        ]
                    }
                },
            )
        ],
        # Pushing isn't pulling.
        [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["ecr:PutImage", "ecr:InitiateLayerUpload"],
            }
        ],
        # A Deny only takes away.
        [{"Effect": "Deny", "Principal": "*", "Action": "ecr:*"}],
        # A NotAction that leaves out both of a pull's actions.
        [
            {
                "Effect": "Allow",
                "Principal": "*",
                "NotAction": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
            }
        ],
    ],
    ids=[
        "no-statement",
        "lambda-for-this-account",
        "this-account",
        "this-account-id",
        "a-role-here",
        "an-assumed-role-here",
        "lambda-by-source-account",
        "lambda-by-function-arns",
        "push-only",
        "deny",
        "not-action-of-both",
    ],
)
def test_policies_that_let_no_one_outside_the_account_pull(statements):
    assert selection.repository_policy_gaps(policy(*statements), REGISTRY) == []


def test_no_policy_lets_no_one_outside_the_account_pull():
    assert selection.repository_policy_gaps(None, REGISTRY) == []


def test_a_statement_alone_rather_than_a_list_is_read():
    document = json.dumps(
        {"Statement": pull_statement({"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:root"})}
    )
    assert selection.repository_policy_gaps(document, REGISTRY) == [
        f"repository policy allows account {OTHER_ACCOUNT}"
    ]


@pytest.mark.parametrize(
    "statement, gap",
    [
        (
            pull_statement({"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:root"}),
            f"repository policy allows account {OTHER_ACCOUNT}",
        ),
        (
            pull_statement({"AWS": [REGISTRY, OTHER_ACCOUNT]}),
            f"repository policy allows account {OTHER_ACCOUNT}",
        ),
        (
            pull_statement({"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:role/ci"}),
            f"repository policy allows account {OTHER_ACCOUNT}",
        ),
        (pull_statement("*"), "repository policy allows *"),
        (pull_statement({"AWS": "*"}), "repository policy allows *"),
        (
            pull_statement(
                {"AWS": f"arn:aws:iam::{REGISTRY}:root"},
                Condition={
                    "ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": "o-a/*"}
                },
            ),
            "repository policy allows an organization (aws:PrincipalOrgPaths in statement 'Pull')",
        ),
        (
            {
                "Sid": "AllButMe",
                "Effect": "Allow",
                "NotPrincipal": {"AWS": f"arn:aws:iam::{REGISTRY}:root"},
                "Action": "ecr:BatchGetImage",
            },
            "repository policy allows everyone but a NotPrincipal (statement 'AllButMe')",
        ),
        (
            pull_statement({"AWS": "AROAEXAMPLEUNIQUEID"}),
            "repository policy allows a principal the job can't place in an account: AROAEXAMPLEUNIQUEID",
        ),
        (
            pull_statement({"Service": "codebuild.amazonaws.com"}),
            "repository policy allows service codebuild.amazonaws.com",
        ),
        (
            pull_statement({"Federated": "cognito-identity.amazonaws.com"}),
            "repository policy allows Federated principal cognito-identity.amazonaws.com",
        ),
        (
            pull_statement({"Service": "lambda.amazonaws.com"}),
            "repository policy allows lambda.amazonaws.com for functions it doesn't prove are this account's "
            "(statement 'Pull')",
        ),
    ],
    ids=[
        "another-account",
        "another-account-among-this-one",
        "a-role-in-another-account",
        "star",
        "aws-star",
        "organization",
        "not-principal",
        "unique-id",
        "another-service",
        "federated",
        "lambda-without-a-condition",
    ],
)
def test_policies_that_let_someone_outside_the_account_pull(statement, gap):
    assert gap in selection.repository_policy_gaps(policy(statement), REGISTRY)


@pytest.mark.parametrize(
    "condition",
    [
        {"StringLike": {"aws:sourceArn": f"arn:aws:lambda:{REGION}:*:function:*"}},
        {
            "StringLike": {
                "aws:sourceArn": f"arn:aws:lambda:{REGION}:{OTHER_ACCOUNT}:function:*"
            }
        },
        {
            "StringLike": {
                "aws:sourceArn": [
                    f"arn:aws:lambda:{REGION}:{REGISTRY}:function:*",
                    f"arn:aws:lambda:{REGION}:{OTHER_ACCOUNT}:function:*",
                ]
            }
        },
        {"StringLike": {"aws:sourceArn": f"arn:aws:lambda:*:{REGISTRY}*"}},
        {
            "StringLikeIfExists": {
                "aws:sourceArn": f"arn:aws:lambda:{REGION}:{REGISTRY}:function:*"
            }
        },
        {
            "StringNotLike": {
                "aws:sourceArn": f"arn:aws:lambda:{REGION}:{OTHER_ACCOUNT}:function:*"
            }
        },
        {"StringLike": {"aws:SourceAccount": "1111*"}},
        {"ArnLike": {"aws:SourceAccount": REGISTRY}},
    ],
    ids=[
        "any-account",
        "another-account",
        "this-and-another-account",
        "wildcard-in-the-account",
        "if-exists",
        "negated",
        "wildcard-source-account",
        "source-account-as-an-arn",
    ],
)
def test_lambda_for_functions_the_job_cant_place_here(condition):
    statement = dict(LAMBDA_STATEMENT, Condition=condition)
    gaps = selection.repository_policy_gaps(policy(statement), REGISTRY)
    assert gaps == [
        "repository policy allows lambda.amazonaws.com for functions it doesn't prove are this account's "
        "(statement 'LambdaECRImageRetrievalPolicy')"
    ]


@pytest.mark.parametrize(
    "actions",
    [
        {"Action": "ecr:*"},
        {"Action": "*"},
        {"Action": "ECR:BatchGet*"},
        {"Action": "ecr:GetDownloadUrlFor?ayer"},
        {"Action": ["ecr:DescribeImages", "ecr:GetDownloadUrlForLayer"]},
        {"NotAction": "ecr:BatchGetImage"},
        {"NotAction": "s3:*"},
    ],
    ids=[
        "ecr-wildcard",
        "star",
        "prefix-any-case",
        "question-mark",
        "one-of-the-two",
        "not-action-of-one",
        "not-action-of-another-service",
    ],
)
def test_an_action_that_lets_pull(actions):
    statement = dict(
        {"Effect": "Allow", "Principal": {"AWS": OTHER_ACCOUNT}}, **actions
    )
    assert selection.repository_policy_gaps(policy(statement), REGISTRY) == [
        f"repository policy allows account {OTHER_ACCOUNT}"
    ]


@pytest.mark.parametrize(
    "statement",
    [
        "Allow",
        dict(pull_statement({"AWS": OTHER_ACCOUNT}), Action=7),
        dict(pull_statement({"AWS": [OTHER_ACCOUNT, 7]})),
        dict(pull_statement(["*"])),
        dict(pull_statement({"AWS": REGISTRY}), Condition=["aws:SourceAccount"]),
    ],
    ids=["not-an-object", "action", "principal-values", "principal", "condition"],
)
def test_a_statement_the_job_cant_read_makes_the_view_incomplete(statement):
    gaps = selection.repository_policy_gaps(policy(statement), REGISTRY)
    assert len(gaps) == 1
    assert gaps[0].startswith("repository policy has a statement the job can't read")


@pytest.mark.parametrize("text", ["not json", "[]"])
def test_a_policy_that_isnt_a_json_object_fails_the_run(text):
    with pytest.raises(selection.RepositoryError):
        selection.repository_policy_gaps(text, REGISTRY)


# --- Fail closed: ECS, Lambda and the repository's policy ---


# Each read: the client that makes it, and for a paginated read, the key of its items, and the keys that carry the
# next page's token out of one call and into the next.
VIEW_READS = {
    "get_repository_policy": ("ecr", None),
    "list_clusters": ("ecs", ("clusterArns", "nextToken", "nextToken")),
    "list_tasks": ("ecs", ("taskArns", "nextToken", "nextToken")),
    "describe_tasks": ("ecs", None),
    "list_services": ("ecs", ("serviceArns", "nextToken", "nextToken")),
    "describe_services": ("ecs", None),
    "describe_task_definition": ("ecs", None),
    "list_functions": ("lambda_", ("Functions", "NextMarker", "Marker")),
    "get_function": ("lambda_", None),
}


def a_repository_ecs_and_lambda_run() -> Tuple[Repo, Dict[str, str]]:
    """A candidate nothing runs, in a repository whose ECS cluster and Lambda function each run another image."""
    repo = Repo()
    made = pulled_long_ago(repo, "old", tags=["abc"], pushed=40)
    running = pulled_long_ago(repo, "running", tags=["def"])
    repo.task(None, running["index"])
    repo.service("web", [("PRIMARY", repo.task_definition("web:1", uri("def")))])
    repo.function("fn", "1", resolved=uri(image_digest=running["platform"]))
    return repo, made


class _StopStubbing(Exception):
    """The failed read is stubbed: the run makes no call after it."""


class FailingStub:
    """
    A Stubber that passes every answer through but one operation's, which it fails: on its first page, or on its
    second, after a first page with no items.
    """

    def __init__(self, stub: Stubber, operation: str, page: int, code: str) -> None:
        self.stub = stub
        self.operation = operation
        self.page = page
        self.code = code

    def add_response(
        self,
        name: str,
        response: Dict[str, Any],
        expected: Optional[Dict[str, Any]] = None,
    ) -> None:
        if name != self.operation:
            self.stub.add_response(name, response, expected)
            return
        self.add_client_error(name, expected_params=expected, response=response)

    def add_client_error(self, name: str, **kwargs: Any) -> None:
        if name != self.operation:
            self.stub.add_client_error(name, **kwargs)
            return
        expected = kwargs.get("expected_params")
        if self.page == 2:
            items_key, token_out, token_in = VIEW_READS[name][1]
            first = dict(
                kwargs.get("response") or {}, **{items_key: [], token_out: "page-2"}
            )
            self.stub.add_response(name, first, expected)
            expected = dict(expected or {}, **{token_in: "page-2"})
        self.stub.add_client_error(
            name,
            service_error_code=self.code,
            http_status_code=400,
            expected_params=expected,
        )
        raise _StopStubbing()


def fail_on(repo: Repo, stubs: Stubs, operation: str, page: int, code: str) -> None:
    """Answer the run's reads in order, up to ``operation``, which fails."""
    client = VIEW_READS[operation][0]
    failing = {
        name: (
            FailingStub(getattr(stubs, name), operation, page, code)
            if name == client
            else getattr(stubs, name)
        )
        for name in ("ecr", "ecs", "lambda_")
    }
    with contextlib.suppress(_StopStubbing):
        repo.stub_ecr_reads(stubs.ecr)
        stubs.inspector.add_response("list_findings", {"findings": repo.findings})
        stubs.inspector.add_response(
            "list_coverage", {"coveredResources": repo.coverage}
        )
        repo.stub_policy(failing["ecr"])
        repo.stub_tasks(failing["ecs"], repo.tasks, services=True)
        repo.stub_task_definitions(failing["ecs"])
        repo.stub_functions(failing["lambda_"])


@pytest.mark.parametrize("code", ["ThrottlingException", "AccessDeniedException"])
@pytest.mark.parametrize(
    "operation, page",
    [
        (operation, page)
        for operation, (_, paginated) in VIEW_READS.items()
        for page in ((1, 2) if paginated else (1,))
    ],
)
def test_a_failed_read_of_the_view_deletes_nothing(operation, page, code):
    # No delete is stubbed, so a delete would fail the test with another error than the ClientError.
    repo, _ = a_repository_ecs_and_lambda_run()
    if operation == "get_repository_policy":
        repo.allow(LAMBDA_STATEMENT)
    with Stubs() as stubs:
        fail_on(repo, stubs, operation, page, code)
        with pytest.raises(ClientError, match=code):
            cleanup.run(settings(), stubs.clients, NOW)
        stubs.assert_no_pending_responses()


@pytest.mark.parametrize("operation", ["describe_tasks", "describe_services"])
@pytest.mark.parametrize("answer", ["failure", "left-out"])
def test_ecs_not_describing_what_it_listed_fails_the_run(operation, answer):
    repo, _ = a_repository_ecs_and_lambda_run()
    key, arn_key = (
        ("tasks", "taskArn")
        if operation == "describe_tasks"
        else ("services", "serviceArn")
    )
    with Stubs() as stubs:

        class Answering:
            def __init__(self, stub: Stubber) -> None:
                self.stub = stub

            def add_response(self, name, response, expected=None):
                if name == operation:
                    arn = response[key][0][arn_key]
                    response = dict(response, **{key: []})
                    if answer == "failure":
                        response["failures"] = [{"arn": arn, "reason": "MISSING"}]
                    self.stub.add_response(name, response, expected)
                    raise _StopStubbing()
                return self.stub.add_response(name, response, expected)

        repo.stub_ecr_reads(stubs.ecr)
        stubs.inspector.add_response("list_findings", {"findings": repo.findings})
        stubs.inspector.add_response(
            "list_coverage", {"coveredResources": repo.coverage}
        )
        repo.stub_policy(stubs.ecr)
        with contextlib.suppress(_StopStubbing):
            repo.stub_tasks(Answering(stubs.ecs), repo.tasks, services=True)
        with pytest.raises(cleanup.CleanupError, match="ECS didn't describe"):
            cleanup.run(settings(), stubs.clients, NOW)


def test_a_failed_read_of_the_running_tasks_before_deleting_deletes_nothing():
    repo, made = a_repository_ecs_and_lambda_run()
    with Stubs() as stubs:
        repo.stub_reads(stubs)
        repo.stub_recheck(stubs.ecr, [made["platform"]])
        stubs.ecs.add_response(
            "list_clusters",
            {"clusterArns": [repo.cluster()], "nextToken": "page-2"},
            {},
        )
        stubs.ecs.add_client_error(
            "list_clusters",
            service_error_code="ThrottlingException",
            http_status_code=400,
        )
        with pytest.raises(ClientError, match="ThrottlingException"):
            cleanup.run(settings(), stubs.clients, NOW)


def test_the_reads_of_the_view_ask_for_what_they_must():
    # Running tasks only, and every function version: the Stubber checks each call's parameters.
    repo, made = a_repository_ecs_and_lambda_run()
    summary = repo.run(deletions=deletes(made), recheck=[made["platform"]])
    assert summary["deleted"] == 1
    assert summary["images_in_use_by"]["ecs"] == 1
    assert summary["images_in_use_by"]["lambda"] == 1


# --- Reading the running tasks again before deleting ---


def test_a_task_that_starts_before_the_delete_keeps_its_image(caplog):
    repo = Repo()
    made = pulled_long_ago(repo, "rollback", tags=["abc"])
    repo.cluster()
    repo.task(None, made["index"], service="api", on_recheck=True)
    with caplog.at_level("INFO"):
        summary = repo.run(recheck=[made["platform"]])
    assert summary["deleted"] == 0
    assert summary["candidates"] == 0
    assert summary["dropped_on_recheck"] == 1
    (recheck,) = [line for line in logged(caplog) if line.get("action") == "recheck"]
    assert recheck["dropped"] == [made["index"]]
    line = kept_line(caplog)
    assert line["use_judged_by"] == "ecs"
    assert line["in_use_by"][0]["via"] == "running_task"


def test_a_task_that_stops_before_the_delete_still_keeps_its_image():
    # A use one read shows counts, though a later one misses it.
    repo = Repo()
    made = pulled_long_ago(repo, "stopping", tags=["abc"])
    repo.task(None, made["index"])
    repo.tasks_on_recheck = {repo.cluster(): []}
    summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 1


def test_a_task_that_starts_frees_its_place_under_the_cap_for_the_next():
    repo = Repo()
    older = pulled_long_ago(repo, "older", tags=["a"], pushed=40)
    newer = pulled_long_ago(repo, "newer", tags=["b"], pushed=30)
    repo.cluster()
    repo.task(None, older["platform"], on_recheck=True)
    summary = repo.run(
        deletions=deletes(newer),
        recheck=[older["platform"], newer["platform"]],
        max_deletions=1,
    )
    assert summary["deleted"] == 1
    assert summary["left_by_cap"] == 0
    assert summary["dropped_on_recheck"] == 1


def test_the_reads_again_cover_every_candidates_pull_record():
    # Judged by Inspector, never pulled, pulled before the soak: each candidate's runnable manifests, oldest first.
    repo = Repo()
    by_inspector = vulnerable_index(repo, "inspector", tags=["a"], pushed=50)
    never = never_pulled_index(repo, "never", tags=["b"], pushed=40)
    old = pulled_long_ago(repo, "old", tags=["c"], pushed=30)
    summary = repo.run(
        deletions=deletes(by_inspector) + deletes(never) + deletes(old),
        recheck=[by_inspector["platform"], never["platform"], old["platform"]],
    )
    assert summary["deleted"] == 3


def test_a_lambda_version_runs_the_digest_it_resolved_not_its_tags_image_now():
    # The tag v2 has moved on since the version was deployed: Lambda still runs the digest it resolved then.
    repo = Repo()
    old = pulled_long_ago(repo, "old", tags=["v1"], pushed=40)
    moved = pulled_long_ago(repo, "moved", tags=["v2"])
    repo.function(
        "fn", "1", resolved=uri(image_digest=old["index"]), image_uri=uri("v2")
    )
    summary = repo.run(deletions=deletes(moved), recheck=[moved["platform"]])
    assert summary["deleted"] == 1
    assert summary["protected"]["in_use"] == 1


def test_a_lambda_version_without_a_resolved_digest_keeps_what_its_uri_names():
    repo = Repo()
    pulled_long_ago(repo, "old", tags=["v1"])
    repo.function("fn", "1", image_uri=uri("v1"))
    assert repo.run()["protected"]["in_use"] == 1
