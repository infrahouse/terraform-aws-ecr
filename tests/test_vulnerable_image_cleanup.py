"""
Unit tests of the vulnerable image cleanup: no AWS.

Each test describes a repository and what Inspector says about it, then runs the Lambda's code against boto3 clients
whose answers botocore's Stubber serves. The Stubber checks every answer against botocore's model, so they are shaped
as botocore gives them, and fails a test on any call it wasn't given an answer for: a delete in a dry run, or one
in the wrong order.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import cleanup
import selection

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
REGISTRY = "111122223333"
REPOSITORY = "test-repo"
REGION = "us-west-2"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"


def digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def days_ago(days: Optional[float]) -> Optional[datetime]:
    return None if days is None else NOW - timedelta(days=days)


def settings(**overrides: Any) -> selection.Settings:
    values = dict(
        repository_name=REPOSITORY,
        registry_id=REGISTRY,
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


class Repo:
    """A repository, and what Inspector says about it, as the AWS APIs answer."""

    def __init__(self) -> None:
        self.details: List[Dict[str, Any]] = []
        self.manifests: Dict[str, str] = {}
        self.findings: List[Dict[str, Any]] = []
        self.coverage: List[Dict[str, Any]] = []

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
        **overrides: Any,
    ) -> Dict[str, Any]:
        """
        Run the cleanup. ``deletions`` are the BatchDeleteImage calls the run must make, in order; any other delete
        fails the test. ECR refuses the images in ``refused`` with their failure codes, and the call numbered
        ``throttled`` (from 0) fails with ThrottlingException.
        """
        ecr, inspector = clients()
        with Stubber(ecr) as ecr_stub, Stubber(inspector) as inspector_stub:
            self.stub_reads(ecr_stub, inspector_stub)
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
            summary = cleanup.run(settings(**overrides), ecr, inspector, NOW)
            ecr_stub.assert_no_pending_responses()
            inspector_stub.assert_no_pending_responses()
        return summary

    def stub_reads(self, ecr_stub: Stubber, inspector_stub: Stubber) -> None:
        self.stub_ecr_reads(ecr_stub)
        inspector_stub.add_response("list_findings", {"findings": self.findings})
        inspector_stub.add_response(
            "list_coverage", {"coveredResources": self.coverage}
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


def clients():
    session = boto3.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name=REGION
    )
    return session.client("ecr"), session.client("inspector2")


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
    # A task pulled the arm64 image a month ago and may still run it.
    repo = Repo()
    multi_platform(repo, arm_pulled=30)
    assert repo.run()["protected"]["in_use_unknown"] == 1


def test_platform_images_judged_by_inspector_and_by_ecr_pull_record(caplog):
    repo = Repo()
    index, amd, arm = multi_platform(repo)
    with caplog.at_level("INFO"):
        summary = repo.run(deletions=[[index], [amd, arm]])
    assert summary["deleted"] == 1
    line, _ = logged(caplog)
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
        summary = repo.run(deletions=deletes(made))
    assert summary["deleted"] == 1
    assert summary["protected"] == dict.fromkeys(selection.REASONS, 0)
    assert summary["judged_never_pulled"] == 1
    line, _ = logged(caplog)
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
    line, _ = logged(caplog)
    assert line["action"] == "kept"
    assert line["reasons"] == ["in_use"]
    assert line["use_judged_by"] == "ecr_pull_record"
    assert line["never_pulled"] is False


@pytest.mark.parametrize("coverage", NO_IN_USE_DATA)
def test_pulled_before_the_soak_is_unknown(coverage, caplog):
    # A long-running task pulled its image once, weeks ago, and still runs it: nothing here can tell.
    repo = Repo()
    without_in_use_data(
        repo, "long-running", coverage, tags=["abc"], pulled=30, platform_pulled=30
    )
    with caplog.at_level("INFO"):
        summary = repo.run()
    assert summary["deleted"] == 0
    assert summary["protected"]["in_use"] == 0
    assert summary["protected"]["in_use_unknown"] == 1
    assert summary["judged_never_pulled"] == 0
    line, _ = logged(caplog)
    assert line["action"] == "kept"
    assert line["reasons"] == ["in_use_unknown"]
    assert line["use_judged_by"] == "unknown"
    assert line["never_pulled"] is False


def test_an_index_pulled_recently_whose_platform_image_was_never_pulled_is_not_in_use():
    # The job's own BatchGetImage of the index each run records a pull of the index, and of nothing else.
    repo = Repo()
    made = without_in_use_data(
        repo, "read", "no-coverage-record", tags=["abc"], pulled=0.1
    )
    summary = repo.run(deletions=deletes(made))
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
    # A runtime doesn't pull an attestation to run the image; a scanner may. Its pull protects nothing, by ECR's
    # pull record or by Inspector's data.
    repo = Repo()
    made = repo.index("old", tags=["abc"], attestation_pulled=0.1)
    repo.vulnerable(made["platform"])
    if coverage == "unused":
        repo.unused(made["platform"])
    summary = repo.run(deletions=deletes(made))
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
    summary = repo.run(deletions=deletes(made) if deleted else [])
    assert summary["deleted"] == int(deleted)
    assert summary["protected"]["in_use_unknown"] == int(not deleted)
    assert summary["judged_never_pulled"] == int(deleted)


@pytest.mark.parametrize(
    "operation", ["describe_images", "list_findings", "list_coverage"]
)
def test_an_error_mid_pagination_deletes_nothing(operation):
    # The first page holds everything a deletion needs; the second fails, as throttling that outlasts the retries
    # does. No delete is stubbed, so a delete would fail the test with another error than the ClientError.
    repo = Repo()
    vulnerable_index(repo, "old", tags=["abc"])
    ecr, inspector = clients()
    with Stubber(ecr) as ecr_stub, Stubber(inspector) as inspector_stub:
        if operation == "describe_images":
            ecr_stub.add_response(
                operation, {"imageDetails": repo.details, "nextToken": "page-2"}
            )
            ecr_stub.add_client_error(
                operation,
                service_error_code="ThrottlingException",
                http_status_code=400,
            )
        else:
            repo.stub_ecr_reads(ecr_stub)
            pages = {
                "list_findings": {"findings": repo.findings},
                "list_coverage": {"coveredResources": repo.coverage},
            }
            if operation == "list_coverage":
                inspector_stub.add_response("list_findings", pages["list_findings"])
            inspector_stub.add_response(
                operation, dict(pages[operation], nextToken="page-2")
            )
            inspector_stub.add_client_error(
                operation,
                service_error_code="ThrottlingException",
                http_status_code=400,
            )
        with pytest.raises(ClientError, match="ThrottlingException"):
            cleanup.run(settings(), ecr, inspector, NOW)


def test_a_manifest_ecr_does_not_return_deletes_nothing():
    repo = Repo()
    made = vulnerable_index(repo, "old", tags=["abc"])
    ecr, inspector = clients()
    with Stubber(ecr) as ecr_stub, Stubber(inspector):
        ecr_stub.add_response("describe_images", {"imageDetails": repo.details})
        ecr_stub.add_response(
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
            cleanup.run(settings(), ecr, inspector, NOW)


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
    (line,) = logged(caplog)
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
    deleted, failed = logged(caplog)
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

    ecr, _ = clients()
    with pytest.raises(cleanup.CleanupError, match="inUseCount"):
        cleanup.check_models(ecr, OldInspector)


def test_an_ecr_model_without_the_pull_time_fails_the_run_before_any_call():
    # A botocore that drops lastRecordedPullTime would make every image without Inspector's in-use data look never
    # pulled.
    real, inspector = clients()
    model = real.meta.service_model

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

    # Inspector's Stubber has no answers: a call to Inspector fails the test too.
    with Stubber(inspector), pytest.raises(
        cleanup.CleanupError, match="lastRecordedPullTime"
    ):
        cleanup.run(settings(), OldEcr(), inspector, NOW)


def test_the_installed_botocore_models_the_fields():
    cleanup.check_models(*clients())


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
    assert len(lines) == 2
    line, summary = lines
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

    def run(parsed, ecr, inspector, now):
        seen.update(
            ecr=ecr.meta.region_name,
            inspector=inspector.meta.region_name,
            dry_run=parsed.dry_run,
        )
        return {}

    monkeypatch.setattr(cleanup, "run", run)
    for name, value in environment(REPOSITORY_REGION="eu-central-1").items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    cleanup.lambda_handler({}, None)
    assert seen == {"ecr": "eu-central-1", "inspector": "eu-central-1", "dry_run": True}


def test_the_findings_filter():
    repo = Repo()
    ecr, inspector = clients()
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
    assert repo and ecr
