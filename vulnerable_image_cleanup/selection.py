"""
Decides which images the vulnerable image cleanup deletes.

Nothing here calls AWS. The functions take the answers ECR, Inspector, ECS and Lambda give, shaped as botocore
returns them, so the rules can be tested on their own.

An image is protected, and kept, when any of these hold:

* it carries a tag in ``retain_tags``;
* it is a rollback candidate the lifecycle policy keeps (``policy.tf``);
* it is in use, or was within the soak;
* it was pushed within the least age;
* it isn't ACTIVE (archived images are outside the lifecycle's rules too);
* the job can't tell whether it is in use.

The job judges use from what ECS and Lambda run, from Inspector's in-use data and from ECR's pull record. A unit is in
use when a running ECS task, the task definition of an ECS service's deployment, or a Lambda function version names
one of its digests or tags. Otherwise a container runtime pulls an image to run it, and ECR records the pull on the
manifest it fetched, so an image whose runnable manifests ECR never recorded a pull of was never run. One pulled before
the soak is not in use when the view is complete: ECS and Lambda were read in full, and the repository's policy lets
no one outside the account pull, so nothing the job can't see runs it from another account.

An image index and the manifests it references are judged, and deleted, as one image: a "unit".
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import (
    Any,
    Deque,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
# ECR reports a BuildKit attestation with this artifact media type, and the index that holds it annotates it.
ATTESTATION_ARTIFACT_MEDIA_TYPE = "application/vnd.docker.attestation.manifest.v1+json"
ATTESTATION_REFERENCE_TYPE = "attestation-manifest"

# Inspector's severities that the least severity may name, from the least to the most severe.
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ACTIVE = "ACTIVE"

RETAINED_TAG = "retained_tag"
ROLLBACK_CANDIDATE = "rollback_candidate"
IN_USE = "in_use"
IN_USE_UNKNOWN = "in_use_unknown"
RECENT = "recent"
NOT_ACTIVE = "not_active"
REASONS = (RETAINED_TAG, ROLLBACK_CANDIDATE, IN_USE, IN_USE_UNKNOWN, RECENT, NOT_ACTIVE)

# How a unit's use was judged, as its log line says.
JUDGED_BY_ECS = "ecs"
JUDGED_BY_LAMBDA = "lambda"
JUDGED_BY_INSPECTOR = "inspector"
JUDGED_BY_PULL_RECORD = "ecr_pull_record"
JUDGED_UNKNOWN = "unknown"
# What can show a unit in use, as the summary counts them.
USE_SOURCES = (
    JUDGED_BY_ECS,
    JUDGED_BY_LAMBDA,
    JUDGED_BY_INSPECTOR,
    JUDGED_BY_PULL_RECORD,
)

# What a run counts of what it read, as the summary's view says.
VIEW_COUNTS = (
    "ecs_clusters",
    "ecs_running_tasks",
    "ecs_services",
    "ecs_service_revisions",
    "ecs_task_definitions",
    "lambda_image_versions",
)
# How ECS or Lambda names an image a use runs, as a use's log line says.
VIA_RUNNING_TASK = "running_task"
VIA_DEPLOYMENT = "deployment"
VIA_FUNCTION_VERSION = "function_version"
# A service's deployments, and task sets, whose task definitions it runs or may go back to: the one it deploys, and
# those it is replacing. INACTIVE ones are done with; DRAINING task sets' tasks are stopping, and running ones are read.
DEPLOYED_STATUSES = frozenset({"PRIMARY", "ACTIVE"})
# The deployment controllers that resolve a container's tag to a digest when a deployment starts its first task, and
# start every later task of it from that digest (version consistency). CODE_DEPLOY and EXTERNAL don't. A service
# without a controller set uses ECS's.
TAG_RESOLVING_CONTROLLERS = frozenset({None, "ECS"})
# What a pull needs: the manifest, and the layers.
PULL_ACTIONS = ("ecr:batchgetimage", "ecr:getdownloadurlforlayer")
# Condition keys that grant an organization, or a part of one, rather than an account.
ORGANIZATION_KEYS = frozenset(
    {
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:sourceorgid",
        "aws:sourceorgpaths",
    }
)
# Condition operators under which a value names what a request must come from. IfExists, ForAllValues and the negated
# operators let a request without the key through.
_RESTRICTING_OPERATORS = frozenset(
    {"StringEquals", "StringLike", "ArnEquals", "ArnLike"}
)

# AWS released ECR's lastRecordedPullTime on 2022-03-02: botocore 1.24.11's changelog notes "This release adds support
# for tracking images lastRecordedPullTime". An image pushed before then may have been pulled without a record. The
# next day, so the day of the release is covered.
PULL_RECORD_START = datetime(2022, 3, 3, tzinfo=timezone.utc)

# How one runnable manifest's use was judged.
_BY_INSPECTOR = "inspector"
_NEVER_PULLED = "never_pulled"
_PULLED_WITHIN_SOAK = "pulled_within_soak"
_PULLED_BEFORE_SOAK = "pulled_before_soak"
_UNKNOWN = "unknown"
_BY_PULL_RECORD = frozenset({_NEVER_PULLED, _PULLED_WITHIN_SOAK, _PULLED_BEFORE_SOAK})

_IMAGE_ARN = re.compile(
    r"^arn:[^:]+:ecr:[^:]+:(?P<account>\d{12}):repository/(?P<repository>.+)/(?P<digest>sha256:[0-9a-f]{64})$"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACCOUNT_ID = re.compile(r"^\d{12}$")
# An IAM or STS principal's ARN: its account is the fifth field.
_PRINCIPAL_ARN = re.compile(r"^arn:[^:*?]+:(?:iam|sts)::(?P<account>\d{12}):.+$")


class SettingsError(ValueError):
    """The job's settings are missing or wrong."""


class RepositoryError(ValueError):
    """The repository's images can't be mapped, so nothing can be judged."""


@dataclass(frozen=True)
class Settings:
    """
    What the job looks for and what protects an image.

    :param repository_name: The ECR repository.
    :param registry_id: Its registry, the account id.
    :param region: Its Region: the job reads ECR, Inspector, ECS and Lambda there.
    :param repository_arn: Its ARN, which the registry's policy names it by.
    :param dry_run: Log what would be deleted, and delete nothing.
    :param min_severity: The least Inspector severity that makes an image vulnerable.
    :param min_age: An image pushed within this is protected.
    :param soak: An image in use, or pulled, within this is protected.
    :param max_deletions: The most images (an index with its manifests is one) deleted in a run.
    :param retain_tags: Tags whose images are protected.
    :param protect_rollback_candidates: Protect the rollback candidates the lifecycle policy keeps.
    :param rollback_candidate_tag_prefix: The rollback candidates' tag prefix, as in the lifecycle policy.
    :param rollback_candidate_retain_count: The lifecycle's rollback candidate count, or None.
    :param rollback_candidate_retain_days: The lifecycle's rollback candidate days, or None.
    """

    repository_name: str
    registry_id: str
    region: str
    repository_arn: str
    dry_run: bool
    min_severity: str
    min_age: timedelta
    soak: timedelta
    max_deletions: int
    retain_tags: FrozenSet[str]
    protect_rollback_candidates: bool
    rollback_candidate_tag_prefix: str
    rollback_candidate_retain_count: Optional[int]
    rollback_candidate_retain_days: Optional[float]

    def __post_init__(self) -> None:
        if not self.repository_name:
            raise SettingsError("The repository name is empty.")
        if not re.fullmatch(r"\d{12}", self.registry_id):
            raise SettingsError(
                f"The registry id must be 12 digits. Got: {self.registry_id!r}"
            )
        if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d+", self.region):
            raise SettingsError(f"The Region isn't one. Got: {self.region!r}")
        if not re.fullmatch(
            rf"arn:[a-z-]+:ecr:{re.escape(self.region)}:{self.registry_id}:"
            rf"repository/{re.escape(self.repository_name)}",
            self.repository_arn,
        ):
            raise SettingsError(
                f"The repository's ARN isn't this repository's. Got: {self.repository_arn!r}"
            )
        if self.min_severity not in SEVERITIES:
            raise SettingsError(
                f"The least severity must be one of {SEVERITIES}. Got: {self.min_severity!r}"
            )
        if self.min_age < timedelta(0) or self.soak < timedelta(0):
            raise SettingsError("The least age and the soak can't be negative.")
        if self.max_deletions < 1:
            raise SettingsError(
                f"The cap must be at least 1. Got: {self.max_deletions}"
            )
        if (
            self.rollback_candidate_retain_count is not None
            and self.rollback_candidate_retain_count < 0
        ):
            raise SettingsError("The rollback candidate count can't be negative.")
        if (
            self.rollback_candidate_retain_days is not None
            and self.rollback_candidate_retain_days < 0
        ):
            raise SettingsError("The rollback candidate days can't be negative.")

    @classmethod
    def from_environment(cls, environ: Mapping[str, str]) -> "Settings":
        """
        Read the settings from the function's environment, as the module sets it.

        :param environ: The environment, e.g. ``os.environ``.
        :return: The settings.
        :raise SettingsError: if a variable is missing or wrong.
        """
        try:
            return cls(
                repository_name=environ["REPOSITORY_NAME"],
                registry_id=environ["REGISTRY_ID"],
                region=environ["REPOSITORY_REGION"],
                repository_arn=environ["REPOSITORY_ARN"],
                dry_run=_boolean(environ, "DRY_RUN"),
                min_severity=environ["MIN_SEVERITY"],
                min_age=timedelta(days=float(environ["MIN_AGE_DAYS"])),
                soak=timedelta(days=float(environ["SOAK_DAYS"])),
                max_deletions=int(environ["MAX_DELETIONS"]),
                retain_tags=frozenset(_string_list(environ, "RETAIN_TAGS")),
                protect_rollback_candidates=_boolean(
                    environ, "PROTECT_ROLLBACK_CANDIDATES"
                ),
                rollback_candidate_tag_prefix=environ["ROLLBACK_CANDIDATE_TAG_PREFIX"],
                rollback_candidate_retain_count=_optional_number(
                    environ, "ROLLBACK_CANDIDATE_RETAIN_COUNT", int
                ),
                rollback_candidate_retain_days=_optional_number(
                    environ, "ROLLBACK_CANDIDATE_RETAIN_DAYS", float
                ),
            )
        except KeyError as err:
            raise SettingsError(f"The environment variable {err} is missing.") from err
        except (TypeError, ValueError) as err:
            if isinstance(err, SettingsError):
                raise
            raise SettingsError(f"A setting is wrong: {err}") from err

    @property
    def severities(self) -> List[str]:
        """
        :return: The severities at or above the least one.
        """
        return list(SEVERITIES[SEVERITIES.index(self.min_severity) :])

    def names_this_repository(self, reference: "ImageReference") -> bool:
        """
        :param reference: An image reference, as a task definition or a function names an image.
        :return: True if it names an image in this repository: through ECR's registry host of this account and Region,
            in any of its forms (``dkr.ecr``, FIPS, dual-stack), and this repository's name.
        """
        if reference.host is None:
            return False
        labels = reference.host.split(".")
        return (
            labels[0] == self.registry_id
            and self.region in labels
            and any("ecr" in label for label in labels)
            and reference.path == self.repository_name
        )


@dataclass(frozen=True)
class Image:
    """
    One manifest in the repository, as ECR's DescribeImages gives it.

    :param digest: The manifest's digest.
    :param tags: Its tags.
    :param pushed_at: When it was pushed.
    :param last_pulled_at: ECR's last recorded pull, if any.
    :param media_type: The manifest's media type, if ECR gave one.
    :param artifact_media_type: The artifact media type, if ECR gave one.
    :param status: ACTIVE, ARCHIVED or ACTIVATING; None if ECR didn't say.
    """

    digest: str
    tags: Tuple[str, ...]
    pushed_at: Optional[datetime]
    last_pulled_at: Optional[datetime]
    media_type: Optional[str]
    artifact_media_type: Optional[str]
    status: Optional[str]

    @classmethod
    def from_detail(cls, detail: Mapping[str, Any]) -> "Image":
        """
        :param detail: One ``imageDetails`` item of DescribeImages.
        :return: The image.
        """
        return cls(
            digest=detail["imageDigest"],
            tags=tuple(detail.get("imageTags") or ()),
            pushed_at=detail.get("imagePushedAt"),
            last_pulled_at=detail.get("lastRecordedPullTime"),
            media_type=detail.get("imageManifestMediaType"),
            artifact_media_type=detail.get("artifactMediaType"),
            status=detail.get("imageStatus"),
        )

    @property
    def is_index(self) -> bool:
        """
        :return: True if the manifest is an image index (a manifest list).
        """
        return self.media_type in INDEX_MEDIA_TYPES


def needs_manifest(media_type: Optional[str]) -> bool:
    """
    :param media_type: An image's ``imageManifestMediaType``, as DescribeImages gives it, or None.
    :return: True if the job must read the manifest to know what it references: an index, or a manifest whose media
        type ECR didn't give.
    """
    return media_type is None or media_type in INDEX_MEDIA_TYPES


@dataclass(frozen=True)
class Unit:
    """
    An image as the job judges and deletes it: a manifest no index references, with everything it references.

    :param root: The digest of the manifest no index references: an index, or a single manifest.
    :param members: The root first, then what it references, level by level.
    """

    root: str
    members: Tuple[str, ...]


class Repository:
    """
    The repository's images, and which manifests each index references.

    :param images: The images, by digest.
    :param references: For each index, the digests it references.
    :param attestations: The digests an index annotates as an attestation.
    """

    def __init__(
        self,
        images: Mapping[str, Image],
        references: Mapping[str, Tuple[str, ...]],
        attestations: FrozenSet[str],
    ) -> None:
        self.images = dict(images)
        self.references = dict(references)
        self.attestations = attestations
        self.referenced_by: Dict[str, Set[str]] = {}
        for index, children in self.references.items():
            for child in children:
                self.referenced_by.setdefault(child, set()).add(index)

    # --- Public properties ---

    @property
    def units(self) -> List[Unit]:
        """
        :return: One unit per manifest that no index in the repository references.
        """
        return [
            Unit(root=digest, members=self._closure(digest))
            for digest in sorted(self.images)
            if digest not in self.referenced_by
        ]

    # --- Public methods ---

    @classmethod
    def build(
        cls,
        details: Iterable[Mapping[str, Any]],
        manifests: Mapping[str, Mapping[str, Any]],
    ) -> "Repository":
        """
        :param details: Every ``imageDetails`` item DescribeImages gave.
        :param manifests: The parsed manifest of every image :func:`needs_manifest` names, by digest.
        :return: The repository.
        :raise RepositoryError: if a manifest the job needs is missing, or an index lists no manifests.
        """
        images: Dict[str, Image] = {}
        for detail in details:
            image = Image.from_detail(detail)
            images[image.digest] = image
        references: Dict[str, Tuple[str, ...]] = {}
        attestations: Set[str] = set()
        for digest, image in images.items():
            if not needs_manifest(image.media_type):
                continue
            if digest not in manifests:
                raise RepositoryError(
                    f"The manifest of {digest} wasn't read, so what it references is unknown."
                )
            listed = manifests[digest].get("manifests")
            if listed is None:
                if image.is_index:
                    raise RepositoryError(f"The index {digest} lists no manifests.")
                continue
            references[digest] = tuple(entry["digest"] for entry in listed)
            attestations.update(
                entry["digest"]
                for entry in listed
                if (entry.get("annotations") or {}).get("vnd.docker.reference.type")
                == ATTESTATION_REFERENCE_TYPE
            )
        return cls(images, references, frozenset(attestations))

    def with_pulls(self, pulls: Mapping[str, datetime]) -> "Repository":
        """
        :param pulls: Pull times a later read gave, by digest.
        :return: The repository, with each of those images' pull time the later of the two.
        """
        images = dict(self.images)
        for digest, moment in pulls.items():
            image = images[digest]
            if image.last_pulled_at is None or moment > image.last_pulled_at:
                images[digest] = replace(image, last_pulled_at=moment)
        return Repository(images, self.references, self.attestations)

    def is_runnable(self, digest: str) -> bool:
        """
        :param digest: An image's digest.
        :return: True if it is an image a container can run: not an index, and not an attestation.
        """
        image = self.images[digest]
        return (
            digest not in self.references
            and not image.is_index
            and digest not in self.attestations
            and image.artifact_media_type != ATTESTATION_ARTIFACT_MEDIA_TYPE
        )

    # --- Private methods ---

    def _closure(self, root: str) -> Tuple[str, ...]:
        members: List[str] = []
        seen: Set[str] = set()
        queue: Deque[str] = deque([root])
        while queue:
            digest = queue.popleft()
            if digest in seen or digest not in self.images:
                continue
            seen.add(digest)
            members.append(digest)
            queue.extend(self.references.get(digest, ()))
        return tuple(members)


@dataclass(frozen=True)
class Evidence:
    """
    What Inspector says about the repository's images.

    :param vulnerabilities: For each digest, the ids of its qualifying findings' vulnerabilities.
    :param coverage: For each digest, its coverage records' ``ecrImage`` metadata.
    :param finding_usage: For each digest, the in-use details its findings carry.
    """

    vulnerabilities: Mapping[str, FrozenSet[str]]
    coverage: Mapping[str, Tuple[Mapping[str, Any], ...]]
    finding_usage: Mapping[str, Tuple[Mapping[str, Any], ...]]

    @classmethod
    def build(
        cls,
        findings: Iterable[Mapping[str, Any]],
        coverage: Iterable[Mapping[str, Any]],
        settings: Settings,
    ) -> "Evidence":
        """
        Keep the findings and coverage records of this repository's images that qualify, whatever the API's filter let
        through.

        :param findings: ListFindings' ``findings`` items.
        :param coverage: ListCoverage's ``coveredResources`` items.
        :param settings: The job's settings.
        :return: The evidence.
        """
        vulnerabilities: Dict[str, Set[str]] = {}
        finding_usage: Dict[str, List[Mapping[str, Any]]] = {}
        for finding in findings:
            if (
                finding.get("status") != "ACTIVE"
                or finding.get("severity") not in settings.severities
                or finding.get("fixAvailable") != "YES"
            ):
                continue
            details = finding.get("packageVulnerabilityDetails") or {}
            vulnerability = (
                details.get("vulnerabilityId")
                or finding.get("title")
                or finding.get("findingArn")
            )
            for resource in finding.get("resources") or ():
                image = (resource.get("details") or {}).get(
                    "awsEcrContainerImage"
                ) or {}
                if (
                    resource.get("type") != "AWS_ECR_CONTAINER_IMAGE"
                    or image.get("repositoryName") != settings.repository_name
                    or image.get("registry") != settings.registry_id
                    or not image.get("imageHash")
                ):
                    continue
                vulnerabilities.setdefault(image["imageHash"], set()).add(vulnerability)
                finding_usage.setdefault(image["imageHash"], []).append(image)
        records: Dict[str, List[Mapping[str, Any]]] = {}
        for record in coverage:
            match = _IMAGE_ARN.match(record.get("resourceId", ""))
            if (
                record.get("resourceType") != "AWS_ECR_CONTAINER_IMAGE"
                or match is None
                or match["account"] != settings.registry_id
                or match["repository"] != settings.repository_name
            ):
                continue
            records.setdefault(match["digest"], []).append(
                (record.get("resourceMetadata") or {}).get("ecrImage") or {}
            )
        return cls(
            vulnerabilities={
                digest: frozenset(ids) for digest, ids in vulnerabilities.items()
            },
            coverage={digest: tuple(items) for digest, items in records.items()},
            finding_usage={
                digest: tuple(items) for digest, items in finding_usage.items()
            },
        )


@dataclass(frozen=True)
class ImageReference:
    """
    An image as a task definition, a task or a function names it: ``[host/]path[:tag][@digest]``.

    :param host: The registry host, lowercase, or None if the reference names none (Docker Hub).
    :param path: The repository's path in the registry.
    :param tag: The tag, if any.
    :param digest: The digest, if any.
    """

    host: Optional[str]
    path: str
    tag: Optional[str]
    digest: Optional[str]

    @classmethod
    def parse(cls, text: str) -> "ImageReference":
        """
        :param text: An image reference.
        :return: Its parts. A reference with neither a tag nor a digest names the tag ``latest``, as a runtime pulls it.
        """
        name, _, digest = text.partition("@")
        tag: Optional[str] = None
        slash = name.rfind("/")
        colon = name.rfind(":")
        if colon > slash:
            name, tag = name[:colon], name[colon + 1 :]
        host: Optional[str] = None
        first, separator, rest = name.partition("/")
        if separator and ("." in first or ":" in first or first == "localhost"):
            host, name = first.lower(), rest
        if tag is None and not digest:
            tag = "latest"
        return cls(host=host, path=name, tag=tag, digest=digest or None)


@dataclass(frozen=True)
class Use:
    """
    Something ECS or Lambda runs, or would start, that names an image.

    :param source: ``ecs`` or ``lambda``.
    :param via: How it names the image: a running task, a service's deployment, or a function version.
    :param cluster: The ECS cluster's name.
    :param service: The ECS service's name, for a deployment or a task the service started.
    :param task: A running task's ARN, for a task outside a service.
    :param task_definition: The ECS task definition, ``family:revision``.
    :param function: The Lambda function's name.
    :param version: The function's version: a number, or ``$LATEST``.
    """

    source: str
    via: str
    cluster: Optional[str] = None
    service: Optional[str] = None
    task: Optional[str] = None
    task_definition: Optional[str] = None
    function: Optional[str] = None
    version: Optional[str] = None

    @property
    def sort_key(self) -> Tuple[str, ...]:
        """
        :return: A key that orders uses for a log line.
        """
        return tuple(
            value or ""
            for value in (
                self.source,
                self.via,
                self.cluster,
                self.service,
                self.task,
                self.task_definition,
                self.function,
                self.version,
            )
        )

    def describe(self) -> Dict[str, str]:
        """
        :return: Its facts, for a log line, without the empty ones.
        """
        facts = {
            "source": self.source,
            "via": self.via,
            "cluster": self.cluster,
            "service": self.service,
            "task": self.task,
            "task_definition": self.task_definition,
            "function": self.function,
            "version": self.version,
        }
        return {key: value for key, value in facts.items() if value is not None}


@dataclass(frozen=True)
class Runtime:
    """
    What ECS and Lambda say runs in the repository's account and Region, and whether that is all there is to see.

    :param digests: For each digest a use names, the uses.
    :param tags: For each tag of this repository a use names, the uses.
    :param incomplete_because: Why the view isn't complete: who outside the account the repository's policy lets
        pull. Empty if it is complete.
    :param counts: What was read: clusters, running tasks, services, task definitions, function versions.
    """

    digests: Mapping[str, FrozenSet[Use]] = field(default_factory=dict)
    tags: Mapping[str, FrozenSet[Use]] = field(default_factory=dict)
    incomplete_because: Tuple[str, ...] = ()
    counts: Mapping[str, int] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        """
        :return: True if every read finished (a failed one fails the run) and no one outside the account may pull.
        """
        return not self.incomplete_because

    def describe(self) -> Dict[str, Any]:
        """
        :return: The view, for the summary.
        """
        return dict(
            self.counts,
            complete=self.complete,
            incomplete_because=list(self.incomplete_because),
        )

    def merged(self, other: "Runtime") -> "Runtime":
        """
        :param other: A later read.
        :return: Every use either names. A use only protects, so one a read showed counts though a later read misses
            it. The counts and the completeness are this view's.
        """
        return Runtime(
            digests=_union(self.digests, other.digests),
            tags=_union(self.tags, other.tags),
            incomplete_because=self.incomplete_because,
            counts=self.counts,
        )

    def uses_of(self, images: Iterable[Image]) -> FrozenSet[Use]:
        """
        :param images: A unit's manifests.
        :return: The uses that name any of their digests or tags.
        """
        uses: Set[Use] = set()
        for image in images:
            uses.update(self.digests.get(image.digest, ()))
            for tag in image.tags:
                uses.update(self.tags.get(tag, ()))
        return frozenset(uses)


class RuntimeBuilder:
    """
    Builds the view from botocore-shaped answers.

    :param settings: The job's settings.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._digests: Dict[str, Set[Use]] = {}
        self._tags: Dict[str, Set[Use]] = {}
        self._incomplete: List[str] = []
        self._counts: Dict[str, int] = dict.fromkeys(VIEW_COUNTS, 0)

    # --- Public methods ---

    def add_cluster(self) -> None:
        """Count a cluster read."""
        self._count("ecs_clusters")

    def add_function_version(
        self, configuration: Mapping[str, Any], code: Mapping[str, Any]
    ) -> None:
        """
        :param configuration: One ``Functions`` item of ListFunctions, of a container image function.
        :param code: The ``Code`` of GetFunction for that version: Lambda runs the image ``ResolvedImageUri`` names.
        """
        use = Use(
            source=JUDGED_BY_LAMBDA,
            via=VIA_FUNCTION_VERSION,
            function=configuration["FunctionName"],
            version=configuration["Version"],
        )
        self._count("lambda_image_versions")
        # Lambda resolves ImageUri to a digest when the version is deployed, and runs that digest from then on, where
        # ECS resolves a tag each time a task starts. Without a digest in ResolvedImageUri, ImageUri names the image.
        resolved = ImageReference.parse(code.get("ResolvedImageUri") or "")
        if resolved.digest:
            self._add_digest(resolved.digest, use)
        elif code.get("ImageUri"):
            self._add_reference(code["ImageUri"], use)

    def add_registry_policy(self, text: Optional[str]) -> None:
        """
        :param text: The registry's policy, as GetRegistryPolicy gives it; None if it has none.
        """
        self._incomplete.extend(
            registry_policy_gaps(
                text, self._settings.registry_id, self._settings.repository_arn
            )
        )

    def add_repository_policy(self, text: Optional[str]) -> None:
        """
        :param text: The repository's policy, as GetRepositoryPolicy gives it; None if it has none.
        """
        self._incomplete.extend(
            repository_policy_gaps(text, self._settings.registry_id)
        )

    def add_service(
        self,
        cluster_arn: str,
        service: Mapping[str, Any],
        task_definitions: Sequence[Mapping[str, Any]],
        revisions: Sequence[Mapping[str, Any]],
    ) -> None:
        """
        What a service runs, or starts when it scales up or rolls back.

        Its deployments' task definitions name images by tag or digest. Under ECS's deployment controller, a
        deployment resolves each tag to a digest when it starts its first task, and starts every later task of it from
        that digest, though the tag has moved since: its service revision records the digest. So both count: the
        revisions' digests, and the task definitions' tags and digests, for a deployment that has started no task
        yet, a container with version consistency off, or another controller. A service under ECS's controller that
        shows no revision, whose task definitions name this repository by tag with version consistency on, may run a
        digest the job can't see: the view isn't complete.

        :param cluster_arn: The service's cluster.
        :param service: One ``services`` item of DescribeServices.
        :param task_definitions: The ``taskDefinition`` of DescribeTaskDefinition for each task definition it deploys
            (:func:`deployed_task_definitions`).
        :param revisions: The ``serviceRevisions`` of DescribeServiceRevisions for each revision it runs or may go
            back to (:func:`service_revision_arns`).
        """
        self._count("ecs_services")
        cluster = _last_part(cluster_arn)
        name = service.get("serviceName") or _last_part(service["serviceArn"])
        for task_definition in task_definitions:
            use = Use(
                source=JUDGED_BY_ECS,
                via=VIA_DEPLOYMENT,
                cluster=cluster,
                service=name,
                task_definition=_last_part(task_definition["taskDefinitionArn"]),
            )
            for container in task_definition.get("containerDefinitions") or ():
                if container.get("image"):
                    self._add_reference(container["image"], use)
                if revisions or not resolves_tags(service):
                    continue
                reference = ImageReference.parse(container.get("image") or "")
                if (
                    container.get("versionConsistency") != "disabled"
                    and reference.digest is None
                    and self._settings.names_this_repository(reference)
                ):
                    self._incomplete.append(
                        f"ECS service {cluster}/{name} shows no service revision, so not the digest its tag "
                        f"{reference.tag} resolved to"
                    )
        for revision in revisions:
            self._count("ecs_service_revisions")
            use = Use(
                source=JUDGED_BY_ECS,
                via=VIA_DEPLOYMENT,
                cluster=cluster,
                service=name,
                task_definition=_last_part(revision.get("taskDefinition") or "")
                or None,
            )
            for image in revision.get("containerImages") or ():
                if image.get("imageDigest"):
                    self._add_digest(image["imageDigest"], use)
                if image.get("image"):
                    self._add_reference(image["image"], use)

    def add_task(self, cluster_arn: str, task: Mapping[str, Any]) -> None:
        """
        :param cluster_arn: The task's cluster.
        :param task: One ``tasks`` item of DescribeTasks, of a task whose desired status is RUNNING.
        """
        group = task.get("group") or ""
        service = group[len("service:") :] if group.startswith("service:") else None
        use = Use(
            source=JUDGED_BY_ECS,
            via=VIA_RUNNING_TASK,
            cluster=_last_part(cluster_arn),
            service=service,
            # The tasks a service started are told apart by their service.
            task=None if service else task.get("taskArn"),
            task_definition=_last_part(task.get("taskDefinitionArn") or "") or None,
        )
        self._count("ecs_running_tasks")
        for container in task.get("containers") or ():
            # The digest ECS resolved, the index's when the image is one; a container still pending may have none
            # yet, and then the reference names what it will pull.
            if container.get("imageDigest"):
                self._add_digest(container["imageDigest"], use)
            if container.get("image"):
                self._add_reference(container["image"], use)

    def add_task_definition(self) -> None:
        """Count a task definition read."""
        self._count("ecs_task_definitions")

    def build(self) -> Runtime:
        """
        :return: The view.
        """
        return Runtime(
            digests={digest: frozenset(uses) for digest, uses in self._digests.items()},
            tags={tag: frozenset(uses) for tag, uses in self._tags.items()},
            incomplete_because=tuple(dict.fromkeys(self._incomplete)),
            counts=dict(self._counts),
        )

    # --- Private methods ---

    def _add_digest(self, digest: str, use: Use) -> None:
        if _DIGEST.match(digest):
            self._digests.setdefault(digest, set()).add(use)

    def _add_reference(self, text: str, use: Use) -> None:
        reference = ImageReference.parse(text)
        # A digest is the image's content, whichever repository the reference names: the same digest here is the
        # same image. A tag belongs to one repository.
        if reference.digest:
            self._add_digest(reference.digest, use)
        if reference.tag and self._settings.names_this_repository(reference):
            self._tags.setdefault(reference.tag, set()).add(use)

    def _count(self, name: str) -> None:
        self._counts[name] = self._counts.get(name, 0) + 1


def deployed_task_definitions(service: Mapping[str, Any]) -> List[str]:
    """
    :param service: One ``services`` item of DescribeServices.
    :return: The task definitions it runs or may go back to: its own, and those of its PRIMARY and ACTIVE deployments
        and task sets. A service scaled to zero has its deployments too.
    """
    arns = [service.get("taskDefinition")]
    for item in list(service.get("deployments") or ()) + list(
        service.get("taskSets") or ()
    ):
        if item.get("status") in DEPLOYED_STATUSES:
            arns.append(item.get("taskDefinition"))
    return list(dict.fromkeys(arn for arn in arns if arn))


def resolves_tags(service: Mapping[str, Any]) -> bool:
    """
    :param service: One ``services`` item of DescribeServices.
    :return: True if its deployment controller resolves tags to digests when a deployment starts: ECS's.
    """
    return (service.get("deploymentController") or {}).get(
        "type"
    ) in TAG_RESOLVING_CONTROLLERS


def service_revision_arns(
    service: Mapping[str, Any], deployment: Optional[Mapping[str, Any]]
) -> List[str]:
    """
    :param service: One ``services`` item of DescribeServices.
    :param deployment: Its current service deployment, as DescribeServiceDeployments gives it, if it has one.
    :return: The service revisions it runs or may go back to: its current ones, and its current deployment's target,
        the revisions that deployment replaces, and the one it rolls back to.
    """
    arns = [item.get("arn") for item in service.get("currentServiceRevisions") or ()]
    if deployment:
        arns.append((deployment.get("targetServiceRevision") or {}).get("arn"))
        arns.extend(
            item.get("arn") for item in deployment.get("sourceServiceRevisions") or ()
        )
        arns.append((deployment.get("rollback") or {}).get("serviceRevisionArn"))
    return list(dict.fromkeys(arn for arn in arns if arn))


def registry_policy_gaps(
    text: Optional[str], registry_id: str, repository_arn: str
) -> List[str]:
    """
    Who outside the account the registry's policy lets pull from this repository, as far as the job can't prove
    otherwise: :func:`repository_policy_gaps`'s rules, over the statements whose ``Resource`` may name this
    repository (a wildcard included), whose ``NotResource`` doesn't, or that name neither.

    :param text: The policy, as GetRegistryPolicy gives it; None if the registry has none.
    :param registry_id: This account.
    :param repository_arn: This repository's ARN.
    :return: Why the view is incomplete; empty if no one outside the account may pull.
    :raise RepositoryError: if the policy isn't a JSON object.
    """
    return _policy_gaps(text, registry_id, "registry policy", repository_arn)


def repository_policy_gaps(text: Optional[str], registry_id: str) -> List[str]:
    """
    Who outside the account the repository's policy lets pull, as far as the job can't prove otherwise.

    A statement lets pull when it allows ``ecr:BatchGetImage`` or ``ecr:GetDownloadUrlForLayer``, by name, by a
    wildcard, or by a NotAction that leaves one of them out. Then the view is incomplete if it allows any principal
    the job can't prove is this account: another account; ``*``; NotPrincipal; a principal it can't read; an
    organization condition; a service principal other than Lambda acting for this account's functions.

    :param text: The policy, as GetRepositoryPolicy gives it; None if the repository has none.
    :param registry_id: This account.
    :return: Why the view is incomplete; empty if no one outside the account may pull.
    :raise RepositoryError: if the policy isn't a JSON object.
    """
    return _policy_gaps(text, registry_id, "repository policy", None)


def _policy_gaps(
    text: Optional[str],
    registry_id: str,
    source: str,
    repository_arn: Optional[str],
) -> List[str]:
    """
    :param text: The policy; None for none.
    :param registry_id: This account.
    :param source: Which policy it is, as its gaps say.
    :param repository_arn: For a registry's policy, this repository's ARN, which a statement must cover to count. None
        for the repository's own, whose every statement covers it.
    :return: Why the view is incomplete.
    :raise RepositoryError: if the policy isn't a JSON object.
    """
    if text is None:
        return []
    try:
        document = json.loads(text)
    except ValueError as err:
        raise RepositoryError(f"The {source} isn't JSON: {err}") from err
    if not isinstance(document, dict):
        raise RepositoryError(f"The {source} isn't a JSON object.")
    statements = document.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return [f"{source} has a Statement the job can't read"]
    gaps: List[str] = []
    for statement in statements:
        try:
            if repository_arn is None or _covers(statement, repository_arn):
                gaps.extend(_statement_gaps(statement, registry_id, source))
        except _UnreadablePolicy as err:
            gaps.append(f"{source} has a statement the job can't read: {err}")
    return list(dict.fromkeys(gaps))


@dataclass(frozen=True)
class Verdict:
    """
    What the job decided about one unit.

    :param unit: The unit.
    :param tags: The tags of its manifests.
    :param pushed_at: When its root was pushed.
    :param vulnerabilities: The vulnerabilities its manifests' qualifying findings name.
    :param reasons: Why it is protected; empty if nothing protects it.
    :param last_in_use_at: The latest ``lastInUseAt`` Inspector gave for its manifests.
    :param in_use_count: The highest ``inUseCount`` Inspector gave for its manifests.
    :param last_pulled_at: The latest pull ECR recorded for its runnable manifests.
    :param use_judged_by: How its use was judged: by ECS or Lambda (the first of the two that runs it), by Inspector,
        by ECR's pull record, or unknown. None if it has no runnable manifest and nothing runs it.
    :param never_pulled: True if its use was judged from ECR's pull record, and ECR recorded no pull of any of its
        runnable manifests.
    :param runnable_digests: Its runnable manifests: the platform images, or the single manifest. Their pull records
        are what the job reads again before deleting.
    :param in_use_by: The ECS and Lambda uses that name one of its digests or tags.
    :param in_use_sources: What shows it in use: ``ecs``, ``lambda``, ``inspector``, ``ecr_pull_record``.
    """

    unit: Unit
    tags: Tuple[str, ...]
    pushed_at: Optional[datetime]
    vulnerabilities: Tuple[str, ...]
    reasons: FrozenSet[str]
    last_in_use_at: Optional[datetime]
    in_use_count: Optional[int]
    last_pulled_at: Optional[datetime]
    use_judged_by: Optional[str]
    never_pulled: bool
    runnable_digests: Tuple[str, ...] = ()
    in_use_by: Tuple[Use, ...] = ()
    in_use_sources: FrozenSet[str] = frozenset()

    @property
    def is_vulnerable(self) -> bool:
        """
        :return: True if a qualifying finding names one of its manifests.
        """
        return bool(self.vulnerabilities)

    @property
    def is_candidate(self) -> bool:
        """
        :return: True if it is vulnerable and nothing protects it.
        """
        return self.is_vulnerable and not self.reasons

    def describe(self) -> Dict[str, Any]:
        """
        :return: The facts a log line gives about it.
        """
        return {
            "digests": list(self.unit.members),
            "tags": list(self.tags),
            "pushed_at": _iso(self.pushed_at),
            "last_in_use_at": _iso(self.last_in_use_at),
            "in_use_count": self.in_use_count,
            "last_pulled_at": _iso(self.last_pulled_at),
            "use_judged_by": self.use_judged_by,
            "never_pulled": self.never_pulled,
            "in_use_by": [use.describe() for use in self.in_use_by],
            "vulnerabilities": list(self.vulnerabilities),
        }


@dataclass(frozen=True)
class Deletion:
    """
    How one unit is deleted.

    :param verdict: The unit's verdict.
    :param batches: The digests to delete, in order: the root alone first, then what it referenced, level by level.
    :param kept: The manifests it references that another index, still in the repository, references too.
    """

    verdict: Verdict
    batches: Tuple[Tuple[str, ...], ...]
    kept: Tuple[str, ...]

    @property
    def digests(self) -> List[str]:
        """
        :return: The digests it deletes, in order.
        """
        return [digest for batch in self.batches for digest in batch]

    def describe(self) -> Dict[str, Any]:
        """
        :return: The facts a log line gives about it: the digests it deletes, and those it keeps for another index.
        """
        facts = self.verdict.describe()
        facts["digests"] = self.digests
        facts["kept_for_another_index"] = list(self.kept)
        return facts


@dataclass(frozen=True)
class Plan:
    """
    What a run decided.

    :param verdicts: A verdict for every unit.
    :param deletions: The units to delete, oldest first, up to the cap.
    :param left_by_cap: The candidates the cap leaves for a later run.
    :param manifests_seen: How many manifests the repository holds.
    :param view: What ECS and Lambda say runs, and whether the view is complete.
    :param pulled_on_recheck: The candidates' manifests that a read before deleting showed a newer pull of.
    :param dropped_on_recheck: The candidates the reads before deleting showed in use: their roots.
    """

    verdicts: Tuple[Verdict, ...]
    deletions: Tuple[Deletion, ...]
    left_by_cap: Tuple[Verdict, ...]
    manifests_seen: int
    view: Runtime = field(default_factory=Runtime)
    pulled_on_recheck: Tuple[str, ...] = ()
    dropped_on_recheck: Tuple[str, ...] = ()

    @property
    def candidates(self) -> List[Verdict]:
        """
        :return: Every candidate, those the cap leaves included, oldest first.
        """
        return [deletion.verdict for deletion in self.deletions] + list(
            self.left_by_cap
        )

    @property
    def recheck_digests(self) -> List[str]:
        """
        :return: The runnable manifests of every candidate, the cap's leftovers included, once each: whose pull records
            the job reads again before deleting. A pull a read finds, or a task it shows, can only protect more, so
            the candidates after it are among these.
        """
        return list(
            dict.fromkeys(
                digest
                for verdict in self.candidates
                for digest in verdict.runnable_digests
            )
        )

    @property
    def kept_vulnerable(self) -> List[Verdict]:
        """
        :return: The vulnerable units something protects.
        """
        return [
            verdict
            for verdict in self.verdicts
            if verdict.is_vulnerable and verdict.reasons
        ]

    def summary(self, settings: Settings) -> Dict[str, Any]:
        """
        :param settings: The job's settings.
        :return: The run's counts.
        """
        vulnerable = [verdict for verdict in self.verdicts if verdict.is_vulnerable]
        return {
            "repository": settings.repository_name,
            "dry_run": settings.dry_run,
            "images_seen": len(self.verdicts),
            "manifests_seen": self.manifests_seen,
            "vulnerable": len(vulnerable),
            "protected": {
                reason: sum(reason in verdict.reasons for verdict in vulnerable)
                for reason in REASONS
            },
            "judged_never_pulled": sum(verdict.never_pulled for verdict in vulnerable),
            # Of every image seen, vulnerable or not: what each source shows in use.
            "images_in_use_by": {
                source: sum(
                    source in verdict.in_use_sources for verdict in self.verdicts
                )
                for source in USE_SOURCES
            },
            "view": self.view.describe(),
            "pulled_on_recheck": len(self.pulled_on_recheck),
            "dropped_on_recheck": len(self.dropped_on_recheck),
            "candidates": len(self.deletions) + len(self.left_by_cap),
            "deleted": 0 if settings.dry_run else len(self.deletions),
            "would_delete": len(self.deletions) if settings.dry_run else 0,
            "left_by_cap": len(self.left_by_cap),
        }


def rollback_candidates_kept(
    images: Iterable[Image], settings: Settings, now: datetime
) -> Set[str]:
    """
    The rollback candidates the lifecycle policy keeps, by the rules ``policy.tf`` writes.

    The count rule sorts the ACTIVE images with a tag that starts with the prefix by push time, newest first, and keeps
    the first ``count``; a retained image counts among them. The days rule keeps those pushed within ``days``. An image
    either rule keeps is kept. Ties at the count's edge are all kept.

    :param images: The repository's images.
    :param settings: The job's settings.
    :param now: The time of the run.
    :return: The digests of the rollback candidates the lifecycle keeps.
    """
    count = settings.rollback_candidate_retain_count
    days = settings.rollback_candidate_retain_days
    # Without either rule, the lifecycle has no rollback candidate rule, and keeps none as such.
    if not settings.protect_rollback_candidates or (count is None and days is None):
        return set()
    # The lifecycle's rules select images in the standard storage class only: ACTIVE ones.
    candidates = [
        image
        for image in images
        if image.status == ACTIVE
        and any(
            tag.startswith(settings.rollback_candidate_tag_prefix) for tag in image.tags
        )
    ]
    # An image without a push time can't be placed: it is kept, and takes no place from another.
    kept = {image.digest for image in candidates if image.pushed_at is None}
    known = sorted(
        (image for image in candidates if image.pushed_at is not None),
        key=lambda image: image.pushed_at,
        reverse=True,
    )
    if count is not None and count > 0 and known:
        edge = known[min(count, len(known)) - 1].pushed_at
        kept.update(image.digest for image in known if image.pushed_at >= edge)
    if days is not None:
        oldest = now - timedelta(days=days)
        kept.update(image.digest for image in known if image.pushed_at >= oldest)
    return kept


def judge(
    repository: Repository,
    unit: Unit,
    evidence: Evidence,
    view: Runtime,
    settings: Settings,
    rollback_kept: Set[str],
    now: datetime,
) -> Verdict:
    """
    Decide what protects one unit. A reason that holds for any of its manifests protects the whole unit.

    :param repository: The repository.
    :param unit: The unit.
    :param evidence: What Inspector says.
    :param view: What ECS and Lambda say runs.
    :param settings: The job's settings.
    :param rollback_kept: The rollback candidates the lifecycle keeps.
    :param now: The time of the run.
    :return: The verdict.
    """
    images = [repository.images[digest] for digest in unit.members]
    reasons: Set[str] = set()
    if any(set(image.tags) & settings.retain_tags for image in images):
        reasons.add(RETAINED_TAG)
    if any(image.digest in rollback_kept for image in images):
        reasons.add(ROLLBACK_CANDIDATE)
    if any(
        image.pushed_at is None or image.pushed_at > now - settings.min_age
        for image in images
    ):
        reasons.add(RECENT)
    if any(image.status != ACTIVE for image in images):
        reasons.add(NOT_ACTIVE)

    soak_start = now - settings.soak
    in_use_counts: List[int] = []
    last_uses: List[datetime] = []
    for image in images:
        for metadata in evidence.coverage.get(
            image.digest, ()
        ) + evidence.finding_usage.get(image.digest, ()):
            if metadata.get("inUseCount") is not None:
                in_use_counts.append(metadata["inUseCount"])
            if metadata.get("lastInUseAt") is not None:
                last_uses.append(metadata["lastInUseAt"])
    # Only the pulls of what a container runs count: a platform image or a single manifest. An index's own pull time
    # doesn't: the job reads every index with BatchGetImage each run, and ECR records that read as a pull. A real pull
    # of an index records its platform image's pull too, and the job never reads those, so their pull times still say
    # when the image was last pulled. An attestation's doesn't either: a pull that fetches it, as docker pull may,
    # fetches the platform image too, and a tool such as a scanner may fetch the attestation alone.
    runnable = [image for image in images if repository.is_runnable(image.digest)]
    pulls = [
        image.last_pulled_at for image in runnable if image.last_pulled_at is not None
    ]
    # What ECS and Lambda run, or would start: a digest of any of its manifests (ECS gives the index's), or a tag.
    in_use_by = tuple(sorted(view.uses_of(images), key=lambda use: use.sort_key))
    sources = {use.source for use in in_use_by}
    if any(count > 0 for count in in_use_counts) or any(
        moment >= soak_start for moment in last_uses
    ):
        sources.add(JUDGED_BY_INSPECTOR)
    if any(moment >= soak_start for moment in pulls):
        sources.add(JUDGED_BY_PULL_RECORD)
    if sources:
        reasons.add(IN_USE)
    # Fail closed: the use of every manifest a container could run must be judged, by Inspector or by ECR's pull
    # record, unless ECS or Lambda runs the unit. A unit is unknown when any of them is.
    use_by_digest = {
        image.digest: _judge_use(image, evidence, soak_start, view.complete)
        for image in runnable
    }
    uses = set(use_by_digest.values())
    use_judged_by: Optional[str]
    if in_use_by:
        use_judged_by = JUDGED_BY_ECS if JUDGED_BY_ECS in sources else JUDGED_BY_LAMBDA
    elif _UNKNOWN in uses:
        reasons.add(IN_USE_UNKNOWN)
        use_judged_by = JUDGED_UNKNOWN
    elif uses & _BY_PULL_RECORD:
        use_judged_by = JUDGED_BY_PULL_RECORD
    elif uses:
        use_judged_by = JUDGED_BY_INSPECTOR
    else:
        use_judged_by = None

    vulnerabilities: Set[str] = set()
    for image in images:
        vulnerabilities.update(evidence.vulnerabilities.get(image.digest, ()))
    root = repository.images[unit.root]
    return Verdict(
        unit=unit,
        tags=tuple(tag for image in images for tag in image.tags),
        pushed_at=root.pushed_at,
        vulnerabilities=tuple(sorted(vulnerabilities)),
        reasons=frozenset(reasons),
        last_in_use_at=max(last_uses, default=None),
        in_use_count=max(in_use_counts, default=None),
        last_pulled_at=max(pulls, default=None),
        use_judged_by=use_judged_by,
        never_pulled=use_judged_by == JUDGED_BY_PULL_RECORD and not pulls,
        runnable_digests=tuple(image.digest for image in runnable),
        in_use_by=in_use_by,
        in_use_sources=frozenset(sources),
    )


def plan(
    repository: Repository,
    evidence: Evidence,
    view: Runtime,
    settings: Settings,
    now: datetime,
) -> Plan:
    """
    Judge every unit and order the deletions.

    :param repository: The repository.
    :param evidence: What Inspector says.
    :param view: What ECS and Lambda say runs.
    :param settings: The job's settings.
    :param now: The time of the run.
    :return: The plan.
    """
    rollback_kept = rollback_candidates_kept(repository.images.values(), settings, now)
    verdicts = tuple(
        judge(repository, unit, evidence, view, settings, rollback_kept, now)
        for unit in repository.units
    )
    candidates = sorted(
        (verdict for verdict in verdicts if verdict.is_candidate),
        key=lambda verdict: (
            verdict.pushed_at is None,
            verdict.pushed_at or now,
            verdict.unit.root,
        ),
    )
    chosen = candidates[: settings.max_deletions]
    # An index still in the repository keeps everything it references, so a manifest goes only once no index left
    # references it. The cap leaves some candidates' indexes in place: they keep their manifests too.
    present = set(repository.references)
    deletions = []
    for verdict in chosen:
        batches: List[Tuple[str, ...]] = [(verdict.unit.root,)]
        present.discard(verdict.unit.root)
        kept: List[str] = []
        level = list(repository.references.get(verdict.unit.root, ()))
        done: Set[str] = {verdict.unit.root}
        while level:
            batch = []
            next_level: List[str] = []
            for digest in dict.fromkeys(level):
                if digest in done or digest not in repository.images:
                    continue
                done.add(digest)
                if repository.referenced_by.get(digest, set()) & present:
                    kept.append(digest)
                    continue
                batch.append(digest)
                present.discard(digest)
                next_level.extend(repository.references.get(digest, ()))
            if batch:
                batches.append(tuple(batch))
            level = next_level
        deletions.append(
            Deletion(verdict=verdict, batches=tuple(batches), kept=tuple(kept))
        )
    return Plan(
        verdicts=verdicts,
        deletions=tuple(deletions),
        left_by_cap=tuple(candidates[settings.max_deletions :]),
        manifests_seen=len(repository.images),
        view=view,
    )


def parse_manifest(text: str) -> Dict[str, Any]:
    """
    :param text: A manifest, as BatchGetImage returns it.
    :return: The parsed manifest.
    :raise RepositoryError: if it isn't a JSON object.
    """
    manifest = json.loads(text)
    if not isinstance(manifest, dict):
        raise RepositoryError("A manifest isn't a JSON object.")
    return manifest


def _judge_use(
    image: Image, evidence: Evidence, soak_start: datetime, view_complete: bool
) -> str:
    """
    How the use of one runnable manifest is judged, when ECS and Lambda run nothing of its unit.

    :param image: A platform image or a single manifest.
    :param evidence: What Inspector says.
    :param soak_start: The start of the soak.
    :param view_complete: True if ECS and Lambda were read in full and no one outside the account may pull.
    :return: By Inspector, never pulled, pulled within the soak, pulled before it, or unknown.
    """
    coverage = evidence.coverage.get(image.digest, ())
    if _usage_known(coverage):
        return _BY_INSPECTOR
    # Some of Inspector's in-use data, without the rest, says something about use that ECR's pull record can't
    # overrule: such an image is judged as before, unknown. Botocore drops a field its model doesn't know, too.
    if any(
        _has_usage(record)
        for record in coverage + evidence.finding_usage.get(image.digest, ())
    ):
        return _UNKNOWN
    if image.last_pulled_at is None:
        # Never pulled, so never run: a runtime pulls an image to run it, and ECR records that pull on the manifest
        # fetched. Unless it was pushed before AWS released ECR's pull time.
        if image.pushed_at is not None and image.pushed_at >= PULL_RECORD_START:
            return _NEVER_PULLED
        return _UNKNOWN
    if image.last_pulled_at >= soak_start:
        return _PULLED_WITHIN_SOAK
    # Pulled before the soak. With the whole view, nothing that runs it went unseen: no ECS task or deployment, no
    # Lambda version names it, and no other account may pull it. Without, a task that pulled it then may still run it.
    if view_complete:
        return _PULLED_BEFORE_SOAK
    return _UNKNOWN


class _UnreadablePolicy(ValueError):
    """A repository policy statement in a shape the job can't read."""


def _covers(statement: Any, repository_arn: str) -> bool:
    """
    :param statement: One statement of a registry's policy.
    :param repository_arn: This repository's ARN.
    :return: True if it may cover the repository: a ``Resource`` that matches its ARN, a ``NotResource`` that doesn't,
        or neither. Matched as IAM matches, wildcards included, and case-insensitively, so a statement counts rather
        than not.
    :raise _UnreadablePolicy: if it isn't shaped as IAM documents it.
    """
    if not isinstance(statement, dict):
        raise _UnreadablePolicy("not an object")
    if "NotResource" in statement:
        return not any(
            _wildcard_matches(pattern, repository_arn.lower())
            for pattern in _strings(statement["NotResource"], "NotResource")
        )
    if "Resource" in statement:
        return any(
            _wildcard_matches(pattern, repository_arn.lower())
            for pattern in _strings(statement["Resource"], "Resource")
        )
    return True


def _statement_gaps(statement: Any, registry_id: str, source: str) -> List[str]:
    """
    :param statement: One statement of a repository's or a registry's policy.
    :param registry_id: This account.
    :param source: Which policy it is, as its gaps say.
    :return: Who outside the account it lets pull.
    :raise _UnreadablePolicy: if it isn't shaped as IAM documents it.
    """
    if not isinstance(statement, dict):
        raise _UnreadablePolicy("not an object")
    if statement.get("Effect") != "Allow" or not _allows_pull(statement):
        return []
    name = f"statement {statement['Sid']!r}" if statement.get("Sid") else "a statement"
    condition = statement.get("Condition") or {}
    if not isinstance(condition, dict):
        raise _UnreadablePolicy(f"{name}'s Condition isn't an object")
    gaps = [
        f"{source} allows an organization ({key} in {name})"
        for operator in condition.values()
        if isinstance(operator, dict)
        for key in operator
        if key.lower() in ORGANIZATION_KEYS
    ]
    if "NotPrincipal" in statement:
        gaps.append(f"{source} allows everyone but a NotPrincipal ({name})")
    principal = statement.get("Principal")
    if principal is None:
        if "NotPrincipal" not in statement:
            gaps.append(f"{source} names no principal ({name})")
        return gaps
    if principal == "*":
        return gaps + [f"{source} allows *"]
    if not isinstance(principal, dict):
        raise _UnreadablePolicy(f"{name}'s Principal isn't an object")
    for kind, values in principal.items():
        for value in _strings(values, f"{name}'s Principal"):
            if kind == "AWS":
                account = _principal_account(value)
                if value == "*":
                    gaps.append(f"{source} allows *")
                elif account is None:
                    gaps.append(
                        f"{source} allows a principal the job can't place in an account: {value}"
                    )
                elif account != registry_id:
                    gaps.append(f"{source} allows account {account}")
            elif kind == "Service" and value.lower() == "lambda.amazonaws.com":
                if not _for_this_accounts_functions(condition, registry_id):
                    gaps.append(
                        f"{source} allows lambda.amazonaws.com for functions it doesn't prove are this "
                        f"account's ({name})"
                    )
            elif kind == "Service":
                gaps.append(f"{source} allows service {value}")
            else:
                gaps.append(f"{source} allows {kind} principal {value}")
    return gaps


def _allows_pull(statement: Mapping[str, Any]) -> bool:
    """
    :param statement: An Allow statement.
    :return: True if it allows an action a pull needs: by name, by a wildcard, or by a NotAction that leaves it out.
    """
    if "NotAction" in statement:
        excluded = _strings(statement["NotAction"], "NotAction")
        return any(
            not any(_wildcard_matches(pattern, action) for pattern in excluded)
            for action in PULL_ACTIONS
        )
    actions = _strings(statement.get("Action", []), "Action")
    return any(
        _wildcard_matches(pattern, action)
        for pattern in actions
        for action in PULL_ACTIONS
    )


def _wildcard_matches(pattern: str, value: str) -> bool:
    """
    :param pattern: An action or a resource in a policy, maybe with ``*`` and ``?``.
    :param value: An action or an ARN, in lowercase.
    :return: True if the pattern matches it, wildcards included, case-insensitively: as IAM matches an action, and
        more broadly than it matches an ARN.
    """
    expression = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char)
        for char in pattern.lower()
    )
    return re.fullmatch(expression, value) is not None


def _for_this_accounts_functions(
    condition: Mapping[str, Any], registry_id: str
) -> bool:
    """
    :param condition: A statement's Condition.
    :param registry_id: This account.
    :return: True if a condition limits Lambda to this account's functions: ``aws:SourceAccount`` this account, or
        ``aws:SourceArn`` only this account's function ARNs, with no wildcard before the function's name.
    """
    for operator, entries in condition.items():
        if operator not in _RESTRICTING_OPERATORS or not isinstance(entries, dict):
            continue
        for key, values in entries.items():
            listed = _strings(values, f"{key}'s values")
            if not listed:
                continue
            if (
                key.lower() == "aws:sourceaccount"
                and operator.startswith("String")
                and all(value == registry_id for value in listed)
            ):
                return True
            if key.lower() == "aws:sourcearn" and all(
                _is_this_accounts_function(value, registry_id) for value in listed
            ):
                return True
    return False


def _is_this_accounts_function(arn: str, registry_id: str) -> bool:
    parts = arn.split(":")
    return (
        len(parts) >= 7
        and not any("*" in part or "?" in part for part in parts[:6])
        and parts[0] == "arn"
        and parts[2] == "lambda"
        and parts[4] == registry_id
        and parts[5] == "function"
    )


def _principal_account(value: str) -> Optional[str]:
    """
    :param value: An ``AWS`` principal: an account id, or an IAM or STS ARN.
    :return: Its account, or None if the job can't tell.
    """
    if _ACCOUNT_ID.match(value):
        return value
    match = _PRINCIPAL_ARN.match(value)
    return match["account"] if match else None


def _strings(value: Any, what: str) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise _UnreadablePolicy(f"{what} isn't a string or a list of strings")


def _union(
    first: Mapping[str, FrozenSet[Use]], second: Mapping[str, FrozenSet[Use]]
) -> Dict[str, FrozenSet[Use]]:
    merged = {key: frozenset(uses) for key, uses in first.items()}
    for key, uses in second.items():
        merged[key] = merged.get(key, frozenset()) | uses
    return merged


def _last_part(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _has_usage(record: Mapping[str, Any]) -> bool:
    return record.get("inUseCount") is not None or record.get("lastInUseAt") is not None


def _usage_known(records: Sequence[Mapping[str, Any]]) -> bool:
    return bool(records) and all(
        record.get("inUseCount") is not None and record.get("lastInUseAt") is not None
        for record in records
    )


def _boolean(environ: Mapping[str, str], name: str) -> bool:
    value = environ[name]
    if value not in ("true", "false"):
        raise SettingsError(f"{name} must be true or false. Got: {value!r}")
    return value == "true"


def _string_list(environ: Mapping[str, str], name: str) -> List[str]:
    value = json.loads(environ[name])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SettingsError(
            f"{name} must be a JSON list of strings. Got: {environ[name]!r}"
        )
    return value


def _optional_number(
    environ: Mapping[str, str], name: str, kind: type
) -> Optional[Any]:
    value = json.loads(environ[name])
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SettingsError(f"{name} must be a number or null. Got: {environ[name]!r}")
    return kind(value)


def _iso(moment: Optional[datetime]) -> Optional[str]:
    return moment.isoformat() if moment is not None else None
