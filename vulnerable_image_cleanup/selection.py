"""
Decides which images the vulnerable image cleanup deletes.

Nothing here calls AWS. The functions take the answers ECR and Inspector give, shaped as botocore
returns them, so the rules can be tested on their own.

An image is protected, and kept, when any of these hold:

* it carries a tag in ``retain_tags``;
* it is a rollback candidate the lifecycle policy keeps (``policy.tf``);
* it is in use, or was within the soak;
* it was pushed within the least age;
* it isn't ACTIVE (archived images are outside the lifecycle's rules too);
* the job can't tell whether it is in use.

An image index and the manifests it references are judged, and deleted, as one image: a "unit".
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
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

_IMAGE_ARN = re.compile(
    r"^arn:[^:]+:ecr:[^:]+:(?P<account>\d{12}):repository/(?P<repository>.+)/(?P<digest>sha256:[0-9a-f]{64})$"
)


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
    :param last_pulled_at: The latest pull ECR recorded for its manifests.
    """

    unit: Unit
    tags: Tuple[str, ...]
    pushed_at: Optional[datetime]
    vulnerabilities: Tuple[str, ...]
    reasons: FrozenSet[str]
    last_in_use_at: Optional[datetime]
    in_use_count: Optional[int]
    last_pulled_at: Optional[datetime]

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
    """

    verdicts: Tuple[Verdict, ...]
    deletions: Tuple[Deletion, ...]
    left_by_cap: Tuple[Verdict, ...]
    manifests_seen: int

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
    settings: Settings,
    rollback_kept: Set[str],
    now: datetime,
) -> Verdict:
    """
    Decide what protects one unit. A reason that holds for any of its manifests protects the whole unit.

    :param repository: The repository.
    :param unit: The unit.
    :param evidence: What Inspector says.
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
    # An index's own pull time doesn't count: the job reads every index with BatchGetImage each run, and ECR records
    # that read as a pull. A real pull of an index records its platform image's pull too, and the job never reads
    # those, so their pull times still say when the image was last pulled.
    pulls = [
        image.last_pulled_at
        for image in images
        if image.last_pulled_at is not None
        and image.digest not in repository.references
    ]
    if any(count > 0 for count in in_use_counts) or any(
        moment >= soak_start for moment in last_uses + pulls
    ):
        reasons.add(IN_USE)
    # Fail closed: every manifest a container could run needs a coverage record that says how it was used. Botocore
    # drops a field its model doesn't know, and Inspector leaves both out for an image it hasn't seen in use.
    for image in images:
        if repository.is_runnable(image.digest) and not _usage_known(
            evidence.coverage.get(image.digest, ())
        ):
            reasons.add(IN_USE_UNKNOWN)

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
    )


def plan(
    repository: Repository, evidence: Evidence, settings: Settings, now: datetime
) -> Plan:
    """
    Judge every unit and order the deletions.

    :param repository: The repository.
    :param evidence: What Inspector says.
    :param settings: The job's settings.
    :param now: The time of the run.
    :return: The plan.
    """
    rollback_kept = rollback_candidates_kept(repository.images.values(), settings, now)
    verdicts = tuple(
        judge(repository, unit, evidence, settings, rollback_kept, now)
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
