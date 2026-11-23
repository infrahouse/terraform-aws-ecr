"""
Helpers that push images to ECR for the vulnerable image cleanup's integration tests.
"""

import base64
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tests.conftest import LOG

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
IN_TOTO = "application/vnd.in-toto+json"


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def upload_blob(ecr: Any, repository: str, data: bytes) -> Dict[str, Any]:
    """
    Upload a blob through ECR's layer API.

    :return: The descriptor's digest and size.
    """
    digest = sha256(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    try:
        ecr.complete_layer_upload(
            repositoryName=repository, uploadId=upload_id, layerDigests=[digest]
        )
    except ecr.exceptions.LayerAlreadyExistsException:
        pass
    return {"digest": digest, "size": len(data)}


def put_manifest(
    ecr: Any, repository: str, manifest: Dict[str, Any], tag: Optional[str] = None
) -> Dict[str, Any]:
    """
    Push a manifest.

    :return: Its descriptor: the digest and the size.
    """
    body = json.dumps(manifest, separators=(",", ":")).encode()
    kwargs = dict(
        repositoryName=repository,
        imageManifest=body.decode(),
        imageManifestMediaType=manifest["mediaType"],
        imageDigest=sha256(body),
    )
    if tag:
        kwargs["imageTag"] = tag
    digest = ecr.put_image(**kwargs)["image"]["imageId"]["imageDigest"]
    return {"digest": digest, "size": len(body)}


def push_synthetic_platform(
    ecr: Any, repository: str, name: str, tag: Optional[str] = None
) -> Dict[str, Any]:
    """
    Push a platform image without Docker: one tiny layer and no OS, so Inspector finds nothing in it. Tagged, it is
    a single-manifest image.

    :return: Its descriptor: the digest and the size.
    """
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w") as tar:
        content = f"{name}\n".encode()
        info = tarfile.TarInfo(name="hello.txt")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    layer = gzip.compress(tar_bytes.getvalue(), mtime=0)
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [sha256(tar_bytes.getvalue())]},
        }
    ).encode()
    return put_manifest(
        ecr,
        repository,
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": dict(upload_blob(ecr, repository, config), mediaType=OCI_CONFIG),
            "layers": [dict(upload_blob(ecr, repository, layer), mediaType=OCI_LAYER)],
        },
        tag,
    )


def push_synthetic_index(
    ecr: Any, repository: str, name: str, tag: str
) -> Dict[str, str]:
    """
    Push an index as BuildKit does, without Docker: a platform image with one tiny layer and no OS, so Inspector
    finds nothing in it, and an attestation.

    :return: The digests of the index, the platform image and the attestation, and the platform image's descriptor.
    """
    platform = push_synthetic_platform(ecr, repository, name)
    statement = json.dumps(
        {"_type": "https://in-toto.io/Statement/v0.1", "subject": [{"name": name}]}
    ).encode()
    attestation_config = json.dumps(
        {
            "architecture": "unknown",
            "os": "unknown",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
        }
    ).encode()
    attestation_manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": dict(
            upload_blob(ecr, repository, attestation_config), mediaType=OCI_CONFIG
        ),
        "layers": [
            dict(
                upload_blob(ecr, repository, statement),
                mediaType=IN_TOTO,
                annotations={
                    "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"
                },
            )
        ],
    }
    attestation = put_manifest(ecr, repository, attestation_manifest)
    index = push_index(
        ecr,
        repository,
        tag,
        platforms=[platform],
        attestations=[(attestation, platform["digest"])],
    )
    return {
        "index": index,
        "platform": platform["digest"],
        "attestation": attestation["digest"],
        "platform_descriptor": platform,
    }


def push_index(
    ecr: Any,
    repository: str,
    tag: str,
    platforms: Sequence[Dict[str, Any]],
    attestations: Sequence[Tuple[Dict[str, Any], str]] = (),
) -> str:
    """
    Push an index that references manifests already in the repository. It reads none of them, so it records no pull.

    :param platforms: The platform images' descriptors: digest and size.
    :param attestations: The attestations' descriptors, each with the digest of the platform image it attests.
    :return: The index's digest.
    """
    manifests = [
        dict(
            descriptor,
            mediaType=OCI_MANIFEST,
            platform={"architecture": "amd64", "os": "linux"},
        )
        for descriptor in platforms
    ]
    for descriptor, subject in attestations:
        manifests.append(
            dict(
                descriptor,
                mediaType=OCI_MANIFEST,
                annotations={
                    "vnd.docker.reference.digest": subject,
                    "vnd.docker.reference.type": "attestation-manifest",
                },
                platform={"architecture": "unknown", "os": "unknown"},
            )
        )
    index = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests}
    return put_manifest(ecr, repository, index, tag)["digest"]


def list_digests(ecr: Any, repository: str) -> Dict[str, List[str]]:
    """
    :return: Every image in the repository: its digest, with its tags.
    """
    images = {}
    for page in ecr.get_paginator("describe_images").paginate(
        repositoryName=repository, filter={"tagStatus": "ANY", "imageStatus": "ANY"}
    ):
        for detail in page["imageDetails"]:
            images[detail["imageDigest"]] = sorted(detail.get("imageTags", []))
    return images


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(["docker", "buildx", "version"], capture_output=True).returncode
        == 0
    )


def docker_login(ecr: Any) -> None:
    token = ecr.get_authorization_token()["authorizationData"][0]
    user, password = (
        base64.b64decode(token["authorizationToken"]).decode().split(":", 1)
    )
    subprocess.run(
        [
            "docker",
            "login",
            "-u",
            user,
            "--password-stdin",
            token["proxyEndpoint"].replace("https://", ""),
        ],
        input=password.encode(),
        check=True,
    )


def buildx_push(builder: str, context: str, image: str) -> None:
    """Build for linux/amd64 and push an index with the platform image and its provenance attestation."""
    subprocess.run(
        [
            "docker",
            "buildx",
            "build",
            "--builder",
            builder,
            "--platform",
            "linux/amd64",
            "--provenance=mode=min",
            "--sbom=false",
            "--push",
            "-t",
            image,
            context,
        ],
        check=True,
    )


def wait_for_findings(
    inspector: Any, repository: str, digests: Sequence[str], timeout: int = 1800
) -> None:
    """
    Wait until Inspector has an ACTIVE finding on each digest.
    """
    deadline = time.time() + timeout
    while True:
        found = set()
        for page in inspector.get_paginator("list_findings").paginate(
            filterCriteria={
                "ecrImageRepositoryName": [
                    {"comparison": "EQUALS", "value": repository}
                ],
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            }
        ):
            for finding in page["findings"]:
                for resource in finding["resources"]:
                    found.add(resource["details"]["awsEcrContainerImage"]["imageHash"])
        missing = set(digests) - found
        LOG.info(
            "Inspector findings on %d of %d images",
            len(digests) - len(missing),
            len(digests),
        )
        if not missing:
            return
        if time.time() > deadline:
            raise TimeoutError(
                f"Inspector reported nothing on {sorted(missing)} within {timeout}s"
            )
        time.sleep(30)


def wait_for_pull_time(
    ecr: Any, repository: str, digest: str, timeout: int
) -> Optional[Any]:
    """
    Wait until ECR records a pull time on an image. ECR refreshes it "at least once every 24 hours", so it may not
    come within the timeout.

    :return: The pull time, or None if none came within the timeout.
    """
    deadline = time.time() + timeout
    while True:
        detail = ecr.describe_images(
            repositoryName=repository, imageIds=[{"imageDigest": digest}]
        )["imageDetails"][0]
        if detail.get("lastRecordedPullTime"):
            return detail["lastRecordedPullTime"]
        if time.time() > deadline:
            return None
        time.sleep(30)


def pull_times(ecr: Any, repository: str) -> Dict[str, Optional[Any]]:
    """
    :return: ECR's lastRecordedPullTime of every image in the repository, by digest; None for an image without one.
    """
    times = {}
    for page in ecr.get_paginator("describe_images").paginate(
        repositoryName=repository, filter={"tagStatus": "ANY", "imageStatus": "ANY"}
    ):
        for detail in page["imageDetails"]:
            times[detail["imageDigest"]] = detail.get("lastRecordedPullTime")
    return times
