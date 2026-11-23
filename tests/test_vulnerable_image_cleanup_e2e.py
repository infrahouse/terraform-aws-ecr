"""
The vulnerable image cleanup end to end: real images, Inspector's real findings, real deletions.

Two images are built from an old Debian base, so Inspector reports HIGH and CRITICAL findings with fixes in both, and
pushed as BuildKit pushes them: an index with the platform image and its attestation. One is retained. A third index
shares the retained image's platform image.

1. ECR refuses to delete a manifest an index references.
2. The deployed function, with deletion on, deletes nothing: the images are new, and Inspector has no in-use data for
   an image it never saw in use, so they are protected. ECR records each read of an index as a pull of the index.
3. The function's code, from the test, with the least age at 0 and coverage that says the images were last in use 30
   days ago, deletes the unprotected images in order, and keeps the retained one and the manifest it shares.

Step 3 stands in for the deployed function a month later: Inspector won't say an image it just scanned was used a
month ago, and the module won't take a least age under a day.
"""

import base64
import json
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from os import path as osp

import pytest
from pytest_infrahouse import terraform_apply

import cleanup
import selection
from tests.conftest import LOG, TERRAFORM_ROOT_DIR, prepare_terraform_root
from tests.ecr_images import (
    buildx_push,
    docker_available,
    docker_login,
    list_digests,
    push_index,
    wait_for_findings,
    wait_for_pull_time,
)

REPOSITORY = "test-cleanup-e2e"
# Debian 12 as of 2023-06-12, linux/amd64: Inspector reports HIGH and CRITICAL findings with fixes in it.
VULNERABLE_BASE = (
    "public.ecr.aws/docker/library/debian"
    "@sha256:439cd0f6828e5930c3faec89e42e2ec06a1395a03fa459a36095f6c595c1e64d"
)


def index_contents(ecr, digest):
    manifest = json.loads(
        ecr.batch_get_image(
            repositoryName=REPOSITORY,
            imageIds=[{"imageDigest": digest}],
            acceptedMediaTypes=["application/vnd.oci.image.index.v1+json"],
        )["images"][0]["imageManifest"]
    )
    made = {"index": digest}
    for entry in manifest["manifests"]:
        kind = (entry.get("annotations") or {}).get("vnd.docker.reference.type")
        made["attestation" if kind == "attestation-manifest" else "platform"] = entry[
            "digest"
        ]
        if kind != "attestation-manifest":
            descriptor = {"digest": entry["digest"], "size": entry["size"]}
    return made, descriptor


@pytest.mark.skipif(
    not docker_available(),
    reason="The end-to-end test builds images with docker buildx.",
)
@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_end_to_end(
    test_role_arn, keep_after, aws_region, aws_provider_version, boto3_session, tmp_path
):
    terraform_dir = osp.join(TERRAFORM_ROOT_DIR, "vulnerable_image_cleanup_e2e")
    prepare_terraform_root(
        terraform_dir, aws_region, test_role_arn, aws_provider_version
    )
    with terraform_apply(
        terraform_dir, destroy_after=not keep_after, json_output=True
    ) as tf_output:
        LOG.info(json.dumps(tf_output, indent=4))
        ecr = boto3_session.client("ecr", region_name=aws_region)
        inspector = boto3_session.client("inspector2", region_name=aws_region)
        lambda_client = boto3_session.client("lambda", region_name=aws_region)
        repository_url = tf_output["repository_url"]["value"]
        registry_id = tf_output["repository_arn"]["value"].split(":")[4]
        function_name = tf_output["function_name"]["value"]

        docker_login(ecr)
        builder = f"ecr-cleanup-{uuid.uuid4().hex[:8]}"
        subprocess.run(
            [
                "docker",
                "buildx",
                "create",
                "--name",
                builder,
                "--driver",
                "docker-container",
            ],
            check=True,
        )
        try:
            for name in ("candidate", "pinned"):
                context = tmp_path / name
                context.mkdir()
                (context / "image.txt").write_text(f"{name}\n")
                (context / "Dockerfile").write_text(
                    f"FROM {VULNERABLE_BASE}\nCOPY image.txt /image.txt\n"
                )
                buildx_push(builder, str(context), f"{repository_url}:{name}")
        finally:
            subprocess.run(["docker", "buildx", "rm", builder], check=False)
        by_tag = {
            tags[0]: digest
            for digest, tags in list_digests(ecr, REPOSITORY).items()
            if tags
        }
        candidate, _ = index_contents(ecr, by_tag["candidate"])
        pinned, pinned_platform = index_contents(ecr, by_tag["pinned"])
        alias = push_index(ecr, REPOSITORY, "alias", platforms=[pinned_platform])
        LOG.info("candidate %s, pinned %s, alias %s", candidate, pinned, alias)
        wait_for_findings(
            inspector, REPOSITORY, [candidate["platform"], pinned["platform"]]
        )
        before = list_digests(ecr, REPOSITORY)

        # 1. ECR's answer when a manifest an index references is deleted.
        refused = ecr.batch_delete_image(
            repositoryName=REPOSITORY, imageIds=[{"imageDigest": pinned["platform"]}]
        )
        LOG.info("Deleting a referenced manifest: %s", refused["failures"])
        assert [failure["failureCode"] for failure in refused["failures"]] == [
            "ImageReferencedByManifestList"
        ]
        assert list_digests(ecr, REPOSITORY) == before

        # 2. The deployed function, deletion on: everything is new, so everything is kept.
        lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)
        response = lambda_client.invoke(
            FunctionName=function_name, InvocationType="RequestResponse", LogType="Tail"
        )
        LOG.info(base64.b64decode(response["LogResult"]).decode())
        payload = json.loads(response["Payload"].read())
        assert "FunctionError" not in response, payload
        LOG.info(json.dumps(payload, indent=4))
        assert payload["dry_run"] is False
        assert payload["images_seen"] == 3
        assert payload["vulnerable"] == 3
        assert payload["protected"]["retained_tag"] == 1
        assert payload["protected"]["recent"] == 3
        assert payload["deleted"] == 0
        assert list_digests(ecr, REPOSITORY) == before

        # ECR records a BatchGetImage of an index, the test's own above as the function's, as a pull of the index,
        # some time later. Step 3 shows that pull time doesn't protect the index: the platform images, which nothing
        # read, carry none.
        pulled = wait_for_pull_time(ecr, REPOSITORY, candidate["index"], timeout=1200)
        LOG.info(
            "ECR's pull time on the candidate index, which only BatchGetImage read: %s",
            pulled,
        )
        if pulled is None:
            LOG.warning(
                "ECR recorded no pull time within 20 minutes; step 3 can't show it is ignored."
            )

        # 3. The function's code a month later: deletes the candidate whole, and the alias index alone.
        settings = selection.Settings(
            repository_name=REPOSITORY,
            registry_id=registry_id,
            dry_run=False,
            min_severity="HIGH",
            min_age=timedelta(0),
            soak=timedelta(days=2),
            max_deletions=10,
            retain_tags=frozenset({"pinned"}),
            protect_rollback_candidates=True,
            rollback_candidate_tag_prefix="deployed-at-",
            rollback_candidate_retain_count=None,
            rollback_candidate_retain_days=None,
        )
        now = datetime.now(timezone.utc)
        details = cleanup.read_images(settings, ecr)
        repository = selection.Repository.build(
            details, cleanup.read_manifests(settings, ecr, details)
        )
        coverage = [
            {
                "resourceType": "AWS_ECR_CONTAINER_IMAGE",
                "resourceId": f"arn:aws:ecr:{aws_region}:{registry_id}:repository/{REPOSITORY}/{digest}",
                "resourceMetadata": {
                    "ecrImage": {
                        "inUseCount": 0,
                        "lastInUseAt": now - timedelta(days=30),
                    }
                },
            }
            for digest in repository.images
            if repository.is_runnable(digest)
        ]
        evidence = selection.Evidence.build(
            cleanup.read_findings(settings, inspector), coverage, settings
        )
        summary = cleanup.execute(
            settings, ecr, selection.plan(repository, evidence, settings, now)
        )
        LOG.info(json.dumps(summary, indent=4))
        assert summary["deleted"] == 2
        assert sorted(list_digests(ecr, REPOSITORY)) == sorted(pinned.values())
