"""
The vulnerable image cleanup end to end: real images, Inspector's real findings and coverage, ECR's real pull record,
real deletions.

Three images are built from an old Debian base, so Inspector reports HIGH and CRITICAL findings with fixes in them, and
pushed as BuildKit pushes them: an index with the platform image and its attestation. "pinned" is retained, "pulled"
is pulled by tag with docker pull, and "candidate" is neither. A fourth index, "alias", shares the pinned platform
image.

1. ECR refuses to delete a manifest an index references.
2. The test pulls "pulled", and waits for ECR to record the pull on its platform image.
3. The deployed function, with deletion on, deletes nothing: the images are new.
4. ECR's pull record: the reads of the indexes, the test's with the function's code and the function's, show as pulls
   of the indexes. Neither they nor Inspector's scans show as a pull of a platform image.
5. The function's code, from the test, with the least age at 0, reads Inspector's real coverage, which has no in-use
   data, and ECR's pull record. It deletes the never-pulled candidate whole and the alias index alone, and keeps the
   retained image and the pulled one.

Step 5 stands in for the deployed function a week later: the module won't take a least age under a day.
"""

import base64
import json
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from os import path as osp
from typing import Any, Dict, Mapping, Tuple

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
    pull_times,
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
# How long the test waits for ECR to record a pull. ECR refreshes the pull time "at least once every 24 hours"; in
# the test account it has shown within a minute or two.
PULL_TIMEOUT = 1200


def index_contents(
    manifests: Mapping[str, Mapping[str, Any]], digest: str
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """
    :param manifests: The manifests the function's code read, by digest.
    :param digest: A BuildKit index's digest.
    :return: The digests of the index, its platform image and its attestation, and the platform image's descriptor.
    """
    made = {"index": digest}
    descriptor = {}
    for entry in manifests[digest]["manifests"]:
        kind = (entry.get("annotations") or {}).get("vnd.docker.reference.type")
        if kind == "attestation-manifest":
            made["attestation"] = entry["digest"]
        else:
            made["platform"] = entry["digest"]
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
        # The deployed function's settings, but for the least age.
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
            for name in ("candidate", "pinned", "pulled"):
                context = tmp_path / name
                context.mkdir()
                (context / "image.txt").write_text(f"{name}\n")
                (context / "Dockerfile").write_text(
                    f"FROM {VULNERABLE_BASE}\nCOPY image.txt /image.txt\n"
                )
                buildx_push(builder, str(context), f"{repository_url}:{name}")
        finally:
            subprocess.run(["docker", "buildx", "rm", builder], check=False)
        # Read the indexes as the function does: BatchGetImage of each index, and of nothing else.
        details = cleanup.read_images(settings, ecr)
        manifests = cleanup.read_manifests(settings, ecr, details)
        by_tag = {
            tag: detail["imageDigest"]
            for detail in details
            for tag in detail.get("imageTags", [])
        }
        candidate, _ = index_contents(manifests, by_tag["candidate"])
        pinned, pinned_platform = index_contents(manifests, by_tag["pinned"])
        pulled, _ = index_contents(manifests, by_tag["pulled"])
        alias = push_index(ecr, REPOSITORY, "alias", platforms=[pinned_platform])
        LOG.info(
            "candidate %s, pinned %s, pulled %s, alias %s",
            candidate,
            pinned,
            pulled,
            alias,
        )
        wait_for_findings(
            inspector,
            REPOSITORY,
            [candidate["platform"], pinned["platform"], pulled["platform"]],
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

        # 2. A pull by tag, as a runtime pulls an image to run it.
        image = f"{repository_url}:pulled"
        subprocess.run(
            ["docker", "pull", "--platform", "linux/amd64", image], check=True
        )
        subprocess.run(["docker", "image", "rm", image], check=False)
        pulled_at = wait_for_pull_time(
            ecr, REPOSITORY, pulled["platform"], timeout=PULL_TIMEOUT
        )
        LOG.info("ECR's pull time on the pulled platform image: %s", pulled_at)
        if pulled_at is None:
            LOG.warning(
                "ECR recorded no pull of the pulled platform image within %d s: it counts as never pulled.",
                PULL_TIMEOUT,
            )
        pull_recorded = pulled_at is not None

        # 3. The deployed function, deletion on: everything is new, so everything is kept.
        lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)
        response = lambda_client.invoke(
            FunctionName=function_name, InvocationType="RequestResponse", LogType="Tail"
        )
        LOG.info(base64.b64decode(response["LogResult"]).decode())
        payload = json.loads(response["Payload"].read())
        assert "FunctionError" not in response, payload
        LOG.info(json.dumps(payload, indent=4))
        assert payload["dry_run"] is False
        assert payload["images_seen"] == 4
        assert payload["vulnerable"] == 4
        assert payload["protected"]["retained_tag"] == 1
        assert payload["protected"]["recent"] == 4
        assert payload["protected"]["in_use"] == int(pull_recorded)
        assert payload["judged_never_pulled"] == 4 - int(pull_recorded)
        assert payload["deleted"] == 0
        assert list_digests(ecr, REPOSITORY) == before

        # 4. The reads of the indexes show as pulls of the indexes. Neither they nor Inspector's scans, which found
        # what they found in the platform images, show on a platform image or an attestation the test didn't pull.
        index_pulled_at = wait_for_pull_time(
            ecr, REPOSITORY, candidate["index"], timeout=PULL_TIMEOUT
        )
        times = pull_times(ecr, REPOSITORY)
        LOG.info("Pull times: %s", json.dumps(times, default=str, indent=4))
        if index_pulled_at is None:
            LOG.warning(
                "ECR recorded no pull of the candidate index within %d s: the pull times say nothing.",
                PULL_TIMEOUT,
            )
        else:
            unpulled = [
                candidate["platform"],
                candidate["attestation"],
                pinned["platform"],
                pinned["attestation"],
            ]
            assert [times[digest] for digest in unpulled] == [None] * len(
                unpulled
            ), times

        # 5. The function's code a week later: Inspector's coverage and ECR's pull record, as the function reads them.
        coverage = cleanup.read_coverage(settings, inspector)
        LOG.info(
            "Inspector's coverage: %s", json.dumps(coverage, default=str, indent=4)
        )
        cleanup.check_models(ecr, inspector)
        plan = cleanup.decide(settings, ecr, inspector, datetime.now(timezone.utc))
        verdicts = {verdict.unit.root: verdict for verdict in plan.verdicts}
        for root in (candidate["index"], alias):
            # Judged from ECR's pull record: Inspector gives no in-use data on an image it never saw in use.
            assert verdicts[root].use_judged_by == selection.JUDGED_BY_PULL_RECORD
            assert verdicts[root].never_pulled
            assert not verdicts[root].reasons
        assert selection.RETAINED_TAG in verdicts[pinned["index"]].reasons
        if pull_recorded:
            assert verdicts[pulled["index"]].reasons == {selection.IN_USE}
            assert not verdicts[pulled["index"]].never_pulled
        summary = cleanup.execute(settings, ecr, plan)
        LOG.info(json.dumps(summary, indent=4))
        # The candidate and the alias index; and the pulled image, if ECR didn't show its pull in time.
        assert summary["deleted"] == 3 - int(pull_recorded)
        kept = list(pinned.values()) + (list(pulled.values()) if pull_recorded else [])
        assert sorted(list_digests(ecr, REPOSITORY)) == sorted(kept)
