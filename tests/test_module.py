import json
from os import path as osp
from textwrap import dedent

from pytest_infrahouse import terraform_apply

from tests.conftest import (
    LOG,
    TRACE_TERRAFORM,
    TERRAFORM_ROOT_DIR,
)


def test_module(
    test_role_arn,
    keep_after,
    aws_region,
):
    terraform_dir = osp.join(TERRAFORM_ROOT_DIR, "test_module")

    with open(osp.join(terraform_dir, "terraform.tfvars"), "w") as fp:
        fp.write(
            dedent(
                f"""
                region          = "{aws_region}"
                """
            )
        )
        if test_role_arn:
            fp.write(
                dedent(
                    f"""
                    role_arn      = "{test_role_arn}"
                    """
                )
            )
    with terraform_apply(
        terraform_dir,
        destroy_after=not keep_after,
        json_output=True,
        enable_trace=TRACE_TERRAFORM,
    ) as tf_output:
        LOG.info(json.dumps(tf_output, indent=4))
