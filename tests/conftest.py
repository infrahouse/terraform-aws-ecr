import logging
import sys
from os import path as osp, remove
from shutil import rmtree
from textwrap import dedent

from infrahouse_core.logging import setup_logging

DEFAULT_PROGRESS_INTERVAL = 10
TEST_TIMEOUT = 3600

LOG = logging.getLogger(__name__)
TERRAFORM_ROOT_DIR = "test_data"
# The vulnerable image cleanup's Lambda code. Its modules import each other by name, as they do in the Lambda.
CLEANUP_SOURCE_DIR = osp.join(
    osp.dirname(osp.dirname(osp.abspath(__file__))), "vulnerable_image_cleanup"
)
sys.path.insert(0, CLEANUP_SOURCE_DIR)

setup_logging(LOG, debug=True)


def prepare_terraform_root(
    terraform_dir: str, aws_region: str, test_role_arn: str, aws_provider_version: str
) -> None:
    """
    Start a test root afresh: remove what terraform init left, and write terraform.tfvars and terraform.tf, the
    latter with the AWS provider version under test.

    :param terraform_dir: The root module's directory.
    :param aws_region: The test Region.
    :param test_role_arn: The role the provider assumes, if any.
    :param aws_provider_version: The AWS provider's version constraint.
    """
    for state_file in (
        osp.join(terraform_dir, ".terraform"),
        osp.join(terraform_dir, ".terraform.lock.hcl"),
    ):
        if osp.isdir(state_file):
            rmtree(state_file, ignore_errors=True)
        elif osp.isfile(state_file):
            remove(state_file)
    with open(osp.join(terraform_dir, "terraform.tfvars"), "w") as fp:
        # Aligned as terraform fmt aligns it, so make lint passes after a test run.
        fp.write(f'region   = "{aws_region}"\n')
        if test_role_arn:
            fp.write(f'role_arn = "{test_role_arn}"\n')
    with open(osp.join(terraform_dir, "terraform.tf"), "w") as fp:
        fp.write(dedent(f"""
                terraform {{
                  required_providers {{
                    aws = {{
                      source  = "hashicorp/aws"
                      version = "{aws_provider_version}"
                    }}
                  }}
                }}
                """))
