from pprint import pformat
from textwrap import dedent
from time import sleep

import pytest
import logging
from os import path as osp

from infrahouse_toolkit.logging import setup_logging
from infrahouse_toolkit.terraform import terraform_apply

DEFAULT_PROGRESS_INTERVAL = 10
TEST_TIMEOUT = 3600
TRACE_TERRAFORM = False
UBUNTU_CODENAME = "jammy"

LOG = logging.getLogger(__name__)
TERRAFORM_ROOT_DIR = "test_data"

setup_logging(LOG, debug=True)
