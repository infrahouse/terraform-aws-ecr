"""
The examples in ``examples/`` and the version pins in the documentation.

The examples are checked offline: ``terraform init -backend=false`` and ``terraform validate``, with no AWS account.
They run against this checkout rather than the published module, so a change on a branch that breaks an example
fails here, before a release ships it.
"""

import configparser
import os
import re
import subprocess
from glob import glob
from os import path as osp
from pathlib import Path
from shutil import copytree, ignore_patterns
from typing import Dict, List, Sequence

import pytest

from tests.conftest import LOG

REPO_ROOT = osp.dirname(osp.dirname(osp.abspath(__file__)))
EXAMPLES_DIR = osp.join(REPO_ROOT, "examples")
EXAMPLES = sorted(
    name for name in os.listdir(EXAMPLES_DIR) if osp.isdir(osp.join(EXAMPLES_DIR, name))
)
# A call of the published module, as a reader would copy it: the registry source, and an exact version on the next
# line.
REGISTRY_MODULE_RE = re.compile(
    r"^(?P<indent>[ \t]*)source[ \t]*=[ \t]*"
    r'"registry\.infrahouse\.com/infrahouse/ecr/aws"[ \t]*\n'
    r'[ \t]*version[ \t]*=[ \t]*"(?P<version>[^"]*)"[ \t]*\n',
    re.MULTILINE,
)
REGISTRY_SOURCE = "registry.infrahouse.com/infrahouse/ecr/aws"


def _read(path: str) -> str:
    """
    :param path: A path relative to the repository's root.
    :return: The file's content.
    """
    with open(osp.join(REPO_ROOT, path)) as fp:
        return fp.read()


# Every file of the README, the docs and the examples that shows a call of the published module.
PINNING_FILES = [
    path
    for path in ["README.md"]
    + sorted(
        osp.relpath(name, REPO_ROOT)
        for name in glob(osp.join(REPO_ROOT, "docs", "*.md"))
        + glob(osp.join(EXAMPLES_DIR, "*", "main.tf"))
    )
    if REGISTRY_SOURCE in _read(path)
]


@pytest.fixture(scope="module")
def terraform_env(tmp_path_factory) -> Dict[str, str]:
    """
    :return: The environment for terraform: one plugin cache for every example, so the providers are downloaded once.
    """
    env = dict(os.environ)
    env["TF_PLUGIN_CACHE_DIR"] = str(tmp_path_factory.mktemp("plugin-cache"))
    env["TF_IN_AUTOMATION"] = "1"
    return env


def _terraform(
    args: Sequence[str], cwd: str, env: Dict[str, str]
) -> subprocess.CompletedProcess:
    """
    Run terraform.

    :param args: Its arguments.
    :param cwd: The root module's directory.
    :param env: Its environment.
    :return: The finished process, with its output.
    """
    result = subprocess.run(
        ["terraform", *args], cwd=cwd, env=env, capture_output=True, text=True
    )
    LOG.info("terraform %s:\n%s%s", " ".join(args), result.stdout, result.stderr)
    return result


def _current_version() -> str:
    """
    :return: ``current_version`` from ``.bumpversion.cfg``: the module's version, the one a release bumps.
    """
    return _bumpversion_config()["bumpversion"]["current_version"]


def _bumpversion_config() -> configparser.ConfigParser:
    """
    :return: ``.bumpversion.cfg``, parsed.
    """
    config = configparser.ConfigParser(interpolation=None)
    config.read(osp.join(REPO_ROOT, ".bumpversion.cfg"))
    return config


def _bumped_files() -> List[str]:
    """
    :return: The files a release bumps the version in.
    """
    prefix = "bumpversion:file:"
    return [
        section[len(prefix) :]
        for section in _bumpversion_config().sections()
        if section.startswith(prefix)
    ]


def _point_example_at_checkout(root_dir: str) -> str:
    """
    Make the example in ``root_dir`` call this checkout instead of the published module. ``main.tf`` is rewritten in
    place: the registry source and its version become a local source.

    :param root_dir: A directory with a copy of the example.
    :return: The version the example pins.
    :raise ValueError: if ``main.tf`` doesn't call the published module exactly once, with its version on the line
        after the source. Otherwise the test could validate another module.
    """
    main_tf = osp.join(root_dir, "main.tf")
    with open(main_tf) as fp:
        content = fp.read()
    matches = list(REGISTRY_MODULE_RE.finditer(content))
    if len(matches) != 1:
        raise ValueError(
            f"{main_tf} must call registry.infrahouse.com/infrahouse/ecr/aws once, with its version on the next "
            f"line. Found {len(matches)} such calls."
        )
    match = matches[0]
    local_source = f'{match["indent"]}source = "{osp.relpath(REPO_ROOT, root_dir)}"\n'
    with open(main_tf, "w") as fp:
        fp.write(content[: match.start()] + local_source + content[match.end() :])
    return match["version"]


@pytest.mark.parametrize("example", EXAMPLES)
def test_example_validates(
    example: str, tmp_path: Path, terraform_env: Dict[str, str]
) -> None:
    """An example pins the current version, and passes init and validate against this checkout."""
    root_dir = str(tmp_path / example)
    copytree(
        osp.join(EXAMPLES_DIR, example),
        root_dir,
        ignore=ignore_patterns(
            ".terraform", ".terraform.lock.hcl", "terraform.tfstate*"
        ),
    )
    pinned_version = _point_example_at_checkout(root_dir)
    assert (
        pinned_version == _current_version()
    ), f"examples/{example} pins version {pinned_version}, but the module is at {_current_version()}."

    for args in (
        ["init", "-backend=false", "-input=false", "-no-color"],
        ["validate", "-no-color"],
    ):
        result = _terraform(args, root_dir, terraform_env)
        assert result.returncode == 0, result.stdout + result.stderr


def test_example_without_registry_source_is_rejected(tmp_path: Path) -> None:
    """An example that doesn't call the published module fails instead of being validated."""
    (tmp_path / "main.tf").write_text('module "ecr" {\n  source = "../.."\n}\n')
    with pytest.raises(ValueError, match="Found 0 such calls"):
        _point_example_at_checkout(str(tmp_path))


@pytest.mark.parametrize("path", PINNING_FILES)
def test_pins_follow_the_release(path: str) -> None:
    """
    Every call of the published module in the README, the docs and the examples pins the current version, on the
    line after its source, and a release bumps it: the file is in ``.bumpversion.cfg``, whose search finds the pin.
    """
    content = _read(path)
    pins = [match["version"] for match in REGISTRY_MODULE_RE.finditer(content)]
    assert len(pins) == content.count(REGISTRY_SOURCE), (
        f"{path} calls {REGISTRY_SOURCE} {content.count(REGISTRY_SOURCE)} times, but only {len(pins)} of them "
        f"have their version on the line after the source."
    )
    assert set(pins) == {
        _current_version()
    }, f"{path} pins {sorted(set(pins))}, but the module is at {_current_version()}."
    assert f'version = "{_current_version()}"' in content
    assert (
        path in _bumped_files()
    ), f"{path} pins the module's version, but a release won't bump it: add it to .bumpversion.cfg."
