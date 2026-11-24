# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## First Steps

**Your first tool call in this repository MUST be reading .claude/CODING_STANDARD.md.
Do not read any other files, search, or take any actions until you have read it.**
This contains InfraHouse's comprehensive coding standards for Terraform, Python, and general formatting rules.

## Module Overview

This is an InfraHouse Terraform module (`infrahouse/ecr/aws`, version tracked
in `locals.tf`) that creates AWS ECR repositories with configurable lifecycle
policies for automatic image expiration, and an opt-in Lambda that
deletes the images Inspector reports vulnerable.

Requires Terraform ~> 1.9, AWS provider >= 6.0, < 7.0, and the `null`
and `time` providers: what `lambda-monitored`, which runs the cleanup,
needs (its `s3-bucket` needs AWS 6.0). Terraform installs a module's
providers whether its count is 0 or not, so the floor applies to every
caller, with the cleanup on or off. AWS provider 5 is not supported.

## Architecture

The module has three concerns split across files:

- **main.tf** creates the `aws_ecr_repository.repo` resource
- **policy.tf** builds a lifecycle policy using
  `aws_ecr_lifecycle_policy_document`: first one rule per `retain_tags`
  entry (priorities 1..n), each keeping the one image with that tag,
  then the rollback candidate rules and the four `expire_*` rules,
  their priorities shifted by n, each active when its variable is
  non-null. The dynamic blocks handle: retained tags, count- and
  age-based rollback candidate expiry, count-based tagged expiry,
  age-based tagged expiry, count-based untagged expiry, and age-based
  untagged expiry

Tagged image rules use `tag_prefix_list` and `tag_pattern_list` for
filtering. Untagged rules (`expire_days_untagged` /
`expire_count_untagged`) are mutually exclusive.

Default tags (environment, service, created_by_module, module_version)
are defined in `locals.tf` and merged onto the ECR repository.

### Vulnerable image cleanup

- **vulnerable_image_cleanup.tf**: with `count`, off by default
  (`vulnerable_image_cleanup_enabled`): `lambda-monitored` 2.2.1, its IAM
  policy (from a policy document), and an EventBridge rule, target and
  Lambda permission for the schedule. `ecr:DescribeImages`,
  `ecr:BatchGetImage` and `ecr:GetRepositoryPolicy` on the repository;
  `ecr:BatchDeleteImage` on it only when
  `vulnerable_image_cleanup_dry_run` is false;
  `inspector2:ListFindings`, `inspector2:ListCoverage` and
  `ecr:GetRegistryPolicy` on `*`. ECS and Lambda, read-only, in the
  repository's account and Region: `ecs:ListClusters`,
  `ecs:DescribeTaskDefinition` and `lambda:ListFunctions` on `*` (no
  resource type); `ecs:ListTasks` and `ecs:ListServices` on `*` with
  `ecs:cluster` held to this account's and Region's clusters;
  `ecs:DescribeTasks` and `ecs:DescribeServices` on its tasks and
  services; `ecs:DescribeServiceDeployments` and
  `ecs:DescribeServiceRevisions` on its services and service
  deployments or revisions (each names both types);
  `lambda:GetFunction` on its functions. The function gets the
  repository's ARN as `REPOSITORY_ARN`.
- **vulnerable_image_cleanup/cleanup.py**: the handler and the AWS I/O:
  reads ECR (every image, every index's manifest, the repository's and
  the registry's policies), Inspector (findings, coverage), ECS (every
  cluster's running tasks; every service's deployed task definitions,
  current deployment and service revisions) and Lambda (every version
  of every container image function); decides; reads again
  the candidates' pull records and the running tasks (`recheck`); then
  deletes or, dry, only logs.
- **vulnerable_image_cleanup/selection.py**: the rules, as pure Python
  over botocore-shaped answers: the view of what runs (`Runtime`,
  `RuntimeBuilder`) and the policies' gaps (`repository_policy_gaps`,
  `registry_policy_gaps`) included.
- **vulnerable_image_cleanup/requirements.txt**: `boto3 ~= 1.41`, the
  first release whose botocore models Inspector's `inUseCount` and
  `lastInUseAt` and ECR's `imageStatus`. Botocore drops fields its model
  lacks; `check_models()` fails the run if they're missing.

The rules, which must stay right:

- An image index and the manifests it references form one unit, judged,
  capped and deleted as one image. A reason that holds for any of its
  manifests protects the unit; a kept index keeps all it references.
- Protected: a tag in `retain_tags`; a rollback candidate the lifecycle
  keeps (same prefix, count and days as `policy.tf`, push time newest
  first, retained images counted, ACTIVE images only, either rule
  keeping), while `vulnerable_image_cleanup_protect_rollback_candidates`;
  in use (ECS or Lambda runs it; `inUseCount` > 0, or `lastInUseAt` or
  ECR's `lastRecordedPullTime` of a platform image or single manifest
  within the soak); pushed within the least age; not ACTIVE; use
  unknown.
- In use by ECS or Lambda (`use_judged_by` `ecs` or `lambda`, the
  uses in `in_use_by`): a running ECS task (any cluster; its
  `imageDigest`, the index's in production, or its reference); a
  service's deployment, scaled to zero too: the digests its service
  revisions resolved (`containerImages[].imageDigest`; its current
  revisions, and its current deployment's target, sources and rollback
  revision), as ECS's version consistency starts every task of a
  deployment from the digest it resolved, though the tag has moved; and
  the task definitions of its PRIMARY and ACTIVE deployments and task
  sets, whose tags count for a deployment that hasn't resolved yet,
  version consistency off, or a CodeDeploy or external controller; or
  any version of a container image function
  (`ResolvedImageUri`; `ImageUri` only without a digest). A digest
  protects the unit whichever member it names, from any repository's
  reference; a tag only from a reference to this repository (account,
  Region, name; FIPS and dual-stack hosts too). No EKS: not read, not
  detected (Aleks, 2026-11-23).
- Use is judged per runnable manifest (a platform image or single
  manifest; never an index's own pull time, as ECR records the job's
  BatchGetImage of an index as a pull, nor an attestation's):
  Inspector's in-use data, both fields, judged as before; part of it,
  unknown; none (no coverage record, or neither field): ECR's pull
  record. Never pulled means never run, so not in use (`never_pulled`);
  pulled within the soak, in use; pulled before it, not in use when the
  view is complete, unknown otherwise, as a long-running task in
  another account may still run it. The view is complete when every
  read finished, every service under ECS's controller whose task
  definition names this repository by tag (version consistency on)
  shows a revision, and neither the repository's nor the registry's
  policy lets anyone outside the account pull from this repository (a
  registry statement counts when its `Resource` may match the
  repository's ARN, its `NotResource` doesn't, or it has neither;
  another account, `*`, `NotPrincipal`, an organization
  key, an unplaceable principal, a service other than Lambda, or Lambda
  not held to this account's functions by `aws:SourceArn` or
  `aws:SourceAccount`, each make it incomplete). Pushed before
  `PULL_RECORD_START`
  (2022-03-03; AWS's release note of 2022-03-02 in botocore 1.24.11's
  changelog) and never pulled: unknown. A unit is unknown when any of
  its runnable manifests is. A shared manifest has one pull record,
  which counts for every index. ECR refreshes the pull time at least
  daily and records a pull only in the repository that served it: the
  docs tell callers to put pinned tags in `retain_tags`.
- Read again before deleting: DescribeImages answers flap for about five
  minutes after a first pull shows (in the test account, 22% to 60% of
  reads lost it, in runs of up to 18 s). So `decide` reads every
  candidate's runnable manifests again, the cap's leftovers included,
  `RECHECK_READS` (13) times, `RECHECK_INTERVAL` (10 s) apart, then the
  running ECS tasks, and judges again with any newer pull and every
  use either read of the tasks showed; that only adds protection, so
  one round is enough. Dry runs read again too.
- Fail closed: any API error, failed page or unreadable manifest raises
  before a deletion, in the reads of the policy, ECS and Lambda too, and
  so does a task or service ECS lists but doesn't describe. ECR's `ImageReferencedByManifestList` or any other
  refusal (but `ImageNotFound`) fails the run, after a `delete_failed`
  line names the digests ECR deleted (`DeletionError.deleted`).
- Deletion order: the index alone, then its manifests that no index
  still in the repository references, level by level. Oldest first, up
  to `vulnerable_image_cleanup_max_deletions`.

## Build and Development Commands

| Command | Purpose |
|---------|---------|
| `make bootstrap` | Install Python dependencies (assumes virtualenv) |
| `make format` | Format with `terraform fmt -recursive` and `black tests vulnerable_image_cleanup` |
| `make lint` | Check formatting (non-modifying) |
| `make test` | Run full test suite |
| `make test-keep` | Run tests, keep AWS infrastructure for debugging |
| `make test-clean` | Run tests, destroy infrastructure (run before PRs) |
| `make clean` | Remove `.pytest_cache` and `.terraform` dirs |

Run a single test with a specific provider version:
```
pytest -xvvs tests/test_module.py -k "aws-6"
```

Default test region: `us-west-2`. Default test role: `arn:aws:iam::303467602807:role/ecr-tester`.

`make test-clean TEST_PATH=tests/<file>.py` needs `TEST_FILTER=aws-6` on
the command line: the Makefile's default filter carries quotes that
break `-k`.

## Testing

Tests in `tests/test_module.py` are integration tests that create real
AWS infrastructure. They use `pytest-infrahouse` fixtures
(`terraform_apply`, `test_role_arn`, `keep_after`, `aws_region`).

Tests are parametrized on the AWS provider version, now v6 (`~> 6.0`)
only: the module needs AWS 6.0. The test dynamically writes
`terraform.tf` and `terraform.tfvars` into `test_data/test_module/` to
configure the provider version and region.

The test module in `test_data/test_module/` is a working Terraform root
module that calls the ECR module at `../../` (the repo root). It sets
the `created_by` tag in provider `default_tags`.

The vulnerable image cleanup's tests:

- `tests/test_vulnerable_image_cleanup.py`: unit tests, no AWS. Run them
  with plain `pytest tests/test_vulnerable_image_cleanup.py`. botocore's
  Stubber serves model-checked answers and fails any unexpected call,
  such as a delete in a dry run.
- `tests/test_vulnerable_image_cleanup_dry_run.py`
  (`test_data/vulnerable_image_cleanup_dry_run/`): on and dry, a
  repository with nothing vulnerable, an ECS service scaled to zero
  naming an image by tag, and a container image function the test makes
  (version 1 and `$LATEST` on two images); checks the deployed function
  reads ECS (the service's revision included) and Lambda under its role
  and sees both, that a repository
  policy letting another account pull makes the view incomplete, the
  role's policies (DescribeTasks's scope through IAM's simulator, as no
  task runs), and that the function's reads record a pull of the
  indexes only. Ageing a pull past the soak can't be done in a test,
  nor a registry policy set in the shared account: those are the unit
  tests'.
- `tests/test_vulnerable_image_cleanup_e2e.py`
  (`test_data/vulnerable_image_cleanup_e2e/`): needs `docker buildx`;
  pushes images from an old Debian base, pulls one with `docker pull`,
  waits for Inspector, and for ECR's answers to agree on that pull for
  3 minutes in a row (one read showing it isn't enough), and checks
  ECR's refusal, the deployed function, that neither the reads nor
  Inspector's scans record a pull of a platform image, and deletion,
  reading Inspector's real coverage with the function's code, the reads
  again included.
- `tests/test_module.py` checks the cleanup creates nothing when off.
- `tests/ecr_images.py`: helpers that push images.

Python dependencies: see `requirements.txt`.

## CI/CD

Six GitHub Actions workflows in `.github/workflows/`:
- **terraform-CI.yml** - PR validation (lint + tests)
- **terraform-CD.yml** - Post-merge on main
- **terraform-review.yml** - Automated Claude code review on PRs
- **docs.yml** - MkDocs deployment to GitHub Pages
- **release.yml** - GitHub Release from tags
- **vuln-scanner-pr.yml** - Security scanning on PRs

## Key Standards

- Use Conventional Commits (`feat:`, `fix:`, `docs:`, etc.)
- Use ternary operators (not `||`) for nullable variable validation
- Use `aws_iam_policy_document` data sources, not `jsonencode` for IAM policies
- All variables need explicit `type` and `description`
- Dynamic blocks (not `count`) for conditional resource sections
- Maximum line length: 120 characters
- All files must end with a newline

## Governed Files

Files marked "managed by Terraform in github-control" must not be
edited directly. These include `.terraform-docs.yml`, `mkdocs.yml`,
`cliff.toml`, `.claude/CODING_STANDARD.md`,
`.claude/TERRAFORM_MODULE_REQUIREMENTS.md`, and several workflow files.

## Releasing

Use `make release-patch`, `make release-minor`, or
`make release-major`. These run `git-cliff` for changelog,
`bumpversion` for version update, then push with tags. The
`release.yml` workflow creates the GitHub Release automatically.
