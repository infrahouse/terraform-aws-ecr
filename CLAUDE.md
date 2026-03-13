# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## First Steps

**Your first tool call in this repository MUST be reading .claude/CODING_STANDARD.md.
Do not read any other files, search, or take any actions until you have read it.**
This contains InfraHouse's comprehensive coding standards for Terraform, Python, and general formatting rules.

## Module Overview

This is an InfraHouse Terraform module (`infrahouse/ecr/aws`, version tracked
in `locals.tf`) that creates AWS ECR repositories with configurable lifecycle
policies for automatic image expiration. Requires Terraform ~> 1.5 and
AWS provider >= 5.11, < 7.0.

## Architecture

The module has two main concerns split across files:

- **main.tf** creates the `aws_ecr_repository.repo` resource
- **policy.tf** builds a lifecycle policy using
  `aws_ecr_lifecycle_policy_document` with four dynamic rule blocks
  (priorities 1-4) that conditionally activate based on which `expire_*`
  variables are non-null. The dynamic blocks handle: count-based tagged
  expiry, age-based tagged expiry, count-based untagged expiry, and
  age-based untagged expiry

Tagged image rules use `tag_prefix_list` and `tag_pattern_list` for
filtering. Untagged rules (`expire_days_untagged` /
`expire_count_untagged`) are mutually exclusive.

Default tags (environment, service, created_by_module, module_version)
are defined in `locals.tf` and merged onto the ECR repository.

## Build and Development Commands

| Command | Purpose |
|---------|---------|
| `make bootstrap` | Install Python dependencies (assumes virtualenv) |
| `make format` | Format with `terraform fmt -recursive` and `black tests` |
| `make lint` | Check formatting (non-modifying) |
| `make test` | Run full test suite |
| `make test-keep` | Run tests, keep AWS infrastructure for debugging |
| `make test-clean` | Run tests, destroy infrastructure (run before PRs) |
| `make clean` | Remove `.pytest_cache` and `.terraform` dirs |

Run a single test with a specific provider version:
```
pytest -xvvs tests/test_module.py -k "aws-5"
```

Default test region: `us-west-2`. Default test role: `arn:aws:iam::303467602807:role/ecr-tester`.

## Testing

Tests in `tests/test_module.py` are integration tests that create real
AWS infrastructure. They use `pytest-infrahouse` fixtures
(`terraform_apply`, `test_role_arn`, `keep_after`, `aws_region`).

Tests are parametrized to run against both AWS provider v5 (`~> 5.31`)
and v6 (`~> 6.0`). The test dynamically writes `terraform.tf` and
`terraform.tfvars` into `test_data/test_module/` to configure the
provider version and region.

The test module in `test_data/test_module/` is a working Terraform root
module that calls the ECR module at `../../` (the repo root). It sets
the `created_by` tag in provider `default_tags`.

Python dependencies: `infrahouse-core ~= 0.17`,
`pytest-infrahouse ~= 0.15`.

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