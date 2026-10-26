"""Shared inventory of the ``infra/account`` stack (FREES-163, FREES-36).

The plan role test and the image build test both pin the exact tracked file set and the
exact ``kind.type.name`` block inventory of the stack through these constants and helpers, so
a new file or block is added to one list in one place.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Final, cast

from hcl2 import api as hcl2_api

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
ACCOUNT_DIRECTORY: Final[Path] = REPOSITORY_ROOT / "infra" / "account"
GIT_TIMEOUT_SECONDS: Final[int] = 30

EXPECTED_FILES: Final[frozenset[str]] = frozenset(
    {
        ".terraform.lock.hcl",
        "account.example.tfvars",
        "backend.hcl.example",
        "budget.tf",
        "iam_image_build_role.tf",
        "iam_plan_role.tf",
        "image_build.tf",
        "locals.tf",
        "oidc.tf",
        "outputs.tf",
        "providers.tf",
        "variables.tf",
        "versions.tf",
    }
)

EXPECTED_BLOCKS: Final[frozenset[str]] = frozenset(
    {
        "data.aws_iam_openid_connect_provider.github",
        "data.aws_iam_policy_document.codebuild_permissions",
        "data.aws_iam_policy_document.codebuild_trust",
        "data.aws_iam_policy_document.image_build_permissions",
        "data.aws_iam_policy_document.image_build_trust",
        "data.aws_iam_policy_document.plan_image_build_permissions",
        "data.aws_iam_policy_document.plan_permissions",
        "data.aws_iam_policy_document.plan_trust",
        "resource.aws_budgets_budget.monthly",
        "resource.aws_cloudwatch_log_group.image_build",
        "resource.aws_codebuild_project.runner_image",
        "resource.aws_ecr_lifecycle_policy.runner_staging",
        "resource.aws_ecr_repository.runner_staging",
        "resource.aws_iam_role.codebuild_service",
        "resource.aws_iam_role.image_build",
        "resource.aws_iam_role.plan",
        "resource.aws_iam_role_policy.codebuild_service",
        "resource.aws_iam_role_policy.image_build",
        "resource.aws_iam_role_policy.plan",
        "resource.aws_iam_role_policy.plan_image_build",
        "resource.aws_kms_key.image_build",
    }
)

LOCAL_ONLY_FILES: Final[frozenset[str]] = frozenset({"backend.hcl", "account.local.tfvars"})
TERRAFORM_FILES: Final[tuple[str, ...]] = tuple(
    sorted(name for name in EXPECTED_FILES if name.endswith(".tf"))
)
AUTO_LOADED_PATTERNS: Final[tuple[str, ...]] = (
    "*.tf.json",
    "*.auto.tfvars",
    "*.auto.tfvars.json",
    "terraform.tfvars",
    "terraform.tfvars.json",
    "override.tf",
    "*_override.tf",
)
PROVIDER_CACHE: Final[str] = ".terraform"


def load_terraform(path: Path) -> dict[str, Any]:
    """Parse one ``.tf`` file with python-hcl2."""
    with path.open(encoding="utf-8") as handle:
        return cast("dict[str, Any]", hcl2_api.load(handle))


def blocks_of(document: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    """Return the blocks of one kind (``resource``, ``data``, ``locals``, ...) of a document."""
    return cast("list[dict[str, Any]]", document.get(kind, []))


def git_tracked_files(directory: Path) -> list[str]:
    """Return the files Git tracks under ``directory``, relative to it."""
    git = shutil.which("git")
    if git is None:
        message = "git is required to list the tracked files of infra/account"
        raise RuntimeError(message)
    prefix = f"{directory.relative_to(REPOSITORY_ROOT).as_posix()}/"
    completed = subprocess.run(
        [git, "-C", str(REPOSITORY_ROOT), "ls-files", "-z", "--", prefix],
        capture_output=True,
        check=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        shell=False,
        env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
    )
    return [entry.removeprefix(prefix) for entry in completed.stdout.split("\0") if entry]


def file_inventory(directory: Path) -> object:
    """Return the tracked files of the real stack, or every file of a copy."""
    if directory == ACCOUNT_DIRECTORY:
        return sorted(git_tracked_files(directory))
    return sorted(
        path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()
    )


def block_inventory(directory: Path) -> object:
    """Return every ``kind.type.name`` block of the stack, including any ``module`` block."""
    found: set[str] = set()
    for path in sorted(directory.glob("*.tf")):
        document = load_terraform(path)
        for kind in ("resource", "data"):
            for entry in blocks_of(document, kind):
                for type_name, named in entry.items():
                    found.update(f"{kind}.{type_name}.{name}" for name in named)
        for entry in blocks_of(document, "module"):
            found.update(f"module.{name}" for name in entry)
    return sorted(found)


def auto_loaded_files_on_disk(directory: Path) -> list[str]:
    """Return files OpenTofu would load implicitly that exist on disk, tracked or not."""
    found: set[str] = set()
    for pattern in AUTO_LOADED_PATTERNS:
        for path in directory.rglob(pattern):
            relative = path.relative_to(directory)
            if path.is_file() and PROVIDER_CACHE not in relative.parts:
                found.add(relative.as_posix())
    return sorted(found)


def copy_account(destination: Path) -> Path:
    """Copy the tracked stack files into ``destination`` for a mutation test."""
    destination.mkdir()
    for name in sorted(EXPECTED_FILES):
        shutil.copy(ACCOUNT_DIRECTORY / name, destination / name)
    return destination
