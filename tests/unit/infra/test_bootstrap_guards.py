"""The bootstrap refuses unexpected stack files and extra variables (FREES-163 review, FREES-36).

The rendered bootstrap script is sourced, which defines its functions without running ``main``,
and two of its guards are called against a temporary Git checkout of ``infra/account``:

* ``refuse_unexpected_stack_files`` fails on uncommitted changes and on any untracked file that
  OpenTofu could load, but accepts the gitignored local files the bootstrap itself writes and
  ignores the provider cache in ``.terraform``;
* ``verify_tfvars_file`` accepts an ``account.local.tfvars`` that sets ``budget_alert_email`` once
  and nothing else.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING, Final

import pytest

from tests.unit.infra.account_stack import EXPECTED_FILES, REPOSITORY_ROOT, copy_account

if TYPE_CHECKING:
    from pathlib import Path

TEMPLATE: Final[Path] = REPOSITORY_ROOT / "infra" / "bootstrap" / "bootstrap.sh.tmpl"
RENDERED_VALUES: Final[dict[str, str]] = {
    "@@AWS_ACCOUNT_ID@@": "910736812072",
    "@@AWS_REGION@@": "eu-west-1",
    "@@STATE_BUCKET@@": "freesecdev-tfstate-910736812072-eu-west-1",
    "@@GITHUB_REPOSITORY@@": "FreeSecDev/ansible-linux-compliance",
    "@@RUNNER_REPOSITORY@@": "FreeSecDev/linux-compliance-runner",
}
TIMEOUT_SECONDS: Final[int] = 60
BASH: Final[str] = shutil.which("bash") or "/bin/bash"
GIT: Final[str] = shutil.which("git") or "/usr/bin/git"
VALID_TFVARS: Final[str] = 'budget_alert_email = "alerts@example.org"\n'


def clean_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def run_git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        [
            GIT,
            "-C",
            str(repository),
            "-c",
            "user.name=test",
            "-c",
            "user.email=t@example.invalid",
            *arguments,
        ],
        check=True,
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
        env=clean_environment(),
    )


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    stack = repository / "infra"
    stack.mkdir(parents=True)
    copy_account(stack / "account")
    script = tmp_path / "bootstrap.sh"
    text = TEMPLATE.read_text(encoding="utf-8")
    for placeholder, value in RENDERED_VALUES.items():
        text = text.replace(placeholder, value)
    script.write_text(text, encoding="utf-8")
    run_git(repository, "init", "--quiet")
    run_git(repository, "add", ".")
    run_git(repository, "commit", "--quiet", "-m", "stack")
    return repository


def call(repository: Path, function: str) -> subprocess.CompletedProcess[str]:
    script = repository.parent / "bootstrap.sh"
    return subprocess.run(
        [
            BASH,
            "-c",
            f'source "$1" && cd "$2" && {function}',
            "guard",
            str(script),
            str(repository),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_SECONDS,
        env=clean_environment(),
    )


def account(repository: Path) -> Path:
    return repository / "infra" / "account"


def test_template_does_not_run_main_when_sourced(checkout: Path) -> None:
    result = call(checkout, "true")
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_clean_checkout_with_local_files_passes(checkout: Path) -> None:
    for name in ("backend.hcl", "account.local.tfvars", "account.tfplan"):
        (account(checkout) / name).write_text("x\n", encoding="utf-8")
    cache = account(checkout) / ".terraform" / "modules"
    cache.mkdir(parents=True)
    (cache / "cached.tf.json").write_text("{}\n", encoding="utf-8")
    result = call(checkout, "refuse_unexpected_stack_files")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "name",
    [
        "extra.tf.json",
        "x.auto.tfvars",
        "terraform.tfvars",
        "iam_plan_role_override.tf",
        "new.tf",
        "notes.txt",
    ],
)
def test_untracked_file_is_refused(checkout: Path, name: str) -> None:
    (account(checkout) / name).write_text("{}\n", encoding="utf-8")
    result = call(checkout, "refuse_unexpected_stack_files")
    assert result.returncode == 1
    assert f"unexpected untracked file infra/account/{name}" in result.stderr


def test_uncommitted_change_is_refused(checkout: Path) -> None:
    path = account(checkout) / "iam_plan_role.tf"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    result = call(checkout, "refuse_unexpected_stack_files")
    assert result.returncode == 1
    assert "has uncommitted changes" in result.stderr


def test_every_expected_file_is_tracked_in_the_fixture(checkout: Path) -> None:
    assert {path.name for path in account(checkout).iterdir()} == set(EXPECTED_FILES)


@pytest.mark.parametrize(
    "content",
    [
        VALID_TFVARS,
        "\n" + VALID_TFVARS + "\n   \n",
        VALID_TFVARS.rstrip("\n"),
        'budget_alert_email="alerts@example.org"\n',
    ],
)
def test_tfvars_with_only_the_budget_email_passes(checkout: Path, content: str) -> None:
    (account(checkout) / "account.local.tfvars").write_text(content, encoding="utf-8")
    result = call(checkout, "verify_tfvars_file")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (VALID_TFVARS + 'runner_repository_id = "1"\n', "may set only budget_alert_email"),
        (VALID_TFVARS + VALID_TFVARS, "must set budget_alert_email exactly once"),
        ("", "must set budget_alert_email exactly once"),
        (VALID_TFVARS + "# note\n", "may set only budget_alert_email"),
        ('budget_alert_email = "not-an-address"\n', "may set only budget_alert_email"),
        ('budget_alert_email = "a@b.org" image_build_environment = "pr"\n', "may set only"),
    ],
)
def test_tfvars_with_anything_else_is_refused(checkout: Path, content: str, message: str) -> None:
    (account(checkout) / "account.local.tfvars").write_text(content, encoding="utf-8")
    result = call(checkout, "verify_tfvars_file")
    assert result.returncode == 1
    assert message in result.stderr
