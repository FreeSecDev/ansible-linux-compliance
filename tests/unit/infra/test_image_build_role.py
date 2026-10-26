"""Pin the runner image build trust, permissions and CodeBuild settings (FREES-36).

Checkov's CKV_AWS_358 does not recognise GitHub immutable subjects and CKV_AWS_316 fails on the
privileged build container that rootless Buildah needs, so ``infra/.checkov.baseline`` exempts
exactly those two findings. These tests replace the exempted signal: any change to the trust
conditions, a wildcard, a new permission or a weaker CodeBuild setting fails here and needs a
reviewed change to this file and to ADR 0014.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Final, cast

import pytest
from hcl2.api import load as load_hcl

ROOT: Final[Path] = Path(__file__).resolve().parents[3]
ACCOUNT: Final[Path] = ROOT / "infra" / "account"
BASELINE: Final[Path] = ROOT / "infra" / ".checkov.baseline"

OIDC_HOST: Final[str] = "${local.oidc_host}"
EXPECTED_TRUST_CONDITIONS: Final[frozenset[tuple[str, str, tuple[str, ...]]]] = frozenset(
    {
        ("StringEquals", f"{OIDC_HOST}:aud", ("sts.amazonaws.com",)),
        ("StringEquals", f"{OIDC_HOST}:sub", ("${local.image_build_subject}",)),
        ("StringEquals", f"{OIDC_HOST}:repository_id", ("${var.runner_repository_id}",)),
        ("StringEquals", f"{OIDC_HOST}:repository_owner_id", ("${var.github_owner_id}",)),
        ("StringEquals", f"{OIDC_HOST}:job_workflow_ref", ("${local.image_build_workflow}",)),
    }
)
EXPECTED_SUBJECT_EXPRESSION: Final[str] = (
    "repo:${local.runner_owner_name}@${var.github_owner_id}/"
    "${local.runner_repository_name}@${var.runner_repository_id}"
    ":environment:${var.image_build_environment}"
)
EXPECTED_WORKFLOW_EXPRESSION: Final[str] = (
    "${var.runner_repository}/.github/workflows/${var.image_build_workflow_file}@refs/heads/main"
)
EXPECTED_SUBJECT: Final[str] = (
    "repo:FreeSecDev@347867179/linux-compliance-runner@1433323102:environment:release"
)
EXPECTED_WORKFLOW: Final[str] = (
    "FreeSecDev/linux-compliance-runner/.github/workflows/image-build.yml@refs/heads/main"
)
EXPECTED_DEFAULTS: Final[dict[str, str]] = {
    "runner_repository": "FreeSecDev/linux-compliance-runner",
    "runner_repository_id": "1433323102",
    "github_owner_id": "347867179",
    "image_build_workflow_file": "image-build.yml",
    "image_build_environment": "release",
}

Statement = tuple[str, tuple[str, ...], tuple[str, ...]]

EXPECTED_BUILD_ROLE_PERMISSIONS: Final[frozenset[Statement]] = frozenset(
    {
        (
            "RunTheImageBuild",
            ("codebuild:BatchGetBuilds", "codebuild:StartBuild", "codebuild:StopBuild"),
            ("${aws_codebuild_project.runner_image.arn}",),
        ),
        (
            "ReadTheBuildLogs",
            ("logs:GetLogEvents",),
            ("${local.image_build_log_group_arn}:log-stream:*",),
        ),
        ("GetRegistryToken", ("ecr:GetAuthorizationToken",), ("*",)),
        (
            "PullAndDescribeStagedImages",
            (
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:DescribeImages",
                "ecr:GetDownloadUrlForLayer",
            ),
            ("${aws_ecr_repository.runner_staging.arn}",),
        ),
    }
)
EXPECTED_CODEBUILD_PERMISSIONS: Final[frozenset[Statement]] = frozenset(
    {
        (
            "WriteBuildLogs",
            ("logs:CreateLogStream", "logs:PutLogEvents"),
            ("${local.image_build_log_group_arn}:log-stream:*",),
        ),
        ("GetRegistryToken", ("ecr:GetAuthorizationToken",), ("*",)),
        (
            "PushStagingImage",
            (
                "ecr:BatchCheckLayerAvailability",
                "ecr:CompleteLayerUpload",
                "ecr:InitiateLayerUpload",
                "ecr:PutImage",
                "ecr:UploadLayerPart",
            ),
            ("${local.staging_repository_arn}",),
        ),
        (
            "UseBuildKey",
            ("kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"),
            ("${aws_kms_key.image_build.arn}",),
        ),
    }
)
ACTIONS_REQUIRING_STAR: Final[frozenset[str]] = frozenset({"ecr:GetAuthorizationToken"})
EXPECTED_BASELINE: Final[dict[str, set[tuple[str, str]]]] = {
    "/account/iam_plan_role.tf": {("aws_iam_policy_document.plan_trust", "CKV_AWS_358")},
    "/account/iam_image_build_role.tf": {
        ("aws_iam_policy_document.image_build_trust", "CKV_AWS_358")
    },
    "/account/image_build.tf": {("aws_codebuild_project.runner_image", "CKV_AWS_316")},
}
DIGEST_PINNED_IMAGE: Final[re.Pattern[str]] = re.compile(
    r"[a-z0-9.-]+(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}"
)
INTERPOLATION: Final[re.Pattern[str]] = re.compile(r"\$\{(local|var)\.([a-z_]+)\}")


def _one(value: object) -> object:
    """Unwrap the single-element lists that python-hcl2 produces for every attribute."""
    current: object = value
    while isinstance(current, list):
        items = cast("list[object]", current)
        if len(items) != 1:
            return items
        current = items[0]
    return current


def _strings(value: object) -> tuple[str, ...]:
    """Return an attribute that holds one string or a list of strings as a tuple."""
    unwrapped = _one(value)
    items = cast("list[object]", unwrapped) if isinstance(unwrapped, list) else [unwrapped]
    assert all(isinstance(item, str) for item in items), items
    return tuple(cast("list[str]", items))


def _load(name: str) -> dict[str, object]:
    with (ACCOUNT / name).open(encoding="utf-8") as handle:
        return cast("dict[str, object]", load_hcl(handle))


def _blocks(document: dict[str, object], kind: str, block_type: str) -> dict[str, object]:
    found: dict[str, object] = {}
    for entry in cast("list[dict[str, dict[str, object]]]", document.get(kind, [])):
        found.update(entry.get(block_type, {}))
    return found


def _policy_document(name: str, file_name: str) -> list[dict[str, object]]:
    documents = _blocks(_load(file_name), "data", "aws_iam_policy_document")
    block = cast("dict[str, object]", documents[name])
    return cast("list[dict[str, object]]", block["statement"])


def _resource(file_name: str, resource_type: str, name: str) -> dict[str, object]:
    resources = _blocks(_load(file_name), "resource", resource_type)
    return cast("dict[str, object]", resources[name])


def _locals() -> dict[str, object]:
    merged: dict[str, object] = {}
    for path in sorted(ACCOUNT.glob("*.tf")):
        for entry in cast("list[dict[str, object]]", _load(path.name).get("locals", [])):
            merged.update(entry)
    return merged


def _defaults() -> dict[str, object]:
    merged: dict[str, object] = {}
    for entry in cast("list[dict[str, dict[str, object]]]", _load("variables.tf")["variable"]):
        for name, body in entry.items():
            merged[name] = _one(body.get("default"))
    return merged


def _statements(statements: list[dict[str, object]]) -> frozenset[Statement]:
    return frozenset(
        (
            cast("str", _one(statement["sid"])),
            tuple(sorted(_strings(statement["actions"]))),
            tuple(sorted(_strings(statement["resources"]))),
        )
        for statement in statements
    )


def _render(expression: str, values: dict[str, str]) -> str:
    return INTERPOLATION.sub(lambda match: values[match.group(2)], expression)


def test_trust_has_one_statement_for_the_oidc_provider_only() -> None:
    statements = _policy_document("image_build_trust", "iam_image_build_role.tf")
    assert len(statements) == 1
    statement = statements[0]
    assert set(statement) - {"__start_line__", "__end_line__"} == {
        "sid",
        "effect",
        "actions",
        "principals",
        "condition",
    }
    assert _one(statement["effect"]) == "Allow"
    assert _strings(statement["actions"]) == ("sts:AssumeRoleWithWebIdentity",)
    principals = cast("list[dict[str, object]]", statement["principals"])
    assert len(principals) == 1
    assert _one(principals[0]["type"]) == "Federated"
    assert _strings(principals[0]["identifiers"]) == (
        "${data.aws_iam_openid_connect_provider.github.arn}",
    )


def test_trust_conditions_are_pinned_exactly() -> None:
    statement = _policy_document("image_build_trust", "iam_image_build_role.tf")[0]
    conditions = cast("list[dict[str, object]]", statement["condition"])
    found = [
        (
            cast("str", _one(condition["test"])),
            cast("str", _one(condition["variable"])),
            _strings(condition["values"]),
        )
        for condition in conditions
    ]
    assert len(found) == len(set(found))
    assert frozenset(found) == EXPECTED_TRUST_CONDITIONS
    for _test, _variable, values in found:
        assert all("*" not in value and "?" not in value for value in values)


def test_subject_and_workflow_expressions_render_to_the_runner_release_environment() -> None:
    local_values = _locals()
    assert _one(local_values["image_build_subject"]) == EXPECTED_SUBJECT_EXPRESSION
    assert _one(local_values["image_build_workflow"]) == EXPECTED_WORKFLOW_EXPRESSION
    defaults = _defaults()
    for name, value in EXPECTED_DEFAULTS.items():
        assert defaults[name] == value, name
    owner, _, repository = EXPECTED_DEFAULTS["runner_repository"].partition("/")
    values = {
        **EXPECTED_DEFAULTS,
        "runner_owner_name": owner,
        "runner_repository_name": repository,
    }
    assert _render(EXPECTED_SUBJECT_EXPRESSION, values) == EXPECTED_SUBJECT
    assert _render(EXPECTED_WORKFLOW_EXPRESSION, values) == EXPECTED_WORKFLOW


@pytest.mark.parametrize(
    ("document", "file_name", "expected"),
    [
        ("image_build_permissions", "iam_image_build_role.tf", EXPECTED_BUILD_ROLE_PERMISSIONS),
        ("codebuild_permissions", "image_build.tf", EXPECTED_CODEBUILD_PERMISSIONS),
    ],
)
def test_permissions_are_pinned_and_star_is_only_used_where_aws_requires_it(
    document: str, file_name: str, expected: frozenset[Statement]
) -> None:
    statements = _policy_document(document, file_name)
    for statement in statements:
        assert _one(statement["effect"]) == "Allow"
        assert "condition" not in statement
        assert "not_actions" not in statement
        assert "not_resources" not in statement
        actions = _strings(statement["actions"])
        assert all("*" not in action for action in actions), actions
        if "*" in _strings(statement["resources"]):
            assert set(actions) <= ACTIONS_REQUIRING_STAR, actions
    assert _statements(statements) == expected


def test_roles_have_one_hour_sessions() -> None:
    for file_name, name in (
        ("iam_image_build_role.tf", "image_build"),
        ("image_build.tf", "codebuild_service"),
    ):
        role = _resource(file_name, "aws_iam_role", name)
        assert _one(role["max_session_duration"]) == 3600, name


def test_codebuild_trust_is_limited_to_this_project_and_account() -> None:
    statements = _policy_document("codebuild_trust", "image_build.tf")
    assert len(statements) == 1
    statement = statements[0]
    assert _strings(statement["actions"]) == ("sts:AssumeRole",)
    principals = cast("list[dict[str, object]]", statement["principals"])
    assert [(_one(p["type"]), _strings(p["identifiers"])) for p in principals] == [
        ("Service", ("codebuild.amazonaws.com",))
    ]
    conditions = {
        (
            cast("str", _one(condition["test"])),
            cast("str", _one(condition["variable"])),
            _strings(condition["values"]),
        )
        for condition in cast("list[dict[str, object]]", statement["condition"])
    }
    assert conditions == {
        ("StringEquals", "aws:SourceAccount", ("${var.account_id}",)),
        ("ArnEquals", "aws:SourceArn", ("${local.codebuild_project_arn}",)),
    }


def test_codebuild_project_keeps_its_guardrails() -> None:
    project = _resource("image_build.tf", "aws_codebuild_project", "runner_image")
    assert _one(project["concurrent_build_limit"]) == 1
    assert _one(project["build_timeout"]) == "${var.image_build_timeout_minutes}"
    assert _one(project["queued_timeout"]) == "${var.image_build_queued_timeout_minutes}"
    assert _one(project["encryption_key"]) == "${aws_kms_key.image_build.arn}"
    artifacts = cast("dict[str, object]", _one(project["artifacts"]))
    assert _one(artifacts["type"]) == "NO_ARTIFACTS"
    environment = cast("dict[str, object]", _one(project["environment"]))
    assert _one(environment["image"]) == "${var.image_builder_image}"
    assert _one(environment["image_pull_credentials_type"]) == "CODEBUILD"
    assert _one(environment["privileged_mode"]) is True
    source = cast("dict[str, object]", _one(project["source"]))
    assert _one(source["type"]) == "GITHUB"
    assert _one(source["location"]) == "${local.codebuild_source_url}"
    assert _one(source["insecure_ssl"]) is False
    assert "secondary_sources" not in project
    assert "vpc_config" not in project
    defaults = _defaults()
    assert DIGEST_PINNED_IMAGE.fullmatch(cast("str", defaults["image_builder_image"]))
    assert cast("int", defaults["image_build_timeout_minutes"]) <= 60
    assert cast("int", defaults["image_staging_retention_days"]) == 14


def test_staging_repository_is_immutable_scanned_and_expires() -> None:
    repository = _resource("image_build.tf", "aws_ecr_repository", "runner_staging")
    assert _one(repository["image_tag_mutability"]) == "IMMUTABLE"
    assert _one(repository["force_delete"]) is False
    scanning = cast("dict[str, object]", _one(repository["image_scanning_configuration"]))
    assert _one(scanning["scan_on_push"]) is True
    lifecycle = _resource("image_build.tf", "aws_ecr_lifecycle_policy", "runner_staging")
    assert "sinceImagePushed" in cast("str", _one(lifecycle["policy"]))


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
