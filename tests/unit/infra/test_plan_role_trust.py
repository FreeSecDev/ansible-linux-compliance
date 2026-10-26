from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest
from hcl2 import api as hcl2_api

ACCOUNT_DIRECTORY = Path(__file__).resolve().parents[3] / "infra" / "account"
TERRAFORM_FILES = ("iam_plan_role.tf", "locals.tf", "oidc.tf", "variables.tf")
LINE_MARKER_PREFIX = "__"
OIDC_HOST = "${local.oidc_host}"
STRING_EQUALS = "StringEquals"

EXPECTED_TRUST: dict[str, object] = {
    "statement": [
        {
            "sid": "GitHubActionsMainOnly",
            "effect": "Allow",
            "actions": ["sts:AssumeRoleWithWebIdentity"],
            "principals": [
                {
                    "type": "Federated",
                    "identifiers": ["${data.aws_iam_openid_connect_provider.github.arn}"],
                },
            ],
            "condition": [
                {
                    "test": STRING_EQUALS,
                    "variable": f"{OIDC_HOST}:aud",
                    "values": ["sts.amazonaws.com"],
                },
                {
                    "test": STRING_EQUALS,
                    "variable": f"{OIDC_HOST}:sub",
                    "values": ["${local.plan_subject}"],
                },
                {
                    "test": STRING_EQUALS,
                    "variable": f"{OIDC_HOST}:repository_id",
                    "values": ["${var.github_repository_id}"],
                },
                {
                    "test": STRING_EQUALS,
                    "variable": f"{OIDC_HOST}:repository_owner_id",
                    "values": ["${var.github_owner_id}"],
                },
                {
                    "test": STRING_EQUALS,
                    "variable": f"{OIDC_HOST}:job_workflow_ref",
                    "values": "${local.plan_workflow_refs}",
                },
            ],
        },
    ],
}

EXPECTED_ROLE_TRUST_BINDING = "${data.aws_iam_policy_document.plan_trust.json}"

EXPECTED_LOCALS: dict[str, object] = {
    "oidc_host": "token.actions.githubusercontent.com",
    "oidc_provider_arn": "arn:aws:iam::${var.account_id}:oidc-provider/${local.oidc_host}",
    "github_owner_name": '${split("/",var.github_repository)[0]}',
    "github_repository_name": '${split("/",var.github_repository)[1]}',
    "plan_subject": (
        "repo:${local.github_owner_name}@${var.github_owner_id}"
        "/${local.github_repository_name}@${var.github_repository_id}:ref:refs/heads/main"
    ),
    "plan_workflow_refs": (
        '${[for file in var.plan_workflow_files : "${var.github_repository}'
        '/.github/workflows/${file}@refs/heads/main"]}'
    ),
}

EXPECTED_VARIABLES: dict[str, object] = {
    "github_owner_id": {
        "description": "Numeric ID of the GitHub organization; immutable subjects embed it.",
        "type": "${string}",
        "default": "347867179",
        "validation": [
            {
                "condition": '${can(regex("^[0-9]+$",var.github_owner_id))}',
                "error_message": "github_owner_id must be numeric.",
            },
        ],
    },
    "github_repository_id": {
        "description": "Numeric ID of the GitHub repository; immutable subjects embed it.",
        "type": "${string}",
        "default": "1433323044",
        "validation": [
            {
                "condition": '${can(regex("^[0-9]+$",var.github_repository_id))}',
                "error_message": "github_repository_id must be numeric.",
            },
        ],
    },
    "github_repository": {
        "description": "GitHub repository (owner/name) whose workflows may assume the plan role.",
        "type": "${string}",
        "default": "FreeSecDev/ansible-linux-compliance",
    },
    "plan_workflow_files": {
        "description": (
            "Workflow files on main that may assume the plan role; "
            "each is matched exactly through job_workflow_ref."
        ),
        "type": "${list(string)}",
        "default": ["oidc-check.yml"],
        "validation": [
            {
                "condition": (
                    "${length(var.plan_workflow_files) > 0 && alltrue([for f in "
                    'var.plan_workflow_files : can(regex("^[A-Za-z0-9._-]+\\\\.ya?ml$",f))])}'
                ),
                "error_message": (
                    "plan_workflow_files must list plain workflow file names "
                    "such as oidc-check.yml."
                ),
            },
        ],
    },
}

EXPECTED_OIDC: dict[str, object] = {
    "arn": "${local.oidc_provider_arn}",
    "lifecycle": [
        {
            "postcondition": [
                {
                    "condition": '${contains(self.client_id_list,"sts.amazonaws.com")}',
                    "error_message": (
                        "The existing GitHub OIDC provider must list the audience "
                        "sts.amazonaws.com."
                    ),
                },
            ],
        },
    ],
}


def load_terraform(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return cast("dict[str, Any]", hcl2_api.load(handle))


def normalise_member(member: object) -> object:
    if not isinstance(member, list):
        return member
    items = cast("list[object]", member)
    if items and all(isinstance(item, dict) for item in items):
        return [normalise_block(cast("dict[str, object]", item)) for item in items]
    if len(items) == 1:
        return items[0]
    return items


def normalise_block(block: dict[str, object]) -> dict[str, object]:
    return {
        key: normalise_member(member)
        for key, member in block.items()
        if not key.startswith(LINE_MARKER_PREFIX)
    }


def condition_order(condition: object) -> str:
    return json.dumps(condition, sort_keys=True)


def sort_conditions(policy: dict[str, object]) -> dict[str, object]:
    statements = policy.get("statement")
    if isinstance(statements, list):
        for statement in cast("list[object]", statements):
            if isinstance(statement, dict):
                entries = cast("dict[str, object]", statement)
                conditions = entries.get("condition")
                if isinstance(conditions, list):
                    entries["condition"] = sorted(
                        cast("list[object]", conditions), key=condition_order
                    )
    return policy


def blocks_of(document: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", document.get(kind, []))


def labelled_blocks(
    document: dict[str, Any], kind: str, type_name: str, name: str
) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for block in blocks_of(document, kind):
        by_name = cast("dict[str, dict[str, object]]", block.get(type_name, {}))
        if name in by_name:
            found.append(by_name[name])
    return found


def only_block(blocks: list[dict[str, object]]) -> dict[str, object] | None:
    return normalise_block(blocks[0]) if len(blocks) == 1 else None


def trust_policy(directory: Path) -> object:
    document = load_terraform(directory / "iam_plan_role.tf")
    block = only_block(labelled_blocks(document, "data", "aws_iam_policy_document", "plan_trust"))
    return None if block is None else sort_conditions(block)


def role_trust_binding(directory: Path) -> object:
    document = load_terraform(directory / "iam_plan_role.tf")
    block = only_block(labelled_blocks(document, "resource", "aws_iam_role", "plan"))
    return None if block is None else block.get("assume_role_policy")


def local_values(directory: Path) -> object:
    document = load_terraform(directory / "locals.tf")
    merged: dict[str, object] = {}
    for entry in blocks_of(document, "locals"):
        merged.update(normalise_block(cast("dict[str, object]", entry)))
    return {name: merged.get(name) for name in EXPECTED_LOCALS}


def variable_blocks(directory: Path) -> object:
    document = load_terraform(directory / "variables.tf")
    declared: dict[str, object] = {}
    for entry in blocks_of(document, "variable"):
        for name, body in entry.items():
            declared[name] = normalise_block(cast("dict[str, object]", body))
    return {name: declared.get(name) for name in EXPECTED_VARIABLES}


def oidc_data_source(directory: Path) -> object:
    document = load_terraform(directory / "oidc.tf")
    return only_block(
        labelled_blocks(document, "data", "aws_iam_openid_connect_provider", "github")
    )


SECTIONS = {
    "trust_policy": (trust_policy, sort_conditions(dict(EXPECTED_TRUST))),
    "role_trust_binding": (role_trust_binding, EXPECTED_ROLE_TRUST_BINDING),
    "locals": (local_values, EXPECTED_LOCALS),
    "variables": (variable_blocks, EXPECTED_VARIABLES),
    "oidc_data_source": (oidc_data_source, EXPECTED_OIDC),
}


def copy_account(destination: Path) -> Path:
    destination.mkdir()
    for name in TERRAFORM_FILES:
        shutil.copy(ACCOUNT_DIRECTORY / name, destination / name)
    return destination


def mutate(directory: Path, file_name: str, old: str, new: str) -> None:
    path = directory / file_name
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


SECOND_STATEMENT = """  }

  statement {
    sid     = "Extra"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }
  }
}

data "aws_iam_policy_document" "plan_permissions" {"""

NEGATIVE_CASES = {
    "subject_is_repo_wildcard": (
        "locals.tf",
        "locals",
        (
            'plan_subject           = "repo:${local.github_owner_name}@${var.github_owner_id}'
            '/${local.github_repository_name}@${var.github_repository_id}:ref:refs/heads/main"'
        ),
        'plan_subject           = "repo:*"',
    ),
    "subject_condition_is_repo_wildcard": (
        "iam_plan_role.tf",
        "trust_policy",
        "values   = [local.plan_subject]",
        'values   = ["repo:*"]',
    ),
    "string_like_instead_of_string_equals": (
        "iam_plan_role.tf",
        "trust_policy",
        'test     = "StringEquals"\n      variable = "${local.oidc_host}:sub"',
        'test     = "StringLike"\n      variable = "${local.oidc_host}:sub"',
    ),
    "removed_condition": (
        "iam_plan_role.tf",
        "trust_policy",
        (
            '    condition {\n      test     = "StringEquals"\n'
            '      variable = "${local.oidc_host}:repository_id"\n'
            "      values   = [var.github_repository_id]\n    }\n\n"
        ),
        "",
    ),
    "extra_condition": (
        "iam_plan_role.tf",
        "trust_policy",
        (
            '    condition {\n      test     = "StringEquals"\n'
            '      variable = "${local.oidc_host}:aud"'
        ),
        (
            '    condition {\n      test     = "StringLike"\n'
            '      variable = "${local.oidc_host}:ref"\n      values   = ["*"]\n    }\n\n'
            '    condition {\n      test     = "StringEquals"\n'
            '      variable = "${local.oidc_host}:aud"'
        ),
    ),
    "second_statement": (
        "iam_plan_role.tf",
        "trust_policy",
        '  }\n}\n\ndata "aws_iam_policy_document" "plan_permissions" {',
        SECOND_STATEMENT,
    ),
    "changed_principal": (
        "iam_plan_role.tf",
        "trust_policy",
        "identifiers = [data.aws_iam_openid_connect_provider.github.arn]\n    }\n\n    condition",
        'identifiers = ["*"]\n    }\n\n    condition',
    ),
    "url_lookup_in_oidc": (
        "oidc.tf",
        "oidc_data_source",
        "arn = local.oidc_provider_arn",
        'url = "https://token.actions.githubusercontent.com"',
    ),
    "audience_postcondition_removed": (
        "oidc.tf",
        "oidc_data_source",
        'contains(self.client_id_list, "sts.amazonaws.com")',
        "true",
    ),
    "owner_id_default_changed": (
        "variables.tf",
        "variables",
        '"347867179"',
        '"1"',
    ),
    "repository_id_validation_removed": (
        "variables.tf",
        "variables",
        'can(regex("^[0-9]+$", var.github_repository_id))',
        "true",
    ),
    "workflow_refs_widened": (
        "locals.tf",
        "locals",
        '@refs/heads/main"\n  ]',
        '@refs/heads/*"\n  ]',
    ),
    "role_uses_other_policy": (
        "iam_plan_role.tf",
        "role_trust_binding",
        "assume_role_policy   = data.aws_iam_policy_document.plan_trust.json",
        "assume_role_policy   = data.aws_iam_policy_document.plan_permissions.json",
    ),
}


@pytest.mark.parametrize("section", sorted(SECTIONS))
def test_account_stack_matches_the_pinned_section(section: str) -> None:
    reader, expected = SECTIONS[section]

    assert reader(ACCOUNT_DIRECTORY) == expected


def test_trust_policy_has_exactly_one_statement() -> None:
    policy = cast("dict[str, list[object]]", trust_policy(ACCOUNT_DIRECTORY))

    assert list(policy) == ["statement"]
    assert len(policy["statement"]) == 1


def test_trust_policy_conditions_are_all_string_equals() -> None:
    policy = cast(
        "dict[str, list[dict[str, list[dict[str, str]]]]]", trust_policy(ACCOUNT_DIRECTORY)
    )
    conditions = policy["statement"][0]["condition"]

    assert {condition["test"] for condition in conditions} == {STRING_EQUALS}
    assert sorted(condition["variable"].split(":")[1] for condition in conditions) == [
        "aud",
        "job_workflow_ref",
        "repository_id",
        "repository_owner_id",
        "sub",
    ]


def test_unmutated_copy_passes_every_section(tmp_path: Path) -> None:
    copy = copy_account(tmp_path / "account")

    for reader, expected in SECTIONS.values():
        assert reader(copy) == expected


@pytest.mark.parametrize("case", sorted(NEGATIVE_CASES))
def test_mutated_copy_fails_the_pinned_section(tmp_path: Path, case: str) -> None:
    file_name, section, old, new = NEGATIVE_CASES[case]
    copy = copy_account(tmp_path / "account")
    mutate(copy, file_name, old, new)
    reader, expected = SECTIONS[section]

    assert reader(copy) != expected
