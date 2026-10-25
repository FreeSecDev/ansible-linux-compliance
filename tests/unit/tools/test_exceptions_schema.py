from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    exceptions,
    model,
    yamlsubset,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "exceptions-v1.schema.json"
EXAMPLE_PATH = REPO_ROOT / "docs" / "examples" / "exceptions.yml"
POLICY_PATH = REPO_ROOT / "docs" / "exceptions.md"
NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.UTC)

DIFFERENTIAL_DOCUMENTS = [
    "---\na: b\n",
    "---\na: |\n  x\n  y\n",
    "---\na: |-\n  x\n\n  y\n\n",
    "---\na: |+\n  x\n\n\nb: c\n",
    "---\na: |+\n  x\n\n",
    "---\na: >\n  x\n  y\n\n  z\n",
    "---\na: >\n\n  x\n  y\n",
    "---\na: >-\n  x\n  y\n\n\n  z\n\nb: q\n",
    "---\na: |\n  x\n    more\n  back\n",
    "---\na: |\nb: c\n",
    "---\na: |+\n\nb: c\n",
    "---\na: |\n\n  x\n",
    "---\nlist:\n- a\n- b\nother: c\n",
    "---\nlist:\n  - a\n  -   b\n",
    "---\n- a: 1x\n  b: c\n- - x\n  - z\n-\n",
    '---\na: [x, \'y z\', "q\\"r"]\nb: []\nc: [ a , b ]  # c\n',
    "---\na: 'it''s'\nb: \"tab\\there\"\n",
    "---\n# comment\na: b # trailing\nc: d#e\nd: http://example.com/x\n",
    "---\na:\n  b:\n    c: d\n  e: ~\nf:\ng: null\n",
    "---\na: 2026-10-01\nb: 0.1.82\nc: web01\n",
    "---\na: |\n  # not a comment\n  x: z\n# real comment\nb: c\n",
    "---\nx: \"\"\nq: ''\n",
    "---\na: >+\n  x\n\n",
    "---\na:\n  - b: |\n      text\n    c: d\n",
]


def schema() -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def stringify(value: object) -> object:
    if isinstance(value, dict):
        return {key: stringify(item) for key, item in cast("dict[str, object]", value).items()}
    if isinstance(value, list):
        return [stringify(item) for item in cast("list[object]", value)]
    if isinstance(value, dt.date):
        return value.isoformat()
    return value


@pytest.mark.parametrize("text", DIFFERENTIAL_DOCUMENTS)
def test_the_subset_loader_agrees_with_pyyaml(text: str) -> None:
    assert yamlsubset.load(text) == stringify(yaml.safe_load(text))


def test_the_example_agrees_with_pyyaml_and_is_valid() -> None:
    text = EXAMPLE_PATH.read_text(encoding="utf-8")
    assert yamlsubset.load(text) == stringify(yaml.safe_load(text))
    parsed = exceptions.parse_exceptions(text, NOW)
    assert [record.exception_id for record in parsed.records] == ["EXC-2026-001", "EXC-2026-002"]


def objects(node: object) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        mapping = cast("dict[str, Any]", node)
        if mapping.get("type") == "object":
            found.append(mapping)
        for item in mapping.values():
            found.extend(objects(item))
    elif isinstance(node, list):
        for item in cast("list[object]", node):
            found.extend(objects(item))
    return found


def test_every_schema_object_is_closed() -> None:
    found = objects(schema())
    assert len(found) == 5
    assert all(item["additionalProperties"] is False for item in found)


def test_the_schema_matches_the_validator() -> None:
    document = schema()
    definitions = document["$defs"]
    entry = definitions["exception"]
    scope = definitions["scope"]["properties"]
    assert document["required"] == list(exceptions.DOCUMENT_KEYS)
    assert document["properties"]["schema_version"]["const"] == exceptions.FILE_SCHEMA_VERSION
    assert document["properties"]["exceptions"]["maxItems"] == exceptions.MAX_EXCEPTIONS
    assert entry["required"] == list(exceptions.ENTRY_KEYS)
    assert list(entry["properties"]) == list(exceptions.ENTRY_KEYS)
    assert entry["properties"]["id"]["pattern"] == f"^{exceptions.ID_PATTERN}$"
    assert entry["properties"]["id"]["maxLength"] == exceptions.MAX_ID_LENGTH
    assert entry["properties"]["framework"]["enum"] == [item.value for item in model.FrameworkId]
    assert entry["properties"]["risk"]["enum"] == [item.value for item in exceptions.Risk]
    assert entry["properties"]["justification"]["maxLength"] == exceptions.MAX_JUSTIFICATION_LENGTH
    assert entry["properties"]["approval"]["required"] == list(exceptions.APPROVAL_KEYS)
    assert definitions["person"]["maxLength"] == exceptions.MAX_PERSON_LENGTH
    assert definitions["date"]["pattern"] == f"^{exceptions.DATE_PATTERN}$"
    assert list(scope) == list(exceptions.SCOPE_KEYS)
    assert scope["hosts"]["maxItems"] == scope["groups"]["maxItems"] == exceptions.MAX_SCOPE_ITEMS
    assert scope["hosts"]["items"]["pattern"] == f"^{exceptions.HOST_PATTERN}$"
    assert scope["hosts"]["items"]["maxLength"] == exceptions.MAX_HOST_LENGTH
    assert scope["groups"]["items"]["pattern"] == f"^{exceptions.GROUP_PATTERN}$"
    assert scope["groups"]["items"]["maxLength"] == exceptions.MAX_GROUP_LENGTH
    assert set(scope["groups"]["items"]["not"]["enum"]) == exceptions.RESERVED_GROUPS
    assert scope["benchmark"]["required"] == list(exceptions.BENCHMARK_KEYS)
    assert scope["benchmark"]["properties"]["version"]["maxLength"] == exceptions.MAX_VERSION_LENGTH
    assert f"at most {exceptions.MAX_VALIDITY_DAYS} days" in document["description"]


@pytest.mark.parametrize(
    ("kind", "value", "valid"),
    [
        ("rule", "xccdf_org.ssgproject.content_rule_sshd_disable_root_login", True),
        ("rule", "xccdf_org.ssgproject.content_profile_cis", False),
        ("rule", "sshd_disable_root_login", False),
        ("benchmark", "xccdf_org.ssgproject.content_benchmark_RHEL-9", True),
        ("benchmark", "xccdf_org.ssgproject.content_rule_x", False),
    ],
)
def test_the_schema_identifier_patterns_match_the_model(kind: str, value: str, valid: bool) -> None:
    properties = schema()["$defs"]["exception"]["properties"]
    pattern = (
        properties["rule"]["pattern"]
        if kind == "rule"
        else schema()["$defs"]["scope"]["properties"]["benchmark"]["properties"]["id"]["pattern"]
    )
    assert (re.search(pattern, value) is not None) is valid
    try:
        model.validate_xccdf_id(value, "value", kind)
    except model.ModelError:
        accepted = False
    else:
        accepted = True
    assert accepted is valid


def test_the_policy_page_states_the_cap() -> None:
    text = POLICY_PATH.read_text(encoding="utf-8")
    assert f"{exceptions.MAX_VALIDITY_DAYS} days" in text
    assert "schemas/exceptions-v1.schema.json" in text


def validator() -> Any:
    document = schema()
    Draft202012Validator.check_schema(document)
    return Draft202012Validator(document, format_checker=FormatChecker())


def test_the_example_validates_against_the_schema() -> None:
    loaded = yamlsubset.load(EXAMPLE_PATH.read_text(encoding="utf-8"))
    assert list(validator().iter_errors(loaded)) == []


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("scope",), {}),
        (("scope",), {"hosts": []}),
        (("scope",), {"groups": ["all"]}),
        (("scope",), {"hosts": ["a", "a"]}),
        (("scope", "benchmark"), {"id": "xccdf_org.ssgproject.content_benchmark_X"}),
        (("risk",), "none"),
        (("framework",), "iso27001"),
        (("rule",), "sshd_disable_root_login"),
        (("id",), "-bad"),
        (("created",), "2026/10/01"),
        (("owner",), " padded"),
        (("justification",), "   "),
        (("approval",), {"approver": "a"}),
        (("comment",), "x"),
        (("owner",), None),
    ],
)
def test_the_schema_rejects_what_the_validator_rejects(
    path: tuple[str, ...], value: object
) -> None:
    loaded = cast("dict[str, Any]", yamlsubset.load(EXAMPLE_PATH.read_text(encoding="utf-8")))
    entry = loaded["exceptions"][0]
    if path == ("scope", "benchmark"):
        entry["scope"] = {"benchmark": value}
    else:
        entry[path[0]] = value
    assert list(validator().iter_errors(loaded))
    with pytest.raises(exceptions.ExceptionsError):
        exceptions.parse_document(loaded, NOW)
