"""The shared safe YAML loader of the repository tools, with and without libyaml (FREES-206)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml

from tools import yaml_loader
from tools.roles import check_lifecycle_topics, generate_toggles

if TYPE_CHECKING:
    from pathlib import Path

TEXT = "---\nname: value\nnumbers: [1, 2]\nmode: 0644\nflag: yes\n"
EXPECTED = {"name": "value", "numbers": [1, 2], "mode": 420, "flag": True}
INVALID = "---\nkey: [unclosed\n"


@pytest.fixture
def without_libyaml(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make PyYAML look as it does when it was built without libyaml."""
    monkeypatch.setattr(yaml, "__with_libyaml__", False)
    monkeypatch.delattr(yaml, "CSafeLoader", raising=False)


def test_the_loader_parses_what_the_safe_loader_parses() -> None:
    assert yaml_loader.safe_load(TEXT) == EXPECTED
    assert yaml_loader.safe_load(TEXT) == yaml.safe_load(TEXT)


@pytest.mark.usefixtures("without_libyaml")
def test_without_libyaml_the_loader_falls_back_to_the_python_safe_loader() -> None:
    assert yaml_loader.safe_load(TEXT) == EXPECTED


@pytest.mark.usefixtures("without_libyaml")
def test_without_libyaml_invalid_yaml_is_a_yaml_error() -> None:
    with pytest.raises(yaml.YAMLError):
        yaml_loader.safe_load(INVALID)


def test_the_safe_loader_constructs_no_python_object() -> None:
    with pytest.raises(yaml.YAMLError):
        yaml_loader.safe_load("--- !!python/object/apply:os.getcwd []\n")


@pytest.mark.usefixtures("without_libyaml")
def test_without_libyaml_the_tools_report_invalid_yaml_as_their_own_error(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yml"
    path.write_text(INVALID, encoding="utf-8")
    with pytest.raises(generate_toggles.GenerationError, match="cannot be read as YAML"):
        generate_toggles.load_catalogue(path)
    versions = tmp_path / check_lifecycle_topics.VERSIONS
    versions.parent.mkdir(parents=True)
    versions.write_text(INVALID, encoding="utf-8")
    with pytest.raises(check_lifecycle_topics.GenerationError, match="cannot be read as YAML"):
        check_lifecycle_topics.platforms(tmp_path)
