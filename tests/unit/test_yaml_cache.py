from __future__ import annotations

import shutil
from pathlib import Path
from typing import cast

import yaml

from tests.unit import yaml_cache

CATALOGUE = Path(__file__).resolve().parents[2] / "roles" / "remediate" / "vars" / "rules.yml"


def test_the_cache_gives_what_the_safe_loader_gives() -> None:
    expected = cast("object", yaml.safe_load(CATALOGUE.read_text(encoding="utf-8")))
    assert yaml_cache.load(CATALOGUE) == expected
    assert yaml_cache.load(CATALOGUE) == expected


def test_every_call_returns_its_own_copy() -> None:
    first = cast("dict[str, object]", yaml_cache.load(CATALOGUE))
    first.clear()
    second = cast("dict[str, object]", yaml_cache.load(CATALOGUE))
    assert second
    assert second is not first


def test_a_changed_file_is_parsed_again(tmp_path: Path) -> None:
    path = tmp_path / "data.yml"
    path.write_text("---\nvalue: 1\n", encoding="utf-8")
    assert yaml_cache.load(path) == {"value": 1}
    path.write_text("---\nvalue: 2\n", encoding="utf-8")
    assert yaml_cache.load(path) == {"value": 2}


def test_a_copy_at_another_path_is_parsed_on_its_own(tmp_path: Path) -> None:
    copy = tmp_path / "rules.yml"
    shutil.copyfile(CATALOGUE, copy)
    assert yaml_cache.load(copy) == yaml_cache.load(CATALOGUE)
    assert {str(copy.resolve()), str(CATALOGUE)} <= yaml_cache.parsed_paths()
