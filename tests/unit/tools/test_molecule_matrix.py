from __future__ import annotations

import json
import runpy
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.roles import check_lifecycle_topics, generate_toggles
from tools.roles import molecule_matrix as matrix

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def make_root(tmp_path: Path, *, scenarios: tuple[str, ...], native: bool = True) -> Path:
    root = tmp_path / "repository"
    catalogue = root / generate_toggles.CATALOGUE
    catalogue.parent.mkdir(parents=True)
    data = cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / generate_toggles.CATALOGUE).read_text(encoding="utf-8")),
    )
    if not native:
        rules = cast("list[dict[str, object]]", data[generate_toggles.RULES_KEY])
        audit_only = cast("dict[str, list[str]]", data[generate_toggles.AUDIT_ONLY_KEY])
        for rule in rules:
            family = str(rule["family"])
            audit_only[family] = sorted([*audit_only[family], str(rule["rule_id"])])
        data[generate_toggles.RULES_KEY] = []
    catalogue.write_text("---\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    versions = root / check_lifecycle_topics.VERSIONS
    versions.parent.mkdir(parents=True)
    shutil.copyfile(REPOSITORY_ROOT / check_lifecycle_topics.VERSIONS, versions)
    for scenario in scenarios:
        directory = root / matrix.MOLECULE / scenario
        directory.mkdir(parents=True)
        (directory / "molecule.yml").write_text("---\n{}\n", encoding="utf-8")
    return root


def test_the_repository_matrix_covers_every_native_topic_in_both_modes_on_every_platform(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert matrix.main(["--root", str(REPOSITORY_ROOT)]) == 0
    found = cast("dict[str, list[dict[str, str]]]", json.loads(capsys.readouterr().out))
    catalogue = generate_toggles.load_catalogue(REPOSITORY_ROOT / generate_toggles.CATALOGUE)
    topics = generate_toggles.native_families(catalogue)
    platforms = sorted(check_lifecycle_topics.platforms(REPOSITORY_ROOT))
    assert found["include"] == [
        {
            "platform": platform,
            "scenario": matrix.scenario_of(platform),
            "topic": topic,
            "mode": mode,
        }
        for platform in platforms
        for topic in topics
        for mode in ("topic", "rule")
    ]
    declared = sorted(
        path.stem for path in (REPOSITORY_ROOT / check_lifecycle_topics.TOPICS).glob("*.yml")
    )
    assert sorted({leg["topic"] for leg in found["include"]}) == declared


def test_the_scenario_of_a_platform_follows_the_scenario_names() -> None:
    assert matrix.scenario_of("ubuntu") == "docker-ubuntu-lifecycle"
    assert matrix.scenario_of("rhel_compatible") == "docker-rhel-compatible-lifecycle"
    for platform in check_lifecycle_topics.platforms(REPOSITORY_ROOT):
        assert (
            REPOSITORY_ROOT / matrix.MOLECULE / matrix.scenario_of(platform) / "molecule.yml"
        ).is_file()


def test_a_platform_without_its_lifecycle_scenario_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = make_root(tmp_path, scenarios=("docker-ubuntu-lifecycle",))
    assert matrix.main(["--root", str(root)]) == 2
    assert "has no lifecycle scenario" in capsys.readouterr().err


def test_a_catalogue_without_a_native_topic_is_an_error(tmp_path: Path) -> None:
    root = make_root(
        tmp_path,
        scenarios=("docker-ubuntu-lifecycle", "docker-rhel-compatible-lifecycle"),
        native=False,
    )
    with pytest.raises(matrix.GenerationError, match="has no native topic"):
        matrix.legs(root)


def test_the_module_runs_as_a_script(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["molecule_matrix", "--root", str(REPOSITORY_ROOT)])
    sys.modules.pop("tools.roles.molecule_matrix", None)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("tools.roles.molecule_matrix", run_name="__main__")
    assert exit_info.value.code == 0
    assert '"topic":"pwquality"' in capsys.readouterr().out
