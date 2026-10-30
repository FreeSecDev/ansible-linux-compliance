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
LIFECYCLE_SCENARIOS = (
    "docker-ubuntu-lifecycle",
    "docker-rhel-compatible-lifecycle",
    "libvirt-ubuntu-lifecycle",
    "libvirt-rhel-compatible-lifecycle",
)
BASE_SCENARIOS = ("libvirt-ubuntu", "libvirt-rhel-compatible")


def write_scenario(root: Path, scenario: str) -> None:
    driver, rest = scenario.split("-", 1)
    lifecycle = rest.endswith(matrix.SCENARIO_SUFFIX)
    platform = rest.removesuffix(matrix.SCENARIO_SUFFIX).replace("-", "_")
    config: dict[str, object] = {"platforms": [{"name": platform, "image": platform}]}
    if lifecycle:
        config["ansible"] = {
            "playbooks": {"side_effect": check_lifecycle_topics.LIFECYCLE_PLAYBOOK}
        }
    directory = root / matrix.MOLECULE / scenario
    directory.mkdir(parents=True)
    assert driver in matrix.DRIVERS
    (directory / "molecule.yml").write_text("---\n" + yaml.safe_dump(config), encoding="utf-8")


def make_root(
    tmp_path: Path,
    *,
    scenarios: tuple[str, ...] = LIFECYCLE_SCENARIOS + BASE_SCENARIOS,
    native: bool = True,
    declarations: dict[str, object] | None = None,
) -> Path:
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
    shutil.copytree(
        REPOSITORY_ROOT / check_lifecycle_topics.TOPICS, root / check_lifecycle_topics.TOPICS
    )
    shutil.copytree(
        REPOSITORY_ROOT / check_lifecycle_topics.REGRESSION_DISPATCH.parent,
        root / check_lifecycle_topics.REGRESSION_DISPATCH.parent,
    )
    for family, declaration in (declarations or {}).items():
        path = root / check_lifecycle_topics.TOPICS / f"{family}.yml"
        path.write_text("---\n" + yaml.safe_dump(declaration), encoding="utf-8")
    for scenario in scenarios:
        write_scenario(root, scenario)
    return root


def native_topics(root: Path) -> list[str]:
    catalogue = generate_toggles.load_catalogue(root / generate_toggles.CATALOGUE)
    return generate_toggles.native_families(catalogue)


def test_the_repository_libvirt_matrix_has_a_base_leg_the_libvirt_cycles_and_the_selftest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert matrix.main(["--root", str(REPOSITORY_ROOT), "--driver", "libvirt"]) == 0
    found = cast("dict[str, list[dict[str, str]]]", json.loads(capsys.readouterr().out))
    cycles = check_lifecycle_topics.cycle_platforms(REPOSITORY_ROOT)
    expected: list[dict[str, str]] = []
    for platform in sorted(check_lifecycle_topics.platforms(REPOSITORY_ROOT)):
        expected.append(
            {
                "platform": platform,
                "scenario": matrix.scenario_of(platform, "libvirt", ""),
                "topic": "",
                "mode": "",
            }
        )
        expected.extend(
            {
                "platform": platform,
                "scenario": matrix.scenario_of(platform, "libvirt"),
                "topic": topic,
                "mode": mode,
            }
            for topic in native_topics(REPOSITORY_ROOT)
            if platform in cycles[topic].get("libvirt", frozenset())
            for mode in matrix.MODES
        )
    expected.append({"platform": "ubuntu", "scenario": "libvirt-selftest", "topic": "", "mode": ""})
    assert found["include"] == expected
    ownership = [leg for leg in found["include"] if leg["topic"] == "file_permissions"]
    assert {(leg["platform"], leg["mode"]) for leg in ownership} == {
        (platform, mode)
        for platform in check_lifecycle_topics.platforms(REPOSITORY_ROOT)
        for mode in matrix.MODES
    }


def test_the_repository_matrix_covers_every_native_topic_in_both_modes_on_every_platform(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert matrix.main(["--root", str(REPOSITORY_ROOT)]) == 0
    found = cast("dict[str, list[dict[str, str]]]", json.loads(capsys.readouterr().out))
    topics = native_topics(REPOSITORY_ROOT)
    platforms = sorted(check_lifecycle_topics.platforms(REPOSITORY_ROOT))
    regressions = check_lifecycle_topics.regression_platforms(REPOSITORY_ROOT)
    assert found["include"] == [
        {
            "platform": platform,
            "scenario": matrix.scenario_of(platform),
            "topic": topic,
            "mode": mode,
        }
        for platform in platforms
        for topic in topics
        for mode in (
            "topic",
            "rule",
            *(
                matrix.REGRESSION_MODE_PREFIX + name
                for name, chosen in regressions[topic].items()
                if platform in chosen
            ),
        )
    ]
    sudo = {(leg["platform"], leg["mode"]) for leg in found["include"] if leg["topic"] == "sudo"}
    assert {mode for _, mode in sudo if mode.startswith(matrix.REGRESSION_MODE_PREFIX)} == {
        "regressions-changes",
        "regressions-files",
        "regressions-profiles",
    }
    assert ("rhel_compatible", "regressions-files") not in sudo
    declared = sorted(
        path.stem for path in (REPOSITORY_ROOT / check_lifecycle_topics.TOPICS).glob("*.yml")
    )
    assert sorted({leg["topic"] for leg in found["include"]}) == declared


def test_the_scenario_of_a_platform_follows_the_scenario_names() -> None:
    assert matrix.scenario_of("ubuntu") == "docker-ubuntu-lifecycle"
    assert matrix.scenario_of("rhel_compatible") == "docker-rhel-compatible-lifecycle"
    assert matrix.scenario_of("ubuntu", "libvirt") == "libvirt-ubuntu-lifecycle"
    assert matrix.scenario_of("rhel_compatible", "libvirt", "") == "libvirt-rhel-compatible"
    for platform in check_lifecycle_topics.platforms(REPOSITORY_ROOT):
        for scenario in (
            matrix.scenario_of(platform, "libvirt"),
            matrix.scenario_of(platform, "libvirt", ""),
        ):
            assert (REPOSITORY_ROOT / matrix.MOLECULE / scenario / "molecule.yml").is_file()


def test_the_docker_matrix_holds_every_topic_with_a_docker_cycle(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    topics = native_topics(root)
    cycles = [leg for leg in matrix.legs(root) if leg["mode"] in matrix.MODES]
    assert cycles == [
        {
            "platform": platform,
            "scenario": matrix.scenario_of(platform),
            "topic": topic,
            "mode": mode,
        }
        for platform in sorted(check_lifecycle_topics.platforms(root))
        for topic in topics
        for mode in matrix.MODES
    ]
    assert all(leg["topic"] for leg in matrix.legs(root))


def test_regression_groups_get_docker_legs_only(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    docker = [leg for leg in matrix.legs(root) if leg["mode"].startswith("regressions-")]
    assert {(leg["topic"], leg["mode"]) for leg in docker} >= {("sudo", "regressions-files")}
    assert all(not leg["mode"].startswith("regressions-") for leg in matrix.legs(root, "libvirt"))


def test_a_topic_that_requires_libvirt_has_no_docker_leg(tmp_path: Path) -> None:
    path = REPOSITORY_ROOT / check_lifecycle_topics.TOPICS / "file_permissions.yml"
    declaration = cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))
    declaration["requires"] = ["libvirt"]
    root = make_root(tmp_path, declarations={"file_permissions": declaration})
    assert all(leg["topic"] != "file_permissions" for leg in matrix.legs(root, "docker"))
    libvirt = [leg for leg in matrix.legs(root, "libvirt") if leg["topic"] == "file_permissions"]
    assert len(libvirt) == len(check_lifecycle_topics.platforms(root)) * len(matrix.MODES)


@pytest.mark.parametrize(
    ("driver", "missing", "message"),
    [
        ("docker", "docker-rhel-compatible-lifecycle", "has no lifecycle scenario"),
        ("libvirt", "libvirt-ubuntu-lifecycle", "has no lifecycle scenario"),
        ("libvirt", "libvirt-ubuntu", "has no libvirt base scenario"),
    ],
)
def test_a_platform_without_its_scenario_is_an_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    driver: str,
    missing: str,
    message: str,
) -> None:
    root = make_root(tmp_path)
    directory = root / matrix.MOLECULE / missing
    directory.rename(directory.with_name(missing + "-renamed"))
    assert matrix.main(["--root", str(root), "--driver", driver]) == 2
    assert message in capsys.readouterr().err


def test_a_catalogue_without_a_native_topic_is_an_error(tmp_path: Path) -> None:
    root = make_root(tmp_path, native=False)
    with pytest.raises(matrix.GenerationError, match="has no native topic"):
        matrix.legs(root)


def test_an_unknown_driver_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(matrix.GenerationError, match="unknown driver 'vagrant'"):
        matrix.legs(make_root(tmp_path), "vagrant")


def test_an_invalid_declaration_plans_no_leg(tmp_path: Path) -> None:
    root = make_root(tmp_path, declarations={"file_permissions": {"family": "other"}})
    with pytest.raises(matrix.GenerationError, match="family must be 'file_permissions'"):
        matrix.legs(root, "libvirt")


def test_the_selftest_platform_must_be_a_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(matrix, "LIBVIRT_SELFTEST_PLATFORM", "debian")
    with pytest.raises(matrix.GenerationError, match="the self-test platform debian"):
        matrix.legs(make_root(tmp_path), "libvirt")


def test_the_module_runs_as_a_script(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["molecule_matrix", "--root", str(REPOSITORY_ROOT), "--driver", "libvirt"],
    )
    sys.modules.pop("tools.roles.molecule_matrix", None)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("tools.roles.molecule_matrix", run_name="__main__")
    assert exit_info.value.code == 0
    assert '"scenario":"libvirt-selftest"' in capsys.readouterr().out
