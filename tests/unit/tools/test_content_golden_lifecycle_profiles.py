"""Golden test: a lifecycle ``profiles`` entry never narrows the rules a topic runs (FREES-190)."""

from __future__ import annotations

from typing import cast

import yaml

from tests.unit.tools.test_content_golden_kernel_modules import PROFILE, TOPICS, read
from tests.unit.tools.test_content_golden_native import REPOSITORY_ROOT, pinned_benchmarks
from tools.roles import check_lifecycle_topics, generate_toggles

PLATFORM_OF_BENCHMARK = {
    "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04": "ubuntu",
    "xccdf_org.ssgproject.content_benchmark_RHEL-9": "rhel_compatible",
}


def load(path: object) -> dict[str, object]:
    return cast(
        "dict[str, object]", yaml.safe_load(REPOSITORY_ROOT.joinpath(str(path)).read_text("utf-8"))
    )


def own_profiles() -> dict[str, str]:
    images = cast(
        "dict[str, dict[str, str]]", load(check_lifecycle_topics.VERSIONS)["molecule_images"]
    )
    return {platform: image["profile"] for platform, image in images.items()}


def topic_rules() -> dict[str, set[str]]:
    catalogue = generate_toggles.load_catalogue(REPOSITORY_ROOT / generate_toggles.CATALOGUE)
    rules: dict[str, set[str]] = {}
    for rule in catalogue.rules:
        if rule["revert_strategy"] != "audit_only":
            rules.setdefault(str(rule["family"]), set()).add(str(rule["rule_id"]))
    return rules


def test_a_declared_profile_never_narrows_and_together_covers_every_rule_of_its_topic() -> None:
    own = own_profiles()
    rules = topic_rules()
    declarations = {
        path.stem: cast("dict[str, object]", yaml.safe_load(path.read_text(encoding="utf-8")))
        for path in sorted(TOPICS.glob("*.yml"))
    }
    with_profiles = {
        family: {
            str(item["platform"]): str(item["profile"])
            for item in cast("list[dict[str, object]]", data["profiles"])
        }
        for family, data in declarations.items()
        if "profiles" in data
    }
    assert set(with_profiles) == {"filesystem_modules", "protocol_modules", "wireless_modules"}
    cycles: dict[str, set[str]] = {family: set() for family in with_profiles}
    selectable: dict[str, set[str]] = {family: set() for family in with_profiles}
    for path, sha256, benchmark in pinned_benchmarks():
        content = read(path, sha256)
        platform = PLATFORM_OF_BENCHMARK[benchmark]
        for family, chosen in with_profiles.items():
            native = rules[family]
            for selected in content.profiles.values():
                selectable[family] |= selected & native
            own_rules = content.profiles[PROFILE + own[platform]] & native
            chosen_rules = content.profiles[PROFILE + chosen.get(platform, own[platform])] & native
            assert chosen_rules >= own_rules, (family, platform, sorted(own_rules - chosen_rules))
            cycles[family] |= chosen_rules
    for family, covered in cycles.items():
        assert covered == selectable[family], (family, sorted(selectable[family] - covered))
