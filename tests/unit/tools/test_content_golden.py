from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
    toggles,
)
from tools.content import fetch_content as fetch
from tools.roles import generate_catalogue, generate_toggles

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GOLDEN_PATH = REPOSITORY_ROOT / "tests" / "fixtures" / "catalog" / "golden-rules.yml"
CONTENT_DIRECTORY = Path(
    os.environ.get("FREESECDEV_CONTENT_DIR", str(REPOSITORY_ROOT / "build" / "content"))
)
REQUIRE_CONTENT = os.environ.get("FREESECDEV_REQUIRE_CONTENT") == "1"


def load_golden() -> list[dict[str, object]]:
    document = cast("dict[str, object]", yaml.safe_load(GOLDEN_PATH.read_text(encoding="utf-8")))
    assert document["schema_version"] == 1
    return cast("list[dict[str, object]]", document["datastreams"])


def rule_list_digest(rule_ids: tuple[str, ...]) -> str:
    return hashlib.sha256(("\n".join(rule_ids) + "\n").encode()).hexdigest()


def test_the_golden_file_matches_the_manifest() -> None:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    golden = load_golden()
    assert [(item["name"], item["sha256"]) for item in golden] == [
        (stream.name, stream.sha256) for stream in manifest.datastreams
    ]
    for item, stream in zip(golden, manifest.datastreams, strict=True):
        profiles = cast("list[dict[str, object]]", item["profiles"])
        assert [entry["id"] for entry in profiles] == [p.profile_id for p in stream.profiles]
        assert all(isinstance(entry["rule_count"], int) for entry in profiles)


def test_first_milestone_counts_are_recorded() -> None:
    counts = {
        (str(item["name"]), str(entry["id"]).rsplit("content_profile_", 1)[1]): entry["rule_count"]
        for item in load_golden()
        for entry in cast("list[dict[str, object]]", item["profiles"])
    }
    assert counts[("ubuntu2404", "cis_level1_server")] == 408
    assert counts[("rhel9", "stig")] == 481
    assert counts[("rhel9", "cis")] == 401


def test_the_catalog_reproduces_the_recorded_rule_lists_for_the_pinned_content() -> None:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    for item, stream in zip(load_golden(), manifest.datastreams, strict=True):
        path = CONTENT_DIRECTORY / stream.file_name
        if not path.is_file():
            if REQUIRE_CONTENT:
                pytest.fail(f"pinned content {path} is missing but FREESECDEV_REQUIRE_CONTENT=1")
            pytest.skip(f"pinned content {path} is not present; run make test-content-golden")
        benchmark = catalog.single_benchmark(catalog.read_benchmarks(str(path), stream.sha256))
        recorded = cast("list[dict[str, object]]", item["profiles"])
        assert [p.profile_id for p in benchmark.profiles] == [entry["id"] for entry in recorded]
        for profile, entry in zip(benchmark.profiles, recorded, strict=True):
            assert len(profile.rule_ids) == entry["rule_count"], profile.profile_id
            assert rule_list_digest(profile.rule_ids) == entry["rule_ids_sha256"], (
                profile.profile_id
            )


def test_the_generated_catalogue_matches_the_pinned_content() -> None:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    missing = [
        stream.file_name
        for stream in manifest.datastreams
        if not (CONTENT_DIRECTORY / stream.file_name).is_file()
    ]
    if missing:
        if REQUIRE_CONTENT:
            pytest.fail(f"pinned content {missing} is missing but FREESECDEV_REQUIRE_CONTENT=1")
        pytest.skip(f"pinned content {missing} is not present; run make test-content-golden")
    generated = generate_catalogue.generate(REPOSITORY_ROOT, CONTENT_DIRECTORY)
    for relative, content in generated.items():
        assert (REPOSITORY_ROOT / relative).read_text(encoding="utf-8") == content, relative
    streams = [
        generate_catalogue.read_stream(stream)
        for stream in generate_catalogue.streams_of(manifest, CONTENT_DIRECTORY)
    ]
    source = generate_catalogue.load_source(REPOSITORY_ROOT / generate_catalogue.SOURCE)
    catalogued = {str(rule["rule_id"]) for rule in generate_catalogue.build(source, streams).rules}
    for item, stream in zip(load_golden(), streams, strict=True):
        for entry in cast("list[dict[str, object]]", item["profiles"]):
            rule_ids = stream.profiles[str(entry["id"])]
            assert len(rule_ids) == entry["rule_count"], entry["id"]
            assert set(rule_ids) <= catalogued, entry["id"]


def test_every_topic_toggle_switches_off_exactly_its_rules_in_every_pinned_profile() -> None:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    missing = [
        stream.file_name
        for stream in manifest.datastreams
        if not (CONTENT_DIRECTORY / stream.file_name).is_file()
    ]
    if missing:
        if REQUIRE_CONTENT:
            pytest.fail(f"pinned content {missing} is missing but FREESECDEV_REQUIRE_CONTENT=1")
        pytest.skip(f"pinned content {missing} is not present; run make test-content-golden")
    loaded = generate_toggles.load_catalogue(REPOSITORY_ROOT / generate_toggles.CATALOGUE)
    families = {str(rule["rule_id"]): str(rule["family"]) for rule in loaded.rules}
    streams = [
        generate_catalogue.read_stream(stream)
        for stream in generate_catalogue.streams_of(manifest, CONTENT_DIRECTORY)
    ]
    for stream in streams:
        for profile_id, rule_ids in stream.profiles.items():
            profile = frozenset(rule_ids)
            for topic in generate_toggles.topics(loaded):
                toggle = toggles.toggle_name(topic)
                members = generate_toggles.governed(loaded, topic)
                expected = {
                    rule_id
                    for rule_id in profile
                    if families[rule_id] in members
                    or any(tag in members for tag in loaded.tags.get(rule_id, ()))
                }
                switched_off = toggles.disabled_rules(
                    loaded.rules,
                    {toggle: False},
                    profile,
                    umbrellas=loaded.umbrellas,
                    tags=loaded.tags,
                )
                assert {str(item["rule_id"]) for item in switched_off} == expected, (
                    profile_id,
                    topic,
                )
                assert {item["disabled_by"] for item in switched_off} <= {toggle}
                warned = toggles.topic_warnings(
                    toggles.Catalogue(
                        rules=loaded.rules,
                        families=loaded.families,
                        toggles={toggle: False},
                        umbrellas=loaded.umbrellas,
                        tags=loaded.tags,
                    ),
                    profile,
                )
                assert bool(warned) is not bool(expected), (profile_id, topic)


REVIEWED_EXAMPLES: dict[str, tuple[str, ...]] = {
    "sssd": (
        "file_permissions_var_log_sssd",
        "file_ownerships_var_log_sssd",
        "file_groupownerships_var_log_sssd",
    ),
    "time_sync": (
        "file_permissions_etc_chrony_keys",
        "file_owner_etc_chrony_keys",
        "file_groupowner_etc_chrony_keys",
    ),
    "cron": ("file_owner_cron_deny", "file_groupowner_at_deny", "file_permissions_crontab"),
    "smartcard": ("sssd_enable_smartcards", "dconf_gnome_lock_screen_on_smartcard_removal"),
    "pwhistory": ("accounts_password_pam_unix_remember", "accounts_password_pam_unix_no_remember"),
}
AUDIT_WATCHES: dict[str, tuple[str, ...]] = {
    "apparmor": (
        "audit_rules_mac_modification_etc_apparmor",
        "audit_rules_mac_modification_etc_apparmor_d",
    ),
    "selinux": ("audit_rules_mac_modification",),
}


def switched_off_in(loaded: toggles.Catalogue, topic: str, profile: frozenset[str]) -> set[str]:
    return {
        str(item["rule_id"])
        for item in toggles.disabled_rules(
            loaded.rules,
            {toggles.toggle_name(topic): False},
            profile,
            umbrellas=loaded.umbrellas,
            tags=loaded.tags,
        )
    }


def pinned_profiles() -> list[tuple[str, frozenset[str]]]:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    missing = [
        stream.file_name
        for stream in manifest.datastreams
        if not (CONTENT_DIRECTORY / stream.file_name).is_file()
    ]
    if missing:
        if REQUIRE_CONTENT:
            pytest.fail(f"pinned content {missing} is missing but FREESECDEV_REQUIRE_CONTENT=1")
        pytest.skip(f"pinned content {missing} is not present; run make test-content-golden")
    return [
        (profile_id, frozenset(rule_ids))
        for stream in generate_catalogue.streams_of(manifest, CONTENT_DIRECTORY)
        for profile_id, rule_ids in generate_catalogue.read_stream(stream).profiles.items()
    ]


def test_the_reviewed_examples_follow_their_subsystem_toggle_in_every_pinned_profile() -> None:
    profiles = pinned_profiles()
    loaded = generate_toggles.load_catalogue(REPOSITORY_ROOT / generate_toggles.CATALOGUE)
    seen: set[str] = set()
    for profile_id, profile in profiles:
        for topic, shorts in (REVIEWED_EXAMPLES | AUDIT_WATCHES).items():
            switched_off = switched_off_in(loaded, topic, profile)
            present = [short for short in shorts if toggles.RULE_PREFIX + short in profile]
            seen.update(present)
            for short in present:
                assert (toggles.RULE_PREFIX + short in switched_off) is (
                    topic in REVIEWED_EXAMPLES
                ), (profile_id, topic, short)
    assert len(profiles) == 25
    every_example = {short for shorts in REVIEWED_EXAMPLES.values() for short in shorts}
    every_watch = {short for shorts in AUDIT_WATCHES.values() for short in shorts}
    assert seen == every_example | every_watch
