from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import catalog
from tools.content import fetch_content as fetch
from tools.roles import generate_catalogue

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
