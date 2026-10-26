from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
import yaml

from tools.content import fetch_content as fetch

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = REPOSITORY_ROOT / "content" / "manifest.yml"
PROFILE_ID = re.compile(r"xccdf_org\.ssgproject\.content_profile_[A-Za-z0-9_.+-]+")
MINIMUM_PIN_AGE = timedelta(days=7)


@pytest.fixture(scope="module")
def document() -> dict[str, object]:
    return cast("dict[str, object]", yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def manifest() -> fetch.Manifest:
    return fetch.load_manifest(MANIFEST_PATH)


def test_the_manifest_starts_with_a_document_marker_and_has_no_comments() -> None:
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    assert not [line for line in text.splitlines() if line.lstrip().startswith("#")]


def test_the_manifest_passes_the_tool_validation(manifest: fetch.Manifest) -> None:
    assert manifest.version == "v0.1.82"
    assert manifest.archive.url.startswith("https://")
    assert manifest.archive.url.endswith("/v0.1.82/scap-security-guide-0.1.82.zip")


def test_only_the_in_scope_datastreams_are_pinned(manifest: fetch.Manifest) -> None:
    assert {stream.name: stream.file_name for stream in manifest.datastreams} == {
        "ubuntu2404": "ssg-ubuntu2404-ds.xml",
        "rhel9": "ssg-rhel9-ds.xml",
    }


def test_the_source_records_the_licence_and_an_old_enough_release(
    document: dict[str, object],
) -> None:
    source = cast("dict[str, str]", document["source"])
    assert source["licence"] == "BSD-3-Clause"
    released = datetime.fromisoformat(source["released_at"])
    assert datetime.now(UTC) - released >= MINIMUM_PIN_AGE


def test_every_datastream_lists_unique_well_formed_profiles(manifest: fetch.Manifest) -> None:
    for stream in manifest.datastreams:
        identifiers = [profile.profile_id for profile in stream.profiles]
        assert identifiers
        assert len(set(identifiers)) == len(identifiers)
        assert all(PROFILE_ID.fullmatch(identifier) for identifier in identifiers)
        assert all(profile.title for profile in stream.profiles)
        assert stream.benchmark_id.startswith("xccdf_org.ssgproject.content_benchmark_")


def test_the_first_milestone_profile_is_present_for_ubuntu(manifest: fetch.Manifest) -> None:
    ubuntu = next(stream for stream in manifest.datastreams if stream.name == "ubuntu2404")
    assert "xccdf_org.ssgproject.content_profile_cis_level1_server" in {
        profile.profile_id for profile in ubuntu.profiles
    }


def test_profiles_are_not_shared_between_unrelated_benchmarks(manifest: fetch.Manifest) -> None:
    benchmarks = {stream.benchmark_id for stream in manifest.datastreams}
    assert len(benchmarks) == len(manifest.datastreams)


def test_the_repository_holds_no_downloaded_content() -> None:
    assert sorted(item.name for item in (REPOSITORY_ROOT / "content").iterdir()) == [
        "catalogue.yml",
        "manifest.yml",
    ]
    ignored = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "*.zip" in ignored
