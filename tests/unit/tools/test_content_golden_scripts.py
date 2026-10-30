from __future__ import annotations

import collections
from pathlib import Path

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
    xmlsafe,
)
from tests.unit.tools.test_content_golden_native import pinned_benchmarks
from tools.content import fetch_content as fetch

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
XCCDF = f"{{{catalog.XCCDF_NAMESPACE}}}"
DATASTREAM = f"{{{catalog.DATASTREAM_NAMESPACE}}}"
SCE_PREFIX = f"{{{catalog.SCE_NAMESPACE}}}"
REMOVED = {"ubuntu2404": (81, 81), "rhel9": (438, 438)}
PINNED_PROFILES = 25


class ScriptCounter:
    """Counts the check systems, extended components and SCE elements of a datastream."""

    def __init__(self) -> None:
        self.systems: collections.Counter[str] = collections.Counter()
        self.extended_components = 0
        self.sce_elements = 0
        self.rules: dict[str, set[str]] = {}
        self.rule = ""

    def start(self, name: str, attributes: dict[str, str], /) -> None:
        if name == f"{XCCDF}Rule":
            self.rule = attributes.get("id", "")
            self.rules[self.rule] = set()
        elif name == f"{XCCDF}check":
            system = attributes.get("system", "")
            self.systems[system] += 1
            self.rules.setdefault(self.rule, set()).add(system)
        elif name == f"{DATASTREAM}extended-component":
            self.extended_components += 1
        elif name.startswith(SCE_PREFIX):
            self.sce_elements += 1

    def end(self, name: str, /) -> None:
        if name == f"{XCCDF}Rule":
            self.rule = ""

    def text(self, data: str, /) -> None:
        """Ignore character data."""


def counted(path: str) -> ScriptCounter:
    counter = ScriptCounter()
    xmlsafe.parse_chunks(xmlsafe.iter_file_chunks(path, catalog.DEFAULT_MAX_BYTES), counter)
    return counter


def test_no_pinned_datastream_or_profile_holds_a_script_check() -> None:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    by_benchmark = {stream.benchmark_id: stream for stream in manifest.datastreams}
    checked = 0
    for path, sha256, benchmark_id in pinned_benchmarks():
        counter = counted(path)
        assert set(counter.systems) <= catalog.ACCEPTED_CHECK_SYSTEMS, benchmark_id
        assert counter.systems[catalog.SCE_CHECK_SYSTEM] == 0
        assert counter.extended_components == 0
        assert counter.sce_elements == 0
        benchmark = catalog.single_benchmark(catalog.read_benchmarks(path, sha256))
        for entry in by_benchmark[benchmark_id].profiles:
            profile = catalog.find_profile(benchmark, entry.profile_id)
            systems = {
                system for rule_id in profile.rule_ids for system in counter.rules.get(rule_id, ())
            }
            assert systems <= catalog.ACCEPTED_CHECK_SYSTEMS, entry.profile_id
            checked += 1
    assert checked == PINNED_PROFILES


def test_the_manifest_records_every_script_that_was_removed() -> None:
    manifest = fetch.load_manifest(REPOSITORY_ROOT / "content" / "manifest.yml")
    assert {
        stream.name: (stream.removed_sce_checks, stream.removed_sce_scripts)
        for stream in manifest.datastreams
    } == REMOVED
    assert all(stream.source_sha256 != stream.sha256 for stream in manifest.datastreams)
    assert sum(len(stream.profiles) for stream in manifest.datastreams) == PINNED_PROFILES
