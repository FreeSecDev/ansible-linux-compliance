from __future__ import annotations

import hashlib
import json
import runpy
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import catalog
from tools.content import generate_stig_mapping as gen
from tools.reporting import stig_mapping

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
NS = (
    'xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2" '
    'xmlns:x="http://checklists.nist.gov/xccdf/1.2"'
)
STIG_HREF = next(iter(catalog.STIG_ID_REFERENCES))
OTHER_HREF = (
    "https://www.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cgeneral-purpose-os"
)
RULE = "xccdf_org.ssgproject.content_rule_"
PROFILE = "xccdf_org.ssgproject.content_profile_"
BENCHMARK = "xccdf_org.ssgproject.content_benchmark_SYNTHETIC"
RULES: dict[str, tuple[str, ...]] = {
    "one": ("SYNT-01-000010",),
    "split_a": ("SYNT-01-000020",),
    "split_b": ("SYNT-01-000020",),
    "joint": ("SYNT-01-000030", "SYNT-01-000040", "SYNT-01-000030"),
    "support": ("needed_rules",),
    "plain": (),
    "unselected": ("SYNT-01-000050",),
}


def rule(name: str, stig_ids: tuple[str, ...]) -> str:
    references = "".join(
        f'<x:reference href="{STIG_HREF}">{value}</x:reference>' for value in stig_ids
    )
    other = f'<x:reference href="{OTHER_HREF}">SRG-OS-000001-GPOS-00001</x:reference>'
    title = f"<x:title>{name}</x:title>"
    return f'<x:Rule id="{RULE}{name}" severity="medium">{title}{other}{references}</x:Rule>'


def profile(name: str, version: str, rules: dict[str, tuple[str, ...]]) -> str:
    selects = "".join(
        f'<x:select idref="{RULE}{item}" selected="{str(item != "unselected").lower()}"/>'
        for item in rules
    )
    shown = f"<x:version>{version}</x:version><x:version>V9R9</x:version>"
    return f'<x:Profile id="{PROFILE}{name}">{shown}<x:title>{name}</x:title>{selects}</x:Profile>'


def stream(rules: dict[str, tuple[str, ...]] | None = None, stig_version: str = "V1R2") -> bytes:
    rules = RULES if rules is None else rules
    body = (
        f'<x:Benchmark id="{BENCHMARK}"><x:version>0.1.82</x:version>'
        f"{profile('stig', stig_version, rules)}{profile('cis', '1.0.0', rules)}"
        f'<x:Group id="xccdf_org.ssgproject.content_group_system">'
        f"{''.join(rule(name, ids) for name, ids in rules.items())}</x:Group></x:Benchmark>"
    )
    component = f"<ds:component>{body}</ds:component>"
    return f"<ds:data-stream-collection {NS}>{component}</ds:data-stream-collection>".encode()


def write_root(root: Path, data: bytes | None = None, *, other: bytes | None = None) -> Path:
    content = root / "build" / "content"
    content.mkdir(parents=True)
    manifest = cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / gen.MANIFEST).read_text(encoding="utf-8")),
    )
    streams = {"synthetic": stream() if data is None else data}
    if other is not None:
        streams["plainstream"] = other
    entries: list[dict[str, object]] = []
    for name, body in streams.items():
        (content / f"ssg-{name}-ds.xml").write_bytes(body)
        entries.append(
            {
                "name": name,
                "os_family": "test",
                "os_version": "1",
                "path": f"scap-security-guide-0.1.82/ssg-{name}-ds.xml",
                "sha256": hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body),
                "benchmark_id": BENCHMARK,
                "benchmark_version": "0.1.82",
                "profiles": [
                    {"id": f"{PROFILE}stig", "title": "stig"},
                    {"id": f"{PROFILE}cis", "title": "cis"},
                ],
            }
        )
    manifest["datastreams"] = entries
    (root / "content").mkdir()
    (root / gen.MANIFEST).write_text("---\n" + yaml.safe_dump(manifest), encoding="utf-8")
    return root


def generated(root: Path) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(gen.generate(root, gen.CONTENT_DIR)[gen.MAPPING]))


def test_the_mapping_joins_rules_on_their_stig_ids_many_to_many(tmp_path: Path) -> None:
    document = generated(write_root(tmp_path))
    assert document["schema_version"] == 1
    assert str(document["source"]).startswith("ComplianceAsCode/content v")
    streams = cast("list[dict[str, object]]", document["datastreams"])
    assert [item["name"] for item in streams] == ["synthetic"]
    assert streams[0]["benchmark_id"] == BENCHMARK
    assert streams[0]["file_name"] == "ssg-synthetic-ds.xml"
    profiles = cast("list[dict[str, object]]", streams[0]["profiles"])
    assert [item["profile_id"] for item in profiles] == [f"{PROFILE}stig"]
    assert profiles[0]["stig_release"] == "V1R2"
    assert profiles[0]["stig_ids"] == {
        "SYNT-01-000010": [f"{RULE}one"],
        "SYNT-01-000020": [f"{RULE}split_a", f"{RULE}split_b"],
        "SYNT-01-000030": [f"{RULE}joint"],
        "SYNT-01-000040": [f"{RULE}joint"],
    }
    assert profiles[0]["rules_without_stig_id"] == [f"{RULE}plain", f"{RULE}support"]


def test_the_generated_file_is_a_valid_mapping_for_the_reader(tmp_path: Path) -> None:
    root = write_root(tmp_path)
    text = gen.generate(root, gen.CONTENT_DIR)[gen.MAPPING]
    parsed = stig_mapping.parse_mapping(text.encode("utf-8"), "generated")
    assert parsed.profiles[0].rules_of("SYNT-01-000020") == (f"{RULE}split_a", f"{RULE}split_b")


def test_a_stream_without_a_release_profile_is_left_out(tmp_path: Path) -> None:
    root = write_root(tmp_path, other=stream(stig_version="2.0.0"))
    streams = cast("list[dict[str, object]]", generated(root)["datastreams"])
    assert [item["name"] for item in streams] == ["synthetic"]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (stream({"bad": ("UBTU-24-1",)}), "references the STIG ID 'UBTU-24-1', which is not"),
        (stream({"plain": ()}), "versioned as the DISA release V1R2, but none of its rules"),
        (b"<x/>", "synthetic: the root is not"),
    ],
)
def test_malformed_or_empty_mappings_are_refused(tmp_path: Path, data: bytes, message: str) -> None:
    with pytest.raises(gen.GenerationError, match=message):
        gen.generate(write_root(tmp_path, data), gen.CONTENT_DIR)


def test_main_writes_then_checks_the_mapping(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_root(tmp_path)
    assert gen.main(["--root", str(root), "--check"]) == 1
    assert "the STIG mapping is out of date; run make stig-mapping" in capsys.readouterr().err
    assert gen.main(["--root", str(root)]) == 0
    assert "generated content/stig-mapping.json" in capsys.readouterr().out
    assert gen.main(["--root", str(root), "--check"]) == 0
    assert "matches the pinned content" in capsys.readouterr().out


def test_main_reports_missing_content_and_a_broken_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_root(tmp_path)
    (root / "build" / "content" / "ssg-synthetic-ds.xml").unlink()
    assert gen.main(["--root", str(root)]) == 2
    assert "ssg-synthetic-ds.xml is missing; run make content" in capsys.readouterr().err
    (root / gen.MANIFEST).write_text("---\n[]\n", encoding="utf-8")
    assert gen.main(["--root", str(root)]) == 2
    assert f"{gen.MANIFEST}: manifest must be a mapping" in capsys.readouterr().err


def test_main_runs_as_a_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_root(tmp_path)
    assert gen.main(["--root", str(root)]) == 0
    monkeypatch.setattr(sys, "argv", ["generate_stig_mapping", "--root", str(root), "--check"])
    monkeypatch.delitem(sys.modules, "tools.content.generate_stig_mapping", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.content.generate_stig_mapping", run_name="__main__")
    assert raised.value.code == 0
    assert "matches the pinned content" in capsys.readouterr().out


def test_the_committed_mapping_is_valid_and_names_only_identifiers() -> None:
    path = REPOSITORY_ROOT / gen.MAPPING
    mapping = stig_mapping.load_mapping(path)
    ubuntu = mapping.find(
        "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04",
        "xccdf_org.ssgproject.content_profile_stig",
    )
    assert ubuntu is not None
    assert ubuntu.stig_release == "V1R5"
    assert all(key.startswith("UBTU-24-") for key in ubuntu.checks)
    manifest = cast(
        "dict[str, object]", yaml.safe_load((REPOSITORY_ROOT / gen.MANIFEST).read_text())
    )
    pinned = {
        str(item["name"]): str(item["sha256"])
        for item in cast("list[dict[str, object]]", manifest["datastreams"])
    }
    assert all(pinned[profile.datastream] == profile.content_sha256 for profile in mapping.profiles)
