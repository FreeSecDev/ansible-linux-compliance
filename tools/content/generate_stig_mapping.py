"""Generate the DISA STIG to ComplianceAsCode mapping from the pinned content (FREES-146).

A ComplianceAsCode rule names the DISA STIG requirements it checks by their STIG ID (the DISA
rule's ``version``, ``Rule_Ver`` in a checklist, for example ``UBTU-24-100010``) in ``reference``
elements whose ``href`` is the DISA download page (:data:`catalog.STIG_ID_REFERENCES`). A
ComplianceAsCode STIG profile names the DISA release that it implements as its own ``version``,
for example ``V1R5``. This tool reads every datastream of ``content/manifest.yml`` that
``tools/content/fetch_content.py`` fetched, through :func:`catalog.read_benchmarks`, which verifies
the pinned SHA-256 before it parses a byte, and writes ``content/stig-mapping.json``:

- for every pinned profile whose version is a DISA release (``V<n>R<n>``), the STIG IDs that its
  selected rules reference, each with the sorted ComplianceAsCode rules that reference it, and the
  selected rules that reference none, the DISA benchmark ID that the profile implements
  (:data:`DISA_BENCHMARKS`, pinned here by hand because no pinned stream carries it), and the
  pairs of DISA rule ID (``SV-<n>r<n>_rule``) and STIG ID that the stream states;
- the datastream's file name, SHA-256, benchmark ID and version, so that a scan of other content
  is never exported with this mapping.

The DISA rule IDs are read only where the stream states them unambiguously: a rule that references
exactly one STIG ID and at least one DISA rule ID pairs each of them with that STIG ID, and a rule
that references several STIG IDs pairs none, because the stream does not say which belongs to
which. Two rules that pair one DISA rule ID with different STIG IDs are an error. The RHEL 9 stream
carries these references; the Ubuntu stream carries none, so its profile has no pairs (ADR 0020,
amendment of FREES-171). The pairs are identifiers only and no DISA text.

Mappings are many-to-many: one STIG ID can have several rules and one rule several STIG IDs. Only
identifiers of the BSD-licensed ComplianceAsCode content are written, never benchmark text, and no
DISA content is read: the DISA group and rule IDs of a STIG ID are joined at export time from the
DISA content that the operator supplies (ADR 0020, amendment of FREES-146). ComplianceAsCode marks
rules that other STIG rules need, but that check no STIG requirement of their own, with the
reference text ``needed_rules`` (:data:`SUPPORT_MARKERS`); such a rule references no STIG ID. Any
other text that is not of the form ``<PREFIX>-<nn>-<nnnnnn>``, a release profile that maps no STIG
ID and an unreadable stream are errors; nothing is guessed. With ``--check`` nothing is written: a
unified diff is printed and the exit status is 1, which is how CI detects drift from the pinned
content.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import catalog
from tools.content import fetch_content
from tools.roles import generate_catalogue, generate_toggles

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

MAPPING: Final[Path] = Path("content/stig-mapping.json")
MANIFEST: Final[Path] = Path("content/manifest.yml")
CONTENT_DIR: Final[Path] = Path("build/content")
SCHEMA_VERSION: Final[int] = 1
GENERATOR: Final[str] = "tools/content/generate_stig_mapping.py"
JOIN_KEY: Final[str] = "STIG ID: the DISA rule version, Rule_Ver in a checklist"
STIG_ID: Final[re.Pattern[str]] = re.compile(r"[A-Z][A-Z0-9]{1,15}-[0-9]{2}-[0-9]{6}")
STIG_RELEASE: Final[re.Pattern[str]] = re.compile(r"V[0-9]{1,3}R[0-9]{1,3}")
DISA_RULE: Final[re.Pattern[str]] = re.compile(r"SV-[0-9]+r[0-9]+_rule")
SUPPORT_MARKERS: Final[frozenset[str]] = frozenset({"needed_rules"})
DISA_BENCHMARKS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "xccdf_org.ssgproject.content_benchmark_UBUNTU_24-04": (
            "xccdf_mil.disa.stig_benchmark_CAN_Ubuntu_24-04_STIG"
        ),
        "xccdf_org.ssgproject.content_benchmark_RHEL-9": (
            "xccdf_mil.disa.stig_benchmark_RHEL_9_STIG"
        ),
    }
)


class GenerationError(generate_toggles.GenerationError):
    """Raised when the mapping cannot be generated without guessing."""


def _stig_ids(rule: catalog.Rule, profile_id: str) -> list[str]:
    values = [value for value in rule.stig_ids if value not in SUPPORT_MARKERS]
    for value in values:
        if STIG_ID.fullmatch(value) is None:
            message = (
                f"{profile_id}: rule {rule.rule_id} references the STIG ID {value[:64]!r}, which "
                "is not of the form <PREFIX>-<nn>-<nnnnnn>"
            )
            raise GenerationError(message)
    return sorted(set(values))


def _pair(pairs: dict[str, str], rule: catalog.Rule, stig_ids: list[str], profile_id: str) -> None:
    for disa_rule in sorted(set(rule.disa_rules)):
        if DISA_RULE.fullmatch(disa_rule) is None:
            message = (
                f"{profile_id}: rule {rule.rule_id} references the DISA rule ID "
                f"{disa_rule[:64]!r}, which is not of the form SV-<n>r<n>_rule"
            )
            raise GenerationError(message)
        if len(stig_ids) == 1 and pairs.setdefault(disa_rule, stig_ids[0]) != stig_ids[0]:
            message = (
                f"{profile_id}: the DISA rule ID {disa_rule} is paired with {pairs[disa_rule]} "
                f"and with {stig_ids[0]}"
            )
            raise GenerationError(message)


def profile_mapping(benchmark: catalog.Benchmark, profile: catalog.Profile) -> dict[str, object]:
    """Return the mapping of one STIG release profile.

    Raises:
        GenerationError: If a STIG ID or DISA rule ID is malformed or paired twice, no DISA
            benchmark ID is pinned for the benchmark, or the profile maps no STIG ID.
    """
    if benchmark.benchmark_id not in DISA_BENCHMARKS:
        message = (
            f"{profile.profile_id} is versioned as the DISA release {profile.version}, but no DISA "
            f"benchmark ID is pinned for {benchmark.benchmark_id}"
        )
        raise GenerationError(message)
    rules = catalog.profile_rules(benchmark, profile)
    checks: dict[str, list[str]] = {}
    pairs: dict[str, str] = {}
    without: list[str] = []
    for rule in rules:
        stig_ids = _stig_ids(rule, profile.profile_id)
        if not stig_ids:
            without.append(rule.rule_id)
        _pair(pairs, rule, stig_ids, profile.profile_id)
        for stig_id in stig_ids:
            checks.setdefault(stig_id, []).append(rule.rule_id)
    if not checks:
        message = (
            f"{profile.profile_id} is versioned as the DISA release {profile.version}, but none "
            "of its rules references a STIG ID"
        )
        raise GenerationError(message)
    return {
        "profile_id": profile.profile_id,
        "stig_release": profile.version,
        "disa_benchmark_id": DISA_BENCHMARKS[benchmark.benchmark_id],
        "stig_ids": {stig_id: sorted(checks[stig_id]) for stig_id in sorted(checks)},
        "disa_rules": {disa_rule: pairs[disa_rule] for disa_rule in sorted(pairs)},
        "rules_without_stig_id": sorted(without),
    }


def stream_mapping(
    stream: generate_catalogue.Stream, benchmark: catalog.Benchmark
) -> dict[str, object] | None:
    """Return the mapping of one datastream, or ``None`` when no pinned profile is a release."""
    profiles = [
        profile_mapping(benchmark, catalog.find_profile(benchmark, profile_id))
        for profile_id in stream.profile_ids
        if STIG_RELEASE.fullmatch(catalog.find_profile(benchmark, profile_id).version)
    ]
    if not profiles:
        return None
    return {
        "name": stream.name,
        "file_name": stream.path.name,
        "sha256": stream.sha256,
        "benchmark_id": benchmark.benchmark_id,
        "benchmark_version": benchmark.version,
        "profiles": profiles,
    }


def read_stream(stream: generate_catalogue.Stream) -> catalog.Benchmark:
    """Verify and parse one pinned datastream.

    Raises:
        GenerationError: If the stream does not verify or parse.
    """
    try:
        return catalog.single_benchmark(catalog.read_benchmarks(str(stream.path), stream.sha256))
    except catalog.CatalogError as error:
        message = f"{stream.name}: {error}"
        raise GenerationError(message) from error


def render(manifest: fetch_content.Manifest, streams: Sequence[dict[str, object]]) -> str:
    """Return the mapping document as canonical JSON text."""
    document = {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "source": f"ComplianceAsCode/content {manifest.version}",
        "join_key": JOIN_KEY,
        "datastreams": list(streams),
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


def generate(root: Path, content_dir: Path) -> dict[Path, str]:
    """Read the manifest and the pinned content below ``root`` and return the mapping file.

    Raises:
        GenerationError: If the manifest, a stream or a profile cannot be used.
    """
    try:
        manifest = fetch_content.load_manifest(root / MANIFEST)
    except fetch_content.ContentError as error:
        message = f"{MANIFEST}: {error}"
        raise GenerationError(message) from error
    try:
        streams = generate_catalogue.streams_of(manifest, root / content_dir)
    except generate_toggles.GenerationError as error:
        raise GenerationError(str(error)) from error
    mapped = [stream_mapping(stream, read_stream(stream)) for stream in streams]
    return {MAPPING: render(manifest, [item for item in mapped if item is not None])}


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path())
    parser.add_argument("--content-dir", type=Path, default=CONTENT_DIR)
    parser.add_argument("--check", action="store_true", help="report drift instead of writing")
    arguments = parser.parse_args(argv)
    root = cast("Path", arguments.root)
    try:
        generated = generate(root, cast("Path", arguments.content_dir))
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if arguments.check:
        differences = generate_toggles.drift(root, generated)
        if differences:
            print("\n".join(differences), file=sys.stderr)
            print("error: the STIG mapping is out of date; run make stig-mapping", file=sys.stderr)
            return 1
        print(f"{MAPPING} matches the pinned content")
        return 0
    for relative, content in generated.items():
        (root / relative).write_text(content, encoding="utf-8")
    print(f"generated {MAPPING} from the pinned content")
    return 0


if __name__ == "__main__":
    sys.exit(main())
