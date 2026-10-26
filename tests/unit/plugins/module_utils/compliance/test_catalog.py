from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
from typing import Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
    xmlsafe,
)

FIXTURES = Path(__file__).resolve().parents[4] / "fixtures"
CATALOG = FIXTURES / "catalog"
ADVERSARIAL = CATALOG / "adversarial"
SYNTHETIC = CATALOG / "synthetic-ds.xml"
BENCHMARK = "xccdf_org.example.synthetic_benchmark_demo"
BASELINE = "xccdf_org.example.synthetic_profile_baseline"
STRICT = "xccdf_org.example.synthetic_profile_strict"
MINIMAL = "xccdf_org.example.synthetic_profile_minimal"
RULE = "xccdf_org.example.synthetic_rule_"
NAMESPACES = (
    'xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2" '
    'xmlns:x="http://checklists.nist.gov/xccdf/1.2"'
)


def wrong_digest(_handle: object, _max_bytes: int) -> str:
    return "f" * 64


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collection(*parts: str) -> bytes:
    body = "".join(parts)
    return f"<ds:data-stream-collection {NAMESPACES}>{body}</ds:data-stream-collection>".encode()


def benchmark(inner: str = "", benchmark_id: str = BENCHMARK, version: str = "1.0") -> str:
    version_element = f"<x:version>{version}</x:version>" if version else ""
    return f'<x:Benchmark id="{benchmark_id}">{version_element}{inner}</x:Benchmark>'


def rule(name: str, attributes: str = "", inner: str = "") -> str:
    return f'<x:Rule id="{RULE}{name}" {attributes}>{inner}</x:Rule>'


def select(name: str, flag: str = "true") -> str:
    return f'<x:select idref="{RULE}{name}" selected="{flag}"/>'


def profile(name: str, inner: str = "") -> str:
    return f'<x:Profile id="xccdf_org.example.synthetic_profile_{name}">{inner}</x:Profile>'


def parse(data: bytes, bounds: xmlsafe.XmlBounds | None = None) -> tuple[catalog.Benchmark, ...]:
    return catalog.parse_benchmarks([data], bounds)


def write(directory: Path, data: bytes, name: str = "demo-ds.xml") -> tuple[str, str]:
    path = directory / name
    path.write_bytes(data)
    return str(path), digest(data)


@pytest.fixture(scope="module")
def synthetic() -> catalog.Benchmark:
    data = SYNTHETIC.read_bytes()
    return catalog.single_benchmark(catalog.read_benchmarks(str(SYNTHETIC), digest(data)))


class TestSyntheticDatastream:
    """Test synthetic datastream behaviour."""

    def test_benchmark_data(self, synthetic: catalog.Benchmark) -> None:
        assert synthetic.benchmark_id == BENCHMARK
        assert synthetic.version == "1.2.3"
        assert synthetic.title == "Synthetic demo benchmark"

    def test_profiles_in_document_order(self, synthetic: catalog.Benchmark) -> None:
        assert [(p.profile_id, p.title) for p in synthetic.profiles] == [
            (BASELINE, "Synthetic baseline"),
            (STRICT, ""),
            (MINIMAL, ""),
        ]

    def test_selection_follows_the_last_select_and_the_rule_default(
        self, synthetic: catalog.Benchmark
    ) -> None:
        selected = {p.profile_id: p.rule_ids for p in synthetic.profiles}
        assert selected[BASELINE] == (RULE + "alpha", RULE + "beta")
        assert selected[STRICT] == tuple(
            RULE + name for name in ("alpha", "beta", "delta", "epsilon", "gamma")
        )
        assert selected[MINIMAL] == (RULE + "delta",)

    def test_rule_definitions_from_nested_groups(self, synthetic: catalog.Benchmark) -> None:
        assert [(r.rule_id, r.severity, r.title) for r in synthetic.rules] == [
            (RULE + "alpha", "high", "Synthetic alpha rule"),
            (RULE + "beta", "medium", "Synthetic beta rule"),
            (RULE + "gamma", "unknown", "Synthetic gamma rule"),
            (RULE + "delta", "unknown", "Synthetic delta rule"),
            (RULE + "epsilon", "low", ""),
        ]

    def test_rules_record_their_group_hierarchy(self, synthetic: catalog.Benchmark) -> None:
        one = "xccdf_org.example.synthetic_group_one"
        two = "xccdf_org.example.synthetic_group_two"
        assert {r.rule_id: r.groups for r in synthetic.rules} == {
            RULE + "alpha": (one,),
            RULE + "beta": (one,),
            RULE + "gamma": (one, two),
            RULE + "delta": (one, two),
            RULE + "epsilon": (one, two),
        }

    def test_profile_rules_are_sorted_definitions(self, synthetic: catalog.Benchmark) -> None:
        strict = catalog.find_profile(synthetic, STRICT)
        rules = catalog.profile_rules(synthetic, strict)
        assert [r.rule_id for r in rules] == list(strict.rule_ids)
        assert rules[0].severity == "high"

    def test_foreign_namespace_elements_are_ignored(self, synthetic: catalog.Benchmark) -> None:
        assert "not-an-xccdf-benchmark" not in synthetic.benchmark_id
        assert all(p.profile_id != "not-a-profile" for p in synthetic.profiles)


class TestLookup:
    """Test lookup behaviour."""

    def test_a_missing_profile_is_an_error_and_nothing_is_substituted(
        self, synthetic: catalog.Benchmark
    ) -> None:
        missing = "xccdf_org.example.synthetic_profile_absent"
        with pytest.raises(catalog.ProfileNotFoundError, match="absent"):
            catalog.find_profile(synthetic, missing)

    def test_a_short_profile_id_is_not_accepted(self, synthetic: catalog.Benchmark) -> None:
        with pytest.raises(catalog.CatalogError, match="profile id"):
            catalog.find_profile(synthetic, "baseline")

    def test_one_benchmark_is_required(self, synthetic: catalog.Benchmark) -> None:
        assert catalog.single_benchmark([synthetic]) is synthetic
        with pytest.raises(catalog.CatalogError, match="found 0"):
            catalog.single_benchmark([])
        with pytest.raises(catalog.CatalogError, match="found 2"):
            catalog.single_benchmark([synthetic, synthetic])

    def test_error_types(self) -> None:
        assert catalog.error_type(catalog.DigestMismatchError("x")) == "digest_mismatch"
        assert catalog.error_type(catalog.ProfileNotFoundError("x")) == "profile_not_found"
        assert catalog.error_type(catalog.CatalogError("x")) == "invalid_content"


class TestDigest:
    """Test digest behaviour."""

    def test_a_matching_digest_is_accepted_in_either_case(self, tmp_path: Path) -> None:
        path, expected = write(tmp_path, collection(benchmark()))
        assert catalog.verify_digest(path, expected.upper()) == expected
        assert len(catalog.read_benchmarks(path, expected.upper())) == 1

    def test_a_mismatch_fails_and_never_parses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = write(tmp_path, collection(benchmark()))[0]

        def forbidden(*_arguments: object) -> None:
            message = "the content must not be parsed"
            raise AssertionError(message)

        monkeypatch.setattr(xmlsafe, "parse_chunks", forbidden)
        with pytest.raises(catalog.DigestMismatchError, match="digest mismatch"):
            catalog.read_benchmarks(path, "0" * 64)

    def test_verify_digest_reports_a_mismatch(self, tmp_path: Path) -> None:
        path = write(tmp_path, collection(benchmark()))[0]
        with pytest.raises(catalog.DigestMismatchError, match="expected"):
            catalog.verify_digest(path, "0" * 64)

    def test_a_mismatch_with_hostile_content_never_reaches_the_parser(self, tmp_path: Path) -> None:
        path = write(tmp_path, (ADVERSARIAL / "entity-expansion.xml").read_bytes())[0]
        with pytest.raises(catalog.DigestMismatchError):
            catalog.read_benchmarks(path, "1" * 64)

    def test_content_that_changes_between_the_two_reads_is_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path, expected = write(tmp_path, collection(benchmark()))
        monkeypatch.setattr(catalog, "_handle_digest", wrong_digest)
        with pytest.raises(catalog.DigestMismatchError, match="changed while"):
            catalog.read_benchmarks(path, "f" * 64)
        assert expected != "f" * 64

    @pytest.mark.parametrize("value", ["", "abc", "g" * 64, "a" * 63, "a" * 65, None, 7])
    def test_an_invalid_expected_digest_is_rejected(self, tmp_path: Path, value: Any) -> None:
        path = write(tmp_path, collection(benchmark()))[0]
        with pytest.raises(catalog.CatalogError, match="64 hexadecimal"):
            catalog.verify_digest(path, value)

    def test_an_unreadable_file_is_a_clean_error(self, tmp_path: Path) -> None:
        with pytest.raises(catalog.CatalogError, match="cannot be read"):
            catalog.verify_digest(str(tmp_path / "missing-ds.xml"), "0" * 64)

    def test_the_size_bound_applies(self, tmp_path: Path) -> None:
        path, expected = write(tmp_path, (FIXTURES / "adversarial" / "oversized.xml").read_bytes())
        with pytest.raises(catalog.CatalogError, match="larger than 1024 bytes"):
            catalog.read_benchmarks(path, expected, max_bytes=1024)


class TestAdversarialDatastreams:
    """Test adversarial datastreams behaviour."""

    @pytest.mark.parametrize("name", ["doctype.xml", "entity-expansion.xml"])
    def test_declarations_are_rejected(self, tmp_path: Path, name: str) -> None:
        path, expected = write(tmp_path, (ADVERSARIAL / name).read_bytes())
        with pytest.raises(catalog.CatalogError, match="DOCTYPE and ENTITY"):
            catalog.read_benchmarks(path, expected)

    def test_the_wrong_namespace_is_rejected(self, tmp_path: Path) -> None:
        path, expected = write(tmp_path, (ADVERSARIAL / "wrong-namespace.xml").read_bytes())
        with pytest.raises(catalog.CatalogError, match="root is not"):
            catalog.read_benchmarks(path, expected)

    def test_duplicate_profiles_are_rejected(self, tmp_path: Path) -> None:
        path, expected = write(tmp_path, (ADVERSARIAL / "duplicate-profiles.xml").read_bytes())
        with pytest.raises(catalog.CatalogError, match="appears more than once"):
            catalog.read_benchmarks(path, expected)

    def test_a_profile_that_selects_an_undefined_rule_is_rejected(self, tmp_path: Path) -> None:
        data = (ADVERSARIAL / "profile-selects-unknown-rule.xml").read_bytes()
        path, expected = write(tmp_path, data)
        with pytest.raises(catalog.UnsupportedContentError, match="neither a rule nor a group"):
            catalog.read_benchmarks(path, expected)

    def test_a_missing_profile_in_a_plain_benchmark_is_an_error(self, tmp_path: Path) -> None:
        path, expected = write(tmp_path, (CATALOG / "plain-root.xml").read_bytes())
        parsed = catalog.single_benchmark(catalog.read_benchmarks(path, expected))
        assert [p.profile_id for p in parsed.profiles] == [BASELINE]
        with pytest.raises(catalog.ProfileNotFoundError):
            catalog.find_profile(parsed, "xccdf_org.example.synthetic_profile_cis_level1_server")

    def test_a_deselected_rule_is_not_reported_as_selected(self, tmp_path: Path) -> None:
        path, expected = write(tmp_path, (CATALOG / "plain-root.xml").read_bytes())
        parsed = catalog.single_benchmark(catalog.read_benchmarks(path, expected))
        assert parsed.profiles[0].rule_ids == ()

    def test_element_and_depth_bounds_apply(self) -> None:
        data = collection(benchmark(profile("a") + profile("b")))
        with pytest.raises(catalog.CatalogError, match="more than 4 elements"):
            parse(data, xmlsafe.XmlBounds(max_elements=4))
        with pytest.raises(catalog.CatalogError, match="deeper than 2"):
            parse(data, xmlsafe.XmlBounds(max_depth=2))

    def test_not_well_formed_content_is_rejected(self) -> None:
        with pytest.raises(catalog.CatalogError, match="not well-formed"):
            parse(collection(benchmark())[:-10])

    def test_text_outside_utf8_is_rejected(self) -> None:
        with pytest.raises(catalog.CatalogError, match="UTF-16"):
            parse(b"\xff\xfe<\x00a\x00/\x00>\x00")


class TestMalformedBenchmarks:
    """Malformed benchmark structure behaviour."""

    def test_a_document_without_a_benchmark_is_rejected(self) -> None:
        with pytest.raises(catalog.CatalogError, match=r"no XCCDF 1\.2 Benchmark"):
            parse(collection("<ds:data-stream id='d'/>"))

    def test_an_unrelated_root_is_rejected(self) -> None:
        with pytest.raises(catalog.CatalogError, match="root is not"):
            parse(b"<html/>")

    def test_a_benchmark_without_a_version_is_rejected(self) -> None:
        with pytest.raises(catalog.CatalogError, match="no version"):
            parse(collection(benchmark(version="")))

    @pytest.mark.parametrize("version", ["", "-1", "a b", "x" * 65])
    def test_an_invalid_version_is_rejected(self, version: str) -> None:
        data = collection(benchmark(version=version or " "))
        with pytest.raises(catalog.CatalogError, match="version"):
            parse(data)

    def test_the_first_version_wins(self) -> None:
        parsed = parse(collection(benchmark("<x:version>2.0</x:version>")))
        assert parsed[0].version == "1.0"

    def test_duplicate_benchmarks_are_rejected(self) -> None:
        with pytest.raises(catalog.CatalogError, match="appears more than once"):
            parse(collection(benchmark(), benchmark()))

    def test_two_different_benchmarks_are_both_returned(self) -> None:
        other = benchmark(benchmark_id="xccdf_org.example.synthetic_benchmark_other")
        assert [b.benchmark_id for b in parse(collection(benchmark(), other))] == [
            BENCHMARK,
            "xccdf_org.example.synthetic_benchmark_other",
        ]

    def test_a_nested_benchmark_is_not_a_benchmark(self) -> None:
        nested = benchmark(benchmark(benchmark_id="xccdf_org.example.synthetic_benchmark_inner"))
        assert [b.benchmark_id for b in parse(collection(nested))] == [BENCHMARK]


class TestSelection:
    """Identifier, selection and text handling behaviour."""

    def test_duplicate_rules_are_rejected(self) -> None:
        with pytest.raises(catalog.CatalogError, match="appears more than once"):
            parse(collection(benchmark(rule("a") + rule("a"))))

    @pytest.mark.parametrize(
        "inner",
        [
            '<x:Profile id="nope"/>',
            '<x:Rule id="nope"/>',
            "<x:Rule/>",
            "<x:Profile/>",
        ],
    )
    def test_invalid_identifiers_are_rejected(self, inner: str) -> None:
        with pytest.raises(catalog.CatalogError, match="id"):
            parse(collection(benchmark(inner)))

    def test_an_invalid_benchmark_identifier_is_rejected(self) -> None:
        with pytest.raises(catalog.CatalogError, match="benchmark id"):
            parse(collection(benchmark(benchmark_id="nope")))

    def test_a_select_needs_a_boolean_selected_attribute(self) -> None:
        missing = f'<x:select idref="{RULE}a"/>'
        with pytest.raises(catalog.CatalogError, match="select selected is missing"):
            parse(collection(benchmark(profile("p", missing) + rule("a"))))
        with pytest.raises(catalog.CatalogError, match="not a boolean"):
            parse(collection(benchmark(profile("p", select("a", "maybe")) + rule("a"))))

    def test_a_rule_selected_attribute_must_be_boolean(self) -> None:
        with pytest.raises(catalog.CatalogError, match="not a boolean"):
            parse(collection(benchmark(rule("a", 'selected="perhaps"'))))

    def test_boolean_spellings(self) -> None:
        body = benchmark(
            profile("p", select("a", "0") + select("b", "1"))
            + rule("a", 'selected="true"')
            + rule("b", 'selected="false"')
        )
        assert parse(collection(body))[0].profiles[0].rule_ids == (RULE + "b",)

    def test_a_rule_the_profile_does_not_mention_keeps_its_default(self) -> None:
        body = benchmark(
            profile("p") + rule("a", 'selected="true"') + rule("b", 'selected="false"') + rule("c")
        )
        assert parse(collection(body))[0].profiles[0].rule_ids == (RULE + "a", RULE + "c")

    def test_profile_and_rule_limits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(catalog, "MAX_PROFILES", 1)
        with pytest.raises(catalog.CatalogError, match="more than 1 profiles"):
            parse(collection(benchmark(profile("a") + profile("b"))))
        monkeypatch.setattr(catalog, "MAX_RULES", 1)
        with pytest.raises(catalog.CatalogError, match="more than 1 rules"):
            parse(collection(benchmark(rule("a") + rule("b"))))
        selects = select("a") + select("b")
        with pytest.raises(catalog.CatalogError, match="selects more than 1 items"):
            parse(collection(benchmark(profile("p", selects))))
        repeated = select("a") + select("a")
        assert parse(collection(benchmark(profile("p", repeated) + rule("a"))))

    def test_titles_are_cleaned_and_bounded(self) -> None:
        hostile = "Safe\u202eevil\t\n  text\u2028end"
        body = benchmark(rule("a", inner=f"<x:title>{hostile}</x:title>"))
        assert parse(collection(body))[0].rules[0].title == "Safe evil text end"
        long_title = benchmark(rule("a", inner=f"<x:title>{'t' * 5000}</x:title>"))
        assert len(parse(collection(long_title))[0].rules[0].title) == catalog.MAX_TEXT_LENGTH

    def test_title_language_selection(self) -> None:
        titles = (
            '<x:title xml:lang="fr">Francais</x:title>'
            '<x:title xml:lang="EN-gb">English</x:title>'
            "<x:title>Second</x:title>"
        )
        assert parse(collection(benchmark(titles)))[0].title == "English"

    def test_a_missing_title_is_empty(self) -> None:
        assert parse(collection(benchmark()))[0].title == ""

    def test_unknown_severity_becomes_unknown(self) -> None:
        body = benchmark(rule("a", 'severity="catastrophic"') + rule("b", 'severity="info"'))
        assert [r.severity for r in parse(collection(body))[0].rules] == ["unknown", "info"]

    def test_text_budget_limits_collected_text(self) -> None:
        pieces = "<x:sub>" + "y" * 1000 + "</x:sub>"
        pieces *= 20
        body = benchmark(rule("a", inner=f"<x:title>{pieces}</x:title>"))
        assert len(parse(collection(body))[0].rules[0].title) <= catalog.MAX_TEXT_LENGTH

    def test_a_plain_benchmark_root_is_accepted(self) -> None:
        document = (
            f"<x:Benchmark {NAMESPACES} id='{BENCHMARK}'><x:version>1</x:version></x:Benchmark>"
        )
        assert parse(document.encode())[0].benchmark_id == BENCHMARK


class TestLocate:
    """Test locate behaviour."""

    def test_only_regular_datastream_files_in_the_directory_are_listed(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "b-ds.xml").write_bytes(b"x")
        (tmp_path / "a-ds.xml").write_bytes(b"x")
        (tmp_path / "notes.txt").write_bytes(b"x")
        (tmp_path / "dir-ds.xml").mkdir()
        (tmp_path / "link-ds.xml").symlink_to(tmp_path / "a-ds.xml")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "c-ds.xml").write_bytes(b"x")
        assert catalog.locate_datastreams(str(tmp_path)) == (
            str(tmp_path / "a-ds.xml"),
            str(tmp_path / "b-ds.xml"),
        )

    def test_a_file_is_not_a_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a-ds.xml").write_bytes(b"x")
        with pytest.raises(catalog.CatalogError, match="neither"):
            catalog.locate_datastreams(str(tmp_path / "a-ds.xml"))

    def test_a_symlinked_directory_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "real").mkdir()
        (tmp_path / "link").symlink_to(tmp_path / "real")
        with pytest.raises(catalog.CatalogError, match="neither"):
            catalog.locate_datastreams(str(tmp_path / "link"))

    def test_a_missing_directory_is_a_clean_error(self, tmp_path: Path) -> None:
        with pytest.raises(catalog.CatalogError, match="cannot be read"):
            catalog.locate_datastreams(str(tmp_path / "missing"))

    def test_the_entry_count_is_bounded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "a").write_bytes(b"x")
        (tmp_path / "b").write_bytes(b"x")
        monkeypatch.setattr(catalog, "MAX_DIRECTORY_ENTRIES", 1)
        with pytest.raises(catalog.CatalogError, match="more than 1 entries"):
            catalog.locate_datastreams(str(tmp_path))

    @pytest.mark.parametrize(
        ("path", "message"),
        [
            ("relative/path-ds.xml", "absolute"),
            ("/a/../b-ds.xml", "absolute"),
            ("/a/b\x00-ds.xml", "control character"),
            ("/a/b\n-ds.xml", "control character"),
            ("", "non-empty"),
            ("/" + "a" * catalog.MAX_PATH_LENGTH, "at most"),
            (None, "non-empty"),
            (5, "non-empty"),
        ],
    )
    def test_unsafe_paths_are_rejected(self, path: Any, message: str) -> None:
        with pytest.raises(catalog.CatalogError, match=message):
            catalog.resolve_content_path(path)

    def test_a_regular_file_resolves_to_itself(self, tmp_path: Path) -> None:
        path = write(tmp_path, b"<a/>", "whatever.xml")[0]
        assert catalog.resolve_content_path(path) == path

    def test_a_directory_with_one_datastream_resolves_to_it(self, tmp_path: Path) -> None:
        path = write(tmp_path, b"<a/>", "only-ds.xml")[0]
        assert catalog.resolve_content_path(str(tmp_path)) == path

    def test_zero_or_several_datastreams_are_ambiguous(self, tmp_path: Path) -> None:
        with pytest.raises(catalog.CatalogError, match="found 0"):
            catalog.resolve_content_path(str(tmp_path))
        write(tmp_path, b"<a/>", "one-ds.xml")
        write(tmp_path, b"<a/>", "two-ds.xml")
        with pytest.raises(catalog.CatalogError, match="found 2"):
            catalog.resolve_content_path(str(tmp_path))

    def test_a_symlink_to_a_file_is_refused(self, tmp_path: Path) -> None:
        path = write(tmp_path, b"<a/>", "real-ds.xml")[0]
        link = tmp_path / "link-ds.xml"
        link.symlink_to(path)
        with pytest.raises(catalog.CatalogError, match="neither"):
            catalog.resolve_content_path(str(link))

    def test_a_missing_path_is_a_clean_error(self, tmp_path: Path) -> None:
        with pytest.raises(catalog.CatalogError, match="cannot be read"):
            catalog.resolve_content_path(str(tmp_path / "missing"))


class TestReports:
    """Test reports behaviour."""

    def test_benchmark_report(self) -> None:
        sha = digest(SYNTHETIC.read_bytes())
        report = catalog.benchmark_report(str(SYNTHETIC), sha)
        assert report == {
            "content_path": str(SYNTHETIC),
            "content_sha256": sha,
            "benchmark_id": BENCHMARK,
            "benchmark_version": "1.2.3",
            "benchmark_title": "Synthetic demo benchmark",
            "profiles": [
                {"profile_id": BASELINE, "title": "Synthetic baseline", "rule_count": 2},
                {"profile_id": STRICT, "title": "", "rule_count": 5},
                {"profile_id": MINIMAL, "title": "", "rule_count": 1},
            ],
        }

    def test_profile_report(self) -> None:
        sha = digest(SYNTHETIC.read_bytes())
        report = catalog.profile_report(str(SYNTHETIC), sha.upper(), BASELINE)
        assert report["content_sha256"] == sha
        assert report["rule_count"] == 2
        assert report["rule_ids"] == [RULE + "alpha", RULE + "beta"]
        assert report["rules"] == [
            {"rule_id": RULE + "alpha", "severity": "high", "title": "Synthetic alpha rule"},
            {"rule_id": RULE + "beta", "severity": "medium", "title": "Synthetic beta rule"},
        ]
        assert report["profile_title"] == "Synthetic baseline"
        assert report["benchmark_version"] == "1.2.3"

    def test_profile_report_for_a_missing_profile(self) -> None:
        sha = digest(SYNTHETIC.read_bytes())
        with pytest.raises(catalog.ProfileNotFoundError):
            catalog.profile_report(str(SYNTHETIC), sha, "xccdf_org.example.synthetic_profile_x")

    def test_reports_refuse_a_wrong_digest(self) -> None:
        with pytest.raises(catalog.DigestMismatchError):
            catalog.benchmark_report(str(SYNTHETIC), "0" * 64)
        with pytest.raises(catalog.DigestMismatchError):
            catalog.profile_report(str(SYNTHETIC), "0" * 64, BASELINE)

    def test_a_datastream_with_two_benchmarks_is_refused(self, tmp_path: Path) -> None:
        other = benchmark(benchmark_id="xccdf_org.example.synthetic_benchmark_other")
        path, sha = write(tmp_path, collection(benchmark(), other))
        with pytest.raises(catalog.CatalogError, match="found 2"):
            catalog.benchmark_report(path, sha)


def group(name: str, inner: str, attributes: str = "") -> str:
    return f'<x:Group id="xccdf_org.example.synthetic_group_{name}" {attributes}>{inner}</x:Group>'


def group_select(name: str, flag: str) -> str:
    return f'<x:select idref="xccdf_org.example.synthetic_group_{name}" selected="{flag}"/>'


class TestFailClosed:
    """Unresolved XCCDF constructs never produce a rule list."""

    def test_a_selected_rule_in_a_deselected_group_is_unsupported(self) -> None:
        body = benchmark(
            profile("p", select("a") + group_select("g", "false"))
            + group("g", rule("a", 'selected="false"'))
        )
        with pytest.raises(
            catalog.UnsupportedContentError, match=r"synthetic_profile_p.*deselected"
        ):
            parse(collection(body))

    def test_a_group_deselected_by_default_is_unsupported(self) -> None:
        body = benchmark(
            profile("p", select("a"))
            + group("g", rule("a", 'selected="false"'), 'selected="false"')
        )
        with pytest.raises(catalog.UnsupportedContentError, match="synthetic_group_g"):
            parse(collection(body))

    def test_a_nested_deselected_group_is_unsupported(self) -> None:
        body = benchmark(
            profile("p", select("a") + group_select("inner", "false"))
            + group("outer", group("inner", rule("a", 'selected="false"')))
        )
        with pytest.raises(catalog.UnsupportedContentError, match="synthetic_group_inner"):
            parse(collection(body))

    def test_a_group_selected_by_the_profile_is_resolved(self) -> None:
        body = benchmark(
            profile("p", select("a") + group_select("g", "true"))
            + group("g", rule("a", 'selected="false"'), 'selected="false"')
        )
        assert parse(collection(body))[0].profiles[0].rule_ids == (RULE + "a",)

    def test_a_deselected_group_without_selected_rules_is_harmless(self) -> None:
        body = benchmark(
            profile("p", select("b") + group_select("g", "false"))
            + group("g", rule("a", 'selected="false"'))
            + rule("b", 'selected="false"')
        )
        assert parse(collection(body))[0].profiles[0].rule_ids == (RULE + "b",)

    @pytest.mark.parametrize("flag", ["true", "false"])
    def test_a_select_of_an_unknown_identifier_is_unsupported(self, flag: str) -> None:
        body = benchmark(
            profile("p", select("ghost", flag) + group_select("ghost", flag)) + rule("a")
        )
        with pytest.raises(catalog.UnsupportedContentError, match="neither a rule nor a group"):
            parse(collection(body))

    def test_a_select_of_a_non_identifier_is_unsupported(self) -> None:
        odd = '<x:select idref="not an identifier" selected="true"/>'
        with pytest.raises(catalog.UnsupportedContentError, match="neither a rule nor a group"):
            parse(collection(benchmark(profile("p", odd) + rule("a"))))
        long = f'<x:select idref="{"x" * 300}" selected="true"/>'
        with pytest.raises(catalog.UnsupportedContentError, match="too long"):
            parse(collection(benchmark(profile("p", long))))

    def test_an_identifier_used_for_a_rule_and_a_group_is_unsupported(self) -> None:
        clash = f'<x:Group id="{RULE}a">' + rule("a") + "</x:Group>"
        with pytest.raises(catalog.UnsupportedContentError, match="rule and a group"):
            parse(collection(benchmark(clash)))

    def test_rule_identifiers_that_look_like_groups_are_still_rules(self) -> None:
        names = ("wheel_group_empty", "group_unique_id", "group_rule", "x_group_")
        rules = "".join(rule(name, 'selected="false"') for name in names)
        selects = "".join(select(name) for name in names)
        selected = parse(collection(benchmark(profile("p", selects) + rules)))[0].profiles[0]
        assert selected.rule_ids == tuple(sorted(RULE + name for name in names))

    def test_group_identifiers_that_look_like_rules_are_still_groups(self) -> None:
        inner = '<x:Group id="xccdf_org.example.synthetic_group_rule_x">'
        body = benchmark(
            profile(
                "p",
                select("a")
                + '<x:select idref="xccdf_org.example.synthetic_group_rule_x" selected="false"/>',
            )
            + inner
            + rule("a", 'selected="false"')
            + "</x:Group>"
        )
        with pytest.raises(catalog.UnsupportedContentError, match="synthetic_group_rule_x"):
            parse(collection(body))
        reselected = body.replace('_rule_x" selected="false"/>', '_rule_x" selected="true"/>')
        assert parse(collection(reselected))[0].profiles[0].rule_ids == (RULE + "a",)

    @pytest.mark.parametrize("extends", ["xccdf_org.example.synthetic_profile_base", "x", ""])
    def test_extends_is_unsupported(self, extends: str) -> None:
        body = benchmark(
            '<x:Profile id="xccdf_org.example.synthetic_profile_base"/>'
            f'<x:Profile id="xccdf_org.example.synthetic_profile_child" extends="{extends}"/>'
        )
        with pytest.raises(catalog.UnsupportedContentError, match="synthetic_profile_child"):
            parse(collection(body))

    def test_group_identifiers_are_validated(self) -> None:
        with pytest.raises(catalog.CatalogError, match="group id"):
            parse(collection(benchmark('<x:Group id="nope"/>')))
        with pytest.raises(catalog.CatalogError, match="group id"):
            parse(collection(benchmark("<x:Group/>")))
        with pytest.raises(catalog.CatalogError, match="appears more than once"):
            parse(collection(benchmark(group("g", "") + group("g", ""))))
        with pytest.raises(catalog.CatalogError, match="not a boolean"):
            parse(collection(benchmark(group("g", "", 'selected="x"'))))

    def test_the_group_count_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(catalog, "MAX_RULES", 1)
        with pytest.raises(catalog.CatalogError, match="more than 1 groups"):
            parse(collection(benchmark(group("a", "") + group("b", ""))))

    def test_the_error_type_and_both_modules_report_it(self, tmp_path: Path) -> None:
        assert catalog.error_type(catalog.UnsupportedContentError("x")) == "unsupported_content"
        child = '<x:Profile id="xccdf_org.example.synthetic_profile_c" extends="x"/>'
        path, sha = write(tmp_path, collection(benchmark(child)))
        with pytest.raises(catalog.UnsupportedContentError):
            catalog.benchmark_report(path, sha)
        with pytest.raises(catalog.UnsupportedContentError):
            catalog.profile_report(path, sha, "xccdf_org.example.synthetic_profile_c")

    def test_growth_while_hashing_is_a_clean_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path, sha = write(tmp_path, collection(benchmark()))
        real = Path.lstat

        def understated(self: Path) -> os.stat_result:
            values = list(real(self))
            values[6] = 3
            return os.stat_result(values)

        monkeypatch.setattr(Path, "lstat", understated)
        with pytest.raises(catalog.CatalogError, match="larger than 10 bytes"):
            catalog.read_benchmarks(path, sha, max_bytes=10)


class CloseFails(io.BytesIO):
    """In-memory handle whose first close fails like an I/O error on a network file system."""

    def __init__(self, data: bytes, error: OSError) -> None:
        super().__init__(data)
        self.error = error

    def close(self) -> None:
        first = not self.closed
        super().close()
        if first:
            raise self.error


def fail_on_close(monkeypatch: pytest.MonkeyPatch, target: str, error: OSError) -> None:
    real: Any = Path.open
    path = Path(target)
    data = path.read_bytes()

    def opener(self: Path, *arguments: Any, **keywords: Any) -> Any:
        if self == path:
            return CloseFails(data, error)
        return real(self, *arguments, **keywords)

    monkeypatch.setattr(Path, "open", opener)


class TestCloseErrors:
    """An error while the datastream is closed is a catalog error, never a bare OSError."""

    @pytest.mark.parametrize(
        ("error", "message"),
        [
            (OSError(5, "Input/output error"), "the file cannot be read: Input/output error"),
            (OSError(), "the file cannot be read: OSError"),
        ],
    )
    def test_verify_digest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: OSError, message: str
    ) -> None:
        path, expected = write(tmp_path, collection(benchmark()))
        fail_on_close(monkeypatch, path, error)
        with pytest.raises(catalog.CatalogError) as caught:
            catalog.verify_digest(path, expected)
        assert not isinstance(caught.value, catalog.DigestMismatchError)
        assert catalog.error_type(caught.value) == "invalid_content"
        assert str(caught.value) == message
        assert isinstance(caught.value.__cause__, xmlsafe.CloseError)
        assert caught.value.__cause__.__cause__ is error

    @pytest.mark.parametrize(
        ("error", "message"),
        [
            (OSError(5, "Input/output error"), "the file cannot be read: Input/output error"),
            (OSError(), "the file cannot be read: OSError"),
        ],
    )
    def test_read_benchmarks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: OSError, message: str
    ) -> None:
        path, expected = write(tmp_path, collection(benchmark()))
        fail_on_close(monkeypatch, path, error)
        with pytest.raises(catalog.CatalogError) as caught:
            catalog.read_benchmarks(path, expected)
        assert not isinstance(caught.value, catalog.DigestMismatchError)
        assert catalog.error_type(caught.value) == "invalid_content"
        assert str(caught.value) == message
        assert isinstance(caught.value.__cause__, xmlsafe.CloseError)
        assert caught.value.__cause__.__cause__ is error

    def test_a_digest_mismatch_is_not_replaced_by_a_close_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = write(tmp_path, collection(benchmark()))[0]
        fail_on_close(monkeypatch, path, OSError(5, "Input/output error"))
        with pytest.raises(catalog.DigestMismatchError, match="digest mismatch"):
            catalog.read_benchmarks(path, "0" * 64)

    def test_a_parse_error_is_not_replaced_by_a_close_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path, expected = write(tmp_path, b"<ds:data-stream-collection")
        fail_on_close(monkeypatch, path, OSError(5, "Input/output error"))
        with pytest.raises(catalog.CatalogError, match="not well-formed"):
            catalog.read_benchmarks(path, expected)
