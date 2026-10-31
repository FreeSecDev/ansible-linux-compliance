"""The reader is the oracle: check pam_conf_decision against what the real linux-pam readers read.

``tests/fixtures/pam_conf/reader_verdicts.json`` is produced by ``make pam-reader-verdicts``,
which compiles the readers of the pam source packages that the Molecule images install
(``tools/pam``) and runs them on every case of ``tools.pam.reader_corpus``. These tests require
that the filter's model reads every case exactly as both readers do, that the module lines of
the corpus pass the arguments that libpam passes, and that no decision of the family is
``compliant`` or ``applied`` while a real reader reads a looser value than the profile's,
before or after the change.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import pam_conf
from tools.pam import reader_corpus

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TABLE = REPOSITORY_ROOT / reader_corpus.TABLE
PLATFORMS = frozenset({"ubuntu", "rhel_compatible"})
Key = tuple[str, str, tuple[str, ...], str]


@functools.cache
def table() -> dict[str, object]:
    return cast("dict[str, object]", json.loads(TABLE.read_text(encoding="utf-8")))


@functools.cache
def recorded() -> dict[Key, dict[str, dict[str, int]]]:
    """Return what each platform's reader read, by reader, text, arguments and stack."""
    keys = cast("dict[str, list[str]]", table()["reading_keys"])
    found: dict[Key, dict[str, dict[str, int]]] = {}
    for entry in cast("list[dict[str, object]]", table()["cases"]):
        reader = str(entry["reader"])
        key = (
            reader,
            str(entry["text"]),
            tuple(cast("list[str]", entry["args"])),
            str(entry["stack"]),
        )
        found[key] = {
            platform: dict(zip(keys[reader], values, strict=True))
            for platform, values in cast("dict[str, list[int]]", entry["readings"]).items()
        }
    return found


def readings(case: reader_corpus.Case) -> dict[str, dict[str, int]]:
    key = reader_corpus.key_of(case)
    assert key in recorded(), f"{case.case_id} is not in the table; run make pam-reader-verdicts"
    return recorded()[key]


def satisfies(reader: str, reading: dict[str, int], rule: tuple[str, str, str]) -> bool:
    """Return whether what pam reads is at least as strict as the profile requires."""
    setting, comparison, required = rule
    if reader == "faillock" and reading["rv"] != 0:
        return False
    value = reading[setting]
    if comparison == "present":
        return value == 1
    if comparison == "at_most":
        return 1 <= value <= int(required)
    if setting in {"unlock_time", "root_unlock_time"}:
        return value == 0 if required == "0" else value >= int(required)
    return value >= int(required)


def test_the_table_records_both_images_and_exactly_the_cases_of_the_corpus() -> None:
    document = table()
    assert document["schema_version"] == reader_corpus.SCHEMA_VERSION
    platforms = cast("dict[str, dict[str, str]]", document["platforms"])
    assert set(platforms) == PLATFORMS
    for platform in PLATFORMS:
        assert platforms[platform]["installed"] == platforms[platform]["source"], platform
    corpus = {reader_corpus.key_of(case) for case in reader_corpus.all_cases()}
    assert set(recorded()) == corpus, "run make pam-reader-verdicts"
    assert all(set(reading) == PLATFORMS for reading in recorded().values())


@pytest.mark.parametrize("case", reader_corpus.all_cases(), ids=lambda case: case.case_id)
def test_the_model_reads_every_case_as_both_real_readers(case: reader_corpus.Case) -> None:
    text = "" if "conf=/dev/null" in case.args else case.text
    for platform, reading in readings(case).items():
        if case.reader == "faillock":
            model = pam_conf.read_faillock(text, case.args)
            if reading["rv"] != 0:
                assert model is None, (platform, reading)
            else:
                expected = {key: value for key, value in reading.items() if key != "rv"}
                assert model == expected, platform
        else:
            assert pam_conf.read_pwhistory(text, case.args) == reading, platform


@pytest.mark.parametrize(
    "case",
    [case for case in reader_corpus.base_cases() if case.stack],
    ids=lambda case: case.case_id,
)
def test_the_module_lines_pass_the_arguments_that_libpam_passes(case: reader_corpus.Case) -> None:
    module = pam_conf.READERS[case.reader][0]
    assert list(pam_conf.module_arguments(case.stack, module)) == [list(case.args)]


@pytest.mark.parametrize("case", reader_corpus.base_cases(), ids=lambda case: case.case_id)
def test_no_decision_claims_a_setting_that_pam_reads_looser(case: reader_corpus.Case) -> None:
    for rule in reader_corpus.RULES[case.reader]:
        decision = reader_corpus.decide(case, rule)
        if decision["status"] == "compliant":
            observed = readings(case)
        elif decision["status"] == "applied":
            after = reader_corpus.after_case(case, rule)
            assert after is not None
            observed = readings(after)
        else:
            assert decision["reason"], (case.case_id, rule, decision)
            continue
        for platform, reading in observed.items():
            assert satisfies(case.reader, reading, rule), (case.case_id, rule, decision, platform)


REVIEWED: dict[tuple[str, tuple[str, str, str]], str] = {
    ("faillock-unlock-1000000", ("unlock_time", "at_least", "900")): "applied",
    ("faillock-unlock-01000000-comment", ("unlock_time", "at_least", "900")): "applied",
    ("faillock-interval-999999999", ("fail_interval", "at_least", "900")): "applied",
    ("faillock-unlock-600", ("unlock_time", "at_least", "0")): "applied",
    ("faillock-unlock-0", ("unlock_time", "at_least", "900")): "stricter_setting",
    ("faillock-vt-lead-later", ("deny", "at_most", "4")): "hidden_setting",
    ("faillock-ff-lead-later", ("deny", "at_most", "4")): "hidden_setting",
    ("faillock-cr-lead-later", ("deny", "at_most", "4")): "hidden_setting",
    ("faillock-vt-after-key-later", ("deny", "at_most", "4")): "hidden_setting",
    ("faillock-vt-lead", ("deny", "at_most", "4")): "hidden_setting",
    ("pwhistory-remember-upper-1", ("remember", "at_least", "24")): "hidden_setting",
    ("pwhistory-remember-mixed-1", ("remember", "at_least", "24")): "hidden_setting",
    ("pwhistory-remember-vt-1", ("remember", "at_least", "24")): "hidden_setting",
    ("pwhistory-remember-ff-1-then-24", ("remember", "at_least", "24")): "hidden_setting",
    ("faillock-stack-conf", ("audit", "present", "")): "overridden",
    ("faillock-stack-upper-type", ("deny", "at_most", "4")): "overridden",
    ("faillock-stack-continuation", ("deny", "at_most", "4")): "overridden",
    ("pwhistory-stack-conf", ("enforce_for_root", "present", "")): "overridden",
    ("pwhistory-stack-remember-upper", ("remember", "at_least", "24")): "overridden",
    ("faillock-long-1023", ("deny", "at_most", "4")): "unreadable_file",
    ("faillock-unlock-600", ("unlock_time", "at_least", "604801")): "unsupported_value",
    ("faillock-unlock-600", ("fail_interval", "at_least", "999999999")): "unsupported_value",
    ("faillock-unlock-600", ("unlock_time", "at_least", "604800")): "applied",
}


@pytest.mark.parametrize(("case_id", "rule"), list(REVIEWED), ids=str)
def test_the_reviewed_cases_are_refused_or_fixed(case_id: str, rule: tuple[str, str, str]) -> None:
    cases = {case.case_id: case for case in reader_corpus.base_cases()}
    assert reader_corpus.decide(cases[case_id], rule)["status"] == REVIEWED[(case_id, rule)]
