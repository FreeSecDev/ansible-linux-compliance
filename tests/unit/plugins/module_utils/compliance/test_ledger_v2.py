from __future__ import annotations

import dataclasses
import json
import os
from typing import TYPE_CHECKING, Any

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    ledger,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance.model import (
    RevertStrategy,
)

if TYPE_CHECKING:
    from pathlib import Path

OWNER = os.getuid()
PREFIX = "xccdf_org.ssgproject.content_rule_"
RULE = PREFIX + "accounts_password_pam_minlen"
OTHER_RULE = PREFIX + "sshd_disable_root_login"
STAMP = "2026-11-10T12:00:00Z"
LATER = "2026-11-11T08:30:00Z"

VERSION_1_BYTES = (
    b"{\n"
    b'  "entries": [\n'
    b"    {\n"
    b'      "applied_at": "2026-11-10T12:00:00Z",\n'
    b'      "collection_version": "0.1.0",\n'
    b'      "family": "ssh",\n'
    b'      "prior_values": [\n'
    b"        {\n"
    b'          "name": "PermitRootLogin",\n'
    b'          "sensitive": false,\n'
    b'          "value": "yes"\n'
    b"        }\n"
    b"      ],\n"
    b'      "revert_strategy": "recorded_value",\n'
    b'      "rule_id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"\n'
    b"    }\n"
    b"  ],\n"
    b'  "schema_version": 1\n'
    b"}\n"
)


def make_value(source: str = "override", target: str = "8") -> ledger.ValueRecord:
    return ledger.ValueRecord("var_password_pam_minlen", source, "14", target)


def make_entry(
    rule_id: str = RULE, value: ledger.ValueRecord | None = None, applied_at: str = STAMP
) -> ledger.LedgerEntry:
    return ledger.LedgerEntry(
        rule_id, "pwquality", RevertStrategy.OWNED_DROPIN, (), "0.1.0", applied_at, value
    )


def plain_entry() -> ledger.LedgerEntry:
    return ledger.LedgerEntry(
        OTHER_RULE,
        "ssh",
        RevertStrategy.RECORDED_VALUE,
        (ledger.PriorValue("PermitRootLogin", "yes"),),
        "0.1.0",
        STAMP,
    )


def make_deviation(
    rule_id: str = RULE, effective: str = "8", recorded_at: str = STAMP
) -> ledger.DeviationRecord:
    return ledger.DeviationRecord(
        rule_id, "var_password_pam_minlen", "14", effective, recorded_at, "0.1.0"
    )


@pytest.fixture
def state(tmp_path: Path) -> Path:
    return tmp_path / "var" / "state"


@pytest.fixture
def store(state: Path) -> ledger.Ledger:
    return ledger.Ledger(state_dir=str(state), owner_uid=OWNER, lock_timeout=5.0)


def error_type(call: Any, *arguments: Any, **keywords: Any) -> str:
    with pytest.raises(ledger.LedgerError) as excinfo:
        call(*arguments, **keywords)
    assert excinfo.value.error_type in ledger.ERROR_TYPES
    return excinfo.value.error_type


def version_2(**changes: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "schema_version": 2,
        "entries": [make_entry(value=make_value()).to_dict()],
        "deviations": [make_deviation().to_dict()],
    }
    fields.update(changes)
    return fields


def encode(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields).encode()


def write_ledger(state: Path, data: bytes) -> Path:
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    target = state / "state.json"
    target.write_bytes(data)
    target.chmod(0o600)
    return target


def test_the_versions() -> None:
    assert ledger.SCHEMA_VERSION == 2
    assert ledger.BASE_SCHEMA_VERSION == 1
    assert frozenset({1, 2}) == ledger.SUPPORTED_SCHEMA_VERSIONS
    assert ledger.MAX_DEVIATIONS == ledger.MAX_ENTRIES
    assert frozenset({"profile", "override"}) == ledger.VALUE_SOURCES


def test_value_records_validate_their_fields() -> None:
    record = make_value()
    assert record.to_dict() == {
        "profile_value": "14",
        "target": "8",
        "value_id": "var_password_pam_minlen",
        "value_source": "override",
    }
    assert ledger.ValueRecord.from_dict(record.to_dict()) == record
    assert make_value("profile", "14").value_source == "profile"
    assert make_value(target="").target == ""
    assert make_value(target="curve25519-sha256,ecdh-sha2-nistp521").target.startswith("curve")
    for value_id in ["", "Var_x", "_var", "var-x", "var x", "v" * 129, 5, None]:
        assert error_type(ledger.ValueRecord, value_id, "profile", "1", "1") == "invalid_entry"
    for source in ["", "Profile", "tailoring", None, 1, ["override"]]:
        assert error_type(ledger.ValueRecord, "var_x", source, "1", "1") == "invalid_entry"
    for text in [None, 14, b"14", "1\n4", "1\t4", "a\x00b", "a" + chr(0x202E), chr(0xD800)]:
        assert error_type(ledger.ValueRecord, "var_x", "override", text, "1") == "invalid_entry"
        assert error_type(ledger.ValueRecord, "var_x", "override", "1", text) == "invalid_entry"
    assert error_type(ledger.ValueRecord, "var_x", "override", "1", "x" * 4097) == "invalid_entry"
    assert ledger.ValueRecord("var_x", "override", "1", "x" * 4096).target == "x" * 4096


@pytest.mark.parametrize(
    "data",
    [
        None,
        "text",
        [],
        {"value_id": "var_x", "value_source": "override", "profile_value": "1"},
        {
            "value_id": "var_x",
            "value_source": "override",
            "profile_value": "1",
            "target": "1",
            "x": 1,
        },
    ],
)
def test_value_records_refuse_wrong_shapes(data: Any) -> None:
    assert error_type(ledger.ValueRecord.from_dict, data) == "invalid_entry"


def test_an_entry_without_a_value_keeps_its_version_1_form() -> None:
    entry = plain_entry()
    assert entry.value is None
    assert "value" not in entry.to_dict()
    view = entry.view()
    assert view["value"] is None
    assert view["value_source"] == "profile"


def test_an_entry_with_a_value_records_and_shows_it() -> None:
    entry = make_entry(value=make_value())
    assert entry.to_dict()["value"] == make_value().to_dict()
    assert entry.view()["value"] == make_value().to_dict()
    assert entry.view()["value_source"] == "override"
    assert make_entry(value=make_value("profile", "14")).view()["value_source"] == "profile"
    assert ledger.LedgerEntry.from_dict(entry.to_dict()) == entry
    assert not entry.same_content(make_entry(value=make_value(target="9")))
    assert not entry.same_content(make_entry())
    assert entry.same_content(make_entry(value=make_value(), applied_at=LATER))


def test_an_entry_refuses_a_value_of_another_type() -> None:
    for value in [make_value().to_dict(), "override", 1]:
        assert error_type(make_entry, value=value) == "invalid_entry"


def test_an_entry_of_a_version_1_document_takes_no_value() -> None:
    data = make_entry(value=make_value()).to_dict()
    document = {"schema_version": 1, "entries": [data]}
    assert error_type(ledger.load_document, json.dumps(document).encode()) == "corrupt"
    assert ledger.LedgerEntry.from_dict(plain_entry().to_dict()) == plain_entry()
    for shape in ["text", None, [data]]:
        assert error_type(ledger.LedgerEntry.from_dict, shape) == "invalid_entry"


def test_deviation_records_validate_their_fields() -> None:
    record = make_deviation()
    assert record.to_dict() == {
        "collection_version": "0.1.0",
        "effective_value": "8",
        "profile_value": "14",
        "recorded_at": STAMP,
        "rule_id": RULE,
        "value_id": "var_password_pam_minlen",
    }
    assert ledger.DeviationRecord.from_dict(record.to_dict()) == record
    assert record.same_content(make_deviation(recorded_at=LATER))
    assert not record.same_content(make_deviation(effective="9"))
    assert not record.same_content(make_deviation(OTHER_RULE))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rule_id", "accounts_password_pam_minlen"),
        ("rule_id", None),
        ("value_id", "Var"),
        ("value_id", ""),
        ("profile_value", 14),
        ("profile_value", "1\n4"),
        ("effective_value", None),
        ("effective_value", "x" * 4097),
        ("effective_value", "a" + chr(0x2066)),
        ("recorded_at", "2026-02-30T12:00:00Z"),
        ("recorded_at", "yesterday"),
        ("recorded_at", None),
        ("collection_version", "1.0"),
        ("collection_version", None),
    ],
)
def test_deviation_records_refuse_invalid_fields(field: str, value: Any) -> None:
    assert error_type(dataclasses.replace, make_deviation(), **{field: value}) == "invalid_entry"


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {key: value for key, value in make_deviation().to_dict().items() if key != "value_id"},
        {**make_deviation().to_dict(), "family": "pwquality"},
    ],
)
def test_deviation_records_refuse_wrong_shapes(data: Any) -> None:
    assert error_type(ledger.DeviationRecord.from_dict, data) == "invalid_entry"


def test_the_document_version_follows_the_content() -> None:
    assert ledger.LedgerDocument().schema_version == 1
    assert ledger.LedgerDocument((plain_entry(),)).schema_version == 1
    assert ledger.LedgerDocument((make_entry(value=make_value()),)).schema_version == 2
    assert ledger.LedgerDocument((), (make_deviation(),)).schema_version == 2


def test_a_ledger_without_values_or_deviations_keeps_its_version_1_bytes() -> None:
    assert ledger.dumps((plain_entry(),)) == VERSION_1_BYTES
    assert ledger.dumps((plain_entry(),), ()) == VERSION_1_BYTES
    assert ledger.loads(VERSION_1_BYTES) == (plain_entry(),)
    parsed = ledger.load_document(VERSION_1_BYTES)
    assert parsed == ledger.LedgerDocument((plain_entry(),), ())
    assert ledger.dumps(parsed.entries, parsed.deviations) == VERSION_1_BYTES
    assert ledger.dumps(()) == b'{\n  "entries": [],\n  "schema_version": 1\n}\n'


def test_a_value_or_a_deviation_writes_version_2() -> None:
    valued = ledger.dumps((make_entry(value=make_value()),))
    assert json.loads(valued)["schema_version"] == 2
    assert json.loads(valued)["deviations"] == []
    registered = ledger.dumps((plain_entry(),), (make_deviation(),))
    parsed = json.loads(registered)
    assert parsed["schema_version"] == 2
    assert sorted(parsed) == ["deviations", "entries", "schema_version"]
    assert "value" not in parsed["entries"][0]
    assert parsed["deviations"] == [make_deviation().to_dict()]


def test_version_2_round_trips_sorted_and_deterministic() -> None:
    entries = (make_entry(value=make_value()), plain_entry())
    deviations = (make_deviation(OTHER_RULE), make_deviation())
    data = ledger.dumps(entries, deviations)
    assert data == ledger.dumps(entries[::-1], deviations[::-1])
    assert data.endswith(b"\n")
    parsed = ledger.load_document(data)
    assert [item.rule_id for item in parsed.entries] == [RULE, OTHER_RULE]
    assert [item.rule_id for item in parsed.deviations] == [RULE, OTHER_RULE]
    assert ledger.dumps(parsed.entries, parsed.deviations) == data
    assert ledger.loads(data) == parsed.entries


def test_dumps_refuses_too_many_deviations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ledger, "MAX_DEVIATIONS", 1)
    two = (make_deviation(), make_deviation(OTHER_RULE))
    assert error_type(ledger.dumps, (), two) == "ledger_full"
    monkeypatch.setattr(ledger, "MAX_DEVIATIONS", 10)
    monkeypatch.setattr(ledger, "MAX_LEDGER_BYTES", 100)
    assert error_type(ledger.dumps, (), (make_deviation(),)) == "ledger_full"


@pytest.mark.parametrize("version", [0, 3, 20, -2])
def test_other_versions_are_unsupported(version: int) -> None:
    for fields in (version_2(schema_version=version), {"schema_version": version}):
        assert error_type(ledger.load_document, encode(fields)) == "unsupported_schema"


@pytest.mark.parametrize(
    "fields",
    [
        {"entries": [], "deviations": []},
        {"schema_version": "2", "entries": [], "deviations": []},
        {"schema_version": True, "entries": [], "deviations": []},
        {"schema_version": 1, "entries": [], "deviations": []},
        {"schema_version": 2, "entries": []},
        {"schema_version": 2, "entries": [], "deviations": [], "extra": 1},
        {"schema_version": 2, "entries": [], "deviations": []},
        {"schema_version": 2, "entries": [plain_entry().to_dict()], "deviations": []},
        {"schema_version": 1, "entries": [make_entry(value=make_value()).to_dict()]},
        version_2(deviations={}),
        version_2(deviations="x"),
        version_2(deviations=[None]),
        version_2(deviations=[{**make_deviation().to_dict(), "extra": 1}]),
        version_2(deviations=[{**make_deviation().to_dict(), "effective_value": 8}]),
        version_2(deviations=[make_deviation().to_dict(), make_deviation(effective="9").to_dict()]),
        version_2(entries=[{**make_entry().to_dict(), "value": None}]),
        version_2(entries=[{**make_entry().to_dict(), "value": {"value_id": "var_x"}}]),
        version_2(entries=["text"]),
        version_2(
            entries=[make_entry(value=make_value()).to_dict(), make_entry().to_dict()],
        ),
    ],
)
def test_malformed_and_non_canonical_documents_are_corrupt(fields: dict[str, Any]) -> None:
    assert error_type(ledger.load_document, encode(fields)) == "corrupt"
    assert error_type(ledger.loads, encode(fields)) == "corrupt"


def test_documents_that_are_not_objects_are_corrupt() -> None:
    for data in [b"[]", b"null", b"2", b'"x"']:
        assert error_type(ledger.load_document, data) == "corrupt"


def test_duplicate_keys_inside_a_deviation_are_corrupt() -> None:
    item = json.dumps(make_deviation().to_dict())[:-1] + ', "effective_value": "16"}'
    data = '{"schema_version": 2, "entries": [], "deviations": [' + item + "]}"
    assert error_type(ledger.load_document, data.encode()) == "corrupt"


def test_too_many_deviations_are_corrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    data = encode(
        version_2(deviations=[make_deviation().to_dict(), make_deviation(OTHER_RULE).to_dict()])
    )
    assert len(ledger.load_document(data).deviations) == 2
    monkeypatch.setattr(ledger, "MAX_DEVIATIONS", 1)
    assert error_type(ledger.load_document, data) == "corrupt"


def test_a_missing_ledger_has_no_deviations(store: ledger.Ledger, state: Path) -> None:
    assert store.deviations() == ()
    assert store.document() == ledger.LedgerDocument()
    assert store.remove_deviation(RULE) == ledger.RemoveDeviationResult(None, changed=False)
    assert store.record_deviation(make_deviation(), dry_run=True).changed is True
    assert not state.exists()


def test_record_and_remove_a_deviation(store: ledger.Ledger, state: Path) -> None:
    store.record(plain_entry())
    before = (state / "state.json").read_bytes()
    assert before == VERSION_1_BYTES
    result = store.record_deviation(make_deviation())
    assert result == ledger.DeviationResult(make_deviation(), None, changed=True)
    assert json.loads((state / "state.json").read_bytes())["schema_version"] == 2
    assert store.deviations() == (make_deviation(),)
    assert store.entries() == (plain_entry(),)
    removed = store.remove_deviation(RULE)
    assert removed == ledger.RemoveDeviationResult(make_deviation(), changed=True)
    assert store.deviations() == ()
    assert (state / "state.json").read_bytes() == before
    assert store.remove_deviation(RULE).changed is False


def test_a_deviation_without_an_entry_is_kept(store: ledger.Ledger) -> None:
    store.record_deviation(make_deviation())
    assert store.entries() == ()
    assert store.document() == ledger.LedgerDocument((), (make_deviation(),))
    store.record(plain_entry())
    store.remove(OTHER_RULE)
    assert store.deviations() == (make_deviation(),)


def test_removing_an_entry_keeps_its_deviation(store: ledger.Ledger) -> None:
    store.record(make_entry(value=make_value()))
    store.record_deviation(make_deviation())
    assert store.remove(RULE).changed is True
    assert store.deviations() == (make_deviation(),)
    assert store.remove_deviation(RULE).changed is True
    assert store.document() == ledger.LedgerDocument()


def test_recording_the_same_deviation_keeps_the_original_time(
    store: ledger.Ledger, state: Path
) -> None:
    store.record_deviation(make_deviation())
    before = (state / "state.json").read_bytes()
    again = store.record_deviation(make_deviation(recorded_at=LATER))
    assert again == ledger.DeviationResult(make_deviation(), make_deviation(), changed=False)
    assert (state / "state.json").read_bytes() == before


def test_a_different_deviation_replaces_the_record(store: ledger.Ledger) -> None:
    store.record_deviation(make_deviation())
    store.record_deviation(make_deviation(OTHER_RULE))
    changed = make_deviation(effective="10", recorded_at=LATER)
    result = store.record_deviation(changed)
    assert result == ledger.DeviationResult(changed, make_deviation(), changed=True)
    assert store.deviations() == (changed, make_deviation(OTHER_RULE))


def test_a_dry_run_of_the_register_writes_nothing(store: ledger.Ledger, state: Path) -> None:
    store.record_deviation(make_deviation())
    before = (state / "state.json").read_bytes()
    assert store.record_deviation(make_deviation(effective="9"), dry_run=True).changed is True
    assert store.record_deviation(make_deviation(OTHER_RULE), dry_run=True).changed is True
    assert store.remove_deviation(RULE, dry_run=True).changed is True
    assert (state / "state.json").read_bytes() == before


def test_a_value_change_of_an_entry_needs_replace(store: ledger.Ledger) -> None:
    store.record(make_entry(value=make_value()))
    assert store.record(make_entry(value=make_value(), applied_at=LATER)).changed is False
    for different in (make_entry(value=make_value(target="9")), make_entry()):
        assert error_type(store.record, different) == "conflict"
    assert store.get(RULE) == make_entry(value=make_value())
    replaced = store.record(make_entry(value=make_value("profile", "14")), replace=True)
    assert replaced.previous == make_entry(value=make_value())
    assert store.get(RULE) == make_entry(value=make_value("profile", "14"))


def test_the_register_refuses_invalid_input(store: ledger.Ledger, state: Path) -> None:
    assert error_type(store.record_deviation, make_deviation().to_dict()) == "invalid_entry"
    assert error_type(store.remove_deviation, "short_id") == "invalid_entry"
    assert not state.exists()


def test_a_corrupt_or_unsupported_ledger_is_never_rewritten_by_the_register(
    store: ledger.Ledger, state: Path
) -> None:
    target = write_ledger(state, b"{ not json")
    assert error_type(store.record_deviation, make_deviation()) == "corrupt"
    assert error_type(store.remove_deviation, RULE) == "corrupt"
    assert error_type(store.deviations) == "corrupt"
    assert target.read_bytes() == b"{ not json"
    future = encode(version_2(schema_version=3))
    target = write_ledger(state, future)
    assert error_type(store.record_deviation, make_deviation()) == "unsupported_schema"
    assert error_type(store.record, plain_entry()) == "unsupported_schema"
    assert target.read_bytes() == future


def test_a_version_2_ledger_on_disk_is_read_and_kept(store: ledger.Ledger, state: Path) -> None:
    data = ledger.dumps((make_entry(value=make_value()),), (make_deviation(),))
    target = write_ledger(state, data)
    assert store.document() == ledger.LedgerDocument(
        (make_entry(value=make_value()),), (make_deviation(),)
    )
    assert store.record(make_entry(value=make_value(), applied_at=LATER)).changed is False
    assert store.record_deviation(make_deviation(recorded_at=LATER)).changed is False
    assert target.read_bytes() == data
