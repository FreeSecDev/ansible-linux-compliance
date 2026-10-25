from __future__ import annotations

import dataclasses
import errno
import json
import os
import stat
import threading
from typing import TYPE_CHECKING, Any, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    fileio,
    ledger,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance.model import (
    RevertStrategy,
)

if TYPE_CHECKING:
    from pathlib import Path

OWNER = os.getuid()
PREFIX = "xccdf_org.ssgproject.content_rule_"
RULE = PREFIX + "sshd_disable_root_login"
OTHER_RULE = PREFIX + "sysctl_net_ipv4_ip_forward"
STAMP = "2026-10-25T12:00:00Z"
LATER = "2026-10-26T08:30:00Z"


def make_entry(
    rule_id: str = RULE,
    strategy: RevertStrategy = RevertStrategy.RECORDED_VALUE,
    values: tuple[ledger.PriorValue, ...] | None = None,
    applied_at: str = STAMP,
    family: str = "ssh",
) -> ledger.LedgerEntry:
    if values is None:
        needs = strategy in {RevertStrategy.RECORDED_VALUE, RevertStrategy.RECORDED_STATE}
        values = (ledger.PriorValue("PermitRootLogin", "yes"),) if needs else ()
    return ledger.LedgerEntry(rule_id, family, strategy, values, "0.1.0", applied_at)


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


def prior_views(entry: ledger.LedgerEntry, *, reveal: bool = False) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", entry.view(reveal=reveal)["prior_values"])


def document(**changes: Any) -> bytes:
    entry = make_entry().to_dict()
    fields: dict[str, Any] = {"schema_version": 1, "entries": [entry]}
    fields.update(changes)
    return json.dumps(fields).encode()


def test_prior_values_validate_their_fields() -> None:
    assert ledger.PriorValue("net.ipv4.ip_forward", None).value is None
    assert ledger.PriorValue("a", "").value == ""
    assert ledger.PriorValue("a", "line1\nline2\ttab\r").sensitive is False
    for name in ["", " a", "a b", "-a", "a" * 129, "ключ", 3, None]:
        assert error_type(ledger.PriorValue, name, "v") == "invalid_entry"
    for value in ["a\x00b", "a\x1bb", "a" + chr(0x202E) + "b", "x" * 4097, 3, b"x"]:
        assert error_type(ledger.PriorValue, "a", value) == "invalid_entry"
    assert error_type(ledger.PriorValue, "a", "v", "yes") == "invalid_entry"


def test_prior_value_views_redact_sensitive_values() -> None:
    secret = ledger.PriorValue("token", "s3cret", sensitive=True)
    plain = ledger.PriorValue("mode", "644")
    assert secret.view(reveal=False) == {
        "name": "token",
        "redacted": True,
        "sensitive": True,
        "value": None,
    }
    assert secret.view(reveal=True)["value"] == "s3cret"
    assert plain.view(reveal=False)["value"] == "644"
    assert plain.view(reveal=True)["redacted"] is False
    assert secret.to_dict() == {"name": "token", "sensitive": True, "value": "s3cret"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rule_id", "sshd_disable_root_login"),
        ("rule_id", "xccdf_org.ssgproject.content_profile_x"),
        ("rule_id", ""),
        ("rule_id", RULE + "\n"),
        ("rule_id", "x" * 300),
        ("rule_id", None),
        ("family", "SSH"),
        ("family", ""),
        ("family", "a b"),
        ("family", "x" * 65),
        ("family", None),
        ("revert_strategy", "recorded_value"),
        ("revert_strategy", None),
        ("collection_version", "1.0"),
        ("collection_version", "v1.0.0"),
        ("collection_version", "1.0.0 "),
        ("collection_version", "1.0.0-" + "x" * 70),
        ("applied_at", "2026-10-25 12:00:00"),
        ("applied_at", "2026-13-25T12:00:00Z"),
        ("applied_at", "2026-02-30T12:00:00Z"),
        ("applied_at", "2026-10-25T12:00:00+00:00"),
        ("applied_at", None),
        ("prior_values", [ledger.PriorValue("a", "b")]),
        ("prior_values", ("not a prior value",)),
        ("prior_values", None),
    ],
)
def test_entries_reject_invalid_fields(field: str, value: Any) -> None:
    assert error_type(dataclasses.replace, make_entry(), **{field: value}) == "invalid_entry"


def test_entries_enforce_prior_values_per_strategy() -> None:
    assert error_type(make_entry, strategy=RevertStrategy.RECORDED_VALUE, values=()) == (
        "invalid_entry"
    )
    assert error_type(make_entry, strategy=RevertStrategy.RECORDED_STATE, values=()) == (
        "invalid_entry"
    )
    one = (ledger.PriorValue("a", "b"),)
    assert error_type(make_entry, strategy=RevertStrategy.OWNED_DROPIN, values=one) == (
        "invalid_entry"
    )
    assert error_type(make_entry, strategy=RevertStrategy.IRREVERSIBLE, values=one) == (
        "invalid_entry"
    )
    assert make_entry(strategy=RevertStrategy.OWNED_DROPIN).prior_values == ()
    assert make_entry(strategy=RevertStrategy.IRREVERSIBLE).prior_values == ()


def test_entries_reject_duplicate_and_too_many_prior_values() -> None:
    twice = (ledger.PriorValue("a", "1"), ledger.PriorValue("a", "2"))
    assert error_type(make_entry, values=twice) == "invalid_entry"
    many = tuple(ledger.PriorValue(f"n{index}", "v") for index in range(65))
    assert error_type(make_entry, values=many) == "invalid_entry"


def test_entries_sort_prior_values_by_name() -> None:
    entry = make_entry(values=(ledger.PriorValue("b", "2"), ledger.PriorValue("a", "1")))
    assert [item.name for item in entry.prior_values] == ["a", "b"]


def test_entry_views_and_content_comparison() -> None:
    entry = make_entry(
        values=(ledger.PriorValue("k", "v", sensitive=True), ledger.PriorValue("a", "1"))
    )
    assert prior_views(entry)[0]["name"] == "a"
    assert prior_views(entry)[1]["value"] is None
    assert prior_views(entry, reveal=True)[1]["value"] == "v"
    assert entry.same_content(dataclasses.replace(entry, applied_at=LATER))
    assert not entry.same_content(dataclasses.replace(entry, family="other"))
    assert not entry.same_content(dataclasses.replace(entry, collection_version="0.2.0"))


def test_dumps_is_deterministic_sorted_and_ascii() -> None:
    first = make_entry(OTHER_RULE, RevertStrategy.OWNED_DROPIN, family="sysctl")
    second = make_entry()
    data = ledger.dumps((second, first))
    assert data == ledger.dumps((first, second))
    assert data.endswith(b"\n")
    parsed = json.loads(data)
    assert parsed["schema_version"] == 1
    assert [item["rule_id"] for item in parsed["entries"]] == [RULE, OTHER_RULE]
    assert ledger.loads(data) == (second, first)


def test_dumps_refuses_a_full_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ledger, "MAX_ENTRIES", 1)
    assert error_type(ledger.dumps, (make_entry(), make_entry(OTHER_RULE))) == "ledger_full"
    monkeypatch.setattr(ledger, "MAX_ENTRIES", 10)
    monkeypatch.setattr(ledger, "MAX_LEDGER_BYTES", 50)
    assert error_type(ledger.dumps, (make_entry(),)) == "ledger_full"


def test_loads_round_trips_every_strategy() -> None:
    entries = (
        make_entry(PREFIX + "a", RevertStrategy.OWNED_DROPIN),
        make_entry(PREFIX + "b", RevertStrategy.RECORDED_VALUE),
        make_entry(PREFIX + "c", RevertStrategy.RECORDED_STATE),
        make_entry(PREFIX + "d", RevertStrategy.IRREVERSIBLE),
    )
    assert ledger.loads(ledger.dumps(entries)) == entries
    assert ledger.loads(document(entries=[])) == ()


def test_loads_rejects_malformed_json() -> None:
    for data in [b"", b"{", b"[]", b"null", b"1", b'"x"', b"{'a': 1}", b"\xef\xbb\xbf{}"]:
        assert error_type(ledger.loads, data) == "corrupt"


def test_loads_rejects_invalid_utf8() -> None:
    assert error_type(ledger.loads, b'{"schema_version": 1, "entries": "\xff"}') == "corrupt"


def test_loads_rejects_duplicate_keys_anywhere() -> None:
    top = b'{"schema_version": 1, "schema_version": 1, "entries": []}'
    assert error_type(ledger.loads, top) == "corrupt"
    entry = json.dumps(make_entry().to_dict())[:-1] + ', "family": "ssh"}'
    nested = ('{"schema_version": 1, "entries": [' + entry + "]}").encode()
    assert error_type(ledger.loads, nested) == "corrupt"
    value = (
        '{"name": "a", "name": "b", "sensitive": false, "value": null}',
        '{"name": "a", "sensitive": false, "value": null, "value": "x"}',
    )
    for item in value:
        text = json.dumps(make_entry().to_dict()).replace(
            '"prior_values": [', '"prior_values": [' + item + ","
        )
        assert error_type(
            ledger.loads, ('{"schema_version": 1, "entries": [' + text + "]}").encode()
        ) == ("corrupt")


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_loads_rejects_non_finite_numbers(constant: str) -> None:
    data = f'{{"schema_version": 1, "entries": [], "extra": {constant}}}'.encode()
    assert error_type(ledger.loads, data) == "corrupt"
    data = f'{{"schema_version": {constant}, "entries": []}}'.encode()
    assert error_type(ledger.loads, data) == "corrupt"


def test_loads_rejects_very_deep_nesting() -> None:
    assert error_type(ledger.loads, b"[" * 100000) == "corrupt"
    deep = b'{"schema_version": 1, "entries": ' + b"[" * 100000 + b"]" * 100000 + b"}"
    assert error_type(ledger.loads, deep) == "corrupt"


def test_loads_rejects_unknown_and_missing_document_keys() -> None:
    assert error_type(ledger.loads, document(extra=1)) == "corrupt"
    assert error_type(ledger.loads, b'{"schema_version": 1}') == "corrupt"
    assert error_type(ledger.loads, b'{"entries": []}') == "corrupt"


def test_loads_rejects_wrong_shapes_and_unknown_entry_keys() -> None:
    base = make_entry().to_dict()
    cases: list[Any] = [
        "text",
        [],
        None,
        {**base, "extra": 1},
        {key: value for key, value in base.items() if key != "family"},
        {**base, "revert_strategy": "other"},
        {**base, "revert_strategy": ["recorded_value"]},
        {**base, "prior_values": "x"},
        {**base, "prior_values": [{"name": "a"}]},
        {**base, "prior_values": [{"name": "a", "value": "b", "sensitive": False, "x": 1}]},
        {**base, "prior_values": ["x"]},
        {**base, "prior_values": [{"name": "a", "value": 5, "sensitive": False}]},
        {**base, "prior_values": [{"name": "a", "value": "b", "sensitive": "no"}]},
        {**base, "applied_at": "yesterday"},
        {**base, "rule_id": 5},
    ]
    for bad in cases:
        assert error_type(ledger.loads, document(entries=[bad])) == "corrupt"
    assert error_type(ledger.loads, document(entries={})) == "corrupt"
    assert error_type(ledger.loads, document(entries="x")) == "corrupt"


def test_loads_rejects_a_rule_listed_twice_and_too_many_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = make_entry().to_dict()
    assert error_type(ledger.loads, document(entries=[entry, entry])) == "corrupt"
    monkeypatch.setattr(ledger, "MAX_ENTRIES", 1)
    other = make_entry(OTHER_RULE).to_dict()
    assert error_type(ledger.loads, document(entries=[entry, other])) == "corrupt"


def test_rule_identifier_and_family_checks() -> None:
    assert ledger.check_rule_id(RULE) == RULE
    assert ledger.check_family("auditd") == "auditd"
    assert error_type(ledger.check_rule_id, "bad") == "invalid_entry"
    assert error_type(ledger.check_family, "Bad") == "invalid_entry"


def test_a_missing_ledger_is_empty_and_nothing_is_created(
    store: ledger.Ledger, state: Path
) -> None:
    assert store.entries() == ()
    assert store.get(RULE) is None
    assert store.remove(RULE) == ledger.RemoveResult(None, changed=False)
    assert not state.exists()
    assert store.path == f"{state}/state.json"


def test_record_get_list_and_remove(store: ledger.Ledger, state: Path) -> None:
    entry = make_entry()
    result = store.record(entry)
    assert result == ledger.RecordResult(entry, None, changed=True)
    assert store.get(RULE) == entry
    store.record(make_entry(OTHER_RULE, RevertStrategy.OWNED_DROPIN, family="sysctl"))
    assert [item.rule_id for item in store.entries()] == [RULE, OTHER_RULE]
    removed = store.remove(RULE)
    assert removed == ledger.RemoveResult(entry, changed=True)
    assert store.get(RULE) is None
    assert store.remove(RULE).changed is False
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "state.json").stat().st_mode) == 0o600


def test_record_is_idempotent_and_keeps_the_original_time(
    store: ledger.Ledger, state: Path
) -> None:
    store.record(make_entry())
    before = (state / "state.json").read_bytes()
    again = store.record(make_entry(applied_at=LATER))
    assert again.changed is False
    assert again.entry.applied_at == STAMP
    assert (state / "state.json").read_bytes() == before


def test_record_conflicts_unless_replace_is_set(store: ledger.Ledger) -> None:
    store.record(make_entry())
    different = make_entry(values=(ledger.PriorValue("PermitRootLogin", "no"),))
    assert error_type(store.record, different) == "conflict"
    assert store.get(RULE) == make_entry()
    replaced = store.record(different, replace=True)
    assert replaced.changed is True
    assert replaced.previous == make_entry()
    assert store.get(RULE) == different


def test_dry_run_never_writes_or_creates(store: ledger.Ledger, state: Path) -> None:
    result = store.record(make_entry(), dry_run=True)
    assert result.changed is True
    assert not state.exists()
    store.record(make_entry())
    before = (state / "state.json").read_bytes()
    different = make_entry(values=(ledger.PriorValue("PermitRootLogin", "no"),))
    assert store.record(different, replace=True, dry_run=True).changed is True
    assert error_type(store.record, different, dry_run=True) == "conflict"
    assert store.remove(RULE, dry_run=True).changed is True
    assert (state / "state.json").read_bytes() == before


def test_a_corrupt_ledger_is_an_error_and_is_never_reset(store: ledger.Ledger, state: Path) -> None:
    state.mkdir(parents=True, mode=0o700)
    target = state / "state.json"
    target.write_bytes(b"{ this is not json")
    target.chmod(0o600)
    for call in (store.entries, lambda: store.get(RULE), lambda: store.remove(RULE)):
        assert error_type(call) == "corrupt"
    assert error_type(store.record, make_entry()) == "corrupt"
    assert error_type(store.record, make_entry(), replace=True) == "corrupt"
    assert target.read_bytes() == b"{ this is not json"


def test_an_unsupported_schema_is_never_rewritten(store: ledger.Ledger, state: Path) -> None:
    state.mkdir(parents=True, mode=0o700)
    target = state / "state.json"
    target.write_bytes(document(schema_version=2))
    target.chmod(0o600)
    assert error_type(store.record, make_entry()) == "unsupported_schema"
    assert target.read_bytes() == document(schema_version=2)


def test_an_oversized_ledger_is_refused_without_reading_it_all(
    store: ledger.Ledger, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state.mkdir(parents=True, mode=0o700)
    target = state / "state.json"
    with target.open("wb") as handle:
        handle.truncate(ledger.MAX_LEDGER_BYTES + 1)
    target.chmod(0o600)
    reads: list[int] = []

    def spy(_descriptor: int, count: int) -> bytes:
        reads.append(count)
        return b""

    monkeypatch.setattr(os, "read", spy)
    assert error_type(store.entries) == "too_large"
    assert reads == []


def test_a_symlinked_ledger_is_refused_and_its_target_untouched(
    store: ledger.Ledger, state: Path, tmp_path: Path
) -> None:
    state.mkdir(parents=True, mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("precious", encoding="utf-8")
    victim.chmod(0o600)
    (state / "state.json").symlink_to(victim)
    assert error_type(store.entries) == "symlink"
    assert error_type(store.record, make_entry()) == "symlink"
    assert victim.read_text(encoding="utf-8") == "precious"
    assert (state / "state.json").is_symlink()


def test_a_symlinked_directory_is_refused(
    store: ledger.Ledger, state: Path, tmp_path: Path
) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    state.parent.mkdir(parents=True)
    state.symlink_to(target)
    assert error_type(store.entries) == "symlink"
    assert error_type(store.record, make_entry()) == "symlink"
    assert error_type(store.remove, RULE) == "symlink"
    assert list(target.iterdir()) == []


def test_a_symlinked_parent_directory_is_refused(
    store: ledger.Ledger, state: Path, tmp_path: Path
) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    state.parent.symlink_to(real)
    assert error_type(store.record, make_entry()) == "symlink"
    assert list(real.iterdir()) == []


def test_the_wrong_owner_is_refused(state: Path) -> None:
    ledger.Ledger(state_dir=str(state), owner_uid=OWNER).record(make_entry())
    foreign = ledger.Ledger(state_dir=str(state), owner_uid=OWNER + 1)
    assert error_type(foreign.entries) == "wrong_owner"
    assert error_type(foreign.record, make_entry(OTHER_RULE, RevertStrategy.OWNED_DROPIN)) == (
        "wrong_owner"
    )


def test_the_default_owner_is_root(state: Path) -> None:
    store = ledger.Ledger(state_dir=str(state))
    if OWNER == 0:
        assert store.entries() == ()
    else:
        state.mkdir(parents=True, mode=0o700)
        assert error_type(store.entries) == "wrong_owner"


def test_the_production_location_is_fixed() -> None:
    assert ledger.LEDGER_DIRECTORY == "/var/lib/freesecdev/linux_compliance"
    assert ledger.Ledger().path == "/var/lib/freesecdev/linux_compliance/state.json"
    assert ledger.LEDGER_FILENAME == "state.json"


def test_a_ledger_file_that_is_not_private_is_refused(store: ledger.Ledger, state: Path) -> None:
    store.record(make_entry())
    target = state / "state.json"
    for mode in (0o644, 0o640, 0o604, 0o666):
        target.chmod(mode)
        assert error_type(store.entries) == "unsafe_mode"
        assert error_type(store.record, make_entry(OTHER_RULE, RevertStrategy.OWNED_DROPIN)) == (
            "unsafe_mode"
        )
    assert stat.S_IMODE(target.stat().st_mode) == 0o666


def test_a_directory_that_is_not_private_is_refused(store: ledger.Ledger, state: Path) -> None:
    store.record(make_entry())
    state.chmod(0o755)
    assert error_type(store.entries) == "unsafe_mode"


@pytest.mark.parametrize("kind", ["fifo", "directory", "hardlink"])
def test_a_ledger_that_is_not_a_plain_file_is_refused(
    store: ledger.Ledger, state: Path, kind: str
) -> None:
    state.mkdir(parents=True, mode=0o700)
    target = state / "state.json"
    if kind == "fifo":
        os.mkfifo(target, 0o600)
    elif kind == "directory":
        target.mkdir(mode=0o700)
    else:
        target.write_bytes(document())
        target.chmod(0o600)
        os.link(target, state.parent / "alias")
    expected = "hardlinked" if kind == "hardlink" else "not_regular"
    assert error_type(store.entries) == expected


def test_a_toctou_swap_of_the_ledger_for_a_symlink_is_refused(
    store: ledger.Ledger, state: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.record(make_entry())
    forged = tmp_path / "forged"
    forged.write_bytes(document(entries=[]))
    forged.chmod(0o600)
    real_open = os.open

    def swap_before_open(path: str, *arguments: Any, **keywords: Any) -> int:
        if path == "state.json":
            (state / "state.json").unlink()
            (state / "state.json").symlink_to(forged)
        return real_open(path, *arguments, **keywords)

    monkeypatch.setattr(os, "open", swap_before_open)
    monkeypatch.setattr(os, "supports_dir_fd", set(os.supports_dir_fd) | {swap_before_open})
    assert error_type(store.entries) == "symlink"


def test_a_toctou_swap_of_the_directory_cannot_redirect_a_write(
    store: ledger.Ledger, state: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.record(make_entry())
    attacker = tmp_path / "attacker"
    attacker.mkdir(mode=0o700)
    moved = tmp_path / "moved"
    real_read = fileio.SafeDirectory.read

    def swap_after_open(self: fileio.SafeDirectory, name: str, max_bytes: int) -> bytes | None:
        state.rename(moved)
        state.symlink_to(attacker)
        return real_read(self, name, max_bytes)

    monkeypatch.setattr(fileio.SafeDirectory, "read", swap_after_open)
    store.record(make_entry(OTHER_RULE, RevertStrategy.OWNED_DROPIN))
    assert list(attacker.iterdir()) == []
    assert {
        item["rule_id"] for item in json.loads((moved / "state.json").read_bytes())["entries"]
    } == {
        RULE,
        OTHER_RULE,
    }


@pytest.mark.parametrize("failing", ["fsync", "rename", "write"])
def test_an_interrupted_write_leaves_the_old_ledger_intact(
    store: ledger.Ledger, state: Path, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    store.record(make_entry())
    before = (state / "state.json").read_bytes()

    def boom(*_arguments: Any, **_keywords: Any) -> None:
        raise OSError(errno.EIO, "boom")

    monkeypatch.setattr(os, failing, boom)
    monkeypatch.setattr(os, "supports_dir_fd", set(os.supports_dir_fd) | {boom})
    assert error_type(store.record, make_entry(OTHER_RULE, RevertStrategy.OWNED_DROPIN)) == (
        "io_error"
    )
    monkeypatch.undo()
    assert (state / "state.json").read_bytes() == before
    assert [path.name for path in state.iterdir()] == ["state.json"]
    assert store.get(RULE) == make_entry()
    assert store.get(OTHER_RULE) is None


def test_lock_contention_times_out_without_changing_anything(state: Path) -> None:
    store = ledger.Ledger(state_dir=str(state), owner_uid=OWNER, lock_timeout=0.1)
    store.record(make_entry())
    holder = fileio.open_directory(str(state), OWNER)
    assert holder is not None
    holder.lock(1.0)
    try:
        assert error_type(store.record, make_entry(OTHER_RULE, RevertStrategy.OWNED_DROPIN)) == (
            "lock_timeout"
        )
        assert error_type(store.remove, RULE) == "lock_timeout"
        assert store.get(RULE) == make_entry()
    finally:
        holder.close()
    assert store.remove(RULE).changed is True


def test_concurrent_writers_serialise_and_lose_nothing(state: Path) -> None:
    count = 12
    errors: list[BaseException] = []

    def work(index: int) -> None:
        try:
            writer = ledger.Ledger(state_dir=str(state), owner_uid=OWNER, lock_timeout=30.0)
            writer.record(make_entry(f"{PREFIX}rule_{index:02d}", RevertStrategy.OWNED_DROPIN))
        except (ledger.LedgerError, AssertionError) as error:
            errors.append(error)

    threads = [threading.Thread(target=work, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    final = ledger.Ledger(state_dir=str(state), owner_uid=OWNER).entries()
    assert [entry.rule_id for entry in final] == [
        f"{PREFIX}rule_{index:02d}" for index in range(count)
    ]


def test_concurrent_record_and_remove_keep_the_ledger_valid(state: Path) -> None:
    seed = ledger.Ledger(state_dir=str(state), owner_uid=OWNER, lock_timeout=30.0)
    seed.record(make_entry(PREFIX + "keep", RevertStrategy.OWNED_DROPIN))
    errors: list[BaseException] = []

    def churn(index: int) -> None:
        try:
            writer = ledger.Ledger(state_dir=str(state), owner_uid=OWNER, lock_timeout=30.0)
            rule = f"{PREFIX}churn_{index}"
            writer.record(make_entry(rule, RevertStrategy.OWNED_DROPIN))
            writer.remove(rule)
        except (ledger.LedgerError, AssertionError) as error:
            errors.append(error)

    threads = [threading.Thread(target=churn, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert [entry.rule_id for entry in seed.entries()] == [PREFIX + "keep"]


@pytest.mark.parametrize("version", [0, 2, -1])
def test_loads_rejects_unsupported_schema_versions(version: Any) -> None:
    assert error_type(ledger.loads, document(schema_version=version)) == "unsupported_schema"


@pytest.mark.parametrize("version", ["1", 1.0, 1e400, True, False, None, [], {}])
def test_loads_reports_a_non_integer_schema_version_as_corrupt(version: Any) -> None:
    data = document(schema_version=version).replace(b"Infinity", b"1e400")
    assert error_type(ledger.loads, data) == "corrupt"


def test_values_reject_lone_surrogates() -> None:
    for value in ["a" + chr(0xD800) + "b", chr(0xDFFF)]:
        assert error_type(ledger.PriorValue, "a", value) == "invalid_entry"


def test_the_seams_are_keyword_only() -> None:
    for arguments in [("dir",), ("dir", 1000), ("dir", 1000, 1.0)]:
        with pytest.raises(TypeError):
            ledger.Ledger(*arguments)


def test_a_write_sweeps_stale_temporary_files_holding_old_values(
    store: ledger.Ledger, state: Path, tmp_path: Path
) -> None:
    store.record(make_entry())
    stale = state / ".state.json.0123456789abcdef.tmp"
    stale.write_text("old sensitive value", encoding="utf-8")
    victim = tmp_path / "victim"
    victim.write_text("precious", encoding="utf-8")
    link = state / ".state.json.aaaaaaaaaaaaaaaa.tmp"
    link.symlink_to(victim)
    unrelated = state / "notes.tmp"
    unrelated.write_text("keep", encoding="utf-8")
    store.remove(RULE)
    assert not stale.exists()
    assert link.is_symlink()
    assert victim.read_text(encoding="utf-8") == "precious"
    assert unrelated.exists()


def test_a_dry_run_and_an_unchanged_record_leave_stale_files_alone(
    store: ledger.Ledger, state: Path
) -> None:
    store.record(make_entry())
    stale = state / ".state.json.0123456789abcdef.tmp"
    stale.write_text("x", encoding="utf-8")
    store.record(make_entry())
    store.remove(RULE, dry_run=True)
    assert stale.exists()
