from __future__ import annotations

import json
import os
import runpy
import stat
import sys
from typing import TYPE_CHECKING, Any, cast

import pytest
import yaml
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.testing import patch_module_args

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    ledger,
)
from ansible_collections.freesecdev.linux_compliance.plugins.modules import control_state

if TYPE_CHECKING:
    from pathlib import Path

OWNER = os.getuid()
PREFIX = "xccdf_org.ssgproject.content_rule_"
RULE = PREFIX + "sshd_disable_root_login"
OTHER = PREFIX + "sysctl_net_ipv4_ip_forward"
STAMP = "2026-10-25T12:00:00Z"
CANARY = "hunter2-canary"


@pytest.fixture
def state(tmp_path: Path) -> Path:
    return tmp_path / "state"


@pytest.fixture
def store(state: Path) -> ledger.Ledger:
    return ledger.Ledger(state_dir=str(state), owner_uid=OWNER, lock_timeout=5.0)


def run_module(store: ledger.Ledger) -> None:
    module = AnsibleModule(
        argument_spec=control_state.argument_spec(),
        required_if=control_state.REQUIRED_IF,
        supports_check_mode=True,
    )
    control_state.run(module, store)


def invoke(
    capsys: pytest.CaptureFixture[str],
    store: ledger.Ledger,
    arguments: dict[str, Any],
    *,
    check: bool = False,
) -> tuple[int, dict[str, Any]]:
    capsys.readouterr()
    values = dict(arguments)
    if check:
        values["_ansible_check_mode"] = True
    with patch_module_args(values), pytest.raises(SystemExit) as excinfo:
        run_module(store)
    code = excinfo.value.code
    assert isinstance(code, int)
    return code, json.loads(capsys.readouterr().out)


def record_arguments(**changes: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "action": "record",
        "rule_id": RULE,
        "family": "ssh",
        "revert_strategy": "recorded_value",
        "prior_values": [{"name": "PermitRootLogin", "value": "yes"}],
        "collection_version": "0.1.0",
        "applied_at": STAMP,
    }
    values.update(changes)
    return values


def test_record_then_get_list_and_remove(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, state: Path
) -> None:
    code, recorded = invoke(capsys, store, record_arguments())
    assert code == 0
    assert recorded["changed"] is True
    assert recorded["action"] == "record"
    assert recorded["ledger_path"] == f"{state}/state.json"
    assert recorded["entry"]["prior_values"] == [
        {"name": "PermitRootLogin", "redacted": False, "sensitive": False, "value": "yes"}
    ]
    assert recorded["diff"]["before"] == ""
    assert '"rule_id"' in recorded["diff"]["after"]
    _code, fetched = invoke(capsys, store, {"action": "get", "rule_id": RULE})
    assert fetched["found"] is True
    assert fetched["entry"] == recorded["entry"]
    assert fetched["changed"] is False
    _code, listing = invoke(capsys, store, {"action": "list"})
    assert listing["count"] == 1
    assert listing["entries"] == [recorded["entry"]]
    _code, removed = invoke(capsys, store, {"action": "remove", "rule_id": RULE})
    assert removed["changed"] is True
    assert removed["found"] is True
    assert removed["diff"]["after"] == ""
    assert removed["diff"]["before"] == recorded["diff"]["after"]
    _code, empty = invoke(capsys, store, {"action": "list"})
    assert empty["entries"] == []
    assert empty["count"] == 0


def test_record_is_idempotent(capsys: pytest.CaptureFixture[str], store: ledger.Ledger) -> None:
    invoke(capsys, store, record_arguments())
    _code, again = invoke(capsys, store, record_arguments(applied_at="2026-11-01T00:00:00Z"))
    assert again["changed"] is False
    assert again["entry"]["applied_at"] == STAMP
    assert again["diff"]["before"] == again["diff"]["after"]


def test_record_defaults_the_time_to_now(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger
) -> None:
    arguments = record_arguments()
    del arguments["applied_at"]
    _code, recorded = invoke(capsys, store, arguments)
    assert recorded["entry"]["applied_at"].endswith("Z")
    assert len(recorded["entry"]["applied_at"]) == len(STAMP)


def test_a_conflicting_record_fails_unless_replace_is_set(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger
) -> None:
    invoke(capsys, store, record_arguments())
    different = record_arguments(prior_values=[{"name": "PermitRootLogin", "value": "no"}])
    code, failed = invoke(capsys, store, different)
    assert code == 1
    assert failed["failed"] is True
    assert failed["error_type"] == "conflict"
    assert failed["path"].endswith("state.json")
    _code, replaced = invoke(capsys, store, {**different, "replace": True})
    assert replaced["changed"] is True
    assert replaced["entry"]["prior_values"][0]["value"] == "no"
    assert replaced["diff"]["before"] != replaced["diff"]["after"]


def test_check_mode_never_writes_or_creates_anything(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, state: Path
) -> None:
    _code, would = invoke(capsys, store, record_arguments(), check=True)
    assert would["changed"] is True
    assert not state.exists()
    invoke(capsys, store, record_arguments())
    before = (state / "state.json").read_bytes()
    different = record_arguments(prior_values=[{"name": "PermitRootLogin", "value": "no"}])
    _code, replaced = invoke(capsys, store, {**different, "replace": True}, check=True)
    assert replaced["changed"] is True
    code, conflict = invoke(capsys, store, different, check=True)
    assert (code, conflict["error_type"]) == (1, "conflict")
    _code, removed = invoke(capsys, store, {"action": "remove", "rule_id": RULE}, check=True)
    assert removed["changed"] is True
    assert (state / "state.json").read_bytes() == before
    assert sorted(path.name for path in state.iterdir()) == ["state.json"]


def test_check_mode_remove_on_a_missing_ledger_changes_nothing(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, state: Path
) -> None:
    _code, removed = invoke(capsys, store, {"action": "remove", "rule_id": RULE}, check=True)
    assert removed == {
        "action": "remove",
        "changed": False,
        "diff": {"after": "", "before": ""},
        "found": False,
        "ledger_path": f"{state}/state.json",
    }
    assert not state.exists()


def test_get_of_an_unknown_rule_is_not_an_error(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger
) -> None:
    code, result = invoke(capsys, store, {"action": "get", "rule_id": RULE})
    assert code == 0
    assert result["found"] is False
    assert "entry" not in result


def test_sensitive_prior_values_are_redacted_everywhere_unless_revealed(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, state: Path
) -> None:
    arguments = record_arguments(
        sensitive_prior_values=[{"name": "bind_password", "value": CANARY}]
    )
    code, recorded = invoke(capsys, store, arguments)
    assert code == 0
    assert CANARY not in json.dumps(recorded)
    sensitive = [item for item in recorded["entry"]["prior_values"] if item["sensitive"]]
    assert sensitive == [
        {"name": "bind_password", "redacted": True, "sensitive": True, "value": None}
    ]
    assert CANARY in (state / "state.json").read_text(encoding="utf-8")
    _code, hidden = invoke(capsys, store, {"action": "get", "rule_id": RULE})
    assert CANARY not in json.dumps(hidden)
    _code, listing = invoke(capsys, store, {"action": "list"})
    assert CANARY not in json.dumps(listing)
    _code, revealed = invoke(
        capsys, store, {"action": "get", "rule_id": RULE, "reveal_sensitive": True}
    )
    assert CANARY in json.dumps(revealed)
    _code, revealed_list = invoke(capsys, store, {"action": "list", "reveal_sensitive": True})
    assert CANARY in json.dumps(revealed_list)
    _code, removed = invoke(capsys, store, {"action": "remove", "rule_id": RULE})
    assert CANARY not in json.dumps(removed)
    _code, checked = invoke(capsys, store, arguments, check=True)
    assert CANARY not in json.dumps(checked)


def test_a_sensitive_value_never_reaches_an_error_message(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger
) -> None:
    arguments = record_arguments(
        family="Not A Slug", sensitive_prior_values=[{"name": "p", "value": CANARY}]
    )
    code, failed = invoke(capsys, store, arguments)
    assert code == 1
    assert failed["error_type"] == "invalid_entry"
    assert CANARY not in json.dumps(failed)


def test_argument_spec_marks_only_the_sensitive_values_no_log() -> None:
    spec = cast("dict[str, Any]", control_state.argument_spec())
    assert spec["sensitive_prior_values"]["options"]["value"]["no_log"] is True
    assert spec["prior_values"]["options"]["value"]["no_log"] is False


def test_the_ledger_location_and_owner_cannot_be_set_through_module_arguments() -> None:
    assert sorted(control_state.argument_spec()) == [
        "action",
        "applied_at",
        "collection_version",
        "family",
        "prior_values",
        "replace",
        "reveal_sensitive",
        "revert_strategy",
        "rule_id",
        "sensitive_prior_values",
    ]


@pytest.mark.parametrize(
    "forbidden", ["state_dir", "path", "owner_uid", "directory", "lock_timeout"]
)
def test_unknown_module_arguments_are_rejected(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, forbidden: str
) -> None:
    code, failed = invoke(capsys, store, {"action": "list", forbidden: "value"})
    assert code == 1
    assert "Unsupported parameters" in failed["msg"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"action": "record"},
        {"action": "record", "rule_id": RULE, "family": "ssh", "revert_strategy": "owned_dropin"},
        {"action": "get"},
        {"action": "remove"},
        {"action": "explode"},
        {},
    ],
)
def test_missing_or_invalid_arguments_fail_before_anything_runs(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, state: Path, arguments: dict[str, Any]
) -> None:
    code, failed = invoke(capsys, store, arguments)
    assert code == 1
    assert failed["failed"] is True
    assert not state.exists()


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"rule_id": "short_id"}, "invalid_entry"),
        ({"family": "BAD"}, "invalid_entry"),
        ({"collection_version": "one"}, "invalid_entry"),
        ({"applied_at": "yesterday"}, "invalid_entry"),
        ({"prior_values": []}, "invalid_entry"),
        ({"revert_strategy": "owned_dropin"}, "invalid_entry"),
        ({"prior_values": [{"name": "bad name", "value": "x"}]}, "invalid_entry"),
        (
            {"prior_values": [{"name": "a", "value": "x"}, {"name": "a", "value": "y"}]},
            "invalid_entry",
        ),
    ],
)
def test_invalid_entries_fail_with_a_stable_error_type(
    capsys: pytest.CaptureFixture[str],
    store: ledger.Ledger,
    state: Path,
    changes: dict[str, Any],
    expected: str,
) -> None:
    code, failed = invoke(capsys, store, record_arguments(**changes))
    assert (code, failed["error_type"]) == (1, expected)
    assert not state.exists()


def test_a_prior_value_may_record_that_a_setting_did_not_exist(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger
) -> None:
    _code, recorded = invoke(
        capsys, store, record_arguments(prior_values=[{"name": "PermitRootLogin"}])
    )
    assert recorded["entry"]["prior_values"][0]["value"] is None


def test_invalid_identifiers_for_get_remove_and_list_fail(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger
) -> None:
    for arguments in (
        {"action": "get", "rule_id": "nope"},
        {"action": "remove", "rule_id": "nope"},
        {"action": "list", "family": "NOPE"},
    ):
        code, failed = invoke(capsys, store, arguments)
        assert (code, failed["error_type"]) == (1, "invalid_entry")


def test_list_filters_by_family_and_is_sorted(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger
) -> None:
    invoke(capsys, store, record_arguments())
    invoke(
        capsys,
        store,
        record_arguments(
            rule_id=OTHER, family="sysctl", revert_strategy="owned_dropin", prior_values=[]
        ),
    )
    _code, everything = invoke(capsys, store, {"action": "list"})
    assert [item["rule_id"] for item in everything["entries"]] == [RULE, OTHER]
    _code, only_ssh = invoke(capsys, store, {"action": "list", "family": "ssh"})
    assert [item["rule_id"] for item in only_ssh["entries"]] == [RULE]
    _code, none = invoke(capsys, store, {"action": "list", "family": "pam"})
    assert none["entries"] == []


def test_return_values_are_deterministic(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger
) -> None:
    invoke(capsys, store, record_arguments())
    first = invoke(capsys, store, {"action": "list"})
    second = invoke(capsys, store, {"action": "list"})
    assert first == second
    third = invoke(capsys, store, record_arguments())
    fourth = invoke(capsys, store, record_arguments())
    assert third == fourth


def test_a_corrupt_ledger_fails_the_task_and_is_left_alone(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, state: Path
) -> None:
    state.mkdir(mode=0o700)
    target = state / "state.json"
    target.write_text("{broken", encoding="utf-8")
    target.chmod(0o600)
    for arguments in (
        {"action": "list"},
        {"action": "get", "rule_id": RULE},
        {"action": "remove", "rule_id": RULE},
        record_arguments(),
    ):
        code, failed = invoke(capsys, store, arguments)
        assert (code, failed["error_type"]) == (1, "corrupt")
    assert target.read_text(encoding="utf-8") == "{broken"


def test_an_unsafe_ledger_fails_the_task(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, state: Path, tmp_path: Path
) -> None:
    state.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    (state / "state.json").symlink_to(victim)
    code, failed = invoke(capsys, store, record_arguments())
    assert (code, failed["error_type"]) == (1, "symlink")
    assert victim.read_text(encoding="utf-8") == "keep"


def test_the_written_ledger_is_private(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, state: Path
) -> None:
    invoke(capsys, store, record_arguments())
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "state.json").stat().st_mode) == 0o600


def test_main_builds_the_ledger_without_arguments(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Any, ...]] = []

    def factory(*arguments: Any, **keywords: Any) -> ledger.Ledger:
        calls.append((arguments, keywords))
        return store

    monkeypatch.setattr(control_state, "Ledger", factory)
    capsys.readouterr()
    with patch_module_args({"action": "list"}), pytest.raises(SystemExit) as excinfo:
        control_state.main()
    assert excinfo.value.code == 0
    assert calls == [((), {})]
    assert json.loads(capsys.readouterr().out)["entries"] == []


def test_documentation_blocks_parse_and_match_the_argument_spec() -> None:
    documentation = yaml.safe_load(control_state.DOCUMENTATION)
    assert yaml.safe_load(control_state.EXAMPLES)
    assert yaml.safe_load(control_state.RETURN)
    assert sorted(documentation["options"]) == sorted(control_state.argument_spec())
    assert documentation["attributes"]["check_mode"]["support"] == "full"
    assert documentation["attributes"]["diff_mode"]["support"] == "full"
    assert documentation["options"]["action"]["choices"] == list(control_state.ACTIONS)
    assert documentation["options"]["revert_strategy"]["choices"] == list(control_state.STRATEGIES)


def test_running_the_file_as_a_script_calls_main(
    capsys: pytest.CaptureFixture[str], store: ledger.Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ledger, "Ledger", lambda: store)
    monkeypatch.delitem(sys.modules, control_state.__name__)
    capsys.readouterr()
    with patch_module_args({"action": "list"}), pytest.raises(SystemExit) as excinfo:
        runpy.run_module(control_state.__name__, run_name="__main__")
    assert excinfo.value.code == 0
    assert json.loads(capsys.readouterr().out)["count"] == 0


class RecordingModule:
    """Duck-typed module that records exit_json and fail_json calls."""

    def __init__(self, params: dict[str, Any], *, check_mode: bool = False) -> None:
        self.params: dict[str, Any] = {
            "rule_id": None,
            "family": None,
            "revert_strategy": None,
            "prior_values": [],
            "sensitive_prior_values": [],
            "collection_version": None,
            "applied_at": None,
            "replace": False,
            "reveal_sensitive": False,
            **params,
        }
        self.check_mode = check_mode
        self.exited: list[dict[str, Any]] = []
        self.failed: list[dict[str, Any]] = []

    def exit_json(self, **kwargs: Any) -> None:
        self.exited.append(kwargs)

    def fail_json(self, msg: str, **kwargs: Any) -> None:
        self.failed.append({"msg": msg, **kwargs})


def raw_run(
    store: ledger.Ledger, params: dict[str, Any], *, check: bool = False
) -> RecordingModule:
    fake = RecordingModule(params, check_mode=check)
    control_state.run(cast("Any", fake), store)
    return fake


def test_the_raw_results_never_contain_a_sensitive_value_unless_revealed(
    store: ledger.Ledger,
) -> None:
    sensitive = {
        "rule_id": RULE,
        "family": "ssh",
        "revert_strategy": "recorded_value",
        "collection_version": "0.1.0",
        "applied_at": STAMP,
        "prior_values": [{"name": "plain", "value": "visible"}],
        "sensitive_prior_values": [{"name": "bind_password", "value": CANARY}],
    }
    changed = {**sensitive, "sensitive_prior_values": [{"name": "bind_password", "value": "x"}]}
    steps = [
        raw_run(store, {"action": "record", **sensitive}, check=True),
        raw_run(store, {"action": "record", **sensitive}),
        raw_run(store, {"action": "record", **sensitive}),
        raw_run(store, {"action": "record", **changed}, check=True),
        raw_run(store, {"action": "record", **changed}),
        raw_run(store, {"action": "record", **changed, "replace": True}, check=True),
        raw_run(store, {"action": "get", "rule_id": RULE}),
        raw_run(store, {"action": "list"}),
        raw_run(store, {"action": "remove", "rule_id": RULE}, check=True),
        raw_run(store, {"action": "remove", "rule_id": RULE}),
    ]
    for fake in steps:
        assert CANARY not in json.dumps(fake.exited + fake.failed)
    assert steps[3].failed[0]["error_type"] == "conflict"
    assert steps[4].failed[0]["error_type"] == "conflict"
    assert steps[5].failed == []
    assert steps[0].exited[0]["changed"] is True


def test_the_raw_results_show_the_sensitive_value_only_when_revealed(
    store: ledger.Ledger,
) -> None:
    raw_run(
        store,
        {
            "action": "record",
            "rule_id": RULE,
            "family": "ssh",
            "revert_strategy": "recorded_value",
            "collection_version": "0.1.0",
            "applied_at": STAMP,
            "sensitive_prior_values": [{"name": "bind_password", "value": CANARY}],
        },
    )
    shown = raw_run(store, {"action": "get", "rule_id": RULE, "reveal_sensitive": True})
    assert CANARY in json.dumps(shown.exited)
    hidden = raw_run(store, {"action": "get", "rule_id": RULE})
    assert CANARY not in json.dumps(hidden.exited)


def test_return_documents_every_key_the_module_can_return() -> None:
    returned = yaml.safe_load(control_state.RETURN)
    assert {
        "error_type",
        "path",
        "ledger_path",
        "action",
        "found",
        "entry",
        "entries",
        "count",
    } <= set(returned)
    assert returned["error_type"]["returned"] == "on failure"
