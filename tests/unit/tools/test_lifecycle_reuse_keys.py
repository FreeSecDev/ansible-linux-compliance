"""Which pre-state keys let a lifecycle cycle keep the record of the whole instance (FREES-180).

A cycle keeps the record taken before the first cycle only when its pre-state has no key that
writes to the instance (``lifecycle_cycle.yml``). Every key that ``check_lifecycle_topics``
accepts must be classified as reading or writing in ``shared/vars/lifecycle.yml``, so that a new
key forces that decision instead of letting a writing pre-state keep the record silently.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

from tools.roles import check_lifecycle_topics

LIFECYCLE_VARS = (
    Path(__file__).resolve().parents[3]
    / "extensions"
    / "molecule"
    / "shared"
    / "vars"
    / "lifecycle.yml"
)


def classified() -> tuple[set[str], set[str]]:
    data = cast("dict[str, object]", yaml.safe_load(LIFECYCLE_VARS.read_text(encoding="utf-8")))
    reading = set(cast("list[str]", data["lifecycle_pre_state_reading_keys"]))
    writing = set(cast("list[str]", data["lifecycle_pre_state_writing_keys"]))
    return reading, writing


def test_every_pre_state_key_is_classified_once() -> None:
    reading, writing = classified()
    assert not reading & writing
    assert reading | writing == set(check_lifecycle_topics.PRE_STATE_KEYS)


def test_only_files_writes_and_keeps_the_record_from_being_reused() -> None:
    reading, writing = classified()
    assert writing == {"files"}
    assert reading == {"name", "audit", "modes", "unchanged", "applied", "requires"}


def test_the_cycle_reuses_the_record_only_for_reading_keys() -> None:
    cycle = LIFECYCLE_VARS.parents[1] / "tasks" / "lifecycle_cycle.yml"
    text = cycle.read_text(encoding="utf-8")
    assert "lifecycle_pre_state.keys() | difference(lifecycle_pre_state_reading_keys)" in text
    assert "lifecycle_pre_state.files | default([]) | length" not in text
