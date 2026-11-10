"""The login_defs decisions of the remediate role against the real readers, FREES-198.

The reader is the oracle: ``tests/fixtures/login_defs_readers/verdicts.json`` holds what
``useradd`` and ``chage`` of shadow-utils read on Ubuntu 24.04 and Rocky Linux 9, and what
libeconf reads on Rocky Linux with the call of util-linux ``login``, for every case of
``cases.json`` and for every text that the role writes for them
(``tools/lint/login_defs_readers.py`` produced it in the Molecule images). The role's own
decision tasks (``roles/remediate/tasks/login_defs_decide.yml``) decide every case here, and
no decision may claim a compliant setting that a reader reads as looser, write a value that a
reader does not read, or write one looser than what a reader read before. A case whose state or
written text the table lacks fails until the table is regenerated.

Each decision run starts ansible-playbook and takes about a third of a second per case, so the
cases are decided in ``SHARDS`` interleaved shards, one test per shard, which pytest-xdist spreads
over its workers (FREES-206). Each shard is decided exactly once, and both checks read it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

from tools.lint import login_defs_readers

if TYPE_CHECKING:
    from collections.abc import Mapping

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
FIXTURES: Final[Path] = REPOSITORY_ROOT / "tests" / "fixtures" / "login_defs_readers"
READERS: Final[Mapping[str, tuple[tuple[str, str], ...]]] = {
    "PASS_MAX_DAYS": (("ubuntu", "maximum"), ("rocky", "maximum")),
    "PASS_MIN_DAYS": (("ubuntu", "minimum"), ("rocky", "minimum")),
    "PASS_WARN_AGE": (("ubuntu", "warning"), ("rocky", "warning")),
    "UMASK": (("ubuntu", "home_mode"), ("rocky", "home_mode"), ("ubuntu", "pam"), ("rocky", "pam")),
    "CREATE_HOME": (("ubuntu", "home_created"), ("rocky", "home_created")),
    "FAIL_DELAY": (("rocky", "libeconf"),),
    "PASS_MIN_LEN": (),
}
LOGIN_DEFAULT_DELAY: Final[int] = 5
C_SPACE: Final[str] = " \t\n\v\f\r"
CASE_GROUPS: Final[tuple[str, ...]] = ("values", "control", "review", "readers")
BYTES: Final[tuple[str, ...]] = ("\r", "\v", "\f", "\x00")
SHARDS: Final[int] = 8

Case = dict[str, object]


def load(name: str) -> dict[str, object]:
    return cast("dict[str, object]", json.loads((FIXTURES / name).read_text(encoding="utf-8")))


def cases() -> list[Case]:
    return cast("list[Case]", load("cases.json")["cases"])


def states() -> dict[str, dict[str, dict[str, object]]]:
    return cast("dict[str, dict[str, dict[str, object]]]", load("verdicts.json")["states"])


def shard(index: int) -> list[Case]:
    """Return every ``SHARDS``-th case from ``index`` on, so that each shard mixes the groups."""
    return cases()[index::SHARDS]


def decide(chosen: list[Case], directory: Path) -> dict[str, dict[str, object]]:
    """Decide the chosen cases with the role's decision tasks, on the controller, in memory only."""
    selection = directory / "cases.json"
    selection.write_text(json.dumps({"cases": chosen}), encoding="utf-8")
    output = directory / "decisions.json"
    collections = os.environ.get("ANSIBLE_COLLECTIONS_PATH")
    login_defs_readers.decide(selection, output, Path(collections) if collections else None)
    return cast("dict[str, dict[str, object]]", json.loads(output.read_text(encoding="utf-8")))


def pam_umask(value: object) -> int | None:
    """Return the umask that ``pam_umask`` sets from a value of ``pam_modutil_search_key``.

    ``set_umask`` takes ``strtoul(value, &end, 8) & 0777`` and sets nothing when no digit was read.
    """
    if not isinstance(value, str):
        return None
    text = value.lstrip(C_SPACE)
    sign = -1 if text.startswith("-") else 1
    text = text[1:] if text[:1] in "+-" else text
    digits = len(text) - len(text.lstrip("01234567"))
    if not digits:
        return None
    return (sign * int(text[:digits], 8)) % 2**64 & 0o777


def reading(platform: str, reader: str, state: str) -> object:
    """Return what the program behind ``reader`` uses on ``platform`` for a state.

    A miss of libeconf is the default of util-linux ``login`` (``LOGIN_EXIT_TIMEOUT``, five
    seconds), and a key without a value, on which libeconf crashes, is no delay at all.
    """
    table = states()
    if state not in table:
        return "missing from the table"
    value = table[state][platform][reader]
    if reader == "home_mode":
        return 0o777 & ~int(str(value), 8) if str(value).isdigit() else None
    if reader == "pam":
        return pam_umask(value)
    if reader == "libeconf" and not isinstance(value, int):
        return 0 if value == "crash" else LOGIN_DEFAULT_DELAY
    if reader == "home_created" or isinstance(value, int):
        return value
    return None


def required(case: Case) -> int:
    text = str(case["required"])
    return int(text, 8) if case["comparison"] == "umask" else int(text) if text.isdigit() else 0


def written_value(case: Case, line: str) -> object:
    value = line.split()[1]
    if case["comparison"] == "equal":
        return True
    return int(value, 8) if case["comparison"] == "umask" else int(value)


def satisfies(case: Case, value: object) -> bool:
    comparison = case["comparison"]
    if comparison == "equal":
        return value is True
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    if comparison == "at_most":
        return 0 <= value <= required(case)
    if comparison == "at_least":
        return value >= required(case)
    return value & required(case) == required(case)


def not_looser(case: Case, before: object, written: object) -> bool:
    if not isinstance(before, int) or isinstance(before, bool) or not isinstance(written, int):
        return True
    if case["comparison"] == "at_most":
        return before < 0 or written <= before
    if case["comparison"] == "at_least":
        return written >= before
    return written & before == before


def problems_of(case: Case, decision: Mapping[str, object]) -> list[str]:
    """Return how the decision of a case disagrees with the real readers."""
    before = login_defs_readers.state_key(login_defs_readers.case_state(case))
    found: list[str] = []
    status = decision["status"]
    written = decision.get("written")
    after = None
    if status == "applied":
        assert isinstance(written, str), decision
        after = login_defs_readers.state_key(login_defs_readers.case_state(case, written))
    for platform, reader in READERS[str(case["setting"])]:
        if reader == "libeconf" and not case.get("libeconf"):
            continue
        prior = reading(platform, reader, before)
        if status == "compliant" and not satisfies(case, prior):
            found.append(f"compliant, but {platform} {reader} reads {prior!r}")
        if after is None:
            continue
        value = written_value(case, str(decision["line"]))
        now = reading(platform, reader, after)
        if now != value:
            found.append(f"writes {value!r}, but {platform} {reader} reads {now!r}")
        if not not_looser(case, prior, value):
            found.append(
                f"writes {value!r}, looser than the {prior!r} that {platform} {reader} read"
            )
    return found


def missing_from_table(case: Case, decision: Mapping[str, object]) -> list[str]:
    """Return the states of a case and of its written text that the table lacks."""
    table = states()
    keys = [login_defs_readers.state_key(login_defs_readers.case_state(case))]
    written = decision.get("written")
    if isinstance(written, str):
        keys.append(login_defs_readers.state_key(login_defs_readers.case_state(case, written)))
    return [f"{case['name']}: {key}" for key in keys if key not in table]


def test_the_shards_hold_every_case_exactly_once() -> None:
    names = [str(case["name"]) for index in range(SHARDS) for case in shard(index)]
    assert sorted(names) == sorted(str(case["name"]) for case in cases())
    assert len(names) == len(set(names))
    assert all(shard(index) for index in range(SHARDS))


@pytest.mark.parametrize("index", range(SHARDS))
def test_every_decision_is_in_the_table_and_neither_looser_nor_ineffective_for_a_real_reader(
    index: int, tmp_path: Path
) -> None:
    chosen = shard(index)
    decisions = decide(chosen, tmp_path)
    assert sorted(decisions) == sorted(str(case["name"]) for case in chosen)
    missing = [
        entry for case in chosen for entry in missing_from_table(case, decisions[str(case["name"])])
    ]
    assert missing == [], "regenerate with tools/lint/login_defs_readers.sh: " + "; ".join(
        missing[:5]
    )
    problems = [
        f"{case['name']} ({decisions[str(case['name'])]['status']}): {problem}"
        for case in chosen
        for problem in problems_of(case, decisions[str(case["name"])])
    ]
    assert problems == []


def test_the_cases_cover_every_group_byte_and_form_that_the_readers_treat_differently() -> None:
    texts = [str(case["text"]) for case in cases()]
    groups = {str(case["name"]).split()[1] for case in cases()}
    assert groups == set(CASE_GROUPS)
    for byte in BYTES:
        assert any(byte in text for text in texts), repr(byte)
    assert any(max(len(line.encode()) for line in text.split("\n")) >= 1023 for text in texts)
    assert any(case.get("dropins") for case in cases())
    assert any(case.get("links") for case in cases())
    assert {str(case["setting"]) for case in cases()} == set(READERS)
    assert any(text.count("FAIL_DELAY") > 1 or text.count("UMASK") > 1 for text in texts)


def test_the_readers_are_named_with_their_packages() -> None:
    readers = cast("dict[str, dict[str, str]]", load("verdicts.json")["readers"])
    assert set(readers) == {"ubuntu", "rocky"}
    assert readers["ubuntu"]["shadow"].startswith("passwd ")
    assert readers["rocky"]["shadow"].startswith("shadow-utils-")
    assert readers["rocky"]["libeconf"].startswith("libeconf-")
    assert readers["rocky"]["util-linux"].startswith("util-linux-")
    assert readers["ubuntu"]["pam"].startswith("libpam0g ")
    assert readers["rocky"]["pam"].startswith("pam-")
