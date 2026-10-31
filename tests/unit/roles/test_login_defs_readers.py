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
    "UMASK": (("ubuntu", "home_mode"), ("rocky", "home_mode")),
    "CREATE_HOME": (("ubuntu", "home_created"), ("rocky", "home_created")),
    "FAIL_DELAY": (("rocky", "libeconf"),),
    "PASS_MIN_LEN": (),
}
CASE_GROUPS: Final[tuple[str, ...]] = ("values", "control", "review", "readers")
BYTES: Final[tuple[str, ...]] = ("\r", "\v", "\f", "\x00")

Case = dict[str, object]


def load(name: str) -> dict[str, object]:
    return cast("dict[str, object]", json.loads((FIXTURES / name).read_text(encoding="utf-8")))


def cases() -> list[Case]:
    return cast("list[Case]", load("cases.json")["cases"])


def states() -> dict[str, dict[str, dict[str, object]]]:
    return cast("dict[str, dict[str, dict[str, object]]]", load("verdicts.json")["states"])


@pytest.fixture(scope="module")
def decisions(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, object]]:
    """Decide every case with the role's decision tasks, on the controller and in memory only."""
    output = tmp_path_factory.mktemp("login_defs_readers") / "decisions.json"
    collections = os.environ.get("ANSIBLE_COLLECTIONS_PATH")
    login_defs_readers.decide(
        FIXTURES / "cases.json", output, Path(collections) if collections else None
    )
    return cast("dict[str, dict[str, object]]", json.loads(output.read_text(encoding="utf-8")))


def reading(platform: str, reader: str, state: str) -> object:
    """Return what ``reader`` read on ``platform`` from a state, as a number where it is one."""
    table = states()
    if state not in table:
        return "missing from the table"
    value = table[state][platform][reader]
    if reader == "home_mode":
        return 0o777 & ~int(str(value), 8) if str(value).isdigit() else None
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


def test_the_table_holds_every_case_and_every_text_that_the_role_writes(
    decisions: dict[str, dict[str, object]],
) -> None:
    table = states()
    missing: list[str] = []
    for case in cases():
        decision = decisions[str(case["name"])]
        keys = [login_defs_readers.state_key(login_defs_readers.case_state(case))]
        written = decision.get("written")
        if isinstance(written, str):
            keys.append(login_defs_readers.state_key(login_defs_readers.case_state(case, written)))
        missing += [f"{case['name']}: {key}" for key in keys if key not in table]
    assert missing == [], "regenerate with tools/lint/login_defs_readers.sh: " + "; ".join(
        missing[:5]
    )


def test_no_decision_is_looser_or_ineffective_for_a_real_reader(
    decisions: dict[str, dict[str, object]],
) -> None:
    problems = [
        f"{case['name']} ({decisions[str(case['name'])]['status']}): {problem}"
        for case in cases()
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
