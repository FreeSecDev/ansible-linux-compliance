"""The sshd lexer of the ssh family against what the real sshd read (FREES-200)."""

from __future__ import annotations

import json
import runpy
import sys
from functools import cache
from pathlib import Path
from typing import cast

import pytest

from tools.lint import sshd_readers as readers

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "sshd_readers"


@cache
def table() -> dict[str, object]:
    return cast("dict[str, object]", json.loads((FIXTURES / "verdicts.json").read_text("utf-8")))


def verdicts() -> dict[str, list[list[list[str]]]]:
    return cast("dict[str, list[list[list[str]]]]", table()["verdicts"])


def test_the_cases_are_the_ones_the_generator_builds() -> None:
    document = json.loads((FIXTURES / "cases.json").read_text("utf-8"))
    assert document["cases"] == readers.build_cases()
    assert set(verdicts()) == {case["name"] for case in readers.build_cases()}


def test_both_images_read_every_case_alike() -> None:
    versions = cast("dict[str, str]", table()["readers"])
    assert versions["ubuntu"].startswith("openssh-server 1:9.6p1")
    assert versions["rocky"].startswith("openssh-server-9.9p1")
    assert [name for name, rows in verdicts().items() if rows[0] != rows[1]] == []


def test_the_lexer_reads_every_case_as_sshd_or_refuses() -> None:
    mismatches: list[tuple[str, str, str, str, str]] = []
    for case in readers.build_cases():
        for index, user in enumerate(readers.USERS):
            status, *values = verdicts()[case["name"]][0][index]
            if status != "0":
                continue
            predicted = readers.predict(case["text"], user)
            for keyword, read in zip(readers.KEYWORDS, values, strict=True):
                if predicted[keyword] not in (readers.UNKNOWN, read):
                    mismatches.append((case["name"], user, keyword, read, predicted[keyword]))
    assert mismatches == []


@pytest.mark.parametrize(
    ("line", "user", "value"),
    [
        ('Permit"RootLogin" yes', "freesecdev-probe", "yes"),
        ("=PermitRootLogin yes", "freesecdev-probe", "yes"),
        ("\t=\tPermitRootLogin\tyes", "freesecdev-probe", "yes"),
        ('="PermitRootLogin" yes', "freesecdev-probe", "yes"),
        ('Permit"RootLogin" yes', "freesecdev-other", "without-password"),
    ],
)
def test_the_forms_of_the_review_inside_a_match_block(line: str, user: str, value: str) -> None:
    case = [
        case
        for case in readers.build_cases()
        if case["text"] == readers.MATCHES[0] + "\n" + line + "\n"
    ]
    status, root, _pubkey = verdicts()[case[0]["name"]][0][readers.USERS.index(user)]
    assert (status, root) == ("0", value)
    assert readers.predict(case[0]["text"], user)["permitrootlogin"] == value


def test_a_quoted_match_header_is_a_match_block() -> None:
    text = '="Match" User freesecdev-probe\nPermitRootLogin yes\n'
    assert readers.predict(text, "freesecdev-probe")["permitrootlogin"] == "yes"
    assert readers.predict(text, "freesecdev-other")["permitrootlogin"] == "without-password"


def test_predictions_that_refuse() -> None:
    assert readers.predict("PermitRootLogin\n", "x")["permitrootlogin"] == readers.ERROR
    assert readers.predict("Permit\x00RootLogin yes\n", "x")["permitrootlogin"] == readers.UNKNOWN
    unknown_match = "Match Group wheel\nPermitRootLogin yes\n"
    assert readers.predict(unknown_match, "x")["permitrootlogin"] == readers.UNKNOWN
    odd_match = "Match User a b\nPermitRootLogin yes\n"
    assert readers.predict(odd_match, "x")["permitrootlogin"] == readers.UNKNOWN
    assert readers.predict('PermitRootLogin "yes"\n', "x")["permitrootlogin"] == readers.UNKNOWN


def test_prepare_and_merge_write_the_cases_and_the_table(tmp_path: Path) -> None:
    cases = tmp_path / "fixtures" / "cases.json"
    work = tmp_path / "work"
    assert readers.main(["prepare", str(cases), str(work / "cases")]) == 0
    built = readers.build_cases()
    assert (work / "cases" / f"{built[0]['name']}.conf").read_bytes() == built[0]["text"].encode()
    for platform in readers.PLATFORMS:
        rows = [f"#sshd\topenssh {platform}"] + [
            f"{case['name']}\t{user}\t0\tno\tyes" for case in built for user in readers.USERS
        ]
        (work / f"{platform}.tsv").write_text("\n".join(rows) + "\n")
    table_path = tmp_path / "verdicts.json"
    assert readers.main(["merge", str(work), str(table_path)]) == 0
    document = json.loads(table_path.read_text())
    assert document["readers"] == {"rocky": "openssh rocky", "ubuntu": "openssh ubuntu"}
    assert (
        document["verdicts"][built[0]["name"]] == [[["0", "no", "yes"], ["0", "no", "yes"]]] * 1 * 2
    )


def test_the_generator_runs_as_a_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    arguments = ["sshd_readers", "prepare", str(tmp_path / "cases.json"), str(tmp_path / "cases")]
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.delitem(sys.modules, "tools.lint.sshd_readers", raising=False)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.lint.sshd_readers", run_name="__main__")
    assert raised.value.code == 0
