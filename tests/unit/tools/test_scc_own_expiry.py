"""SCC's own expiry checked against ``SCC_EXPIRES`` (ADR 0019, open item 12, FREES-179).

The tool reads the application debug log that the real scan of ``make
scc-integration`` exports, requires exactly one "Software expires in N days"
record and fails when the scan's start day plus N is earlier than the pin, except
for exactly one day on a scan started at or after 12:00 UTC. The start comes from
the log's name, which the SCC driver turns into the ``--run-date``. The logs here
are synthetic, in the record shape the SCC backend reads.
"""

from __future__ import annotations

import argparse
import runpy
import sys
from datetime import date, datetime
from pathlib import Path

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import scc
from tests.system.scc import scc_driver
from tools.scc import own_expiry

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PINS = REPOSITORY_ROOT / "extensions" / "ci" / "scc" / "scc.pins"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
EXPIRES = date(2026, 11, 25)
OBSERVED = date(2026, 10, 26)
LOG_NAME = "B75D02BCDD4C_SCC-5.15_2026-10-30_112017_Debug_Log_001.txt"


def record(message: str, package: str = "SoftwareExpiration", level: str = "DEBUG") -> str:
    return f"12:00:01\t {level:>6}\t{package:>32}\t {1:4d}\t{message}"


def debug_log(*lines: str) -> str:
    header = ["SCC - 5.15 on host TARGET running Debian Variant Unknown (x86_64)", ""]
    body = [record("Loading options from: /run/o.xml", "SCC_Config", "SCREEN"), *lines]
    return "\n".join([*header, *body, record("SCC Scan Completed", "Output")]) + "\n"


def write_log(directory: Path, text: str, name: str = "TARGET_Debug_Log_001.txt") -> Path:
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def started(value: str) -> own_expiry.RunStart:
    return own_expiry.parse_run_date(value)


EXPIRY_30 = record("Checking if software is out of date. Software expires in 30 days.")


def test_the_one_expiry_record_gives_the_days() -> None:
    assert own_expiry.expiry_days(debug_log(EXPIRY_30)) == 30
    assert own_expiry.expiry_days(debug_log(record("Software expires in -2 days"))) == -2


def test_the_last_day_reads_in_the_singular() -> None:
    assert own_expiry.expiry_days(debug_log(record("Software expires in 1 day."))) == 1
    assert own_expiry.expiry_days(debug_log(record("Software expires in 1 days."))) == 1


def test_the_tool_reads_the_record_the_backend_reads() -> None:
    text = debug_log(record("Software expires in 26 days."))
    assert own_expiry.expiry_days(text) == scc.expiry_days(text) == 26


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (debug_log(), "does not say when the software expires"),
        ("", "does not say when the software expires"),
        (debug_log(EXPIRY_30, EXPIRY_30), "2 times (lines 4, 5), expected once"),
        (
            debug_log(EXPIRY_30, record("Software expires in 400 days.")),
            "mentions the software's expiry 2 times",
        ),
        (
            debug_log(record("Software expires in 30 days. Software expires in 400 days.")),
            "2 times (lines 4, 4)",
        ),
        (debug_log(EXPIRY_30, "SOFTWARE EXPIRED"), "2 times"),
        (debug_log("Software expires in 30 days."), "line 4 of SCC's application debug log is not"),
        (debug_log(f"x{EXPIRY_30}"), "is not a log record"),
        (debug_log(record("Software expires in thirty days")), "does not say 'Software expires"),
        (debug_log(record("Software expires in 2 dayz")), "does not say 'Software expires"),
        (debug_log(record("Software expires in 123456 days")), "does not say 'Software expires"),
        (debug_log(record("Software expired 3 days ago")), "does not say 'Software expires"),
    ],
)
def test_a_missing_repeated_or_malformed_expiry_is_refused(text: str, reason: str) -> None:
    with pytest.raises(own_expiry.ExpiryCheckError) as error:
        own_expiry.expiry_days(text)
    assert reason in str(error.value)


def test_a_hostile_line_is_shown_clipped() -> None:
    line = "Software expires " + "A" * 5000
    with pytest.raises(own_expiry.ExpiryCheckError) as error:
        own_expiry.expiry_days(debug_log(line))
    assert len(str(error.value)) < own_expiry.MAX_SHOWN_CHARACTERS + 100


@pytest.mark.parametrize(
    ("days", "run_date", "holds", "tolerated", "own"),
    [
        (30, "2026-10-26", True, False, EXPIRES),
        (26, "2026-10-30T11:20:17Z", True, False, EXPIRES),
        (29, "2026-10-26", False, False, date(2026, 11, 24)),
        (31, "2026-10-26", True, False, date(2026, 11, 26)),
        (0, "2026-11-01", False, False, date(2026, 11, 1)),
        (-5, "2026-10-26", False, False, date(2026, 10, 21)),
        (25, "2026-10-30T11:59:59Z", False, False, date(2026, 11, 24)),
        (25, "2026-10-30T12:00:00Z", True, True, date(2026, 11, 24)),
        (25, "2026-10-30T23:59:59Z", True, True, date(2026, 11, 24)),
        (25, "2026-10-30", False, False, date(2026, 11, 24)),
        (24, "2026-10-30T12:00:00Z", False, False, date(2026, 11, 23)),
        (26, "2026-10-30T12:00:00Z", True, False, EXPIRES),
        (1, "2026-11-23T18:00:00Z", True, True, date(2026, 11, 24)),
    ],
)
def test_scc_must_not_expire_before_the_pin(
    days: int, run_date: str, holds: bool, tolerated: bool, own: date
) -> None:
    verdict = own_expiry.judge(days, started(run_date), EXPIRES)
    assert verdict.own_expiry == own
    assert verdict.holds is holds
    assert verdict.tolerated is tolerated


@pytest.mark.parametrize(
    ("value", "day", "text", "afternoon"),
    [
        ("2026-10-30", date(2026, 10, 30), "2026-10-30", False),
        ("2026-10-30T11:20:17Z", date(2026, 10, 30), "2026-10-30T11:20:17Z", False),
        ("2026-10-30T12:00:00Z", date(2026, 10, 30), "2026-10-30T12:00:00Z", True),
    ],
)
def test_the_run_date_is_a_day_or_a_utc_start(
    value: str, day: date, text: str, afternoon: bool
) -> None:
    run = own_expiry.parse_run_date(value)
    assert run.day == day
    assert str(run) == text
    assert run.afternoon is afternoon


@pytest.mark.parametrize(
    "value",
    [
        "2026-13-01",
        "2026-10-30T25:00:00Z",
        "2026-10-30T11:20:17",
        "2026-10-30T11:20:17+00:00",
        "2026-10-30 11:20:17Z",
        "",
        "yesterday",
    ],
)
def test_a_malformed_run_date_is_refused(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        own_expiry.parse_run_date(value)


@pytest.mark.parametrize(
    ("name", "start"),
    [
        (LOG_NAME, "2026-10-30T11:20:17Z"),
        ("6769490FF93F_SCC-5.15_2026-10-30_110358_Debug_Log_001.txt", "2026-10-30T11:03:58Z"),
        ("H_SCC-5.15_2026-10-30_235959_Debug_Log_001.txt", "2026-10-30T23:59:59Z"),
        ("H_SCC-5.15_2026-10-30_1120_Debug_Log_001.txt", None),
        ("H_SCC-5.15_2026-10-30_112017_Debug_Log_002.txt", None),
        ("../H_SCC-5.15_2026-10-30_112017_Debug_Log_001.txt", None),
    ],
)
def test_the_driver_reads_the_scan_start_from_the_log_name(name: str, start: str | None) -> None:
    assert scc_driver.log_start(name) == start
    if start is not None:
        assert own_expiry.parse_run_date(start).started == datetime.fromisoformat(start[:-1])


def test_invalid_utf8_is_replaced_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "log.txt"
    path.write_bytes(b"\xff\xfe\n" + EXPIRY_30.encode() + b"\n")
    assert own_expiry.expiry_days(own_expiry.read_log(path)) == 30


def test_a_missing_log_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(own_expiry.ExpiryCheckError) as error:
        own_expiry.read_log(tmp_path / "absent.txt")
    assert "is missing" in str(error.value)
    assert "make scc-integration" in str(error.value)


def test_a_symbolic_link_is_not_followed(tmp_path: Path) -> None:
    target = write_log(tmp_path, debug_log(EXPIRY_30))
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(own_expiry.ExpiryCheckError) as error:
        own_expiry.read_log(link)
    assert "cannot open" in str(error.value)


def test_a_directory_is_not_a_log(tmp_path: Path) -> None:
    with pytest.raises(own_expiry.ExpiryCheckError) as error:
        own_expiry.read_log(tmp_path)
    assert "not a regular file" in str(error.value)


def test_an_oversized_log_is_refused(tmp_path: Path) -> None:
    path = write_log(tmp_path, debug_log(EXPIRY_30))
    with pytest.raises(own_expiry.ExpiryCheckError) as error:
        own_expiry.read_log(path, limit=16)
    assert "larger than 16 bytes" in str(error.value)
    assert own_expiry.read_log(path, limit=path.stat().st_size).endswith("\n")


def run_main(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    status = own_expiry.main(arguments)
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def check(path: Path, run_date: str) -> list[str]:
    return ["--log", str(path), "--expires", "2026-11-25", "--run-date", run_date]


def test_main_passes_when_scc_expires_on_the_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(record("Software expires in 26 days.")))
    status, out, err = run_main(check(path, "2026-10-30T11:20:17Z"), capsys)
    assert status == own_expiry.EXIT_OK
    assert (
        "says 'Software expires in 26 days' for the scan started 2026-10-30T11:20:17Z: "
        "SCC expires on 2026-11-25; SCC_EXPIRES is 2026-11-25"
    ) in out
    assert "SCC's own expiry is SCC_EXPIRES" in out
    assert err == ""


def test_main_passes_and_notes_a_conservative_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(record("Software expires in 40 days.")))
    status, out, _ = run_main(check(path, "2026-10-26"), capsys)
    assert status == own_expiry.EXIT_OK
    assert "SCC_EXPIRES is 10 days earlier than SCC's own expiry" in out


def test_main_fails_when_scc_expires_before_the_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(record("Software expires in 25 days.")))
    status, out, err = run_main(check(path, "2026-10-26"), capsys)
    assert status == own_expiry.EXIT_EARLIER
    assert "SCC expires on 2026-11-20" in out
    assert "SCC expires 5 days before SCC_EXPIRES" in err
    assert "to 2026-11-20 or earlier" in err


@pytest.mark.parametrize(
    ("run_date", "status"),
    [
        ("2026-10-30T11:59:59Z", own_expiry.EXIT_EARLIER),
        ("2026-10-30T12:00:00Z", own_expiry.EXIT_OK),
        ("2026-10-30", own_expiry.EXIT_EARLIER),
    ],
)
def test_main_accepts_one_day_early_only_from_noon_utc_with_a_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], run_date: str, status: int
) -> None:
    path = write_log(tmp_path, debug_log(record("Software expires in 25 days.")))
    result, out, err = run_main(check(path, run_date), capsys)
    assert result == status
    assert "SCC expires on 2026-11-24" in out
    if status == own_expiry.EXIT_OK:
        assert err.startswith("warning: SCC expires one day before SCC_EXPIRES")
        assert "SCC's own expiry is SCC_EXPIRES" not in out
    else:
        assert "SCC expires 1 day before SCC_EXPIRES" in err


def test_main_fails_on_the_last_day_in_the_singular(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(record("Software expires in 1 day.")))
    status, out, err = run_main(check(path, "2026-11-20T08:00:00Z"), capsys)
    assert status == own_expiry.EXIT_EARLIER
    assert "says 'Software expires in 1 day' for the scan started 2026-11-20T08:00:00Z" in out
    assert "SCC expires 4 days before SCC_EXPIRES" in err


@pytest.mark.parametrize("text", [debug_log(), debug_log(EXPIRY_30, EXPIRY_30)])
def test_main_refuses_an_unusable_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], text: str
) -> None:
    path = write_log(tmp_path, text)
    status, out, err = run_main(check(path, "2026-10-26"), capsys)
    assert status == own_expiry.EXIT_UNUSABLE
    assert out == ""
    assert err.startswith("error: SCC's application debug log")


def test_main_refuses_a_missing_log(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    status, _, err = run_main(check(tmp_path / "absent.txt", "2026-10-26"), capsys)
    assert status == own_expiry.EXIT_UNUSABLE
    assert "is missing" in err


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (["--expires", "2026-13-01", "--run-date", "2026-10-26"], "not a date in the form"),
        (["--expires", "2026-11-25", "--run-date", "2026-10-26T1:00:00Z"], "YYYY-MM-DDTHH:MM:SSZ"),
        (["--expires", "2026-11-25"], "--run-date"),
    ],
)
def test_main_refuses_a_malformed_or_missing_date(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], arguments: list[str], reason: str
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        own_expiry.main(["--log", str(tmp_path), *arguments])
    assert exit_info.value.code == own_expiry.EXIT_UNUSABLE
    assert reason in capsys.readouterr().err


def test_the_module_runs_as_a_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(EXPIRY_30))
    monkeypatch.setattr(sys, "argv", ["own_expiry", *check(path, "2026-10-26")])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(own_expiry.__file__, run_name="__main__")
    assert exit_info.value.code == own_expiry.EXIT_OK
    assert "SCC expires on 2026-11-25" in capsys.readouterr().out


def test_the_pinned_expiry_matches_the_backend_release() -> None:
    values = dict(
        line.split(" := ", 1) for line in PINS.read_text(encoding="utf-8").splitlines() if line
    )
    releases = [
        release
        for release in scc.SUPPORTED_RELEASES.values()
        if release.version == values["SCC_VERSION"]
    ]
    assert [release.expires.isoformat() for release in releases] == [values["SCC_EXPIRES"]]


def test_the_make_target_checks_the_exported_log_from_its_start_against_the_pin() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "SCC_EXPIRY_LOG := build/scc/expiry/application-debug-log.txt" in text
    assert f"SCC_EXPIRY_START := $(SCC_EXPIRY_LOG){scc_driver.START_SUFFIX}" in text
    assert "FREESECDEV_SCC_EXPIRY_LOG='$(SCC_EXPIRY_LOG)'" in text
    recipe = text.split("\nscc-own-expiry-check: require-uv\n", 1)[1].split("\n\n", 1)[0]
    assert recipe.startswith("\tstart=\"$$(cat '$(SCC_EXPIRY_START)')\" || {")
    assert recipe.endswith(
        "\t\t$(RUN) --no-dev python -m tools.scc.own_expiry --log '$(SCC_EXPIRY_LOG)' "
        "--expires '$(SCC_EXPIRES)' --run-date \"$$start\""
    )
