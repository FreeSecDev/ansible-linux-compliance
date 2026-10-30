"""SCC's own expiry checked against ``SCC_EXPIRES`` (ADR 0019, open item 12, FREES-179).

The tool reads the application debug log that the real scan of ``make
scc-integration`` exports, requires exactly one "Software expires in N days"
record and fails when the run date plus N is earlier than the pin. The logs here
are synthetic, in the record shape the SCC backend reads.
"""

from __future__ import annotations

import os
import runpy
import sys
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import scc
from tools.scc import own_expiry

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PINS = REPOSITORY_ROOT / "extensions" / "ci" / "scc" / "scc.pins"
MAKEFILE = REPOSITORY_ROOT / "Makefile"
EXPIRES = date(2026, 11, 25)
OBSERVED = date(2026, 10, 26)


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


EXPIRY_30 = record("Checking if software is out of date. Software expires in 30 days.")


def test_the_one_expiry_record_gives_the_days() -> None:
    assert own_expiry.expiry_days(debug_log(EXPIRY_30)) == 30
    assert own_expiry.expiry_days(debug_log(record("Software expires in -2 days"))) == -2


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
        (debug_log(record("Software expires in 1 day")), "does not say 'Software expires"),
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
    ("days", "run_date", "holds", "own"),
    [
        (30, OBSERVED, True, EXPIRES),
        (26, date(2026, 10, 30), True, EXPIRES),
        (29, OBSERVED, False, date(2026, 11, 24)),
        (31, OBSERVED, True, date(2026, 11, 26)),
        (0, date(2026, 11, 1), False, date(2026, 11, 1)),
        (-5, OBSERVED, False, date(2026, 10, 21)),
    ],
)
def test_scc_must_not_expire_before_the_pin(
    days: int, run_date: date, holds: bool, own: date
) -> None:
    verdict = own_expiry.judge(days, run_date, EXPIRES)
    assert verdict.own_expiry == own
    assert verdict.holds is holds


def test_the_log_is_read_with_its_modification_date(tmp_path: Path) -> None:
    path = write_log(tmp_path, debug_log(EXPIRY_30))
    stamp = datetime(2026, 10, 26, 23, 59, 59, tzinfo=UTC).timestamp()
    os.utime(path, (stamp, stamp))
    log = own_expiry.read_log(path)
    assert log.modified == OBSERVED
    assert own_expiry.expiry_days(log.text) == 30


def test_invalid_utf8_is_replaced_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "log.txt"
    path.write_bytes(b"\xff\xfe\n" + EXPIRY_30.encode() + b"\n")
    assert own_expiry.expiry_days(own_expiry.read_log(path).text) == 30


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
    assert own_expiry.read_log(path, limit=path.stat().st_size).text.endswith("\n")


def run_main(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    status = own_expiry.main(arguments)
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def test_main_passes_when_scc_expires_on_the_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(EXPIRY_30))
    arguments = ["--log", str(path), "--expires", "2026-11-25", "--run-date", "2026-10-26"]
    status, out, err = run_main(arguments, capsys)
    assert status == own_expiry.EXIT_OK
    assert "says 'Software expires in 30 days' on 2026-10-26: SCC expires on 2026-11-25" in out
    assert "SCC's own expiry is SCC_EXPIRES" in out
    assert err == ""


def test_main_passes_and_notes_a_conservative_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(record("Software expires in 40 days.")))
    arguments = ["--log", str(path), "--expires", "2026-11-25", "--run-date", "2026-10-26"]
    status, out, _ = run_main(arguments, capsys)
    assert status == own_expiry.EXIT_OK
    assert "SCC_EXPIRES is 10 days earlier than SCC's own expiry" in out


def test_main_fails_when_scc_expires_before_the_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(record("Software expires in 25 days.")))
    arguments = ["--log", str(path), "--expires", "2026-11-25", "--run-date", "2026-10-26"]
    status, out, err = run_main(arguments, capsys)
    assert status == own_expiry.EXIT_EARLIER
    assert "SCC expires on 2026-11-20" in out
    assert "SCC expires 5 days before SCC_EXPIRES" in err
    assert "to 2026-11-20 or earlier" in err


def test_main_defaults_the_run_date_to_the_log_date(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(EXPIRY_30))
    stamp = datetime(2026, 10, 27, 0, 0, 1, tzinfo=UTC).timestamp()
    os.utime(path, (stamp, stamp))
    status, out, _ = run_main(["--log", str(path), "--expires", "2026-11-25"], capsys)
    assert status == own_expiry.EXIT_OK
    assert "on 2026-10-27: SCC expires on 2026-11-26" in out


@pytest.mark.parametrize("text", [debug_log(), debug_log(EXPIRY_30, EXPIRY_30)])
def test_main_refuses_an_unusable_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], text: str
) -> None:
    path = write_log(tmp_path, text)
    status, out, err = run_main(["--log", str(path), "--expires", "2026-11-25"], capsys)
    assert status == own_expiry.EXIT_UNUSABLE
    assert out == ""
    assert err.startswith("error: SCC's application debug log")


def test_main_refuses_a_missing_log(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    arguments = ["--log", str(tmp_path / "absent.txt"), "--expires", "2026-11-25"]
    status, _, err = run_main(arguments, capsys)
    assert status == own_expiry.EXIT_UNUSABLE
    assert "is missing" in err


@pytest.mark.parametrize("flag", ["--expires", "--run-date"])
def test_main_refuses_a_malformed_date(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    arguments = ["--log", str(tmp_path), "--expires", "2026-11-25", flag, "2026-13-01"]
    with pytest.raises(SystemExit) as exit_info:
        own_expiry.main(arguments)
    assert exit_info.value.code == own_expiry.EXIT_UNUSABLE
    assert "not a date in the form YYYY-MM-DD" in capsys.readouterr().err


def test_the_module_runs_as_a_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_log(tmp_path, debug_log(EXPIRY_30))
    arguments = ["own_expiry", "--log", str(path), "--expires", "2026-11-25"]
    monkeypatch.setattr(sys, "argv", [*arguments, "--run-date", "2026-10-26"])
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


def test_the_make_target_checks_the_exported_log_against_the_pin() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "SCC_EXPIRY_LOG := build/scc/expiry/application-debug-log.txt" in text
    assert "FREESECDEV_SCC_EXPIRY_LOG='$(SCC_EXPIRY_LOG)'" in text
    recipe = text.split("\nscc-own-expiry-check: require-uv\n", 1)[1].split("\n\n", 1)[0]
    assert recipe == (
        "\t$(RUN) --no-dev python -m tools.scc.own_expiry --log '$(SCC_EXPIRY_LOG)' "
        "--expires '$(SCC_EXPIRES)'"
    )
