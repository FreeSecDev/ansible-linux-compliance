"""Check SCC's own expiry against the pinned ``SCC_EXPIRES`` (ADR 0019, open item 12, FREES-179).

SCC logs "Software expires in N days" in its application debug log. A real scan
with ``-d`` writes that log below the scan's ``-u`` directory as
``ApplicationLogs/<host>_SCC-<version>_<YYYY-MM-DD>_<HHMMSS>_Debug_Log_001.txt``,
which is where the SCC backend reads it. The time
in the name is the start of the scan in SCC's process time zone, which the backend
and the integration test fix to UTC. The SCC integration test of ``make
scc-integration`` copies the log of its real scan out of the container and writes
that start time next to it, and ``make scc-own-expiry-check`` runs this tool on the
copy with the start time as ``--run-date`` in the ``scc-smoke`` job, so a scan that
crosses midnight cannot shift the run date.

The log is untrusted text. The tool opens it without following a symbolic link,
requires a regular file of at most :data:`MAX_LOG_BYTES` and decodes it as UTF-8
with replacement. It then requires exactly one mention of the software's expiry
("software expire", in any case) in the whole log, in a well-formed log record
whose message says "Software expires in N days" (or "1 day"). A missing, repeated
or malformed mention fails the check, and so does an expiry earlier than the pin:
the run date plus N days must be on or after ``SCC_EXPIRES``.

Two cases pass:

* A later expiry, because the pin is then the earlier and safer date.
* An expiry exactly one day before ``SCC_EXPIRES``, with a warning, when the scan
  started at or after 12:00 UTC. SCC may count the days left from the time of day,
  so on an afternoon a partly used day is no longer counted. The hard stop seven
  days before ``SCC_EXPIRES`` keeps that day unused. A run date without a time never
  gets this tolerance.

Exit status: 0 when the check holds, 1 when SCC expires before ``SCC_EXPIRES``,
2 when the log is missing or unusable, the expiry is missing or ambiguous, or an
argument is malformed.
"""

from __future__ import annotations

import argparse
import errno
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Sequence

MAX_LOG_BYTES: Final[int] = 64 * 1024 * 1024
MAX_SHOWN_CHARACTERS: Final[int] = 200
EXIT_OK: Final[int] = 0
EXIT_EARLIER: Final[int] = 1
EXIT_UNUSABLE: Final[int] = 2
AFTERNOON_HOUR: Final[int] = 12
TOLERATED_DAYS: Final[int] = 1
PINS_FILE: Final[str] = "extensions/ci/scc/scc.pins"
MENTION: Final[re.Pattern[str]] = re.compile(r"(?i)\bsoftware\s+expire")
LOG_RECORD: Final[re.Pattern[str]] = re.compile(
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\t\s*([A-Z]+)\t\s*(\S+)\t\s*([0-9]+)\t(.*)"
)
EXPIRY: Final[re.Pattern[str]] = re.compile(r"\bSoftware expires in (-?[0-9]{1,5}) days?\b")
RUN_DATE: Final[re.Pattern[str]] = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2})(?:T([0-9]{2}:[0-9]{2}:[0-9]{2})Z)?"
)


class ExpiryCheckError(Exception):
    """Raised when the log cannot be read or does not state SCC's expiry exactly once."""


@dataclass(frozen=True, slots=True)
class RunStart:
    """The UTC day the scan started on and, when known, its UTC start time."""

    day: date
    started: datetime | None = None

    @property
    def afternoon(self) -> bool:
        """Whether the scan is known to have started at or after 12:00 UTC."""
        return self.started is not None and self.started.hour >= AFTERNOON_HOUR

    def __str__(self) -> str:
        """Return the start as given: a date, or a date and time in UTC."""
        if self.started is None:
            return self.day.isoformat()
        return f"{self.started.isoformat()}Z"


@dataclass(frozen=True, slots=True)
class Verdict:
    """SCC's own expiry, derived from the run start and N, compared with the pin."""

    days: int
    run: RunStart
    own_expiry: date
    pinned: date

    @property
    def tolerated(self) -> bool:
        """Whether SCC expires exactly one day early on a scan started in the afternoon."""
        early = self.own_expiry == self.pinned - timedelta(days=TOLERATED_DAYS)
        return early and self.run.afternoon

    @property
    def holds(self) -> bool:
        """Whether SCC expires on or after the pinned ``SCC_EXPIRES``, or is tolerated."""
        return self.own_expiry >= self.pinned or self.tolerated


def _shown(line: str) -> str:
    return repr(line[:MAX_SHOWN_CHARACTERS])


def read_log(path: Path, limit: int = MAX_LOG_BYTES) -> str:
    """Return the text of SCC's application debug log at ``path``.

    Raises:
        ExpiryCheckError: If the file is missing, a symbolic link, not a regular
            file, unreadable or larger than ``limit`` bytes.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        if error.errno == errno.ENOENT:
            message = (
                f"SCC's application debug log {path} is missing: the real scan of "
                "make scc-integration did not export it"
            )
        else:
            message = f"cannot open SCC's application debug log {path}: {error.strerror}"
        raise ExpiryCheckError(message) from None
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode):
        os.close(descriptor)
        message = f"SCC's application debug log {path} is not a regular file"
        raise ExpiryCheckError(message)
    with os.fdopen(descriptor, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        message = f"SCC's application debug log {path} is larger than {limit} bytes"
        raise ExpiryCheckError(message)
    return data.decode("utf-8", "replace")


def expiry_days(text: str) -> int:
    """Return the N of the one "Software expires in N days" record of ``text``.

    Raises:
        ExpiryCheckError: If the log mentions the software's expiry nowhere or more
            than once, or the one mention is not a well-formed log record that says
            "Software expires in N days" or "Software expires in N day".
    """
    mentions = [
        (number, line)
        for number, line in enumerate(text.splitlines(), start=1)
        for _ in MENTION.finditer(line)
    ]
    if not mentions:
        message = "SCC's application debug log does not say when the software expires"
        raise ExpiryCheckError(message)
    if len(mentions) > 1:
        lines = ", ".join(str(number) for number, _ in mentions)
        message = (
            f"SCC's application debug log mentions the software's expiry {len(mentions)} times "
            f"(lines {lines}), expected once"
        )
        raise ExpiryCheckError(message)
    number, line = mentions[0]
    record = LOG_RECORD.fullmatch(line)
    if record is None:
        message = (
            f"line {number} of SCC's application debug log is not a log record: {_shown(line)}"
        )
        raise ExpiryCheckError(message)
    found = EXPIRY.search(record.group(4))
    if found is None:
        message = (
            f"line {number} of SCC's application debug log does not say "
            f"'Software expires in N days': {_shown(line)}"
        )
        raise ExpiryCheckError(message)
    return int(found.group(1))


def judge(days: int, run: RunStart, pinned: date) -> Verdict:
    """Return SCC's own expiry, the run's day plus ``days``, compared with ``pinned``."""
    return Verdict(days, run, run.day + timedelta(days=days), pinned)


def parse_run_date(value: str) -> RunStart:
    """Parse ``YYYY-MM-DD`` or the UTC start time ``YYYY-MM-DDTHH:MM:SSZ``.

    Raises:
        argparse.ArgumentTypeError: If the value is neither, or not a real date or time.
    """
    message = f"not a date in the form YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ: {value!r}"
    match = RUN_DATE.fullmatch(value)
    if match is None:
        raise argparse.ArgumentTypeError(message)
    day_text, clock = match.groups()
    try:
        day = date.fromisoformat(day_text)
        started = None if clock is None else datetime.fromisoformat(f"{day_text}T{clock}")
    except ValueError:
        raise argparse.ArgumentTypeError(message) from None
    return RunStart(day, started)


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        message = f"not a date in the form YYYY-MM-DD: {value!r}"
        raise argparse.ArgumentTypeError(message) from None


def _report(log: Path, verdict: Verdict) -> int:
    unit = "day" if abs(verdict.days) == 1 else "days"
    print(
        f"SCC's application debug log {log} says 'Software expires in {verdict.days} {unit}' "
        f"for the scan started {verdict.run}: SCC expires on {verdict.own_expiry}; "
        f"SCC_EXPIRES is {verdict.pinned}"
    )
    gap = (verdict.own_expiry - verdict.pinned).days
    if not verdict.holds:
        early = "1 day" if gap == -1 else f"{-gap} days"
        print(
            f"error: SCC expires {early} before SCC_EXPIRES. Set SCC_EXPIRES in {PINS_FILE} "
            f"to {verdict.own_expiry} or earlier (ADR 0019, decision 7, step 4)",
            file=sys.stderr,
        )
        return EXIT_EARLIER
    if verdict.tolerated:
        print(
            "warning: SCC expires one day before SCC_EXPIRES. The scan started at or after "
            "12:00 UTC, when SCC may no longer count the partly used day; accepted because the "
            "hard stop is seven days before SCC_EXPIRES",
            file=sys.stderr,
        )
    elif gap:
        print(
            f"SCC_EXPIRES is {gap} days earlier than SCC's own expiry, so the pin is the safer date"
        )
    else:
        print("SCC's own expiry is SCC_EXPIRES")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point; returns the process exit status."""
    parser = argparse.ArgumentParser(
        description="Check SCC's own expiry against SCC_EXPIRES (ADR 0019)."
    )
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--expires", required=True, type=_date)
    parser.add_argument("--run-date", required=True, type=parse_run_date)
    arguments = parser.parse_args(argv)
    log = cast("Path", arguments.log)
    try:
        days = expiry_days(read_log(log))
    except ExpiryCheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_UNUSABLE
    run = cast("RunStart", arguments.run_date)
    return _report(log, judge(days, run, cast("date", arguments.expires)))


if __name__ == "__main__":
    sys.exit(main())
