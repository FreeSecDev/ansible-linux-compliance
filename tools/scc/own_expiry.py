"""Check SCC's own expiry against the pinned ``SCC_EXPIRES`` (ADR 0019, open item 12, FREES-179).

SCC logs "Software expires in N days" in its application debug log. A real scan
with ``-d`` writes that log as ``ApplicationLogs/<name>_Debug_Log_001.txt`` below
the scan's ``-u`` directory, which is where the SCC backend reads it. The SCC
integration test of ``make scc-integration`` copies the log of its real scan out of
the container, and ``make scc-own-expiry-check`` runs this tool on the copy in the
``scc-smoke`` job.

The log is untrusted text. The tool opens it without following a symbolic link,
requires a regular file of at most :data:`MAX_LOG_BYTES` and decodes it as UTF-8
with replacement. It then requires exactly one mention of the software's expiry
("software expire", in any case) in the whole log, in a well-formed log record
whose message says "Software expires in N days".
A missing, repeated or malformed mention fails the check, and so does an expiry
earlier than the pin: the run date plus N days must be on or after
``SCC_EXPIRES``. A later expiry passes, because the pin is then the earlier and
safer date. The run date is the UTC date on which the log was last modified,
unless ``--run-date`` names it.

Exit status: 0 when the check holds, 1 when SCC expires before ``SCC_EXPIRES``,
2 when the log is missing or unusable or the expiry is missing or ambiguous.
"""

from __future__ import annotations

import argparse
import errno
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Sequence

MAX_LOG_BYTES: Final[int] = 64 * 1024 * 1024
MAX_SHOWN_CHARACTERS: Final[int] = 200
EXIT_OK: Final[int] = 0
EXIT_EARLIER: Final[int] = 1
EXIT_UNUSABLE: Final[int] = 2
PINS_FILE: Final[str] = "extensions/ci/scc/scc.pins"
MENTION: Final[re.Pattern[str]] = re.compile(r"(?i)\bsoftware\s+expire")
LOG_RECORD: Final[re.Pattern[str]] = re.compile(
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\t\s*([A-Z]+)\t\s*(\S+)\t\s*([0-9]+)\t(.*)"
)
EXPIRY: Final[re.Pattern[str]] = re.compile(r"\bSoftware expires in (-?[0-9]{1,5}) days\b")


class ExpiryCheckError(Exception):
    """Raised when the log cannot be read or does not state SCC's expiry exactly once."""


@dataclass(frozen=True, slots=True)
class DebugLog:
    """The text of SCC's application debug log and the UTC date it was last modified."""

    text: str
    modified: date


@dataclass(frozen=True, slots=True)
class Verdict:
    """SCC's own expiry, derived from the run date and N, compared with the pin."""

    days: int
    run_date: date
    own_expiry: date
    pinned: date

    @property
    def holds(self) -> bool:
        """Whether SCC expires on or after the pinned ``SCC_EXPIRES``."""
        return self.own_expiry >= self.pinned


def _shown(line: str) -> str:
    return repr(line[:MAX_SHOWN_CHARACTERS])


def read_log(path: Path, limit: int = MAX_LOG_BYTES) -> DebugLog:
    """Read SCC's application debug log at ``path``.

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
    modified = datetime.fromtimestamp(status.st_mtime, tz=UTC).date()
    return DebugLog(data.decode("utf-8", "replace"), modified)


def expiry_days(text: str) -> int:
    """Return the N of the one "Software expires in N days" record of ``text``.

    Raises:
        ExpiryCheckError: If the log mentions the software's expiry nowhere or more
            than once,
            or the one mention is not a well-formed log record that says
            "Software expires in N days".
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


def judge(days: int, run_date: date, pinned: date) -> Verdict:
    """Return SCC's own expiry, ``run_date`` plus ``days``, compared with ``pinned``."""
    return Verdict(days, run_date, run_date + timedelta(days=days), pinned)


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        message = f"not a date in the form YYYY-MM-DD: {value!r}"
        raise argparse.ArgumentTypeError(message) from None


def _report(log: Path, verdict: Verdict) -> int:
    print(
        f"SCC's application debug log {log} says 'Software expires in {verdict.days} days' "
        f"on {verdict.run_date}: SCC expires on {verdict.own_expiry}; "
        f"SCC_EXPIRES is {verdict.pinned}"
    )
    gap = (verdict.own_expiry - verdict.pinned).days
    if not verdict.holds:
        print(
            f"error: SCC expires {-gap} days before SCC_EXPIRES. Set SCC_EXPIRES in {PINS_FILE} "
            f"to {verdict.own_expiry} or earlier (ADR 0019, decision 7, step 4)",
            file=sys.stderr,
        )
        return EXIT_EARLIER
    if gap:
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
    parser.add_argument("--run-date", type=_date, default=None)
    arguments = parser.parse_args(argv)
    log = cast("Path", arguments.log)
    try:
        debug_log = read_log(log)
        days = expiry_days(debug_log.text)
    except ExpiryCheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_UNUSABLE
    run_date = cast("date | None", arguments.run_date) or debug_log.modified
    return _report(log, judge(days, run_date, cast("date", arguments.expires)))


if __name__ == "__main__":
    sys.exit(main())
