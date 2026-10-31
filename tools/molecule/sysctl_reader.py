"""Cases and verdicts of the real sysctl readers for the kernel parameter topics (FREES-107).

``make sysctl-reader-verdicts`` runs ``tools/molecule/sysctl-reader-verdicts.sh``, which calls this
tool twice around the real readers in the Molecule images:

* ``materialise CASES OUT`` writes every case of ``tests/fixtures/sysctl_reader/cases.json`` below
  ``OUT/<case>/root`` as regular files, directories and symbolic links, relative to the root of an
  instance;
* ``parse CASES RAW OUT_JSON`` reads what ``systemd-sysctl`` (with debug logging) and ``sysctl
  --system --dry-run`` reported for each case in each image and writes, for every key of the case,
  the value that each reader sets last, or ``null`` when it sets none.

``tests/unit/plugins/filter/test_sysctl_effective.py`` checks the role's model of both readers
against the committed verdicts, so that a case where the model and a real reader disagree fails the
unit tests.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Final, cast

SYSTEMD_SETTING: Final[re.Pattern[str]] = re.compile(
    r"^Setting '/proc/sys/(?P<path>[^']+)' to '(?P<value>.*)'$"
)
PROCPS_SETTING: Final[re.Pattern[str]] = re.compile(r"^(?P<key>[^\s=*]+) = (?P<value>.*)$")
PROCPS_DENIED: Final[re.Pattern[str]] = re.compile(
    r'^sysctl: permission denied on key "(?P<key>[^"]+)"(, ignoring)?$'
)
READERS: Final[dict[str, tuple[str, str]]] = {
    "systemd": ("ubuntu", "systemd"),
    "procps-4": ("ubuntu", "procps"),
    "procps-3": ("rhel_compatible", "procps"),
}


class CaseError(ValueError):
    """A case of the fixture is malformed."""


def load_cases(path: Path) -> dict[str, dict[str, object]]:
    """Return the cases of ``path``."""
    data: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        message = f"{path} must hold an object of cases"
        raise CaseError(message)
    return cast("dict[str, dict[str, object]]", data)


def file_text(entry: dict[str, object]) -> str | None:
    """Return the text of a file entry, or ``None`` for a link or a directory."""
    if "text" in entry:
        return str(entry["text"])
    if "long_key" in entry:
        return f"{entry['long_key']} = {' ' * int(str(entry['padding']))}{entry['long_value']}\n"
    return None


def materialise(cases: dict[str, dict[str, object]], out: Path) -> None:
    """Write every case below ``out/<case>/root``."""
    for name, case in cases.items():
        root = out / name / "root"
        for raw in cast("list[dict[str, object]]", case["files"]):
            entry = dict(raw)
            target = root / str(entry["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            text = file_text(entry)
            if entry.get("directory"):
                target.mkdir()
            elif "link" in entry:
                target.symlink_to(str(entry["link"]))
            elif text is not None:
                target.write_bytes(text.encode("utf-8"))
            else:
                message = f"case {name}: {entry['path']} is neither a file, a link nor a directory"
                raise CaseError(message)


def key_path(key: str) -> str:
    """Return the path below ``/proc/sys`` of a key in the dotted form."""
    return key.replace(".", "/")


def systemd_values(log: str) -> dict[str, str]:
    """Return the value that ``systemd-sysctl`` set for every path below ``/proc/sys``.

    systemd applies every key once, after merging all files. Lines are split at line feeds only: a
    form feed or vertical tab inside a value is part of it.
    """
    values: dict[str, str] = {}
    for line in log.split("\n"):
        found = SYSTEMD_SETTING.match(line)
        if found:
            values[found.group("path")] = found.group("value")
    return values


def procps_sequence(log: str, program: str) -> list[tuple[str, str | None]]:
    """Return every setting that ``sysctl --system --dry-run`` reported, as ``(path, value)``.

    procps reads every file before it sets anything, so its output names no file per setting.
    procps-ng 4 prints ``key = value`` for each setting. procps-ng 3.3 prints only
    ``permission denied on key "<key>"`` for a dry run on a read-only ``/proc/sys``, so its values
    stay ``None``.
    """
    sequence: list[tuple[str, str | None]] = []
    for line in log.split("\n"):
        denied = PROCPS_DENIED.match(line)
        found = PROCPS_SETTING.match(line)
        if program == "procps-3" and denied:
            sequence.append((key_path(denied.group("key")), None))
        elif program == "procps-4" and found:
            sequence.append((key_path(found.group("key")), found.group("value")))
    return sequence


def parse(cases: dict[str, dict[str, object]], raw: Path) -> dict[str, dict[str, object]]:
    """Return the verdict of every reader for the keys of every case.

    ``systemd`` maps each key to the value set, or ``None``. ``procps-4`` and ``procps-3`` list the
    settings of the case's keys in the order procps made them, as ``[key, value]``.
    """
    verdicts: dict[str, dict[str, object]] = {}
    for name, case in cases.items():
        keys = [str(key) for key in cast("list[object]", case["keys"])]
        paths = {key_path(key): key for key in keys}
        verdict: dict[str, object] = {}
        for reader, (image, program) in READERS.items():
            log = (raw / image / f"{name}.{program}.log").read_text(
                encoding="utf-8", errors="surrogateescape"
            )
            if program == "systemd":
                values = systemd_values(log)
                verdict[reader] = {key: values.get(key_path(key)) for key in keys}
            else:
                verdict[reader] = [
                    [paths[path], value]
                    for path, value in procps_sequence(log, reader)
                    if path in paths
                ]
        verdicts[name] = verdict
    return verdicts


def main(argv: list[str]) -> int:
    """Run ``materialise`` or ``parse``."""
    parser = argparse.ArgumentParser(description="Cases and verdicts of the real sysctl readers.")
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser("materialise")
    write.add_argument("cases", type=Path)
    write.add_argument("out", type=Path)
    read = commands.add_parser("parse")
    read.add_argument("cases", type=Path)
    read.add_argument("raw", type=Path)
    read.add_argument("verdicts", type=Path)
    arguments = parser.parse_args(argv)
    cases = load_cases(arguments.cases)
    if arguments.command == "materialise":
        materialise(cases, arguments.out)
    else:
        result = parse(cases, arguments.raw)
        arguments.verdicts.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
