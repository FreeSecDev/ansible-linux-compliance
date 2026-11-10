"""Cases and verdicts of the real sysctl readers for the kernel parameter topics (FREES-107).

``make sysctl-reader-verdicts`` runs ``tools/molecule/sysctl-reader-verdicts.sh``, which calls this
tool twice around the real readers in the Molecule images:

* ``materialise CASES OUT`` writes every case of ``tests/fixtures/sysctl_reader/cases.json`` below
  ``OUT/<case>/root`` as regular files, directories and symbolic links, relative to the root of an
  instance, and ``OUT/proc.list``, the parameters of the private ``/proc/sys`` tree: every key of
  every case, and each per-interface key for the interfaces ``all``, ``default``, ``eth0`` and
  ``lo``, so that globs have interfaces to match;
* ``parse CASES RAW OUT_JSON`` reads the files of that tree as each reader left them, recorded as
  base64, and writes the verdicts: for each reader (``systemd``, ``procps-4``, ``procps-3``) the
  value written to every key of the case, or ``null`` when the key still holds the preset ``9``.

No reader output is parsed: what a reader opened and wrote is what the kernel would have taken.
Every case key must match the role's own key pattern (``CASE_KEY``), because the container
writes ``/proc/sys/<key>`` for each: no key may hold ``..``, ``/`` or anything that leaves the tree.
``tests/unit/plugins/module_utils/compliance/test_sysctl_config.py`` checks the role's model of the
readers against the committed verdicts, so that a case where the model and a real reader disagree
fails the unit tests.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path
from typing import Final, cast

PRESET: Final[bytes] = b"9\n"
INTERFACES: Final[tuple[str, ...]] = ("all", "default", "eth0", "lo")
INTERFACE_KEY: Final[re.Pattern[str]] = re.compile(r"^(net\.ipv[46]\.conf)\.[^.]+\.([^.]+)$")
CASE_KEY: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+){1,7}$")
LONG_LINE: Final[str] = "@LONG_LINE@"
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
    """Return the text of a file entry, or ``None`` for a link or a directory.

    A ``long_line`` entry replaces ``@LONG_LINE@`` in its text with a comment of that many bytes.
    """
    if "long_line" in entry:
        comment = "#" + "x" * (int(str(entry["long_line"])) - 1)
        return str(entry["text"]).replace(LONG_LINE, comment)
    if "text" in entry:
        return str(entry["text"])
    if "long_key" in entry:
        return f"{entry['long_key']} = {' ' * int(str(entry['padding']))}{entry['long_value']}\n"
    return None


def case_keys(case: dict[str, object]) -> list[str]:
    """Return the keys of a case.

    Raises:
        CaseError: If a key does not match the role's key pattern.
    """
    keys = [str(key) for key in cast("list[object]", case["keys"])]
    for key in keys:
        if not CASE_KEY.match(key):
            message = f"{key!r} is not a kernel parameter key that the role accepts"
            raise CaseError(message)
    return keys


def parameters(cases: dict[str, dict[str, object]]) -> list[str]:
    """Return the paths below ``/proc/sys`` of the private tree, sorted."""
    found: set[str] = set()
    for case in cases.values():
        for key in case_keys(case):
            interface = INTERFACE_KEY.match(key)
            names = (
                [f"{interface.group(1)}.{name}.{interface.group(2)}" for name in INTERFACES]
                if interface
                else [key]
            )
            found.update(name.replace(".", "/") for name in names)
    return sorted(found)


def materialise(cases: dict[str, dict[str, object]], out: Path) -> None:
    """Write every case below ``out/<case>/root`` and the tree's parameters to ``out/proc.list``."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "proc.list").write_text(
        "".join(f"{path}\n" for path in parameters(cases)), encoding="utf-8"
    )
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


def written(record: str) -> dict[str, str | None]:
    """Return what a reader left in each file of the tree: its first line, or None for the preset.

    systemd writes without truncating, so a shorter value leaves the rest of the preset behind it;
    only the first line is the value.
    """
    values: dict[str, str | None] = {}
    for line in record.split("\n"):
        if not line:
            continue
        path, _, encoded = line.partition("\t")
        content = base64.b64decode(encoded)
        values[path] = (
            None
            if content == PRESET
            else content.split(b"\n", 1)[0].decode("utf-8", "surrogateescape")
        )
    return values


def parse(cases: dict[str, dict[str, object]], raw: Path) -> dict[str, dict[str, object]]:
    """Return, for every case and reader, the value written to each key of the case, or ``None``."""
    verdicts: dict[str, dict[str, object]] = {}
    for name, case in cases.items():
        verdict: dict[str, object] = {}
        for reader, (image, program) in READERS.items():
            record = (raw / image / f"{name}.{program}.values").read_text(encoding="utf-8")
            values = written(record)
            verdict[reader] = {key: values[key.replace(".", "/")] for key in case_keys(case)}
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
