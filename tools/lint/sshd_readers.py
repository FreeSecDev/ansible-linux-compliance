"""Record what sshd reads, the oracle of the lexer of the ssh family (FREES-200).

The ``ssh`` family of the remediate role finds settings, ``Match`` lines and ``Include`` lines
with ``plugins/module_utils/compliance/sshd_config.py``, which reproduces ``strdelim`` and the line
reader of OpenSSH. ``sshd -T`` without ``-C`` does not apply ``Match`` blocks, so a lexer that
misses a keyword form would miss a looser ``Match`` block. What the real sshd reads for every case
is kept in ``tests/fixtures/sshd_readers/verdicts.json``, produced in this repository's Molecule
images, and ``tests/unit/tools/test_sshd_verdicts.py`` checks the lexer against it.

Regenerate the cases and the table with ``bash tools/lint/sshd_readers.sh UBUNTU_IMAGE
ROCKY_IMAGE``. That script runs ``prepare`` here, which writes the cases of :func:`build_cases` to
``tests/fixtures/sshd_readers/cases.json`` and one configuration file per case; then
``tools/lint/sshd_readers_probe.sh`` in throwaway containers of both images with ``--network
none``, which runs ``sshd -T -C`` for a user that the ``Match`` lines of the cases name and one
that they do not; and ``merge`` here, which writes the table.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    sshd_config,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

PLATFORMS: Final[tuple[str, ...]] = ("ubuntu", "rocky")
USERS: Final[tuple[str, ...]] = ("freesecdev-probe", "freesecdev-other")
KEYWORDS: Final[tuple[str, ...]] = ("permitrootlogin", "pubkeyauthentication")
DEFAULTS: Final[dict[str, str]] = {
    "permitrootlogin": "without-password",
    "pubkeyauthentication": "yes",
}
UNKNOWN: Final[str] = "unknown"
MATCH_ARGUMENTS: Final[int] = 2
ERROR: Final[str] = "error"
NAME: Final[str] = "PermitRootLogin"
INSERTS: Final[tuple[str, ...]] = ('"', '""', "=", " ", "\t", "\r", "\f", "\v")
SETTINGS: Final[tuple[str, ...]] = (
    "PermitRootLogin yes",
    "permitrootlogin yes",
    'Permit"RootLogin" yes',
    '"PermitRootLogin" yes',
    "=PermitRootLogin yes",
    " = PermitRootLogin yes",
    "\t=\tPermitRootLogin\tyes",
    '="PermitRootLogin" yes',
    "PermitRootLogin=yes",
    "PermitRootLogin = yes",
    "PermitRootLogin == yes",
    "==PermitRootLogin yes",
    "= =PermitRootLogin yes",
    'Permit"Root"Login yes',
    'PermitRootLogin"" yes',
    '""PermitRootLogin yes',
    'Permit"RootLogin yes',
    "PermitRootLogin\ryes",
    "\rPermitRootLogin yes",
    "\fPermitRootLogin yes",
    "PermitRootLogin yes\f",
    "\vPermitRootLogin yes",
    "PermitRootLogin\vyes",
    "#PermitRootLogin yes",
    " #PermitRootLogin yes",
    '"#PermitRootLogin" yes',
    '"" PermitRootLogin yes',
    'PermitRootLogin "yes"',
    "PermitRootLogin yes # site",
    "PermitRootLogin #yes",
    "PermitRootLogin",
    "PermitRootLogin \t",
    "DSAAuthentication no",
    "dsaAuthentication=no",
    'DSA"Authentication" no',
    "PubkeyAuthentication no",
    "Permit\x00RootLogin yes",
)
MATCHES: Final[tuple[str, ...]] = (
    "Match User freesecdev-probe",
    "match user freesecdev-probe",
    'Ma"tch" User freesecdev-probe',
    '="Match" User freesecdev-probe',
    "=Match User freesecdev-probe",
    '"Match" User freesecdev-probe',
    "Match=User freesecdev-probe",
    "\tMatch\tUser\tfreesecdev-probe",
    "\rMatch User freesecdev-probe",
    "#Match User freesecdev-probe",
    'Match User "freesecdev-probe"',
)

Case = dict[str, str]


def build_cases() -> list[Case]:
    """Return every case: settings alone, in a ``Match`` block, and every ``Match`` line form.

    The fuzz cases put each of :data:`INSERTS` at each position of ``PermitRootLogin``, alone and
    inside a ``Match`` block.
    """
    cases: list[Case] = []
    fuzzed = [
        NAME[:index] + insert + NAME[index:] + " yes"
        for insert in INSERTS
        for index in range(len(NAME) + 1)
    ]
    for number, line in enumerate((*SETTINGS, *fuzzed)):
        cases.append({"name": f"global-{number:03d}", "text": line + "\n"})
        cases.append({"name": f"match-{number:03d}", "text": MATCHES[0] + "\n" + line + "\n"})
    for number, line in enumerate(MATCHES):
        cases.append({"name": f"header-{number:03d}", "text": line + "\nPermitRootLogin yes\n"})
        cases.append(
            {"name": f"header-alias-{number:03d}", "text": line + "\nDSAAuthentication no\n"}
        )
    return cases


def _matches(arguments: object, user: str) -> bool | None:
    """Return whether a ``Match`` line of the cases matches ``user``, ``None`` when unknown."""
    if not isinstance(arguments, list) or len(cast("list[object]", arguments)) != MATCH_ARGUMENTS:
        return None
    criterion, name = (str(item) for item in cast("list[object]", arguments))
    if criterion.lower() != "user":
        return None
    return name == user


def predict(text: str, user: str) -> dict[str, str]:
    """Return what the lexer of the collection predicts that sshd reads for ``user``.

    The prediction is :data:`UNKNOWN` where the collection refuses (a text that it cannot read
    exactly, a value or a ``Match`` line that it does not read), and :data:`ERROR` where sshd
    refuses the line.
    """
    read = sshd_config.read_lines(text)
    if not read["exact"]:
        return dict.fromkeys(KEYWORDS, UNKNOWN)
    found: dict[str, str] = {}
    active: bool | None = True
    for line in cast("list[dict[str, object]]", read["lines"]):
        keyword = line["keyword"]
        if line["error"]:
            return dict.fromkeys(KEYWORDS, ERROR)
        if keyword == "match":
            active = _matches(line["arguments"], user)
            continue
        if keyword not in KEYWORDS or keyword in found or active is False:
            continue
        value = line["value"]
        found[str(keyword)] = UNKNOWN if active is None or not isinstance(value, str) else value
    return {keyword: found.get(keyword, DEFAULTS[keyword]) for keyword in KEYWORDS}


def prepare(cases: Path, directory: Path) -> None:
    """Write the cases to ``cases`` and one configuration file per case to ``directory``."""
    built = build_cases()
    cases.parent.mkdir(parents=True, exist_ok=True)
    cases.write_text(json.dumps({"cases": built}, indent=1) + "\n", encoding="utf-8")
    directory.mkdir(parents=True, exist_ok=True)
    for case in built:
        (directory / f"{case['name']}.conf").write_bytes(case["text"].encode("utf-8"))


def read_probe(path: Path) -> tuple[str, dict[str, list[list[str]]]]:
    """Return the sshd version and the readings of one probe output, keyed by case."""
    version = ""
    readings: dict[str, list[list[str]]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if fields[0] == "#sshd":
            version = " ".join(fields[1].split())
            continue
        readings.setdefault(fields[0], []).append(fields[2:])
    return version, readings


def merge(directory: Path, table: Path) -> None:
    """Write the table from the probe outputs of both images in ``directory``."""
    probes = {platform: read_probe(directory / f"{platform}.tsv") for platform in PLATFORMS}
    names = sorted(probes[PLATFORMS[0]][1])
    lines = [
        "{",
        f' "readers": {json.dumps({p: probes[p][0] for p in PLATFORMS}, sort_keys=True)},',
        f' "users": {json.dumps(list(USERS))},',
        f' "keywords": {json.dumps(["status", *KEYWORDS])},',
        ' "verdicts": {',
        ",\n".join(
            f"  {json.dumps(name)}: " + json.dumps([probes[p][1][name] for p in PLATFORMS])
            for name in names
        ),
        " }",
        "}",
    ]
    table.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(arguments: Sequence[str] | None = None) -> int:
    """Run ``prepare <cases> <directory>`` or ``merge <directory> <table>``."""
    parser = argparse.ArgumentParser(description="Record what sshd reads (FREES-200).")
    commands = parser.add_subparsers(dest="command", required=True)
    prepared = commands.add_parser("prepare")
    prepared.add_argument("cases", type=Path)
    prepared.add_argument("directory", type=Path)
    merged = commands.add_parser("merge")
    merged.add_argument("directory", type=Path)
    merged.add_argument("table", type=Path)
    options = parser.parse_args(arguments)
    if options.command == "prepare":
        prepare(options.cases, options.directory)
    else:
        merge(options.directory, options.table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
