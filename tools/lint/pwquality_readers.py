"""Record what libpwquality reads, the oracle of the pwquality family (FREES-200).

The ``pwquality`` family of the remediate role decides every rule with the reader of
``plugins/module_utils/compliance/pwquality.py``, which reproduces ``pwquality_read_config`` of
libpwquality and the argument handling of ``pam_pwquality``. What the real library reads is kept
in ``tests/fixtures/pwquality_readers/verdicts.json``, produced in this repository's Molecule
images and never by an emulation, and ``tests/unit/tools/test_pwquality_verdicts.py``
checks the reader and every decision against it.

Regenerate the table with ``bash tools/lint/pwquality_readers.sh UBUNTU_IMAGE ROCKY_IMAGE``. That
script runs ``prepare`` here, which decides every case of ``tests/fixtures/pwquality_readers/
cases.json`` for every rule of :data:`RULES` with both methods and writes each file state (every
case, and every state that an applied rule leaves) to ``states.json``; then
``tools/lint/pwquality_readers_probe.py`` in throwaway containers of both images with
``--network none``; and ``merge`` here, which writes the table.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pwquality,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

MAIN: Final[str] = "/etc/security/pwquality.conf"
DIRECTORY: Final[str] = "/etc/security/pwquality.conf.d"
RULES: Final[tuple[tuple[str, str], ...]] = (
    ("minlen", "14"),
    ("minclass", "4"),
    ("retry", "3"),
    ("enforce_for_root", ""),
    ("enforcing", "1"),
)
METHODS: Final[tuple[str, ...]] = ("main_file", "dropin")
PLATFORMS: Final[tuple[str, ...]] = ("ubuntu", "rocky")
STATES: Final[str] = "states.json"
DECISIONS: Final[str] = "decisions.json"
PAM_MODULE: Final[str] = "pam_pwquality.so"
SETTINGS: Final[tuple[str, ...]] = (
    "difok",
    "minlen",
    "dcredit",
    "ucredit",
    "lcredit",
    "ocredit",
    "minclass",
    "maxrepeat",
    "maxclassrepeat",
    "gecoscheck",
    "maxsequence",
    "dictcheck",
    "usercheck",
    "enforcing",
    "retry",
    "enforce_for_root",
    "local_users_only",
)
KEY_DIGITS: Final[int] = 16
COMPACT: Final[tuple[str, str]] = (",", ":")
DECISION_FIELDS: Final[tuple[str, ...]] = ("case", "setting", "method", "status", "state", "after")

Case = dict[str, object]
State = dict[str, object]


def encode(text: str) -> str:
    """Return the base64 of the bytes that ``text`` stands for."""
    return base64.b64encode(pwquality.text_bytes(text)).decode("ascii")


def rule_of(setting: str, value: str, method: str) -> pwquality.Rule:
    """Return the rule of the role for ``setting``, as the family file composes it."""
    dropin = f"{DIRECTORY}/50-freesecdev-{setting.replace('_', '-')}.conf"
    line = setting if not value else f"{setting} = {value}"
    content = (
        f"# Managed by freesecdev.linux_compliance for {setting}.\n"
        "# Switching the rule or the pwquality topic off removes this file.\n"
        f"{line}\n"
    )
    return pwquality.Rule(setting, value, method, MAIN, dropin, content)


def dropins_of(case: Mapping[str, object]) -> list[dict[str, object]]:
    """Return the drop-in entries of a case as the role passes them to the decision."""
    entries: list[dict[str, object]] = []
    for entry in cast("Sequence[Mapping[str, str]]", case.get("dropins", [])):
        kind = entry["type"]
        entries.append(
            {
                "path": f"{DIRECTORY}/{entry['name']}",
                "type": "link" if kind == "dangling" else kind,
                "content": entry.get("content") if kind == "file" else None,
            }
        )
    return entries


def pam_of(case: Mapping[str, object]) -> list[tuple[str, str]]:
    """Return the PAM files of a case."""
    text = case.get("pam")
    return [("/etc/pam.d/frees200", text)] if isinstance(text, str) else []


def arguments_of(case: Mapping[str, object]) -> list[str]:
    """Return the arguments that PAM passes to pam_pwquality for the one line of the case.

    The PAM lines of the cases are simple: one line, words separated by spaces, no brackets and
    no continuation, so the words after the module are exactly what PAM passes.
    """
    text = case.get("pam")
    if not isinstance(text, str):
        return []
    found: list[str] = []
    for line in text.split("\n"):
        words = line.split()
        if not words or words[0].startswith("#"):
            continue
        modules = [index for index, word in enumerate(words) if word.endswith(PAM_MODULE)]
        if modules:
            found.extend(encode(word) for word in words[modules[0] + 1 :])
    return found


def state_of(
    main: str | None,
    dropins: Sequence[Mapping[str, object]],
    arguments: Sequence[str],
    directory: str = pwquality.DIRECTORY,
) -> State:
    """Return a file state as the probe installs it; a linked directory is named in the state."""
    state: State = {
        "main": None if main is None else encode(main),
        "dropins": [dict(entry) for entry in dropins],
        "arguments": list(arguments),
    }
    return state if directory == pwquality.DIRECTORY else state | {"directory": directory}


def state_key(state: State) -> str:
    """Return the first 16 hex digits of the SHA-256 that name a state in the table."""
    canonical = json.dumps(state, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()[:KEY_DIGITS]


def keep(states: dict[str, State], state: State) -> str:
    """Add ``state`` to ``states`` under its key and return the key; two states never share one."""
    key = state_key(state)
    if states.setdefault(key, state) != state:
        message = f"two states share the key {key}"
        raise ValueError(message)
    return key


def probe_dropins(case: Mapping[str, object]) -> list[dict[str, object]]:
    """Return the drop-ins of a case as the probe installs them, with base64 contents."""
    entries: list[dict[str, object]] = []
    for entry in cast("Sequence[Mapping[str, str]]", case.get("dropins", [])):
        installed: dict[str, object] = {"name": entry["name"], "type": entry["type"]}
        if entry["type"] in ("file", "link"):
            installed["content"] = encode(entry.get("content", ""))
        entries.append(installed)
    return entries


def after_dropins(case: Mapping[str, object], rule: pwquality.Rule) -> list[dict[str, object]]:
    """Return the drop-ins after the rule wrote its own drop-in."""
    name = rule.dropin.rsplit("/", 1)[-1]
    kept = [entry for entry in probe_dropins(case) if entry["name"] != name]
    return [*kept, {"name": name, "type": "file", "content": encode(rule.content)}]


def decide_case(
    case: Mapping[str, object], rule: pwquality.Rule
) -> tuple[dict[str, object], State, State | None]:
    """Return the decision of a rule for a case, the state of the case and the state after it."""
    main = cast("str | None", case.get("main"))
    directory = str(case.get("directory", pwquality.DIRECTORY))
    decision = pwquality.decide(rule, dropins_of(case), main, pam_of(case), directory)
    arguments = arguments_of(case)
    before = state_of(main, probe_dropins(case), arguments, directory)
    if decision["status"] != "applied":
        return decision, before, None
    if rule.method == "dropin":
        return decision, before, state_of(main, after_dropins(case, rule), arguments, directory)
    text = cast("str", decision["text"])
    return decision, before, state_of(text, probe_dropins(case), arguments, directory)


def prepare(cases: Path, output: Path) -> None:
    """Write every state that the table needs and every decision of the role."""
    output.mkdir(parents=True, exist_ok=True)
    states: dict[str, State] = {}
    decisions: list[dict[str, object]] = []
    for case in cast("list[Case]", json.loads(cases.read_text(encoding="utf-8"))["cases"]):
        for setting, value in RULES:
            for method in METHODS:
                decision, before, after = decide_case(case, rule_of(setting, value, method))
                keep(states, before)
                if after is not None:
                    keep(states, after)
                decisions.append(
                    {
                        "case": case["name"],
                        "setting": setting,
                        "method": method,
                        "status": decision["status"],
                        "state": state_key(before),
                        "after": None if after is None else state_key(after),
                    }
                )
    (output / STATES).write_text(
        json.dumps(states, sort_keys=True, indent=1) + "\n", encoding="utf-8"
    )
    (output / DECISIONS).write_text(json.dumps(decisions, indent=1) + "\n", encoding="utf-8")


def merge(directory: Path, table: Path) -> None:
    """Write the table from the decisions and the readings of both images in ``directory``."""
    readings = {
        platform: cast(
            "dict[str, object]",
            json.loads((directory / f"{platform}.json").read_text(encoding="utf-8")),
        )
        for platform in PLATFORMS
    }
    versions = {
        platform: " ".join((directory / f"{platform}.version").read_text(encoding="utf-8").split())
        for platform in PLATFORMS
    }
    states = cast("dict[str, object]", json.loads((directory / STATES).read_text(encoding="utf-8")))
    decisions = cast(
        "list[dict[str, object]]", json.loads((directory / DECISIONS).read_text(encoding="utf-8"))
    )
    lines = [
        "{",
        f' "readers": {json.dumps(versions, sort_keys=True)},',
        f' "settings": {json.dumps(list(SETTINGS))},',
        ' "verdicts": {',
        ",\n".join(
            f"  {json.dumps(key)}: "
            + json.dumps([readings[platform][key] for platform in PLATFORMS], separators=COMPACT)
            for key in sorted(states)
        ),
        " },",
        ' "decisions": [',
        ",\n".join(
            "  " + json.dumps([decision[field] for field in DECISION_FIELDS], separators=COMPACT)
            for decision in decisions
        ),
        " ]",
        "}",
    ]
    table.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(arguments: Sequence[str] | None = None) -> int:
    """Run ``prepare <cases> <directory>`` or ``merge <directory> <table>``."""
    parser = argparse.ArgumentParser(description="Record what libpwquality reads (FREES-200).")
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
