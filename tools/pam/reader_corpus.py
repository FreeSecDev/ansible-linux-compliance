"""Build the cases of the linux-pam reader verdict table and assemble the table (ADR 0027).

The faillock and pwhistory families decide every setting with the filter
``freesecdev.linux_compliance.pam_conf_decision``, which models how pam_faillock and
pam_pwhistory read their configuration files and their module arguments. The model is only as
good as its agreement with the real readers, so ``tools/pam/generate-reader-verdicts.sh`` runs
the readers that the Molecule images install against every case of this corpus and the table
``tests/fixtures/pam_conf/reader_verdicts.json`` records what they read.

``cases`` writes one directory per case below ``--out``: the file text (``conf``), the reader
and the module arguments (``args``, one per line, ``@conf`` standing for the case's file). The
corpus holds the base cases below and, for every base case and rule whose decision is
``applied``, the file that the family would leave behind (the line written with the
``lineinfile`` semantics of the family), so the table also records what pam reads after the
change. ``assemble`` joins the outputs of every image into the table.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.filter import pam_conf

if TYPE_CHECKING:
    from collections.abc import Sequence

TABLE: Final[Path] = Path("tests/fixtures/pam_conf/reader_verdicts.json")
SCHEMA_VERSION: Final[int] = 1
STACK_PATHS: Final[dict[str, str]] = {
    "faillock": "/etc/pam.d/common-auth",
    "pwhistory": "/etc/pam.d/system-auth",
}
RULES: Final[dict[str, tuple[tuple[str, str, str], ...]]] = {
    "faillock": (
        ("deny", "at_most", "3"),
        ("deny", "at_most", "4"),
        ("unlock_time", "at_least", "0"),
        ("unlock_time", "at_least", "900"),
        ("fail_interval", "at_least", "900"),
        ("root_unlock_time", "at_least", "60"),
        ("even_deny_root", "present", ""),
        ("audit", "present", ""),
        ("silent", "present", ""),
    ),
    "pwhistory": (
        ("remember", "at_least", "4"),
        ("remember", "at_least", "24"),
        ("enforce_for_root", "present", ""),
    ),
}
READING_KEYS: Final[dict[str, tuple[str, ...]]] = {
    "faillock": (
        "rv",
        "deny",
        "fail_interval",
        "unlock_time",
        "root_unlock_time",
        "even_deny_root",
        "audit",
        "silent",
    ),
    "pwhistory": ("remember", "enforce_for_root"),
}
UNCHECKED_STACK: Final[frozenset[tuple[str, str]]] = frozenset({("pwhistory", "enforce_for_root")})


@dataclass(frozen=True)
class Case:
    """One file and the module arguments that a reader reads, with the PAM line that passes them."""

    case_id: str
    reader: str
    text: str
    args: tuple[str, ...] = ()
    stack: str = ""


FAILLOCK_TEXTS: Final[dict[str, str]] = {
    "empty": "",
    "comments": "# deny = 3\n# unlock_time = 600\n",
    "deny-3": "deny = 3\n",
    "deny-4": "deny = 4\n",
    "deny-4-tight": "deny=4\n",
    "deny-4-tabs": "  deny\t=\t4\n",
    "deny-04": "deny = 04\n",
    "deny-4-comment": "deny = 4 # site\n",
    "deny-4x": "deny = 4x\n",
    "deny-plus-4": "deny = +4\n",
    "deny-minus-1": "deny = -1\n",
    "deny-65539": "deny = 65539\n",
    "deny-0": "deny = 0\n",
    "deny-empty": "deny =\n",
    "deny-bare": "deny\n",
    "deny-huge": "deny = 99999999999999999999999\n",
    "deny-double-equals": "deny == 3\n",
    "deny-two-values": "deny = 3 10\n",
    "deny-cr": "deny = 3\r\n",
    "deny-hash": "deny#3\n",
    "deny-upper": "DENY = 1\n",
    "deny-3-then-10": "deny = 3\ndeny = 10\n",
    "deny-10-then-3": "deny = 10\ndeny = 3\n",
    "vt-lead": "\x0bdeny = 10\n",
    "vt-lead-later": "deny = 3\n\x0bdeny = 10\n",
    "ff-lead-later": "deny = 3\n\x0cdeny=10\n",
    "cr-lead-later": "deny = 3\n\rdeny = 10\n",
    "vt-after-key-later": "deny = 3\ndeny\x0b= 10\n",
    "unlock-900": "unlock_time = 900\n",
    "unlock-1000000": "unlock_time = 1000000\n",
    "unlock-01000000-comment": "unlock_time = 01000000 # site\n",
    "unlock-604800": "unlock_time = 604800\n",
    "unlock-604801": "unlock_time = 604801\n",
    "unlock-0": "unlock_time = 0\n",
    "unlock-never": "unlock_time = never\n",
    "unlock-never-comment": "unlock_time = never # site\n",
    "unlock-600": "unlock_time = 600\n",
    "unlock-minus-1": "unlock_time = -1\n",
    "unlock-4294967296": "unlock_time = 4294967296\n",
    "interval-900": "fail_interval = 900\n",
    "interval-999999999": "fail_interval = 999999999\n",
    "interval-0": "fail_interval = 0\n",
    "interval-604800": "fail_interval = 604800\n",
    "root-60": "root_unlock_time = 60\n",
    "root-never": "root_unlock_time = never\n",
    "root-unset-unlock-900": "unlock_time = 900\n",
    "audit": "audit\n",
    "audit-no": "audit = no\n",
    "audit-indented": "  audit\n",
    "audit-vt": "\x0baudit\n",
    "audit-upper": "AUDIT\n",
    "silent": "silent\n",
    "even-deny-root": "even_deny_root\n",
    "long-1022": "deny = 3 #" + "x" * 1012 + "\n",
    "long-1023": "deny = 3 #" + "x" * 1013 + "\n",
    "nul-middle": "deny = 10\0\ndeny = 3\n",
    "nul-last": "deny = 3\ndeny = 10\0",
    "unterminated": "deny = 3",
    "unterminated-long": "deny = 3 #" + "x" * 1013,
}
PWHISTORY_TEXTS: Final[dict[str, str]] = {
    "empty": "",
    "comment": "# remember = 10\n",
    "remember-24": "remember = 24\n",
    "remember-24-tight": "remember=24\n",
    "remember-024": "remember = 024\n",
    "remember-24-comment": "remember = 24 # site\n",
    "remember-upper-1": "REMEMBER = 1\n",
    "remember-mixed-1": "Remember=1\n",
    "remember-vt-1": "\x0bremember = 1\n",
    "remember-ff-1-then-24": "\x0cremember=1\nremember = 24\n",
    "remember-1-then-24": "remember = 1\nremember = 24\n",
    "remember-24-then-1": "remember = 24\nremember = 1\n",
    "remember-minus-1": "remember = -1\n",
    "remember-4294967295": "remember = 4294967295\n",
    "remember-vt-after-key": "remember\x0b= 24\n",
    "remember-hash": "remember # site\n",
    "remember-double-equals": "remember==24\n",
    "remember-cr": "remember = 24\r\n",
    "remember-x": "remember = x\n",
    "remember-nul": "remember = 24\0x\n",
    "enforce": "enforce_for_root\n",
    "enforce-upper": "ENFORCE_FOR_ROOT\n",
    "enforce-0": "enforce_for_root = 0\n",
    "enforce-vt": "\x0benforce_for_root\n",
}
FAILLOCK_STACKS: Final[tuple[tuple[str, str, tuple[str, ...]], ...]] = (
    ("stack-deny", "auth required pam_faillock.so authfail deny=10\n", ("authfail", "deny=10")),
    (
        "stack-upper-type",
        "AUTH required pam_faillock.so authfail deny=10\n",
        ("authfail", "deny=10"),
    ),
    (
        "stack-continuation",
        "auth required pam_faillock.so authfail \\\n    deny=10\n",
        ("authfail", "deny=10"),
    ),
    (
        "stack-continuation-blank",
        "auth required pam_faillock.so authfail \\\n\n    deny=10\n",
        ("authfail", "deny=10"),
    ),
    (
        "stack-silent-type",
        "-auth required /usr/lib64/security/pam_faillock.so deny=10\n",
        ("deny=10",),
    ),
    (
        "stack-bracket-control",
        "auth [success=1 default=die] pam_faillock.so authfail unlock_time=60\n",
        ("authfail", "unlock_time=60"),
    ),
    ("stack-bracket-arg", "auth required pam_faillock.so [deny=10]\n", ("deny=10",)),
    (
        "stack-conf",
        "auth required pam_faillock.so preauth conf=/dev/null\n",
        ("preauth", "conf=/dev/null"),
    ),
    (
        "stack-root-unlock",
        "auth required pam_faillock.so authfail root_unlock_time=5\n",
        ("authfail", "root_unlock_time=5"),
    ),
    (
        "stack-even-deny-root",
        "auth required pam_faillock.so preauth even_deny_root\n",
        ("preauth", "even_deny_root"),
    ),
    ("stack-account", "account required pam_faillock.so\n", ()),
    ("stack-comment", "auth required pam_faillock.so preauth # deny=10\n", ("preauth",)),
)
PWHISTORY_STACKS: Final[tuple[tuple[str, str, tuple[str, ...]], ...]] = (
    (
        "stack-remember",
        "password requisite pam_pwhistory.so remember=1 use_authtok\n",
        ("remember=1", "use_authtok"),
    ),
    ("stack-remember-upper", "password requisite pam_pwhistory.so REMEMBER=1\n", ("REMEMBER=1",)),
    ("stack-upper-type", "PASSWORD requisite pam_pwhistory.so remember=1\n", ("remember=1",)),
    (
        "stack-continuation",
        "password requisite pam_pwhistory.so \\\n  remember=1\n",
        ("remember=1",),
    ),
    ("stack-conf", "password requisite pam_pwhistory.so conf=/dev/null\n", ("conf=/dev/null",)),
    (
        "stack-enforce",
        "password requisite pam_pwhistory.so enforce_for_root\n",
        ("enforce_for_root",),
    ),
    ("stack-plain", "password requisite pam_pwhistory.so use_authtok\n", ("use_authtok",)),
)
STACK_FILES: Final[dict[str, str]] = {
    "faillock": "deny = 3\nunlock_time = 900\n",
    "pwhistory": "remember = 24\n",
}


FUZZ_LEADS: Final[tuple[str, ...]] = ("", " ", "\t", "\x0b", "\x0c", "\r", " \x0b")
FUZZ_SEPARATORS: Final[tuple[str, ...]] = (" = ", "=", "\t=\t", " ", "==", "\x0b= ", " =\x0c")
FUZZ_TRAILS: Final[tuple[str, ...]] = ("", " # site", "\r", "  ", "\x0b", "#")
FUZZ_KEYS: Final[dict[str, tuple[str, ...]]] = {
    "faillock": (
        "deny",
        "DENY",
        "unlock_time",
        "Unlock_Time",
        "fail_interval",
        "root_unlock_time",
        "audit",
    ),
    "pwhistory": ("remember", "REMEMBER", "Remember", "enforce_for_root", "Enforce_For_Root"),
}
FUZZ_VALUES: Final[tuple[str, ...]] = (
    "3",
    "04",
    "10",
    "-1",
    "never",
    "0",
    "1000000",
    "604800",
    "24",
    "x",
    "",
)
FUZZ_STRIDE: Final[int] = 97
FUZZ_COUNT: Final[int] = 80


def fuzz_texts(reader: str) -> list[str]:
    """Return deterministic two-line files built from the lexical corner cases of the readers.

    Every line takes a lead, a key, a separator, a value and a trail; the files walk the product
    of these with a fixed stride, so they mix forms that pam reads and forms that it does not.
    """
    lines = [
        lead + key + separator + value + trail
        for lead in FUZZ_LEADS
        for key in FUZZ_KEYS[reader]
        for separator in FUZZ_SEPARATORS
        for value in FUZZ_VALUES
        for trail in FUZZ_TRAILS
    ]
    texts: list[str] = []
    for index in range(FUZZ_COUNT):
        first = lines[(index * FUZZ_STRIDE) % len(lines)]
        second = lines[(index * FUZZ_STRIDE * 7 + 13) % len(lines)]
        texts.append(f"{first}\n" if index % 3 == 0 else f"{first}\n{second}\n")
    return texts


def base_cases() -> list[Case]:
    """Return the base cases: every file text alone and every stack line over a typical file."""
    found = [Case(f"faillock-{key}", "faillock", text) for key, text in FAILLOCK_TEXTS.items()]
    found += [Case(f"pwhistory-{key}", "pwhistory", text) for key, text in PWHISTORY_TEXTS.items()]
    for reader in ("faillock", "pwhistory"):
        found += [
            Case(f"{reader}-fuzz-{index:03d}", reader, text)
            for index, text in enumerate(fuzz_texts(reader))
        ]
    for reader, stacks in (("faillock", FAILLOCK_STACKS), ("pwhistory", PWHISTORY_STACKS)):
        found += [
            Case(f"{reader}-{key}", reader, STACK_FILES[reader], args, stack)
            for key, stack, args in stacks
        ]
    return found


def stack_of(case: Case) -> dict[str, str]:
    """Return the PAM service files of a case."""
    return {STACK_PATHS[case.reader]: case.stack} if case.stack else {}


def lineinfile(text: str, setting: str, line: str) -> str:
    """Return the text after ``ansible.builtin.lineinfile`` with the family's regexp and line."""
    lines = text.splitlines(keepends=True)
    pattern = rf"^[ \t]*{setting}(?:[ \t=]|$)"
    matches = [index for index, value in enumerate(lines) if re.search(pattern, value)]
    if matches:
        lines[matches[-1]] = line + "\n"
        return "".join(lines)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    return "".join(lines) + line + "\n"


def decide(case: Case, rule: tuple[str, str, str]) -> dict[str, object]:
    """Return the family's decision for one rule of the case."""
    setting, comparison, required = rule
    checked = (case.reader, setting) not in UNCHECKED_STACK
    rule_map = {
        "reader": case.reader,
        "setting": setting,
        "comparison": comparison,
        "required": required,
        "stack_checked": checked,
    }
    return pam_conf.pam_conf_decision(case.text, rule_map, stack_of(case))


def after_id(case: Case, rule: tuple[str, str, str]) -> str:
    """Return the identifier of the case that holds the file after the rule was applied."""
    return f"{case.case_id}--{rule[0]}-{rule[2] or 'flag'}"


def key_of(case: Case) -> tuple[str, str, tuple[str, ...], str]:
    """Return what the readers read of a case: its reader, its text, its arguments and its stack."""
    return (case.reader, case.text, case.args, case.stack)


def after_case(case: Case, rule: tuple[str, str, str]) -> Case | None:
    """Return the case that holds the file after an applied rule, or None when it is not applied."""
    decision = decide(case, rule)
    if decision["status"] != "applied":
        return None
    text = lineinfile(case.text, rule[0], str(decision["line"]))
    return Case(after_id(case, rule), case.reader, text, case.args, case.stack)


def all_cases() -> list[Case]:
    """Return the base cases and the files that applied rules leave behind, each file once."""
    found = base_cases()
    seen = {key_of(case) for case in found}
    for case in list(found):
        for rule in RULES[case.reader]:
            after = after_case(case, rule)
            if after is not None and key_of(after) not in seen:
                seen.add(key_of(after))
                found.append(after)
    return found


def write_cases(directory: Path) -> int:
    """Write every case below ``directory`` and return how many there are."""
    cases = all_cases()
    directory.mkdir(parents=True, exist_ok=False)
    for case in cases:
        folder = directory / case.case_id
        folder.mkdir()
        (folder / "conf").write_bytes(case.text.encode("utf-8"))
        (folder / "reader").write_text(case.reader + "\n", encoding="utf-8")
        (folder / "args").write_text(
            "".join(f"{argument}\n" for argument in ("conf=@conf", *case.args)), encoding="utf-8"
        )
    return len(cases)


def read_outputs(directory: Path) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, object]]]:
    """Return the platforms and the readings per case of every image output below ``directory``."""
    platforms: dict[str, dict[str, str]] = {}
    readings: dict[str, dict[str, object]] = {}
    for path in sorted(directory.glob("*.jsonl")):
        lines = path.read_text(encoding="utf-8").splitlines()
        header = cast("dict[str, str]", json.loads(lines[0]))
        platform = header["platform"]
        platforms[platform] = {"installed": header["installed"], "source": header["source"]}
        for line in lines[1:]:
            entry = cast("dict[str, object]", json.loads(line))
            readings.setdefault(str(entry["id"]), {})[platform] = entry["reading"]
    return platforms, readings


def assemble(outputs: Path, table: Path) -> int:
    """Write the verdict table from the image outputs and return the number of cases."""
    platforms, readings = read_outputs(outputs)
    cases = all_cases()
    missing = [
        case.case_id for case in cases if set(readings.get(case.case_id, {})) != set(platforms)
    ]
    if not platforms or missing:
        message = f"the image outputs miss readings for {missing[:5]} or every platform"
        raise SystemExit(message)
    header = {
        "schema_version": SCHEMA_VERSION,
        "generator": "tools/pam/generate-reader-verdicts.sh",
        "platforms": platforms,
        "reading_keys": {reader: list(keys) for reader, keys in READING_KEYS.items()},
    }
    rows = [
        json.dumps(
            {
                "id": case.case_id,
                "reader": case.reader,
                "text": case.text,
                "args": list(case.args),
                "stack": case.stack,
                "readings": {
                    platform: [
                        cast("dict[str, object]", reading)[key] for key in READING_KEYS[case.reader]
                    ]
                    for platform, reading in sorted(readings[case.case_id].items())
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        for case in cases
    ]
    opening = json.dumps(header, sort_keys=True, separators=(",", ":"))[:-1]
    table.parent.mkdir(parents=True, exist_ok=True)
    table.write_text(opening + ',"cases":[\n' + ",\n".join(rows) + "\n]}\n", encoding="utf-8")
    return len(cases)


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``cases`` or ``assemble``."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    cases = commands.add_parser("cases")
    cases.add_argument("--out", type=Path, required=True)
    joined = commands.add_parser("assemble")
    joined.add_argument("--outputs", type=Path, required=True)
    joined.add_argument("--table", type=Path, default=TABLE)
    arguments = parser.parse_args(argv)
    if arguments.command == "cases":
        count = write_cases(arguments.out)
    else:
        count = assemble(arguments.outputs, arguments.table)
    sys.stdout.write(f"{arguments.command}: {count} cases\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
