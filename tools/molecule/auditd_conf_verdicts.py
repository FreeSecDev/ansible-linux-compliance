"""Write the auditd.conf cases and build the verdict table of the real auditd (FREES-110).

The remediate role decides what ``/etc/audit/auditd.conf`` sets with
``plugins/module_utils/compliance/auditconf.py``, and that reader must decide exactly as auditd
does. auditd has no option that prints its configuration, but with ``-f`` it writes every value
its parser reads to standard error (``<keyword>_parser called with: <value>``) and then either
refuses the file (exit status 6, before it opens anything) or goes on to start, which fails in a
container without the audit capability. ``tools/molecule/auditd-conf-verdicts.sh`` runs the
auditd of each Molecule image that way on every case, in a container without network and
capabilities, and this module writes the cases and turns the output into the table
``tests/fixtures/auditd_conf/verdicts.json``:

* ``python -m tools.molecule.auditd_conf_verdicts cases --base FILE --output DIR`` writes one file
  per case, the image's own ``auditd.conf`` changed as the case says.
* ``python -m tools.molecule.auditd_conf_verdicts table --platform P --results DIR ...`` reads the
  output of each case and records, for that platform, whether auditd accepted the file, refused
  it or neither could be told, and which values it read, together with the auditd package
  version, the image tag, the size of the log's file system and the file as built, from which
  the cases are written again (the table keeps only how each case differs, so it stays small). A
  unit test fails when the package version pinned in the image differs from the version of the
  table.

Nothing here runs a process or a container.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditconf,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
TABLE: Final[Path] = REPO_ROOT / "tests" / "fixtures" / "auditd_conf" / "verdicts.json"
CASE_SUFFIX: Final[str] = ".conf"
AS_BUILT: Final[str] = "as_built"
REFUSED_STATUS: Final[int] = 6
STARTED_MARKERS: Final[tuple[str, ...]] = (
    "Cannot change priority",
    "You must be root or have capabilities to run this program",
)
PARSER_LINE: Final[re.Pattern[str]] = re.compile(r"([a-z0-9_]+)_parser called with: (.*)")
NOTICE: Final[re.Pattern[str]] = re.compile(
    r"Config file .* opened for parsing|Listener support is not enabled, ignoring value at line \d+"
    r"|GSSAPI support is not enabled, ignoring value at line \d+"
    r"|The (dispatcher|disp_qos) option is deprecated - line \d+"
    r"|The audit daemon is exiting\."
)
EVENT_STAMP: Final[re.Pattern[str]] = re.compile(r"audit\(\d+\.\d+:\d+\)")
PLATFORM: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]{0,30}")
MAX_OUTPUT: Final[int] = 64 * 1024
NUMBER_SAMPLES: Final[tuple[str, ...]] = (
    "0",
    "1",
    "50",
    "999",
    "1000",
    "65535",
    "65536",
    "100000",
    "999999999",
    "1000000000",
    "abc",
    "-1",
    "1.5",
)
PATTERN_SAMPLES: Final[dict[str, tuple[str, ...]]] = {
    auditconf.PATH: ("/var/log/audit/audit.log", "relative/path", "/a b"),
    auditconf.NAME: ("root", "adm", "nosuchgroupxyz", "a#b"),
    auditconf.SPACE: ("25%", "100%", "101%", "80", "0%", "x%", "99%"),
    auditconf.ANY: ("x", "/etc/audit/audit.key", "lossy", "a,b;c"),
    auditconf.PORTS: ("60", "1-1023", "0", "65536", "10-5", "a-b", "1-", "70000-70001"),
}


def without(text: str, keyword: str) -> str:
    """Return ``text`` without the lines that set ``keyword`` (in any case)."""
    pattern = re.compile(rf" *{re.escape(keyword)} +=", re.IGNORECASE)
    return "".join(line for line in text.splitlines(keepends=True) if not pattern.match(line))


def setting(text: str, keyword: str, value: str) -> str:
    """Return ``text`` with ``keyword`` set to ``value`` on one line at its end."""
    return without(text, keyword) + f"{keyword} = {value}\n"


def structural(base: str) -> dict[str, str]:
    """Return the cases of the line forms, each the whole file as text."""
    space = without(without(base, "space_left"), "admin_space_left")
    return {
        AS_BUILT: base,
        "duplicate_last_wins": setting(base, "space_left", "80") + "space_left = 90\n",
        "duplicate_decides_the_check": space
        + "space_left = 40\nadmin_space_left = 60\nspace_left = 90\n",
        "keyword_in_capitals": without(base, "space_left") + "SPACE_LEFT = 80\n",
        "no_spaces_around_equals": without(base, "space_left") + "space_left=80\n",
        "tabs_around_equals": without(base, "space_left") + "space_left\t=\t80\n",
        "leading_spaces": without(base, "space_left") + "   space_left = 80\n",
        "leading_tab": without(base, "space_left") + "\tspace_left = 80\n",
        "repeated_spaces": without(base, "space_left") + "space_left  =  80\n",
        "trailing_spaces": without(base, "space_left") + "space_left = 80   \n",
        "carriage_return": without(base, "space_left") + "space_left = 80\r\n",
        "vertical_tab": without(base, "space_left") + "space_left = 80\v\n",
        "form_feed": without(base, "space_left") + "space_left = 80\f\n",
        "nul_byte": without(base, "space_left") + "space_left = 8\x000\n",
        "no_final_newline": without(base, "space_left") + "space_left = 80",
        "trailing_comment": without(base, "space_left") + "space_left = 80 # site\n",
        "line_of_158_bytes": base + "action_mail_acct = " + "a" * 139 + "\n",
        "line_of_159_bytes": base + "action_mail_acct = " + "a" * 140 + "\n",
        "long_comment": base + "#" + "x" * 300 + "\n",
        "long_setting_skipped": without(base, "space_left") + "space_left = " + "0" * 150 + "80\n",
        "unknown_keyword": base + "frobnicate = 1\n",
        "empty_value": without(base, "space_left") + "space_left = \n",
        "keyword_only": without(base, "space_left") + "space_left\n",
        "no_equals": without(base, "space_left") + "space_left 80\n",
        "word_for_equals": without(base, "space_left") + "space_left x 80\n",
        "two_equals": without(base, "space_left") + "space_left = = 80\n",
        "extra_value": without(base, "space_left") + "space_left = 80 90\n",
        "continuation": without(base, "space_left") + "space_left = \\\n80\n",
        "indented_comment": base + "   # comment\n",
        "comment_with_carriage_return": base + "# note\r\n",
        "line_of_spaces": base + "    \n",
        "line_of_tab": base + "\t\n",
        "non_ascii_comment": base + "# café\n",
        "exec_action": setting(base, "space_left_action", "exec /usr/bin/true"),
        "leading_zero": setting(base, "space_left", "080"),
        "plus_sign": setting(base, "space_left", "+80"),
        "out_of_range": setting(base, "space_left", "99999999999999999999"),
        "space_left_unset": without(base, "space_left"),
        "admin_space_left_unset": without(base, "admin_space_left"),
        "both_space_unset": space,
        "space_equal_to_admin": space + "space_left = 50\nadmin_space_left = 50\n",
        "space_in_percent_admin_absolute": space + "space_left = 25%\nadmin_space_left = 50\n",
        "space_both_percent": space + "space_left = 30%\nadmin_space_left = 20%\n",
        "freq_unset_incremental": without(base, "freq"),
        "flush_unset_freq_zero": setting(without(base, "flush"), "freq", "0"),
        "freq_zero_incremental": setting(setting(base, "flush", "INCREMENTAL_ASYNC"), "freq", "0"),
        "rotate_without_num_logs": setting(
            without(base, "num_logs"), "max_log_file_action", "ROTATE"
        ),
        "keep_logs_one_log": setting(
            setting(base, "max_log_file_action", "KEEP_LOGS"), "num_logs", "1"
        ),
        "rotate_one_log": setting(setting(base, "max_log_file_action", "ROTATE"), "num_logs", "1"),
        "line_after_nul": base + "# x\x00\nfrobnicate = 1\n",
        "unknown_keyword_padded_to_200": base + "frobnicate = 1" + " " * 186 + "\n",
        "unknown_keyword_without_final_newline": base + "frobnicate = 1",
        "number_ending_in_tab": setting(base, "max_log_file", "8\t"),
        "choice_ending_in_carriage_return": setting(base, "space_left_action", "email\r"),
        "flush_none_freq_unset": setting(without(base, "freq"), "flush", "NONE"),
        "flush_incremental_freq_unset": setting(
            without(base, "freq"), "flush", "INCREMENTAL_ASYNC"
        ),
        "mail_with_local_domain": setting(base, "action_mail_acct", "admin@localhost"),
        "mail_with_dotted_domain": setting(base, "action_mail_acct", "admin@example.com"),
        "mail_with_domain_not_verified": setting(
            setting(base, "verify_email", "no"), "action_mail_acct", "admin@example.com"
        ),
        **files_and_names(base),
        **options(base),
    }


def files_and_names(base: str) -> dict[str, str]:
    """Return the cases of the log file, the mail account and the node name."""
    mail = without(without(base, "action_mail_acct"), "verify_email")
    return {
        "log_group_adm_log_file_in_var_log": setting(
            setting(base, "log_file", "/var/log/audit.log"), "log_group", "adm"
        ),
        "log_group_root_log_file_in_var_log": setting(
            setting(base, "log_file", "/var/log/audit.log"), "log_group", "root"
        ),
        "log_file_in_missing_directory": setting(base, "log_file", "/nonexistent/audit/audit.log"),
        "log_file_in_short_directory": setting(base, "log_file", "/x/audit.log"),
        "log_file_in_var": setting(base, "log_file", "/var/audit.log"),
        "log_file_in_other_directory": setting(base, "log_file", "/var/lib/audit.log"),
        "log_file_is_a_directory": setting(base, "log_file", "/var/log/audit"),
        "mail_of_one_character": setting(base, "action_mail_acct", "x"),
        "mail_of_two_characters": setting(base, "action_mail_acct", "xy"),
        "mail_of_one_character_not_verified": mail + "verify_email = no\naction_mail_acct = x\n",
        "mail_of_one_character_verified_later": mail + "action_mail_acct = x\nverify_email = no\n",
        "name_format_user_without_name": setting(without(base, "name"), "name_format", "user"),
        "name_format_user_with_name": setting(
            setting(base, "name_format", "user"), "name", "auditor"
        ),
    }


def options(base: str) -> dict[str, str]:
    """Return the cases of an option after the value of a keyword."""
    return {
        "space_left_action_with_option": setting(base, "space_left_action", "email extra"),
        "admin_space_left_action_with_option": setting(
            base, "admin_space_left_action", "single extra"
        ),
        "disk_full_action_with_option": setting(base, "disk_full_action", "halt extra"),
        "disk_error_action_with_option": setting(base, "disk_error_action", "syslog extra"),
        "space_left_action_with_two_options": setting(base, "space_left_action", "email a b"),
        "max_log_file_action_with_option": setting(base, "max_log_file_action", "rotate extra"),
        "overflow_action_with_option": setting(base, "overflow_action", "syslog extra"),
        "unknown_action_with_option": setting(base, "space_left_action", "frobnicate extra"),
    }


def values(form: auditconf.Form) -> tuple[str, ...]:
    """Return the sample values of a keyword's form: valid ones and some that auditd refuses."""
    if form.choices:
        mixed = tuple(choice.capitalize() for choice in form.choices)
        upper = tuple(choice.upper() for choice in form.choices)
        return (*form.choices, *mixed, *upper, "frobnicate")
    if form.pattern == auditconf.DIGITS:
        return NUMBER_SAMPLES
    return PATTERN_SAMPLES[form.pattern]


def keyword_cases(base: str) -> dict[str, str]:
    """Return a case per keyword and sample value of :data:`auditconf.KEYWORDS`."""
    cases: dict[str, str] = {}
    for keyword, form in auditconf.KEYWORDS.items():
        for index, sample in enumerate(values(form)):
            cases[f"value_{keyword}_{index}"] = setting(base, keyword, sample)
    return cases


def all_cases(base: str) -> dict[str, str]:
    """Return every case: the line forms and the values of every keyword."""
    return {**structural(base), **keyword_cases(base)}


def write_cases(base: Path, output: Path) -> list[str]:
    """Write every case as ``<name>.conf`` below ``output``; return the names."""
    cases = all_cases(base.read_bytes().decode("latin-1"))
    output.mkdir(parents=True, exist_ok=True)
    for name, text in cases.items():
        (output / f"{name}{CASE_SUFFIX}").write_bytes(text.encode("latin-1", "surrogateescape"))
    return sorted(cases)


def verdict(status: int, output: str) -> dict[str, object]:
    """Return what auditd did with one case: its verdict, the values it read and its messages.

    The time and serial number of an audit event in a message are replaced, so that the table
    made again from the same images is the same.
    """
    read = [
        list(found.groups()) for found in map(PARSER_LINE.fullmatch, output.splitlines()) if found
    ]
    messages = [
        EVENT_STAMP.sub("audit(<time>:<serial>)", line.strip())
        for line in output.splitlines()
        if line.strip() and not PARSER_LINE.fullmatch(line) and not NOTICE.fullmatch(line.strip())
    ]
    if status == REFUSED_STATUS:
        result = "refused"
    elif any(marker in output for marker in STARTED_MARKERS):
        result = "accepted"
    else:
        result = "unobservable"
    return {"verdict": result, "status": status, "read": read, "messages": messages}


def read_results(results: Path, names: Sequence[str]) -> dict[str, dict[str, object]]:
    """Return the verdict of every case from ``<name>.out`` and ``<name>.status`` files."""
    found: dict[str, dict[str, object]] = {}
    for name in names:
        output = (results / f"{name}.out").read_bytes()[:MAX_OUTPUT].decode("utf-8", "replace")
        status = int((results / f"{name}.status").read_text(encoding="utf-8").strip())
        found[name] = verdict(status, output)
    return found


def load_table(path: Path) -> dict[str, object]:
    """Return the table at ``path``, or an empty one."""
    if not path.is_file():
        return {"platforms": {}, "cases": {}}
    return cast("dict[str, object]", json.loads(path.read_text(encoding="utf-8")))


def last_values(read: Sequence[Sequence[str]]) -> dict[str, str]:
    """Return the value that auditd keeps of every parser that ``read`` names, the last one."""
    return {pair[0]: pair[1] for pair in read}


def compact(result: dict[str, object], base: dict[str, str]) -> dict[str, object]:
    """Return ``result`` as the table keeps it, with only the values that differ from ``base``.

    The values are kept only when auditd accepted the file, as the reader is compared with them
    only then: ``read`` holds the values that differ from those of the file as built, and
    ``unread`` the parsers of the file as built that auditd did not call for the case.
    """
    kept: dict[str, object] = {"verdict": result["verdict"], "status": result["status"]}
    if result["verdict"] == "accepted":
        values = last_values(cast("list[list[str]]", result["read"]))
        changed = {parser: value for parser, value in values.items() if base.get(parser) != value}
        unread = sorted(parser for parser in base if parser not in values)
        if changed:
            kept["read"] = changed
        if unread:
            kept["unread"] = unread
    if result["messages"]:
        kept["messages"] = result["messages"]
    return kept


def merge(
    table: dict[str, object],
    platform: str,
    header: dict[str, object],
    results: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Return ``table`` with the header and the results of ``platform`` replaced.

    The header holds the file as built (``base``), from which ``all_cases`` writes every case
    again, and the values auditd read from it (``read``), against which each case is kept.
    """
    base = last_values(cast("list[list[str]]", results[AS_BUILT]["read"]))
    platforms = cast("dict[str, object]", table.setdefault("platforms", {}))
    platforms[platform] = {**header, "read": base}
    cases = cast("dict[str, dict[str, object]]", table.setdefault("cases", {}))
    for case in cases.values():
        case.pop(platform, None)
    for name, result in results.items():
        cases.setdefault(name, {})[platform] = compact(result, base)
    table["cases"] = {name: case for name, case in sorted(cases.items()) if case}
    table["platforms"] = dict(sorted(platforms.items()))
    return table


def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if pattern.fullmatch(value) is None:
        message = f"{what} {value!r} is not acceptable"
        raise ValueError(message)
    return value


def main(argv: Sequence[str] | None = None, *, out: Callable[[str], object] = print) -> int:
    """Run the command line; return the exit status."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    cases = commands.add_parser("cases")
    cases.add_argument("--base", type=Path, required=True)
    cases.add_argument("--output", type=Path, required=True)
    table = commands.add_parser("table")
    table.add_argument("--platform", required=True)
    table.add_argument("--base", type=Path, required=True)
    table.add_argument("--results", type=Path, required=True)
    table.add_argument("--package", required=True)
    table.add_argument("--version", required=True)
    table.add_argument("--image", required=True)
    table.add_argument("--log-megabytes", type=int, required=True)
    table.add_argument("--output", type=Path, default=TABLE)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "cases":
            names = write_cases(arguments.base, arguments.output)
            out(f"wrote {len(names)} cases to {arguments.output}")
            return 0
        platform = _check(PLATFORM, arguments.platform, "the platform")
        base = arguments.base.read_bytes().decode("latin-1")
        results = read_results(arguments.results, sorted(all_cases(base)))
        header: dict[str, object] = {
            "package": arguments.package,
            "version": arguments.version,
            "image": arguments.image,
            "log_megabytes": arguments.log_megabytes,
            "base": base,
        }
        merged = merge(load_table(arguments.output), platform, header, results)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(
            json.dumps(merged, indent=1, sort_keys=False, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError) as error:
        out(f"error: {error}")
        return 2
    out(f"recorded {len(results)} cases of {platform} in {arguments.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
