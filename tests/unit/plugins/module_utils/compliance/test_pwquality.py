"""Branches of the pwquality reader that the verdict table does not reach (FREES-200)."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import (
    pwquality_decide,
    pwquality_pam_modules,
    pwquality_restore,
)
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    pwquality,
)

MAIN = "/etc/security/pwquality.conf"
DROPIN = "/etc/security/pwquality.conf.d/50-freesecdev-minlen.conf"
MODULE_DIRECTORY = "/usr/lib64/security/"
PWQ_MODULE = MODULE_DIRECTORY + "pam_pwquality.so"
UNIX_MODULE = MODULE_DIRECTORY + "pam_unix.so"
PWQ_STAT: dict[str, object] = {"exists": True, "isreg": True, "checksum": "a1"}
UNIX_STAT: dict[str, object] = {"exists": True, "isreg": True, "checksum": "b2"}
MODULE_STATS: dict[str, dict[str, object]] = {PWQ_MODULE: PWQ_STAT, UNIX_MODULE: UNIX_STAT}
MODULES = pwquality.Modules(MODULE_DIRECTORY, MODULE_STATS)
FILTER_MODULES: dict[str, object] = {"directory": MODULE_DIRECTORY, "stats": MODULE_STATS}


def stack(files: list[tuple[str, str]], modules: pwquality.Modules = MODULES) -> pwquality.PamStack:
    return pwquality.PamStack(files, modules)


def rule(value: str = "14", method: str = "main_file") -> pwquality.Rule:
    return pwquality.Rule("minlen", value, method, MAIN, DROPIN, f"minlen = {value}\n")


def test_an_option_name_longer_than_the_buffer_of_the_library_is_refused() -> None:
    assert pwquality.option_value(b"x" * 80 + b"=1") is None
    assert pwquality.option_value(b"minlen=9") == ("minlen", 9)
    assert pwquality.option_value(b"badwords=a") == ("badwords", None)
    assert pwquality.option_value(b"frobnicate=1") is None


def test_continued_pam_lines_are_joined_and_comment_lines_skipped() -> None:
    text = (
        "# password requisite pam_pwquality.so minlen=1\n"
        "password requisite pam_pwquality.so retry=3 \\\n"
        "    minlen=8 [enforce_for_root]\n"
        "password requisite pam_unix.so minlen=2\n"
        "password requisite pam_pwquality.so \\"
    )
    files = [("/etc/pam.d/site", text)]
    assert pwquality.pam_overrides(stack(files), "minlen", 14) == ["/etc/pam.d/site: minlen=8"]
    assert pwquality.pam_overrides(stack(files), "enforce_for_root", 1) == []
    assert pwquality.pam_overrides(stack(files), "retry", 1) == ["/etc/pam.d/site: retry=3"]


def test_a_rule_whose_value_the_library_changes_is_overridden() -> None:
    decision = pwquality.decide(rule("5"), [], "", stack([]))
    assert decision["status"] == "overridden"
    assert decision["reason"] == f"libpwquality reads minlen 6 from {MAIN}, not 5"


def test_a_setting_that_nothing_sets_is_not_read() -> None:
    reading = pwquality.Reading(())
    assert pwquality.why_not_effective(reading, rule(), MAIN, 0) == (
        f"libpwquality does not read minlen from {MAIN}"
    )
    assert reading.value("minlen") == 8
    assert reading.value("badwords") is None


@pytest.mark.parametrize(
    ("text", "prior", "outcome"),
    [
        ("a\nminlen = 14\n", None, {"reason": None, "already": False, "text": "a\n"}),
        ("a\nminlen = 14", None, {"reason": None, "already": False, "text": "a"}),
        ("minlen = 14\n", None, {"reason": None, "already": False, "text": ""}),
        (
            "a\r\nminlen = 14\nb\r\n",
            "MINLEN=8\r",
            {"reason": None, "already": False, "text": "a\r\nMINLEN=8\r\nb\r\n"},
        ),
        ("a\n", None, {"reason": None, "already": True, "text": "a\n"}),
        ("minlen  8\n", "minlen  8", {"reason": None, "already": True, "text": "minlen  8\n"}),
        (
            "minlen = 14\nMINLEN 9\n",
            None,
            {"reason": "modified_since_apply", "already": False, "text": "minlen = 14\nMINLEN 9\n"},
        ),
        (
            "minlen = 12\n",
            "minlen = 8",
            {"reason": "modified_since_apply", "already": False, "text": "minlen = 12\n"},
        ),
    ],
)
def test_the_restore_of_the_main_file(
    text: str, prior: str | None, outcome: dict[str, object]
) -> None:
    assert pwquality_restore.pwquality_restore(text, "minlen", "minlen = 14", prior) == outcome


def test_the_line_is_appended_after_a_line_break_when_the_file_has_none() -> None:
    assert pwquality.compose("a", "minlen = 14", []) == (1, "a\nminlen = 14")
    assert pwquality.compose("", "minlen = 14", []) == (0, "minlen = 14\n")
    assert pwquality.compose("a\nminlen=1\r\nb", "minlen = 14", [(1, "minlen=1\r")]) == (
        1,
        "a\nminlen = 14\nb",
    )


def test_the_decide_filter_passes_the_rule_and_the_files() -> None:
    decision = pwquality_decide.pwquality_decide(
        {
            "setting": "minlen",
            "value": "14",
            "method": "dropin",
            "main": MAIN,
            "dropin": DROPIN,
            "content": "minlen = 14\n",
        },
        [
            {
                "path": "/etc/security/pwquality.conf.d/90-site.conf",
                "type": "file",
                "content": "minlen 9\n",
            }
        ],
        "",
        [
            {
                "path": "/etc/pam.d/common-password",
                "content": "password requisite pam_pwquality.so\n",
            }
        ],
        FILTER_MODULES,
    )
    assert decision["status"] == "overridden"
    assert decision["reason"] == (
        "libpwquality reads minlen 9 from line 1 of /etc/security/pwquality.conf.d/90-site.conf "
        f"after {DROPIN}"
    )
    filters = pwquality_decide.FilterModule().filters()
    assert filters == {"pwquality_decide": pwquality_decide.pwquality_decide}
    restores = pwquality_restore.FilterModule().filters()
    assert restores == {"pwquality_restore": pwquality_restore.pwquality_restore}


EMPTY: list[object] = []
GOOD_RULE: dict[str, object] = {
    "setting": "minlen",
    "value": "14",
    "method": "main_file",
    "main": MAIN,
    "dropin": DROPIN,
    "content": "",
}


NO_STATS: dict[str, object] = {}
DECIDE_SHAPES: list[tuple[tuple[object, object, object, object, object], str]] = [
    (("rule", EMPTY, "", EMPTY, FILTER_MODULES), "the rule must be a mapping"),
    ((GOOD_RULE, "drop-ins", "", EMPTY, FILTER_MODULES), "the rule must be a mapping"),
    ((GOOD_RULE, EMPTY, "", "pam", FILTER_MODULES), "the PAM files must be a list"),
    ((GOOD_RULE, EMPTY, 1, EMPTY, FILTER_MODULES), "the PAM files must be a list"),
    ((GOOD_RULE | {"value": 14}, EMPTY, "", EMPTY, FILTER_MODULES), "value must be a string"),
    ((GOOD_RULE, ["entry"], "", EMPTY, FILTER_MODULES), "every drop-in must be a mapping"),
    ((GOOD_RULE, EMPTY, "", ["file"], FILTER_MODULES), "every PAM file must be a mapping"),
    (
        (GOOD_RULE, EMPTY, "", [{"path": "/etc/pam.d/x"}], FILTER_MODULES),
        "content must be a string",
    ),
    ((GOOD_RULE, EMPTY, "", EMPTY, "modules"), "the modules must be a mapping"),
    (
        (GOOD_RULE, EMPTY, "", EMPTY, {"directory": "/usr/lib64/security", "stats": NO_STATS}),
        "must be None or a path that ends with a slash",
    ),
    (
        (GOOD_RULE, EMPTY, "", EMPTY, {"directory": 1, "stats": NO_STATS}),
        "must be None or a path that ends with a slash",
    ),
    (
        (GOOD_RULE, EMPTY, "", EMPTY, {"directory": None, "stats": EMPTY}),
        "the stats of the modules must be a mapping",
    ),
    (
        (GOOD_RULE, EMPTY, "", EMPTY, {"directory": None, "stats": {PWQ_MODULE: 1}}),
        "every module stat must be a mapping under its path",
    ),
    (
        (GOOD_RULE, EMPTY, "", EMPTY, {"directory": None, "stats": {1: PWQ_STAT}}),
        "every module stat must be a mapping under its path",
    ),
    (
        (GOOD_RULE | {"directory": 1}, EMPTY, "", EMPTY, FILTER_MODULES),
        "directory must be a string",
    ),
]


@pytest.mark.parametrize(("arguments", "message"), DECIDE_SHAPES)
def test_the_decide_filter_refuses_input_of_the_wrong_shape(
    arguments: tuple[object, object, object, object, object], message: str
) -> None:
    with pytest.raises(pwquality_decide.DecisionInputError, match=message):
        pwquality_decide.pwquality_decide(*arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        (1, "minlen", "minlen = 14", None),
        ("", None, "minlen = 14", None),
        ("", "minlen", None, None),
        ("", "minlen", "minlen = 14", 8),
    ],
)
def test_the_restore_filter_refuses_input_of_the_wrong_shape(
    arguments: tuple[object, object, object, object],
) -> None:
    with pytest.raises(pwquality_restore.RestoreInputError):
        pwquality_restore.pwquality_restore(*arguments)


@pytest.mark.parametrize(
    "argument",
    [
        "enforcing=0",
        "enforcing=00",
        "enforcing=+00",
        "enforcing=-00",
        "enforcing=000",
        "enforcing=-0",
        "ENFORCING=0",
        "[enforcing=00]",
    ],
)
def test_every_form_of_enforcing_0_in_pam_refuses_the_other_rules(argument: str) -> None:
    pam = [("/etc/pam.d/common-password", f"password requisite pam_pwquality.so {argument}\n")]
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack(pam))
    assert decision["status"] == "overridden"
    assert str(decision["reason"]).startswith(
        "enforcing is 0 in /etc/pam.d/common-password: " + argument.strip("[]")
    )


@pytest.mark.parametrize("argument", ["enforcing=1", "enforcing=01", "enforcing=10", "enforcing="])
def test_an_enforcing_argument_that_is_not_0_leaves_the_other_rules(argument: str) -> None:
    pam = [("/etc/pam.d/common-password", f"password requisite pam_pwquality.so {argument}\n")]
    assert pwquality.pam_enforcing_off(stack(pam)) == []
    assert pwquality.decide(rule(), [], "minlen = 14\n", stack(pam))["status"] == "compliant"


@pytest.mark.parametrize(
    ("line", "target"),
    [
        ("@include /etc/site/password", "/etc/site/password"),
        ("@include ../security/password", "../security/password"),
        ("@include site/password", "site/password"),
        ("password include ../security/password", "../security/password"),
        ("password substack ./site/password", "./site/password"),
        ("auth INCLUDE /etc/site/auth", "/etc/site/auth"),
    ],
)
def test_a_pam_include_of_a_path_with_a_slash_is_refused(line: str, target: str) -> None:
    pam = [("/etc/pam.d/common-password", line + "\n")]
    assert pwquality.read_pam(stack(pam)).includes == (
        f"/etc/pam.d/common-password includes {target}",
    )
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack(pam))
    assert decision["status"] == "overridden"
    assert str(decision["reason"]).startswith(f"/etc/pam.d/common-password includes {target}")


@pytest.mark.parametrize(
    "line",
    ["@include common-password", "password include system-auth", "# @include ../x", "@include"],
)
def test_a_pam_include_of_a_name_in_the_pam_directory_is_read(line: str) -> None:
    assert pwquality.read_pam(stack([("/etc/pam.d/sshd", line + "\n")])).includes == ()


@pytest.mark.parametrize(
    ("pam", "reason"),
    [
        (
            [("/usr/share/pam.d/vendor-only", "password requisite pam_pwquality.so minlen=8\n")],
            "pam_pwquality arguments override the file: /usr/share/pam.d/vendor-only: minlen=8",
        ),
        (
            [
                ("/etc/pam.d/passwd", "password requisite pam_pwquality.so\n"),
                ("/usr/share/pam.d/passwd", "password requisite pam_pwquality.so minlen=8\n"),
            ],
            "pam_pwquality arguments override the file: /usr/share/pam.d/passwd: minlen=8",
        ),
        (
            [("/usr/share/pam.d/vendor-only", "password requisite pam_pwquality.so enforcing=0\n")],
            "enforcing is 0 in /usr/share/pam.d/vendor-only: enforcing=0",
        ),
    ],
)
def test_an_argument_in_any_file_of_the_vendor_directory_refuses_the_rule(
    pam: list[tuple[str, str]], reason: str
) -> None:
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack(pam))
    assert decision["status"] == "overridden"
    assert str(decision["reason"]).startswith(reason)


PWQ = "password requisite pam_pwquality.so"
SERVICE = "/etc/pam.d/common-password"


@pytest.mark.parametrize(
    ("text", "arguments"),
    [
        (f"# a comment that ends in a backslash \\\n{PWQ} minlen=1\n", ("minlen=1",)),
        (f"{PWQ} \\\n  minlen=8 [enforce_for_root]\n", ("minlen=8", "enforce_for_root")),
        ("PASSWORD [success=ok default=die]pam_pwquality.so minlen=1\n", ("minlen=1",)),
        (f"-{PWQ} minlen=1\r\n", ("minlen=1\r",)),
        ("auth required /usr/lib64/security/pam_pwquality.so minlen=1 # x\n", ("minlen=1",)),
        (f"{PWQ} minlen=1 \\", ("minlen=1",)),
        ("password requisite\npassword\nfoo requisite pam_pwquality.so minlen=1\n", ()),
        (f"password requisite pam_unix.so minlen=1\n{PWQ}\n", ()),
    ],
)
def test_pam_pwquality_arguments_are_read_as_libpam_assembles_and_splits_the_lines(
    text: str, arguments: tuple[str, ...]
) -> None:
    reading = pwquality.read_pam(stack([(SERVICE, text)]))
    assert reading == pwquality.PamReading(
        tuple((SERVICE, argument) for argument in arguments), (), ()
    )


def test_a_live_line_after_a_comment_that_ends_with_a_backslash_overrides_the_file() -> None:
    pam = [(SERVICE, f"# site \\\n{PWQ} minlen=1 enforcing=0\n")]
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack(pam))
    assert decision["status"] == "overridden"
    assert decision["reason"] == (f"pam_pwquality arguments override the file: {SERVICE}: minlen=1")


@pytest.mark.parametrize(
    "text",
    [
        "#" + "x" * 1022 + f"{PWQ} minlen=1\n",
        "# " + "é" * 511 + "\n",
        f"{PWQ} minlen=14\0 minlen=1\n",
        "\0",
    ],
)
def test_a_pam_file_that_libpam_does_not_read_as_one_line_refuses_the_rule(text: str) -> None:
    pam = [(SERVICE, text), ("/etc/pam.d/login", f"{PWQ} minlen=1\n")]
    reading = pwquality.read_pam(stack(pam))
    assert reading.problems == (
        (
            f"{SERVICE} has a NUL byte or a line of 1023 bytes or more, which libpam does not "
            "read as one line"
        ),
    )
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack(pam))
    assert (decision["status"], decision["text"]) == ("overridden", None)
    assert str(decision["reason"]).startswith(f"{SERVICE} has a NUL byte")
    assert str(decision["reason"]).endswith(
        "so the collection cannot tell which pam_pwquality arguments libpam passes, and an "
        "argument there could override the file"
    )


def test_a_line_of_1022_bytes_is_read_as_one_line() -> None:
    text = "#" + "x" * 1021 + f"\n{PWQ} minlen=14\n"
    assert pwquality.read_pam(stack([(SERVICE, text)])).arguments == ((SERVICE, "minlen=14"),)
    assert pwquality.decide(rule(), [], "minlen = 14\n", stack([(SERVICE, text)]))["status"] == (
        "compliant"
    )


@pytest.mark.parametrize(
    "text",
    [
        f"{PWQ} minlen=14 \\\n\n  minlen=1\n",
        f"{PWQ} minlen=14 \\\n# site\n  enforcing=0\n",
        "password include \\\n\n  common-auth\n",
    ],
)
def test_lines_that_the_two_libpam_readers_assemble_differently_refuse_the_rule(text: str) -> None:
    reading = pwquality.read_pam(stack([(SERVICE, text)]))
    assert reading.problems == (
        (
            f"{SERVICE} has lines that load pam_pwquality or include a file, which the line "
            "readers of libpam 1.5.1 and 1.5.3 assemble differently"
        ),
    )
    assert reading.arguments == ()
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack([(SERVICE, text)]))
    assert decision["status"] == "overridden"


def test_lines_that_only_other_modules_assemble_differently_do_not_refuse() -> None:
    text = f"password requisite pam_unix.so \\\n\n  sha512\n{PWQ} minlen=14\n"
    assert pwquality.read_pam(stack([(SERVICE, text)])) == pwquality.PamReading(
        ((SERVICE, "minlen=14"),), (), ()
    )


@pytest.mark.parametrize(
    ("text", "target"),
    [
        ("@INCLUDE /etc/site/password\n", "/etc/site/password"),
        ("-@include /etc/site/password\n", "/etc/site/password"),
        ("password include \\\n  ../security/password\n", "../security/password"),
        ("password \\\n  include /etc/site/password\n", "/etc/site/password"),
        ("@include \\\n  /etc/site/password\n", "/etc/site/password"),
        ("PASSWORD SUBSTACK /etc/site/password\n", "/etc/site/password"),
        ("-password include /etc/site/password\n", "/etc/site/password"),
        ("# x \\\n@include /etc/site/password\n", "/etc/site/password"),
    ],
)
def test_every_include_form_that_libpam_accepts_on_either_image_is_refused(
    text: str, target: str
) -> None:
    assert pwquality.read_pam(stack([(SERVICE, text)])).includes == (
        f"{SERVICE} includes {target}",
    )
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack([(SERVICE, text)]))
    assert decision["status"] == "overridden"
    assert decision["reason"] == (
        f"{SERVICE} includes {target}, which the collection does not read, so a pam_pwquality "
        "argument there could override the file"
    )


@pytest.mark.parametrize(
    ("argument", "note"),
    [
        ("local_users_only", True),
        ("LOCAL_USERS_ONLY", True),
        ("local_users_only=0", True),
        ("nolocal_users_only", False),
    ],
)
def test_local_users_only_is_noted_from_a_pam_pwquality_argument(
    argument: str, *, note: bool
) -> None:
    pam = [(SERVICE, f"{PWQ} minlen=14 {argument}\n")]
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack(pam))
    assert decision["status"] == "compliant"
    assert (decision["note"] is not None) is note


def test_the_module_directory_is_the_one_that_libpam_is_built_with() -> None:
    assert pwquality.module_directory("RedHat", "x86_64") == "/usr/lib64/security/"
    assert pwquality.module_directory("Debian", "x86_64") == "/usr/lib/x86_64-linux-gnu/security/"
    assert pwquality.module_directory("Debian", "aarch64") == (
        "/usr/lib/aarch64-linux-gnu/security/"
    )
    assert pwquality.module_directory("Debian", "s390x") is None
    assert pwquality.module_directory("Suse", "x86_64") is None


@pytest.mark.parametrize(
    ("module", "path"),
    [
        ("pam_pwquality.so", PWQ_MODULE),
        ("./pam_pwquality.so", MODULE_DIRECTORY + "./pam_pwquality.so"),
        ("/opt/site/pam_pwq.so", "/opt/site/pam_pwq.so"),
        ("/lib/$ISA/pam_pwquality.so", None),
    ],
)
def test_a_module_path_is_resolved_as_libpam_resolves_it(module: str, path: str | None) -> None:
    assert pwquality.module_path(module, MODULE_DIRECTORY) == path


def test_every_module_path_of_both_readers_is_listed_with_pam_pwquality() -> None:
    files = [
        (SERVICE, "password requisite \\\n\n  /opt/site/pam_blank.so\npassword include x/y\n"),
        ("/etc/pam.d/login", "auth required /lib/$ISA/pam_unix.so\nauth required pam_env.so\n"),
    ]
    assert pwquality.module_paths(files, MODULE_DIRECTORY) == [
        "/opt/site/pam_blank.so",
        MODULE_DIRECTORY + "pam_env.so",
        PWQ_MODULE,
    ]
    assert pwquality.module_paths([], MODULE_DIRECTORY) == [PWQ_MODULE]
    assert pwquality.module_paths(files, None) == []


LINKED = "/opt/site/pam_pwq.so"
ELSEWHERE = "/opt/site/pam_other.so"


@pytest.mark.parametrize(
    ("module", "stats", "outcome"),
    [
        ("pam_pwquality.so", {}, True),
        (PWQ_MODULE, {}, True),
        ("pam_pwq.so", {MODULE_DIRECTORY + "pam_pwq.so": PWQ_STAT, PWQ_MODULE: PWQ_STAT}, True),
        (LINKED, {LINKED: PWQ_STAT, PWQ_MODULE: PWQ_STAT}, True),
        (
            "./pam_pwquality.so",
            {MODULE_DIRECTORY + "./pam_pwquality.so": PWQ_STAT} | MODULE_STATS,
            True,
        ),
        (LINKED, {LINKED: UNIX_STAT, PWQ_MODULE: PWQ_STAT}, False),
        ("pam_unix.so", MODULE_STATS, False),
        (LINKED, {LINKED: {"exists": False}}, False),
        (LINKED, {LINKED: {"exists": True, "isreg": False}}, False),
        (LINKED, {LINKED: PWQ_STAT, PWQ_MODULE: {"exists": False}}, False),
        (LINKED, {}, f"{LINKED} was not inspected"),
        (LINKED, {LINKED: PWQ_STAT}, f"{PWQ_MODULE} was not inspected"),
        (
            LINKED,
            {LINKED: {"msg": "Permission denied"}},
            f"stat could not inspect {LINKED}: Permission denied",
        ),
        (LINKED, {LINKED: {"msg": ""}}, f"stat could not inspect {LINKED}"),
        (
            LINKED,
            {LINKED: {"exists": True, "isreg": True}},
            f"{LINKED} could not be read to compare it with pam_pwquality.so",
        ),
        (
            LINKED,
            {LINKED: PWQ_STAT, PWQ_MODULE: {"exists": True, "isreg": True, "checksum": ""}},
            f"{PWQ_MODULE} could not be read to compare it with pam_pwquality.so",
        ),
        (
            "/lib/$ISA/pam_pwquality.so",
            MODULE_STATS,
            (
                "/lib/$ISA/pam_pwquality.so holds $ISA, which libpam replaces and the collection"
                " does not"
            ),
        ),
    ],
)
def test_a_module_is_pam_pwquality_when_libpam_loads_that_file_whatever_its_name(
    module: str, stats: dict[str, dict[str, object]], outcome: bool | str
) -> None:
    assert pwquality.Modules(MODULE_DIRECTORY, stats).identify(module) == outcome


def test_no_module_is_known_without_the_module_directory() -> None:
    assert pwquality.Modules(None, {}).identify("pam_pwquality.so") == (
        "the collection does not know the directory that libpam loads pam_pwquality.so from on"
        " this platform"
    )


def test_a_renamed_pam_pwquality_that_loosens_the_rule_overrides_the_file() -> None:
    text = f"password requisite {LINKED} minlen=1 enforcing=0\n"
    linked = pwquality.Modules(MODULE_DIRECTORY, MODULE_STATS | {LINKED: PWQ_STAT})
    other = pwquality.Modules(MODULE_DIRECTORY, MODULE_STATS | {LINKED: UNIX_STAT})
    assert pwquality.read_pam(stack([(SERVICE, text)], linked)).arguments == (
        (SERVICE, "minlen=1"),
        (SERVICE, "enforcing=0"),
    )
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack([(SERVICE, text)], linked))
    assert (decision["status"], decision["text"]) == ("overridden", None)
    assert decision["reason"] == f"pam_pwquality arguments override the file: {SERVICE}: minlen=1"
    assert pwquality.read_pam(stack([(SERVICE, text)], other)).arguments == ()
    assert (
        pwquality.decide(rule(), [], "minlen = 14\n", stack([(SERVICE, text)], other))["status"]
        == "compliant"
    )


@pytest.mark.parametrize(
    ("modules", "reason"),
    [
        (
            pwquality.Modules(MODULE_DIRECTORY, MODULE_STATS),
            f"{SERVICE} loads the module {LINKED}, but {LINKED} was not inspected",
        ),
        (
            pwquality.Modules(None, {}),
            (
                f"{SERVICE} loads the module pam_unix.so, but the collection does not know the"
                " directory that libpam loads pam_unix.so from on this platform"
            ),
        ),
    ],
)
def test_a_module_that_cannot_be_told_refuses_the_rule(
    modules: pwquality.Modules, reason: str
) -> None:
    text = f"password requisite pam_unix.so \\\n\n  sha512\npassword requisite {LINKED}\n"
    reading = pwquality.read_pam(stack([(SERVICE, text)], modules))
    assert reading.arguments == ()
    assert reading.problems[0] == reason
    assert len(reading.problems) == len(set(reading.problems))
    decision = pwquality.decide(rule(), [], "minlen = 14\n", stack([(SERVICE, text)], modules))
    assert (decision["status"], decision["text"]) == ("overridden", None)
    assert str(decision["reason"]).startswith(reason)


def test_the_module_filter_lists_the_paths_to_inspect() -> None:
    pam: list[object] = [
        {"path": SERVICE, "content": f"{PWQ}\npassword requisite pam_unix.so\n"},
        {"path": "/etc/pam.d/broken", "kind": "broken_link"},
    ]
    assert pwquality_pam_modules.pwquality_pam_modules(pam, "RedHat", "x86_64") == {
        "directory": MODULE_DIRECTORY,
        "paths": [PWQ_MODULE, UNIX_MODULE],
    }
    assert pwquality_pam_modules.pwquality_pam_modules(pam, "Gentoo", "x86_64") == {
        "directory": None,
        "paths": [],
    }
    filters = pwquality_pam_modules.FilterModule().filters()
    assert filters == {"pwquality_pam_modules": pwquality_pam_modules.pwquality_pam_modules}


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (("pam", "RedHat", "x86_64"), "the PAM files must be a list"),
        ((EMPTY, None, "x86_64"), "the OS family and the architecture must be strings"),
        ((EMPTY, "RedHat", 64), "the OS family and the architecture must be strings"),
        ((["file"], "RedHat", "x86_64"), "every PAM file must be a mapping"),
        (([{"path": SERVICE}], "RedHat", "x86_64"), "needs a text path and content"),
        (([{"path": 1, "content": ""}], "RedHat", "x86_64"), "needs a text path and content"),
    ],
)
def test_the_module_filter_refuses_input_of_the_wrong_shape(
    arguments: tuple[object, object, object], message: str
) -> None:
    with pytest.raises(pwquality_pam_modules.ModulePathsInputError, match=message):
        pwquality_pam_modules.pwquality_pam_modules(*arguments)
