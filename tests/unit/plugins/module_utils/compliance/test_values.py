"""Unit tests of the comparators of native values (FREES-203, ADR 0032 §3).

The checks against the Jinja of the remediate role need Jinja2, which the target context of
``ansible-test units`` does not have; they are in
``tests/unit/roles/test_login_defs_comparators.py``.

``SSHD_T`` is what ``sshd -T -o <keyword>=<value>`` printed on the Molecule images of Ubuntu
24.04 (OpenSSH 9.6p1) and Rocky Linux 9 (OpenSSH 9.9p1), which agreed on every case, or ``None``
when sshd refused the value or, for the ``+``, ``-`` and ``^`` modifiers, printed its own default
list changed by the value, which differs between the two versions. The auditd comparators are
checked against ``auditconf.read``, the reader that ``tests/fixtures/auditd_conf/verdicts.json``
pins to auditd.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.filter import pam_conf
from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    auditconf,
    pwquality,
    sysctl,
    sysctl_config,
    values,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
ROLE_VARIABLES = REPOSITORY_ROOT / "roles/remediate/vars/main.yml"
CATALOGUE = REPOSITORY_ROOT / "roles/remediate/vars/rules.yml"
SSH_TASKS = REPOSITORY_ROOT / "roles/remediate/tasks/ssh.yml"
AUDITD_TASKS = REPOSITORY_ROOT / "roles/remediate/tasks/auditd_conf.yml"
PREFIX = "__linux_compliance_remediate_"
SYSCTL_FAMILIES = frozenset({"ipv4_parameters", "ipv6_parameters"})
UNCOMPARED_FAMILIES = frozenset({"banners"})
SSH_VALUE = r"^[A-Za-z0-9@.,:/_+][A-Za-z0-9@.,:/_+-]{0,1023}$"
AUDITD_VALUE = r"^[A-Za-z0-9_.@-]{1,64}(\|[A-Za-z0-9_.@-]{1,64}){0,7}$"
AUDITD_DIGITS = r"^[0-9]{1,9}$"
KEX = "curve25519-sha256"
KEX_NIST = "ecdh-sha2-nistp256"
MAC_512 = "hmac-sha2-512"
MAC_256 = "hmac-sha2-256"
AUDITD_LOG_MEGABYTES = 1000
INTENDED: dict[tuple[str, str], str] = {
    ("login_defs", "FAIL_DELAY"): "login_defs_at_least",
    ("login_defs", "PASS_MAX_DAYS"): "login_defs_at_most",
    ("login_defs", "PASS_MIN_DAYS"): "login_defs_at_least",
    ("login_defs", "PASS_MIN_LEN"): "login_defs_at_least",
    ("login_defs", "PASS_WARN_AGE"): "login_defs_at_least",
    ("login_defs", "UMASK"): "login_defs_umask",
    ("pwquality", "dcredit"): "pwquality_credit",
    ("pwquality", "lcredit"): "pwquality_credit",
    ("pwquality", "ocredit"): "pwquality_credit",
    ("pwquality", "ucredit"): "pwquality_credit",
    ("pwquality", "dictcheck"): "pwquality_flag",
    ("pwquality", "enforcing"): "pwquality_flag",
    ("pwquality", "difok"): "pwquality_at_least",
    ("pwquality", "minclass"): "pwquality_minclass",
    ("pwquality", "minlen"): "pwquality_minlen",
    ("pwquality", "maxrepeat"): "pwquality_max_or_off",
    ("pwquality", "maxclassrepeat"): "pwquality_max_or_off",
    ("pwquality", "maxsequence"): "pwquality_max_or_off",
    ("pwquality", "retry"): "pwquality_retry",
    ("pwhistory", "remember"): "pwhistory_remember",
    ("faillock", "deny"): "faillock_deny",
    ("faillock", "fail_interval"): "faillock_interval",
    ("faillock", "unlock_time"): "faillock_unlock_time",
    ("faillock", "root_unlock_time"): "faillock_unlock_time",
    ("ssh", "ClientAliveInterval"): "sshd_interval",
    ("ssh", "ClientAliveCountMax"): "sshd_count_max",
    ("ssh", "LoginGraceTime"): "sshd_grace_time",
    ("ssh", "MaxAuthTries"): "sshd_at_most",
    ("ssh", "MaxSessions"): "sshd_at_most",
    ("ssh", "MaxStartups"): "sshd_maxstartups",
    ("ssh", "KexAlgorithms"): "sshd_algorithms",
    ("ssh", "MACs"): "sshd_algorithms",
    ("sudo", "logfile"): "sudo_path",
    ("sudo", "timestamp_timeout"): "sudo_timeout",
    ("ipv4_parameters", "*"): "sysctl_exact",
    ("ipv6_parameters", "*"): "sysctl_exact",
    ("auditd_conf", "action_mail_acct:exact"): "auditd_exact",
    ("auditd_conf", "admin_space_left:percent"): "auditd_percent",
    ("auditd_conf", "space_left:percent"): "auditd_percent",
    ("auditd_conf", "max_log_file:minimum"): "auditd_minimum",
    ("auditd_conf", "space_left:minimum"): "auditd_minimum",
    ("auditd_conf", "freq:number"): "auditd_number",
    **{
        ("auditd_conf", f"{setting}:choice"): f"auditd_choice_{setting}"
        for setting in values.AUDITD_CHOICE_SETTINGS
    },
}
AUDITD_KINDS: dict[str, tuple[type[object], str | None]] = {
    "choice": (values.ChoiceSet, None),
    "exact": (values.Exact, None),
    "number": (values.Exact, None),
    "minimum": (values.IntegerOrder, values.AT_LEAST),
    "percent": (values.IntegerOrder, values.AT_LEAST),
}
DIRECTION_OF: dict[str, str] = {
    "at_least": values.AT_LEAST,
    "at_most": values.AT_MOST,
    "umask": "umask",
}
PAM_SETTINGS: list[tuple[str, str, str, str]] = [
    ("faillock", "deny", "at_most", "faillock_deny"),
    ("faillock", "fail_interval", "at_least", "faillock_interval"),
    ("faillock", "unlock_time", "at_least", "faillock_unlock_time"),
    ("faillock", "root_unlock_time", "at_least", "faillock_unlock_time"),
    ("pwhistory", "remember", "at_least", "pwhistory_remember"),
]
PAM_CANDIDATES: dict[str, list[int]] = {
    "deny": [0, 1, 2, 3, 4, 5, 8, 10, 11, 65534, 65535],
    "fail_interval": [0, 1, 59, 600, 899, 900, 901, 1800, 604799, 604800],
    "unlock_time": [0, 1, 59, 60, 600, 899, 900, 1800, 604800],
    "root_unlock_time": [0, 1, 59, 60, 61, 900, 604800],
    "remember": [0, 1, 3, 4, 5, 20, 24, 25, 400, 999999999],
}
PAM_PROFILES: dict[str, list[int]] = {
    "deny": [1, 3, 4, 5, 8, 10, 65535],
    "fail_interval": [0, 900, 604800],
    "unlock_time": [0, 60, 900, 1800, 604800],
    "root_unlock_time": [0, 60, 604800],
    "remember": [0, 4, 20, 24, 999999999],
}
SAMPLES: dict[str, list[str]] = {
    "login_defs_at_least": ["0", "1", "7", "12", "999999"],
    "login_defs_at_most": ["0", "1", "45", "365", "999999"],
    "login_defs_umask": ["000", "002", "007", "022", "027", "037", "070", "077"],
    "pwquality_at_least": ["0", "1", "2", "8", "999999"],
    "pwquality_minlen": ["6", "8", "14", "15", "999999"],
    "pwquality_minclass": ["0", "1", "3", "4"],
    "pwquality_credit": ["-999999", "-2", "-1", "0", "1", "999999"],
    "pwquality_max_or_off": ["0", "1", "3", "4", "999999"],
    "pwquality_flag": ["0", "1"],
    "pwquality_retry": ["1", "3", "4", "999999"],
    "pwhistory_remember": ["0", "4", "24", "999999999"],
    "faillock_deny": ["0", "1", "3", "10", "65535"],
    "faillock_interval": ["0", "1", "900", "604800"],
    "faillock_unlock_time": ["0", "1", "60", "900", "604800"],
    "sshd_interval": ["0", "1", "300", "600", "900", "2147483647"],
    "sshd_count_max": ["0", "1", "3", "2147483647"],
    "sshd_grace_time": ["0", "1", "60", "120", "2147483647"],
    "sshd_at_most": ["0", "1", "4", "5", "10", "2147483647"],
    "sshd_maxstartups": [
        "1:100:1",
        "5:30:100",
        "10:30:10",
        "10:30:60",
        "10:30:100",
        "10:50:60",
        "2147483647:1:2147483647",
    ],
    "sshd_algorithms": [KEX, KEX_NIST, f"{KEX},{KEX_NIST}", f"{KEX_NIST},{KEX}", MAC_512],
    "sudo_timeout": ["0", "5", "15", "9999"],
    "sudo_path": ["/var/log/sudo.log", "/var/log/sudo/other.log"],
    "sysctl_exact": ["0", "1", "2", "-1"],
    "auditd_exact": ["root", "admin"],
    "auditd_minimum": ["0", "6", "100", "999999999"],
    "auditd_percent": ["0", "5", "25", "99"],
    "auditd_number": ["0", "50", "100"],
    **{
        f"auditd_choice_{setting}": [
            *sorted(auditconf.KEYWORDS[setting].choices),
            "|".join(auditconf.KEYWORDS[setting].choices[:2]),
            "|".join(auditconf.KEYWORDS[setting].choices[1:3]),
            "|".join(auditconf.KEYWORDS[setting].choices),
        ]
        for setting in values.AUDITD_CHOICE_SETTINGS
    },
}
SSHD_T: list[tuple[str, str, str | None]] = [
    ("MaxStartups", "10", "10:30:10"),
    ("MaxStartups", "10:30:60", "10:30:60"),
    ("MaxStartups", "010:30:60", "10:30:60"),
    ("MaxStartups", "+10:30:60", "10:30:60"),
    ("MaxStartups", "11:30:10", None),
    ("MaxStartups", "0:30:10", None),
    ("MaxStartups", "10:0:60", None),
    ("MaxStartups", "10:101:60", None),
    ("MaxStartups", "10:30:2147483647", "10:30:2147483647"),
    ("MaxStartups", "10:30:2147483648", None),
    ("LoginGraceTime", "1m", "60"),
    ("LoginGraceTime", "0", "0"),
    ("LoginGraceTime", "060", "60"),
    ("LoginGraceTime", "2147483647", "2147483647"),
    ("LoginGraceTime", "2147483648", None),
    ("ClientAliveInterval", "5m", "300"),
    ("ClientAliveInterval", "0", "0"),
    ("ClientAliveCountMax", "0", "0"),
    ("ClientAliveCountMax", "2147483647", "2147483647"),
    ("ClientAliveCountMax", "2147483648", None),
    ("ClientAliveCountMax", "-1", None),
    ("MaxAuthTries", "0", "0"),
    ("MaxAuthTries", "+4", "4"),
    ("MaxAuthTries", "04", "4"),
    ("MaxSessions", "0", "0"),
    ("MaxSessions", "2147483647", "2147483647"),
    ("MaxSessions", "2147483648", None),
    ("KexAlgorithms", f"{KEX},{KEX_NIST}", f"{KEX},{KEX_NIST}"),
    ("KexAlgorithms", f"{KEX_NIST},{KEX}", f"{KEX_NIST},{KEX}"),
    ("KexAlgorithms", f"+{KEX}", None),
    ("KexAlgorithms", f"-{KEX_NIST}", None),
    ("KexAlgorithms", f"^{KEX}", None),
    ("KexAlgorithms", f"{KEX},{KEX}", KEX),
    ("KexAlgorithms", f"{KEX},,{KEX_NIST}", f"{KEX},{KEX_NIST}"),
    ("KexAlgorithms", "curve*", None),
    ("MACs", f"{MAC_512},{MAC_256}", f"{MAC_512},{MAC_256}"),
    ("MACs", f"{MAC_512},{MAC_512}", MAC_512),
]


def test_every_comparator_has_samples_and_the_registry_cannot_change() -> None:
    assert set(SAMPLES) == set(values.COMPARATORS)
    assert set(INTENDED.values()) == set(values.COMPARATORS)
    with pytest.raises(TypeError):
        cast("dict[str, object]", values.COMPARATORS)["x"] = values.UmaskBits()


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_meets_is_reflexive_and_transitive_and_stricter_meets_both(name: str) -> None:
    found = values.comparator(name)
    samples = SAMPLES[name]
    for value in samples:
        assert found.meets(value, value)
    for first, second, third in itertools.product(samples, repeat=3):
        if found.meets(first, second) and found.meets(second, third):
            assert found.meets(first, third)
    for first, second in itertools.product(samples, repeat=2):
        try:
            chosen = found.stricter(first, second)
        except values.ValueOverrideError:
            assert not any(
                found.meets(value, first) and found.meets(value, second) for value in samples
            ), (first, second)
            continue
        assert found.meets(chosen, first)
        assert found.meets(chosen, second)
        assert values.stricter_of(name, first, [second]) == chosen


@pytest.mark.parametrize(
    "name",
    sorted(
        name
        for name, item in values.COMPARATORS.items()
        if isinstance(item, (values.IntegerOrder, values.SshdInteger))
    ),
)
def test_an_integer_order_is_total_and_its_stricter_value_is_one_of_the_two(name: str) -> None:
    found = values.comparator(name)
    for first, second in itertools.product(SAMPLES[name], repeat=2):
        assert found.meets(first, second) or found.meets(second, first)
        assert found.stricter(first, second) in {first, second}


@pytest.mark.parametrize(
    ("name", "candidate", "profile", "expected"),
    [
        ("login_defs_at_least", "15", "12", True),
        ("login_defs_at_least", "12", "12", True),
        ("login_defs_at_least", "11", "12", False),
        ("login_defs_at_most", "60", "90", True),
        ("login_defs_at_most", "91", "90", False),
        ("login_defs_at_most", "0", "90", True),
        ("login_defs_umask", "077", "027", True),
        ("login_defs_umask", "027", "077", False),
        ("login_defs_umask", "037", "027", True),
        ("login_defs_umask", "070", "027", False),
        ("login_defs_umask", "077", "000", True),
        ("login_defs_umask", "007", "002", True),
        ("login_defs_umask", "000", "002", False),
        ("pwquality_minlen", "16", "14", True),
        ("pwquality_minlen", "8", "14", False),
        ("pwquality_minlen", "6", "6", True),
        ("pwquality_minclass", "4", "3", True),
        ("pwquality_minclass", "2", "3", False),
        ("pwquality_credit", "-2", "-1", True),
        ("pwquality_credit", "0", "-1", False),
        ("pwquality_credit", "1", "0", False),
        ("pwquality_max_or_off", "2", "3", True),
        ("pwquality_max_or_off", "4", "3", False),
        ("pwquality_max_or_off", "0", "3", False),
        ("pwquality_max_or_off", "999999", "0", True),
        ("pwquality_flag", "1", "1", True),
        ("pwquality_flag", "0", "1", False),
        ("pwquality_flag", "1", "0", True),
        ("pwquality_retry", "1", "3", True),
        ("pwquality_retry", "4", "3", False),
        ("pwquality_at_least", "8", "2", True),
        ("pwquality_at_least", "1", "2", False),
        ("pwhistory_remember", "24", "5", True),
        ("pwhistory_remember", "0", "5", False),
        ("faillock_deny", "3", "4", True),
        ("faillock_deny", "5", "4", False),
        ("faillock_deny", "0", "4", False),
        ("faillock_deny", "0", "65535", False),
        ("faillock_interval", "1800", "900", True),
        ("faillock_interval", "600", "900", False),
        ("faillock_unlock_time", "0", "900", True),
        ("faillock_unlock_time", "0", "0", True),
        ("faillock_unlock_time", "604800", "0", False),
        ("faillock_unlock_time", "1800", "900", True),
        ("faillock_unlock_time", "600", "900", False),
    ],
)
def test_judge_compares_the_value_in_force_with_the_profile(
    name: str, candidate: str, profile: str, *, expected: bool
) -> None:
    assert values.judge(name, profile, candidate) is expected


@pytest.mark.parametrize(
    ("name", "raw", "canonical"),
    [
        ("login_defs_at_least", 16, "16"),
        ("login_defs_at_least", "16", "16"),
        ("login_defs_at_least", 0, "0"),
        ("login_defs_at_least", 999999, "999999"),
        ("login_defs_umask", "027", "027"),
        ("pwquality_credit", -1, "-1"),
        ("pwquality_credit", "-1", "-1"),
        ("pwquality_credit", "-999999", "-999999"),
        ("pwquality_minlen", 6, "6"),
        ("pwquality_minclass", 4, "4"),
        ("pwquality_max_or_off", 0, "0"),
        ("pwquality_retry", 1, "1"),
        ("pwquality_flag", 0, "0"),
        ("pwhistory_remember", 999999999, "999999999"),
        ("faillock_deny", 65535, "65535"),
        ("faillock_unlock_time", 0, "0"),
        ("faillock_unlock_time", 604800, "604800"),
        ("faillock_interval", "604800", "604800"),
    ],
)
def test_validate_returns_the_canonical_text(name: str, raw: object, canonical: str) -> None:
    assert values.comparator(name).validate(raw) == canonical


@pytest.mark.parametrize(
    ("name", "raw", "message"),
    [
        ("login_defs_at_least", True, "needs a whole number from 0 to 999999"),
        ("login_defs_at_least", 1000000, "needs a whole number from 0 to 999999"),
        ("login_defs_at_least", -1, "needs a whole number from 0 to 999999"),
        ("login_defs_at_least", "016", "without a plus sign or a leading zero"),
        ("login_defs_at_least", "+16", "without a plus sign or a leading zero"),
        ("login_defs_at_least", " 16", "without a plus sign or a leading zero"),
        ("login_defs_at_least", "16\n", "without a plus sign or a leading zero"),
        ("login_defs_at_least", "0x10", "without a plus sign or a leading zero"),
        ("login_defs_at_least", 16.0, "needs a whole number"),
        ("login_defs_at_least", [16], "needs a whole number"),
        ("login_defs_at_least", None, "needs a whole number"),
        ("pwquality_credit", "-0", "needs a whole number"),
        ("pwquality_credit", -1000000, "from -999999 to 999999"),
        ("pwquality_minlen", 5, "from 6 to 999999"),
        ("pwquality_minclass", 5, "from 0 to 4"),
        ("pwquality_max_or_off", -1, "from 0 to 999999"),
        ("pwquality_flag", 2, "from 0 to 1"),
        ("pwquality_retry", 0, "from 1 to 999999"),
        ("pwhistory_remember", 1000000000, "from 0 to 999999999"),
        ("faillock_deny", 0, "from 1 to 65535"),
        ("faillock_deny", 65536, "from 1 to 65535"),
        ("faillock_interval", 604801, "from 0 to 604800"),
        ("faillock_unlock_time", 604801, "from 0 to 604800"),
        ("faillock_unlock_time", "never", "needs a whole number"),
        ("login_defs_umask", 27, "YAML 1.1 reads 027 as the octal number 23"),
        ("login_defs_umask", "27", "a zero and two octal digits"),
        ("login_defs_umask", "0027", "a zero and two octal digits"),
        ("login_defs_umask", "028", "a zero and two octal digits"),
        ("login_defs_umask", "027\n", "a zero and two octal digits"),
        ("login_defs_umask", "177", "shadow-utils reads it as a decimal number"),
        ("login_defs_umask", "700", "shadow-utils reads it as a decimal number"),
        ("login_defs_umask", "777", "shadow-utils reads it as a decimal number"),
        ("login_defs_umask", "100", "shadow-utils reads it as a decimal number"),
    ],
)
def test_validate_refuses_what_the_family_or_its_reader_would_not_take_as_written(
    name: str, raw: object, message: str
) -> None:
    with pytest.raises(values.ValueOverrideError, match=re.escape(message)):
        values.comparator(name).validate(raw)


def test_an_error_shows_a_bounded_value() -> None:
    with pytest.raises(values.ValueOverrideError) as raised:
        values.comparator("login_defs_at_least").validate("9" * 500)
    assert str(raised.value).endswith("got '" + "9" * 76 + "...")
    with pytest.raises(
        values.ValueOverrideError, match="got a value of type int too large to show"
    ):
        values.comparator("login_defs_at_least").validate(10**5000)


@pytest.mark.parametrize(
    ("name", "candidate", "profile"),
    [
        ("faillock_deny", "65536", "4"),
        ("faillock_deny", "4", "-1"),
        ("faillock_interval", "604801", "900"),
        ("pwquality_minlen", "5", "14"),
        ("login_defs_at_most", "016", "90"),
        ("login_defs_umask", "77", "027"),
        ("login_defs_umask", "177", "027"),
        ("login_defs_umask", "700", "027"),
        ("login_defs_umask", "777", "027"),
        ("login_defs_umask", "777", "000"),
        ("login_defs_umask", "077", "177"),
    ],
)
def test_a_value_that_the_comparator_cannot_judge_raises(
    name: str, candidate: str, profile: str
) -> None:
    with pytest.raises(values.ValueOverrideError):
        values.judge(name, profile, candidate)


def test_a_value_that_is_not_text_cannot_be_judged() -> None:
    order = values.comparator("faillock_deny")
    with pytest.raises(values.ValueOverrideError, match="cannot judge 4"):
        order.meets(cast("str", 4), "4")


def test_an_unknown_comparator_is_refused() -> None:
    with pytest.raises(values.ValueOverrideError, match="unknown value comparison 'equal'"):
        values.judge("equal", "1", "1")
    with pytest.raises(
        values.ValueOverrideError, match="known: auditd_choice_admin_space_left_action, "
    ):
        values.stricter_of("pwquality_max", "1", [])


def test_the_protocol_methods_are_abstract() -> None:
    order = values.comparator("faillock_deny")
    validate: Any = values.Comparator.validate
    meets: Any = values.Comparator.meets
    stricter: Any = values.Comparator.stricter
    with pytest.raises(NotImplementedError):
        validate(order, "4")
    with pytest.raises(NotImplementedError):
        meets(order, "4", "4")
    with pytest.raises(NotImplementedError):
        stricter(order, "4", "4")


@pytest.mark.parametrize(
    ("direction", "minimum", "maximum", "both", "message"),
    [
        ("down", 0, 1, frozenset[int](), "needs a direction"),
        (values.AT_LEAST, 2, 1, frozenset[int](), "a minimum not above its maximum"),
        (values.AT_MOST, 0, 1, frozenset({0}), "both the loosest and the strictest"),
    ],
)
def test_an_invalid_integer_order_is_refused(
    direction: str, minimum: int, maximum: int, both: frozenset[int], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        values.IntegerOrder(direction, minimum, maximum, loosest=both, strictest=both)


def test_an_exact_value_meets_only_itself_and_has_no_stricter_value() -> None:
    exact = values.Exact(r"[a-z/._-]{1,64}")
    assert exact.validate("/var/log/sudo.log") == "/var/log/sudo.log"
    assert values.Exact(r"[0-9]+").validate(15) == "15"
    assert exact.meets("/var/log/sudo.log", "/var/log/sudo.log")
    assert not exact.meets("/var/log/other.log", "/var/log/sudo.log")
    assert exact.stricter("/x", "/x") == "/x"
    with pytest.raises(values.ValueOverrideError, match="have no order"):
        exact.stricter("/x", "/y")
    for raw in (True, None, "/X", "x" * 65, "x" * 1025, ["/x"]):
        with pytest.raises(values.ValueOverrideError, match="that matches"):
            exact.validate(raw)
    with pytest.raises(values.ValueOverrideError, match="at most 1024 characters"):
        values.Exact(r".*").validate("x" * 1025)


@pytest.mark.parametrize(
    ("name", "target", "readings", "expected"),
    [
        ("login_defs_at_least", "12", [], "12"),
        ("login_defs_at_least", "12", ["14", "9"], "14"),
        ("login_defs_at_most", "90", ["60", "365"], "60"),
        ("login_defs_at_most", "90", ["365"], "90"),
        ("login_defs_umask", "027", ["002"], "027"),
        ("login_defs_umask", "027", ["077"], "077"),
        ("login_defs_umask", "027", ["070"], "077"),
        ("login_defs_umask", "022", ["007", "050"], "077"),
        ("faillock_deny", "4", ["0"], "4"),
        ("faillock_unlock_time", "900", ["0", "1800"], "0"),
        ("pwquality_max_or_off", "3", ["0"], "3"),
    ],
)
def test_stricter_of_keeps_the_strictest_value(
    name: str, target: str, readings: list[str], expected: str
) -> None:
    assert values.stricter_of(name, target, readings) == expected


def test_stricter_of_checks_the_target_without_readings() -> None:
    with pytest.raises(values.ValueOverrideError, match="cannot judge '1000000'"):
        values.stricter_of("login_defs_at_least", "1000000", [])


@pytest.mark.parametrize(
    ("target", "readings"),
    [("027", ["177"]), ("027", ["002", "700"]), ("177", []), ("027", ["0077"])],
)
def test_stricter_of_refuses_a_umask_that_the_readers_read_differently(
    target: str, readings: list[str]
) -> None:
    with pytest.raises(values.ValueOverrideError, match="a zero and two octal digits"):
        values.stricter_of("login_defs_umask", target, readings)


@pytest.mark.parametrize(
    ("first", "second", "strictest"),
    [("0", "11", False), ("11", "0", False), ("12", "13", True), ("13", "12", True)],
)
def test_the_stricter_of_two_equally_strict_special_values_is_the_first(
    first: str, second: str, *, strictest: bool
) -> None:
    order = values.IntegerOrder(
        values.AT_MOST,
        1,
        10,
        loosest=frozenset({0, 11}),
        strictest=frozenset({12, 13}),
    )
    assert order.meets(first, second)
    assert order.meets(second, first)
    assert order.stricter(first, second) == first
    assert order.stricter(first, "5") == (first if strictest else "5")


def test_the_bounds_are_those_of_the_readers_and_the_family_validators() -> None:
    variables = cast(
        "dict[str, object]", yaml.safe_load(ROLE_VARIABLES.read_text(encoding="utf-8"))
    )
    login_defs_number = str(variables[f"{PREFIX}login_defs_number_pattern"])
    umask = str(variables[f"{PREFIX}login_defs_umask_pattern"])
    pam_number = str(variables[f"{PREFIX}security_conf_number_pattern"])
    assert re.fullmatch(login_defs_number, str(values.LOGIN_DEFS_MAXIMUM))
    assert not re.fullmatch(login_defs_number, str(values.LOGIN_DEFS_MAXIMUM + 1))
    assert re.fullmatch(pam_number, str(values.PAM_NUMBER_MAXIMUM))
    assert not re.fullmatch(pam_number, str(values.PAM_NUMBER_MAXIMUM + 1))
    assert umask == "^[0-7]{3}$"
    assert values.FAILLOCK_MAX_TIME == pam_conf.MAX_TIME
    assert values.FAILLOCK_MAX_DENY == pam_conf.MAX_DENY
    assert values.PAM_NUMBER_MAXIMUM < pam_conf.INT_MAX
    assert values.PWQUALITY_LIMIT < pwquality.INT_MAX


def catalogue_rules() -> list[dict[str, object]]:
    data = cast("dict[str, object]", yaml.safe_load(CATALOGUE.read_text(encoding="utf-8")))
    return cast("list[dict[str, object]]", data[f"{PREFIX}rules"])


def setting_of(rule: dict[str, object]) -> tuple[str, str]:
    """Return the key of ``INTENDED`` of a value rule of the catalogue."""
    family = str(rule["family"])
    parameters = cast("dict[str, object]", rule["parameters"])
    if family in SYSCTL_FAMILIES:
        return family, "*"
    if family == "auditd_conf":
        return family, f"{parameters['setting']}:{parameters['compare']}"
    if family == "sudo":
        return family, str(cast("list[str]", parameters["options"])[0])
    return family, str(parameters.get("keyword", parameters.get("setting")))


def value_rules() -> list[dict[str, object]]:
    return [
        rule
        for rule in catalogue_rules()
        if "profile_values" in cast("dict[str, object]", rule["parameters"])
        and rule["family"] not in UNCOMPARED_FAMILIES
    ]


def profile_texts(rule: dict[str, object]) -> list[str]:
    parameters = cast("dict[str, object]", rule["parameters"])
    entries = cast("list[dict[str, object]]", parameters["profile_values"])
    return ["".join(cast("list[str]", entry["value"])) for entry in entries]


def test_the_intended_comparator_takes_every_profile_value_of_its_rules_as_it_is() -> None:
    seen: set[tuple[str, str]] = set()
    for rule in value_rules():
        parameters = cast("dict[str, object]", rule["parameters"])
        key = setting_of(rule)
        assert key in INTENDED, key
        seen.add(key)
        found = values.comparator(INTENDED[key])
        comparison = parameters.get("comparison")
        if comparison is not None:
            expected = DIRECTION_OF[str(comparison)]
            assert getattr(found, "direction", "umask") == expected, key
        for text in profile_texts(rule):
            assert found.read_profile(text) == text, (key, text)
            if not isinstance(found, values.ChoiceSet) or "|" not in text:
                assert found.validate(text) == text, (key, text)
    assert seen == set(INTENDED)


def test_every_family_with_profile_values_but_the_banners_has_a_comparator_for_each_rule() -> None:
    families = {str(rule["family"]) for rule in value_rules()}
    assert families == {
        "login_defs",
        "pwquality",
        "pwhistory",
        "faillock",
        "ssh",
        "sudo",
        "ipv4_parameters",
        "ipv6_parameters",
        "auditd_conf",
    }


def test_the_auditd_comparators_compare_as_the_family_and_its_check_compare() -> None:
    for rule in value_rules():
        if rule["family"] != "auditd_conf":
            continue
        parameters = cast("dict[str, object]", rule["parameters"])
        kind, direction = AUDITD_KINDS[str(parameters["compare"])]
        found = values.comparator(INTENDED[setting_of(rule)])
        assert isinstance(found, kind), rule["rule_id"]
        assert getattr(found, "direction", None) == direction, rule["rule_id"]
        if isinstance(found, values.ChoiceSet):
            assert found.setting == parameters["setting"]
            assert found.choices == frozenset(auditconf.KEYWORDS[found.setting].choices)


def test_every_choice_setting_of_the_catalogue_has_its_own_comparator() -> None:
    settings = {
        str(cast("dict[str, object]", rule["parameters"])["setting"])
        for rule in value_rules()
        if cast("dict[str, object]", rule["parameters"]).get("compare") == "choice"
    }
    assert settings == set(values.AUDITD_CHOICE_SETTINGS)


def test_no_catalogue_rule_names_a_comparison_yet() -> None:
    assert not any(
        "value_comparison" in cast("dict[str, object]", rule["parameters"])
        for rule in catalogue_rules()
    )


def pam_rule(reader: str, setting: str, comparison: str, required: int) -> dict[str, object]:
    return {
        "reader": reader,
        "setting": setting,
        "comparison": comparison,
        "required": str(required),
        "stack_checked": False,
    }


@pytest.mark.parametrize(("reader", "setting", "comparison", "name"), PAM_SETTINGS)
def test_the_pam_comparators_judge_as_the_pam_conf_filter_decides(
    reader: str, setting: str, comparison: str, name: str
) -> None:
    for candidate, required in itertools.product(PAM_CANDIDATES[setting], PAM_PROFILES[setting]):
        kept = candidate == 0 and setting in pam_conf.NEVER_SETTINGS and required > 0
        expected = pam_conf.satisfies(setting, comparison, candidate, required) or kept
        assert values.judge(name, str(required), str(candidate)) is expected, (
            setting,
            candidate,
            required,
        )
        decision = pam_conf.pam_conf_decision(
            f"{setting} = {candidate}\n", pam_rule(reader, setting, comparison, required), {}, ()
        )
        assert (decision["status"] in {"compliant", "stricter_setting"}) is expected, (
            setting,
            candidate,
            required,
            decision,
        )


@pytest.mark.parametrize(("reader", "setting", "comparison", "name"), PAM_SETTINGS)
def test_the_pam_comparators_refuse_what_the_pam_conf_filter_does_not_write(
    reader: str, setting: str, comparison: str, name: str
) -> None:
    found = values.comparator(name)
    above = values.FAILLOCK_MAX_DENY + 1 if setting == "deny" else values.FAILLOCK_MAX_TIME + 1
    if setting == "remember":
        above = values.PAM_NUMBER_MAXIMUM + 1
    with pytest.raises(values.ValueOverrideError):
        found.validate(above)
    if reader == "faillock":
        decision = pam_conf.pam_conf_decision(
            "", pam_rule(reader, setting, comparison, above), {}, ()
        )
        assert decision["status"] == "unsupported_value"
    if comparison == "at_most":
        with pytest.raises(values.ValueOverrideError):
            found.validate(0)


@pytest.mark.parametrize(
    ("name", "candidate", "profile", "expected"),
    [
        ("sshd_interval", "300", "300", True),
        ("sshd_interval", "299", "300", True),
        ("sshd_interval", "301", "300", False),
        ("sshd_interval", "0", "300", False),
        ("sshd_interval", "2147483647", "900", False),
        ("sshd_count_max", "1", "3", True),
        ("sshd_count_max", "4", "3", False),
        ("sshd_count_max", "0", "1", False),
        ("sshd_grace_time", "30", "60", True),
        ("sshd_grace_time", "61", "60", False),
        ("sshd_grace_time", "0", "60", False),
        ("sshd_at_most", "3", "4", True),
        ("sshd_at_most", "6", "4", False),
        ("sshd_at_most", "0", "10", True),
        ("sshd_maxstartups", "10:30:60", "10:30:100", True),
        ("sshd_maxstartups", "10:30:100", "10:30:60", False),
        ("sshd_maxstartups", "5:30:60", "10:30:60", True),
        ("sshd_maxstartups", "11:30:60", "10:30:60", False),
        ("sshd_maxstartups", "10:50:60", "10:30:60", True),
        ("sshd_maxstartups", "10:29:60", "10:30:60", False),
        ("sshd_maxstartups", "10:30:10", "10:30:60", True),
        ("sshd_algorithms", KEX, f"{KEX_NIST},{KEX}", True),
        ("sshd_algorithms", f"{KEX},{KEX_NIST}", f"{KEX_NIST},{KEX}", True),
        ("sshd_algorithms", f"{KEX},diffie-hellman-group1-sha1", f"{KEX_NIST},{KEX}", False),
        ("sshd_algorithms", f"{MAC_512},{MAC_256}", MAC_512, False),
        ("sudo_timeout", "15", "15", True),
        ("sudo_timeout", "0", "15", True),
        ("sudo_timeout", "30", "15", False),
        ("sudo_timeout", "5", "0", False),
        ("sudo_path", "/var/log/sudo.log", "/var/log/sudo.log", True),
        ("sudo_path", "/var/log/sudo/other.log", "/var/log/sudo.log", False),
        ("sysctl_exact", "0", "0", True),
        ("sysctl_exact", "1", "0", False),
        ("sysctl_exact", "2", "1", False),
        ("sysctl_exact", "0", "1", False),
        ("auditd_exact", "root", "root", True),
        ("auditd_exact", "Root", "root", False),
        ("auditd_exact", "admin", "root", False),
        ("auditd_minimum", "8", "6", True),
        ("auditd_minimum", "5", "6", False),
        ("auditd_percent", "25", "25", True),
        ("auditd_percent", "30", "25", True),
        ("auditd_percent", "20", "25", False),
        ("auditd_number", "50", "50", True),
        ("auditd_number", "100", "50", False),
        ("auditd_number", "20", "50", False),
        ("auditd_choice_disk_error_action", "single", "syslog|single|halt", True),
        ("auditd_choice_disk_error_action", "HALT", "syslog|single|halt", True),
        ("auditd_choice_disk_error_action", "ignore", "syslog|single|halt", False),
        ("auditd_choice_disk_error_action", "suspend", "syslog|single|halt", False),
        ("auditd_choice_disk_full_action", "halt", "halt|single", True),
        ("auditd_choice_disk_full_action", "rotate", "halt|single", False),
        ("auditd_choice_admin_space_left_action", "single", "single|halt", True),
        ("auditd_choice_admin_space_left_action", "halt", "single", False),
        ("auditd_choice_space_left_action", "email", "email", True),
        ("auditd_choice_space_left_action", "single", "email|single|halt", True),
        ("auditd_choice_space_left_action", "syslog", "email", False),
        ("auditd_choice_max_log_file_action", "keep_logs", "keep_logs", True),
        ("auditd_choice_max_log_file_action", "rotate", "keep_logs", False),
        ("auditd_choice_flush", "data", "data", True),
        ("auditd_choice_flush", "sync", "data", False),
        ("auditd_choice_flush", "incremental", "incremental_async", False),
        ("auditd_choice_name_format", "fqd", "hostname|fqd|numeric", True),
        ("auditd_choice_name_format", "none", "hostname|fqd|numeric", False),
    ],
)
def test_judge_compares_the_value_in_force_of_the_text_families(
    name: str, candidate: str, profile: str, *, expected: bool
) -> None:
    assert values.judge(name, profile, candidate) is expected


@pytest.mark.parametrize(
    ("name", "raw", "canonical"),
    [
        ("sshd_interval", 300, "300"),
        ("sshd_interval", "0", "0"),
        ("sshd_interval", values.SSHD_INT_MAX, "2147483647"),
        ("sshd_count_max", 0, "0"),
        ("sshd_grace_time", "60", "60"),
        ("sshd_at_most", 4, "4"),
        ("sshd_maxstartups", "10:30:60", "10:30:60"),
        ("sshd_maxstartups", "1:100:1", "1:100:1"),
        ("sshd_algorithms", f"{KEX},{KEX_NIST}", f"{KEX},{KEX_NIST}"),
        (
            "sshd_algorithms",
            "sntrup761x25519-sha512@openssh.com",
            "sntrup761x25519-sha512@openssh.com",
        ),
        ("sudo_timeout", 0, "0"),
        ("sudo_timeout", "9999", "9999"),
        ("sudo_path", "/var/log/sudo.log", "/var/log/sudo.log"),
        ("sysctl_exact", 1, "1"),
        ("sysctl_exact", "-1", "-1"),
        ("auditd_exact", "root", "root"),
        ("auditd_minimum", 999999999, "999999999"),
        ("auditd_percent", 99, "99"),
        ("auditd_number", 50, "50"),
        ("auditd_choice_disk_full_action", "HALT", "halt"),
        ("auditd_choice_name_format", "Hostname", "hostname"),
    ],
)
def test_validate_returns_the_canonical_text_of_the_text_families(
    name: str, raw: object, canonical: str
) -> None:
    assert values.comparator(name).validate(raw) == canonical


@pytest.mark.parametrize(
    ("name", "raw", "message"),
    [
        ("sshd_interval", "5m", "a time with a unit such as 5m is refused"),
        ("sshd_interval", "300s", "a time with a unit such as 5m is refused"),
        ("sshd_grace_time", "060", "a time with a unit such as 5m is refused"),
        ("sshd_grace_time", values.SSHD_INT_MAX + 1, "seconds from 0 to 2147483647"),
        ("sshd_interval", True, "seconds from 0 to 2147483647"),
        ("sshd_count_max", -1, "needs a whole number from 0 to 2147483647"),
        ("sshd_at_most", "+4", "without a plus sign or a leading zero"),
        ("sshd_at_most", values.SSHD_INT_MAX + 1, "from 0 to 2147483647"),
        ("sshd_maxstartups", "10", "a single number is refused"),
        ("sshd_maxstartups", 10, "a single number is refused"),
        ("sshd_maxstartups", "10:30", "start:rate:full"),
        ("sshd_maxstartups", "010:30:60", "start:rate:full"),
        ("sshd_maxstartups", "+10:30:60", "start:rate:full"),
        ("sshd_maxstartups", "10:30:60\n", "start:rate:full"),
        ("sshd_maxstartups", "11:30:10", "1 <= start <= full"),
        ("sshd_maxstartups", "0:30:10", "1 <= start <= full"),
        ("sshd_maxstartups", "10:0:60", "a rate from 1 to 100"),
        ("sshd_maxstartups", "10:101:60", "a rate from 1 to 100"),
        ("sshd_maxstartups", "10:30:2147483648", "full <= 2147483647"),
        ("sshd_algorithms", f"+{KEX}", "without a leading +, - or ^"),
        ("sshd_algorithms", f"-{KEX}", "without a leading +, - or ^"),
        ("sshd_algorithms", f"^{KEX}", "without a leading +, - or ^"),
        ("sshd_algorithms", f"{KEX},+{KEX_NIST}", "without a leading +, - or ^"),
        ("sshd_algorithms", "curve*", "a wildcard"),
        ("sshd_algorithms", f"{KEX}, {KEX_NIST}", "or a space"),
        ("sshd_algorithms", f"{KEX},{KEX}", "different algorithm names"),
        ("sshd_algorithms", f"{KEX},,{KEX_NIST}", "different algorithm names"),
        ("sshd_algorithms", "", "different algorithm names"),
        ("sshd_algorithms", ",".join(f"a{index}" for index in range(65)), "at most 64"),
        ("sshd_algorithms", "a" * 129, "algorithm names"),
        (
            "sshd_algorithms",
            ",".join(f"{index:a>100}" for index in range(11)),
            "at most 1024 characters",
        ),
        ("sshd_algorithms", [KEX], "algorithm names"),
        ("sudo_timeout", 10000, "from 0 to 9999"),
        ("sudo_timeout", -1, "from 0 to 9999"),
        ("sudo_timeout", "015", "without a plus sign or a leading zero"),
        ("sudo_timeout", "2.5", "without a plus sign or a leading zero"),
        ("sudo_path", "var/log/sudo.log", "that matches"),
        ("sudo_path", "/var/log/sudo log", "that matches"),
        ("sudo_path", "/var/log/sudo.log,x", "that matches"),
        ("sudo_path", "/." + "a" * 255, "that matches"),
        ("sysctl_exact", "010", "that matches"),
        ("sysctl_exact", "0x1", "that matches"),
        ("sysctl_exact", "+1", "that matches"),
        ("sysctl_exact", "-0", "that matches"),
        ("sysctl_exact", " 1", "that matches"),
        ("sysctl_exact", True, "that matches"),
        ("sysctl_exact", 10**19, "that matches"),
        ("auditd_exact", "r", "that matches"),
        ("auditd_exact", "root@localhost", "that matches"),
        ("auditd_exact", "a" * 65, "that matches"),
        ("auditd_minimum", 1000000000, "from 0 to 999999999"),
        ("auditd_percent", 100, "from 0 to 99"),
        ("auditd_percent", "25%", "without a plus sign or a leading zero"),
        ("auditd_number", "050", "that matches"),
        ("auditd_number", 1000000000, "that matches"),
        ("auditd_choice_disk_error_action", "keep_logs", "one of halt, ignore, single"),
        ("auditd_choice_disk_error_action", "rotate", "one of halt, ignore, single"),
        ("auditd_choice_disk_error_action", "syslog|halt", "not a set of them"),
        ("auditd_choice_space_left_action", "exec", "accepts for space_left_action"),
        ("auditd_choice_flush", " data", "accepts for flush"),
        ("auditd_choice_flush", 1, "accepts for flush"),
        ("auditd_choice_name_format", "", "accepts for name_format"),
    ],
)
def test_validate_refuses_what_a_text_family_or_its_reader_would_not_take_as_written(
    name: str, raw: object, message: str
) -> None:
    with pytest.raises(values.ValueOverrideError, match=re.escape(message)):
        values.comparator(name).validate(raw)


SSHD_COMPARATORS = {
    "ClientAliveInterval": "sshd_interval",
    "ClientAliveCountMax": "sshd_count_max",
    "LoginGraceTime": "sshd_grace_time",
    "MaxAuthTries": "sshd_at_most",
    "MaxSessions": "sshd_at_most",
    "MaxStartups": "sshd_maxstartups",
    "KexAlgorithms": "sshd_algorithms",
    "MACs": "sshd_algorithms",
}


@pytest.mark.parametrize(("keyword", "written", "printed"), SSHD_T)
def test_an_sshd_value_is_taken_only_when_sshd_prints_it_as_written(
    keyword: str, written: str, printed: str | None
) -> None:
    assert SSHD_COMPARATORS[keyword] == INTENDED["ssh", keyword]
    found = values.comparator(SSHD_COMPARATORS[keyword])
    try:
        canonical = found.validate(written)
    except values.ValueOverrideError:
        assert printed != written
        return
    assert canonical == written
    assert printed == written


def test_the_sshd_comparators_judge_what_sshd_prints() -> None:
    for keyword, _written, printed in SSHD_T:
        if printed is None:
            continue
        found = values.comparator(SSHD_COMPARATORS[keyword])
        assert found.meets(printed, printed)


def test_the_text_comparators_take_only_values_that_the_family_validators_take() -> None:
    ssh_tasks = SSH_TASKS.read_text(encoding="utf-8")
    auditd_tasks = AUDITD_TASKS.read_text(encoding="utf-8")
    assert f"is match('{SSH_VALUE}')" in ssh_tasks
    assert f"is match('{AUDITD_VALUE}')" in auditd_tasks
    assert f"is match('{AUDITD_DIGITS}')" in auditd_tasks
    for name in set(SSHD_COMPARATORS.values()):
        for text in SAMPLES[name]:
            assert re.search(SSH_VALUE, values.comparator(name).validate(text)), (name, text)
    for name, found in values.COMPARATORS.items():
        if not name.startswith("auditd_"):
            continue
        for text in SAMPLES[name]:
            assert re.search(AUDITD_VALUE, found.read_profile(text)), (name, text)
            if isinstance(found, values.IntegerOrder) or name == "auditd_number":
                assert re.search(AUDITD_DIGITS, found.validate(text)), (name, text)
    assert values.SSHD_INT_MAX == 2**31 - 1
    assert values.AUDITD_MAX_PERCENT == auditconf.MAX_PERCENT - 1
    assert re.search(AUDITD_DIGITS, str(values.AUDITD_NUMBER_MAXIMUM))
    assert not re.search(AUDITD_DIGITS, str(values.AUDITD_NUMBER_MAXIMUM + 1))
    assert values.AUDITD_NUMBER_MAXIMUM < auditconf.LARGEST


def auditd_settings(name: str) -> list[str]:
    return sorted(
        key[1].split(":")[0]
        for key, intended in INTENDED.items()
        if key[0] == "auditd_conf" and intended == name
    )


def auditd_reading(setting: str, written: str) -> auditconf.Reading:
    baseline = {"space_left": "75", "admin_space_left": "50", "freq": "50", "name": "host"}
    if setting == "space_left":
        baseline["admin_space_left"] = "0"
    if setting == "admin_space_left":
        baseline["space_left"] = "999999999"
    baseline[setting] = written
    text = "".join(f"{key} = {value}\n" for key, value in baseline.items())
    return auditconf.read(text.encode("ascii"), AUDITD_LOG_MEGABYTES)


@pytest.mark.parametrize(
    "name", sorted(name for name in values.COMPARATORS if name.startswith("auditd_"))
)
def test_auditd_reads_every_value_that_an_auditd_comparator_takes_as_it_is_written(
    name: str,
) -> None:
    found = values.comparator(name)
    settings = auditd_settings(name)
    assert settings
    for setting in settings:
        suffix = "%" if name == "auditd_percent" else ""
        for text in SAMPLES[name]:
            if "|" in text or (setting == "space_left" and text == "0"):
                continue
            written = found.validate(text) + suffix
            reading = auditd_reading(setting, written)
            assert reading.accepted is True, (setting, written, reading.reason)
            assert reading.settings[setting][-1].value == written


@pytest.mark.parametrize("setting", values.AUDITD_CHOICE_SETTINGS)
def test_an_auditd_choice_is_taken_exactly_when_auditd_reads_it_for_its_setting(
    setting: str,
) -> None:
    found = values.comparator(f"auditd_choice_{setting}")
    words = {word for form in auditconf.KEYWORDS.values() for word in form.choices} | {
        "exec",
        "user",
        "email|halt",
        "HALT",
        "Data",
        "data\t",
    }
    for word in sorted(words):
        try:
            canonical = found.validate(word)
        except values.ValueOverrideError:
            taken = False
        else:
            taken = True
            assert canonical == word.lower()
        reading = auditd_reading(setting, word)
        assert taken is (reading.accepted is True), (setting, word, reading.reason)


def test_a_space_left_of_zero_is_judged_but_auditd_refuses_it_below_admin_space_left() -> None:
    assert values.judge("auditd_minimum", "100", "0") is False
    assert auditd_reading("space_left", "0").accepted is False


def test_the_kernel_parameter_comparator_takes_only_what_every_reader_reads_alike() -> None:
    found = values.comparator("sysctl_exact")
    assert found == values.Exact(sysctl_config.KERNEL_INTEGER)
    variables = cast(
        "dict[str, object]", yaml.safe_load(ROLE_VARIABLES.read_text(encoding="utf-8"))
    )
    family_value = str(variables[f"{PREFIX}sysctl_value_pattern"])
    for text in [*SAMPLES["sysctl_exact"], "9223372036854775807", "-999999999999999999"]:
        assert found.validate(text) == text
        assert sysctl_config.kernel_integer(text) == int(text)
        assert re.fullmatch(sysctl.VALUE_PATTERN, text)
        assert re.search(family_value, text)
    for text in ["010", "0x1", "+1", "-0", "1 ", "1.0", ""]:
        assert sysctl_config.kernel_integer(text) is None
        with pytest.raises(values.ValueOverrideError):
            found.validate(text)
    for rule in value_rules():
        if rule["family"] in SYSCTL_FAMILIES:
            assert cast("dict[str, object]", rule["parameters"])["datatype"] == "int"


def test_the_sudo_comparators_take_what_the_family_writes() -> None:
    patterns = {
        str(cast("list[str]", parameters["options"])[0]): str(parameters["value_pattern"])
        for parameters in (
            cast("dict[str, object]", rule["parameters"])
            for rule in value_rules()
            if rule["family"] == "sudo"
        )
    }
    assert patterns["logfile"] == f"^{values.SUDO_LOGFILE}$"
    assert values.comparator("sudo_path") == values.Exact(values.SUDO_LOGFILE)
    assert patterns["timestamp_timeout"] == "^[0-9]{1,4}$"
    assert re.search(patterns["timestamp_timeout"], str(values.SUDO_TIMEOUT_MAXIMUM))
    assert not re.search(patterns["timestamp_timeout"], str(values.SUDO_TIMEOUT_MAXIMUM + 1))
    for text in SAMPLES["sudo_timeout"]:
        assert re.search(patterns["timestamp_timeout"], text)


def test_maxstartups_is_ordered_per_component_and_not_totally() -> None:
    found = values.comparator("sshd_maxstartups")
    assert not found.meets("5:30:100", "10:30:50")
    assert not found.meets("10:30:50", "5:30:100")
    assert found.stricter("5:30:100", "10:30:50") == "5:30:50"
    assert found.stricter("10:20:60", "10:30:60") == "10:30:60"
    assert values.stricter_of("sshd_maxstartups", "10:30:100", ["10:30:60", "20:50:100"]) == (
        "10:50:60"
    )
    with pytest.raises(values.ValueOverrideError, match="cannot judge '10'"):
        found.meets("10", "10:30:60")
    with pytest.raises(values.ValueOverrideError, match="not a valid start:rate:full"):
        found.stricter("10:30:60", "11:30:10")


def test_an_algorithm_list_meets_a_profile_in_any_order_and_keeps_the_common_algorithms() -> None:
    found = values.comparator("sshd_algorithms")
    assert found.meets(f"{KEX_NIST},{KEX}", f"{KEX},{KEX_NIST}")
    assert found.stricter(f"{KEX_NIST},{KEX},{MAC_512}", f"{KEX},{KEX_NIST}") == (
        f"{KEX_NIST},{KEX}"
    )
    with pytest.raises(values.ValueOverrideError, match="no algorithm in common"):
        found.stricter(KEX, KEX_NIST)
    with pytest.raises(values.ValueOverrideError, match=re.escape(f"cannot judge '+{KEX}'")):
        found.meets(f"+{KEX}", KEX)
    with pytest.raises(values.ValueOverrideError, match="cannot judge"):
        found.meets(KEX, f"{KEX},{KEX}")


def test_a_choice_set_reads_a_profile_set_and_judges_a_set_by_its_keywords() -> None:
    found = values.comparator("auditd_choice_space_left_action")
    assert found.read_profile("email") == "email"
    assert found.read_profile("Email|SINGLE|halt") == "email|single|halt"
    assert found.meets("single|halt", "email|single|halt")
    assert not found.meets("syslog|halt", "email|single|halt")
    assert found.stricter("halt|single|email", "single|halt") == "halt|single"
    with pytest.raises(values.ValueOverrideError, match="no choice in common"):
        found.stricter("email", "halt")
    for text in ["email|email", "email||halt", "email|program", "|".join(["halt"] * 9)]:
        with pytest.raises(values.ValueOverrideError, match="cannot judge"):
            found.read_profile(text)
    with pytest.raises(values.ValueOverrideError, match="cannot judge 1"):
        found.meets(cast("str", 1), "email")
    assert values.auditd_choices("flush") == values.ChoiceSet(
        "flush", frozenset({"none", "incremental", "incremental_async", "data", "sync"})
    )


def test_an_sshd_count_keeps_the_message_of_its_integer_order() -> None:
    with pytest.raises(values.ValueOverrideError, match="as a YAML integer or its decimal text"):
        values.comparator("sshd_count_max").validate("3x")
    with pytest.raises(values.ValueOverrideError, match="cannot judge '-1'"):
        values.judge("sshd_count_max", "3", "-1")


def test_the_protocol_reads_a_profile_value_abstractly() -> None:
    read_profile: Any = values.Comparator.read_profile
    with pytest.raises(NotImplementedError):
        read_profile(values.comparator("faillock_deny"), "4")


@pytest.mark.parametrize("name", sorted(values.COMPARATORS))
def test_read_profile_takes_every_override_as_it_is(name: str) -> None:
    found = values.comparator(name)
    for text in SAMPLES[name]:
        try:
            canonical = found.validate(text)
        except values.ValueOverrideError:
            continue
        assert found.read_profile(canonical) == canonical


def test_only_a_profile_set_of_an_action_with_a_program_may_name_exec() -> None:
    found = values.comparator("auditd_choice_space_left_action")
    assert found.read_profile("email|exec|single|halt") == "email|exec|single|halt"
    assert found.meets("single", "email|exec|single|halt")
    assert found.stricter("email|exec|single|halt", "exec|halt") == "halt"
    with pytest.raises(values.ValueOverrideError, match="no choice in common"):
        found.stricter("exec", "email|exec")
    with pytest.raises(values.ValueOverrideError, match="cannot judge 'exec'"):
        found.meets("exec", "email|exec|single|halt")
    with pytest.raises(values.ValueOverrideError, match="not a set of them"):
        found.validate("exec")
    for setting in values.AUDITD_CHOICE_SETTINGS:
        choices = values.comparator(f"auditd_choice_{setting}")
        assert isinstance(choices, values.ChoiceSet)
        expected = {"exec"} if setting in auditconf.OPTION_KEYWORDS else set[str]()
        assert choices.profile_only == expected
        assert not choices.profile_only & choices.choices
    with pytest.raises(values.ValueOverrideError, match=re.escape("cannot judge 'data|exec'")):
        values.comparator("auditd_choice_flush").read_profile("data|exec")
