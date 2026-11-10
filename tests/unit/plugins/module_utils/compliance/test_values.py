"""Unit tests of the comparators of native values (FREES-203, ADR 0032 §3).

The checks against the Jinja of the remediate role need Jinja2, which the target context of
``ansible-test units`` does not have; they are in
``tests/unit/roles/test_login_defs_comparators.py``.
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
    pwquality,
    values,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
ROLE_VARIABLES = REPOSITORY_ROOT / "roles/remediate/vars/main.yml"
CATALOGUE = REPOSITORY_ROOT / "roles/remediate/vars/rules.yml"
PREFIX = "__linux_compliance_remediate_"
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
}


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
        chosen = found.stricter(first, second)
        assert found.meets(chosen, first)
        assert found.meets(chosen, second)
        assert values.stricter_of(name, first, [second]) == chosen


@pytest.mark.parametrize(
    "name",
    sorted(
        name for name, item in values.COMPARATORS.items() if isinstance(item, values.IntegerOrder)
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
    with pytest.raises(values.ValueOverrideError, match="known: faillock_deny"):
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


def test_the_intended_comparator_takes_every_profile_value_of_its_rules_as_it_is() -> None:
    seen: set[tuple[str, str]] = set()
    for rule in catalogue_rules():
        parameters = cast("dict[str, object]", rule["parameters"])
        key = (str(rule["family"]), str(parameters.get("setting")))
        if key not in INTENDED or "profile_values" not in parameters:
            continue
        seen.add(key)
        found = values.comparator(INTENDED[key])
        comparison = parameters.get("comparison")
        if comparison is not None:
            expected = DIRECTION_OF[str(comparison)]
            assert getattr(found, "direction", "umask") == expected, key
        for entry in cast("list[dict[str, object]]", parameters["profile_values"]):
            text = "".join(cast("list[str]", entry["value"]))
            assert found.validate(text) == text, (key, text)
    assert seen == set(INTENDED)


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
