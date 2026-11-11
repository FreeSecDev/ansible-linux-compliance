"""The login_defs comparators against the Jinja of the remediate role (FREES-203, ADR 0032 §3).

These checks render the role's own decision templates
(``roles/remediate/tasks/login_defs_decide.yml``) with Jinja2, which only the controller has.
``ansible-test units`` runs ``tests/unit/plugins/module_utils`` in the target context without
Jinja2, so the checks live here, next to the other role tests, and the comparators themselves
are tested in ``tests/unit/plugins/module_utils/compliance/test_values.py``.
"""

from __future__ import annotations

import ast
import itertools
import re
from pathlib import Path
from typing import cast

import jinja2
import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import values

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DECIDE = REPOSITORY_ROOT / "roles/remediate/tasks/login_defs_decide.yml"
ROLE_VARIABLES = REPOSITORY_ROOT / "roles/remediate/vars/main.yml"
DECIDE_TASK = "Login defaults | Decide whether the setting satisfies"
FIND_TASK = "Login defaults | Find the lines that set the setting"
PREFIX = "__linux_compliance_remediate_"


def test_the_strict_umask_reading_of_the_role_is_the_comparator_pattern() -> None:
    assert strict_umask_pattern() == "^[ \t]*UMASK[ \t]+(" + values.UMASK + ")[ \t\r\v\f]*$"


def strict_umask_pattern() -> str:
    tasks = cast("list[dict[str, object]]", yaml.safe_load(DECIDE.read_text(encoding="utf-8")))
    task = next(item for item in tasks if str(item["name"]).startswith(FIND_TASK))
    template = cast("dict[str, str]", task["ansible.builtin.set_fact"])[f"{PREFIX}ld_strict"]
    context: dict[str, object] = {
        f"{PREFIX}rule": {"rule_id": "umask", "parameters": {"comparison": "umask"}},
        f"{PREFIX}ld_setting": "UMASK",
        f"{PREFIX}ld_values": {},
    }
    return render(template, context)


def strtol_base_zero(text: str) -> int:
    if text.startswith("0") and len(text) > 1:
        return int(text[1:], values.UMASK_BASE)
    return int(text)


def test_a_umask_is_taken_exactly_when_every_reader_reads_it_as_written() -> None:
    variables = cast(
        "dict[str, object]", yaml.safe_load(ROLE_VARIABLES.read_text(encoding="utf-8"))
    )
    assertion = str(variables[f"{PREFIX}login_defs_umask_pattern"])
    read = str(variables[f"{PREFIX}login_defs_umask_read_pattern"])
    strict = strict_umask_pattern()
    found = values.comparator("login_defs_umask")
    octal = [f"{number:03o}" for number in range(0o1000)]
    others = [
        "".join(digits)
        for size in range(1, 5)
        for digits in itertools.product("01789", repeat=size)
    ]
    for text in octal + others:
        taken = re.fullmatch(values.UMASK, text) is not None
        assert taken is (re.match(strict, f"UMASK {text}") is not None), text
        if not taken:
            with pytest.raises(values.ValueOverrideError):
                found.validate(text)
            continue
        assert found.validate(text) == text
        assert re.match(assertion, text) is not None, text
        assert re.match(read, text) is not None, text
    for text in octal:
        read_alike = strtol_base_zero(text) == int(text, values.UMASK_BASE)
        assert (re.fullmatch(values.UMASK, text) is not None) is read_alike, text


def login_defs_templates() -> dict[str, str]:
    tasks = cast("list[dict[str, object]]", yaml.safe_load(DECIDE.read_text(encoding="utf-8")))
    task = next(item for item in tasks if str(item["name"]).startswith(DECIDE_TASK))
    found = dict(cast("dict[str, str]", task["vars"]))
    found.update(cast("dict[str, str]", task["ansible.builtin.set_fact"]))
    return found


def matches(value: object, pattern: object) -> bool:
    return re.match(str(pattern), str(value)) is not None


def render(template: str, context: dict[str, object]) -> str:
    environment = jinja2.Environment(autoescape=jinja2.select_autoescape(default_for_string=False))
    environment.tests["match"] = matches
    return environment.from_string(template).render(context)


def strict_reading(comparison: str, current: str) -> str | None:
    if comparison != "umask":
        return current
    found = re.match(strict_umask_pattern(), f"UMASK {current}")
    return None if found is None else found.group(1)


def jinja_decision(
    comparison: str, required: str, current: str, readings: list[int]
) -> tuple[bool, str]:
    templates = login_defs_templates()
    variables = cast(
        "dict[str, object]", yaml.safe_load(ROLE_VARIABLES.read_text(encoding="utf-8"))
    )
    context: dict[str, object] = {
        f"{PREFIX}rule": {"parameters": {"setting": "SETTING"}},
        f"{PREFIX}ld_econf_reader": {},
        f"{PREFIX}ld_econf_separated": True,
        f"{PREFIX}ld_comparison": comparison,
        f"{PREFIX}ld_required": required,
        f"{PREFIX}ld_token": current,
        f"{PREFIX}ld_set": strict_reading(comparison, current),
        f"{PREFIX}ld_readings": readings,
        f"{PREFIX}ld_defaults": [],
        f"{PREFIX}login_defs_umask_read_pattern": variables[
            f"{PREFIX}login_defs_umask_read_pattern"
        ],
    }
    context[f"{PREFIX}ld_bits"] = ast.literal_eval(render(templates[f"{PREFIX}ld_bits"], context))
    satisfied = render(templates[f"{PREFIX}ld_satisfied"], context)
    line = render(templates[f"{PREFIX}ld_line"], context)
    assert line.startswith("SETTING ")
    return satisfied == "True", line.removeprefix("SETTING ")


@pytest.mark.parametrize(
    ("comparison", "required", "current", "readings"),
    [
        ("at_least", "12", "14", [14]),
        ("at_least", "12", "12", [12]),
        ("at_least", "12", "9", [9]),
        ("at_least", "12", "0", [0, 8]),
        ("at_most", "90", "60", [60]),
        ("at_most", "90", "365", [365]),
        ("at_most", "90", "90", [90, 72]),
        ("at_most", "90", "0", [0]),
        ("umask", "027", "077", []),
        ("umask", "027", "027", []),
        ("umask", "027", "022", []),
        ("umask", "077", "070", []),
        ("umask", "027", "007", []),
        ("umask", "027", "000", []),
    ],
)
def test_the_login_defs_comparators_decide_as_the_jinja_of_the_family(
    comparison: str, required: str, current: str, readings: list[int]
) -> None:
    satisfied, written = jinja_decision(comparison, required, current, readings)
    name = f"login_defs_{comparison}"
    assert values.judge(name, required, current) is satisfied
    texts = [current] if comparison == "umask" else [str(reading) for reading in readings]
    assert values.stricter_of(name, required, texts) == written


@pytest.mark.parametrize("current", ["177", "700", "777", "0027"])
def test_the_umask_family_does_not_take_what_the_comparator_cannot_judge(current: str) -> None:
    satisfied, written = jinja_decision("umask", "027", current, [])
    assert not satisfied
    assert written == "027"
    with pytest.raises(values.ValueOverrideError):
        values.judge("login_defs_umask", "027", current)
    with pytest.raises(values.ValueOverrideError):
        values.stricter_of("login_defs_umask", "027", [current])
