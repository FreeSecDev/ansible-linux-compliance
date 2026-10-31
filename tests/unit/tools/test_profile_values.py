from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
import yaml

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
)
from tests.unit.tools.test_generate_catalogue import RULE, read, source_document
from tools.roles import generate_catalogue as gen
from tools.roles import generate_toggles
from tools.roles import profile_values as pv

XCCDF = "http://checklists.nist.gov/xccdf/1.2"
VALUE = pv.VALUE_PREFIX
PROFILE = pv.PROFILE_PREFIX
MINLEN = VALUE + "var_password_pam_minlen"
BANNER = VALUE + "login_banner_text"
TIMEOUT = VALUE + "var_sudo_timestamp_timeout"
FIX_ELEMENT = "fix"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PINNED_TIMEOUT_RULE = RULE + "sudo_require_reauthentication"
PINNED_TIMEOUT_VALUE_ID = TIMEOUT
CIS_TIMEOUT = "15"
STIG_TIMEOUT = "0"
DEFAULT_TIMEOUT = "5"
PINNED_TIMEOUT_VALUES = {
    "ubuntu2404": {
        "cis_level1_server": CIS_TIMEOUT,
        "cis_level1_workstation": CIS_TIMEOUT,
        "cis_level2_server": CIS_TIMEOUT,
        "cis_level2_workstation": CIS_TIMEOUT,
    },
    "rhel9": {
        "ccn_advanced": DEFAULT_TIMEOUT,
        "ccn_basic": DEFAULT_TIMEOUT,
        "ccn_intermediate": DEFAULT_TIMEOUT,
        "pci-dss": DEFAULT_TIMEOUT,
        "cis": CIS_TIMEOUT,
        "cis_server_l1": CIS_TIMEOUT,
        "cis_workstation_l1": CIS_TIMEOUT,
        "cis_workstation_l2": CIS_TIMEOUT,
        "stig": STIG_TIMEOUT,
        "stig_gui": STIG_TIMEOUT,
    },
}


def document(extra: str = "") -> bytes:
    return (
        f'<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2">'
        f"<value>outside the benchmark</value>"
        f'<Benchmark xmlns="{XCCDF}" id="xccdf_org.ssgproject.content_benchmark_TEST">'
        f'<Profile id="{PROFILE}cis"><title>cis</title>'
        f'<refine-value idref="{MINLEN}" selector="14"/><refine-value idref="{BANNER}"/>'
        f"</Profile>"
        f'<Profile id="{PROFILE}stig"><title>stig</title>'
        f'<select idref="{RULE}x" selected="true"/></Profile>'
        f'<Profile id="{PROFILE}odd"><refine-value idref="{MINLEN}" selector="99"/></Profile>'
        f'<Value id="{MINLEN}" type="number"><title>minlen</title>'
        f'<value selector="14">14</value><value>15</value>'
        f'<value selector="14">ignored</value></Value>'
        f'<Group id="xccdf_org.ssgproject.content_group_g">'
        f'<Value id="{BANNER}" type="string">'
        f'<value selector="dod">^(You[\\s\\n]+are)$</value></Value>'
        f'<Rule id="{RULE}accounts_password_pam_minlen"><check system="oval">'
        f'<check-export export-name="v" value-id="{MINLEN}"/><check-content-ref name="d"/></check>'
        f'</Rule><Rule id="{RULE}banner_etc_issue"/>'
        f'<Rule id="{RULE}sudo_require_reauthentication"><{FIX_ELEMENT} system="sh">'
        f'<value selector="0">0</value>t=<sub idref="{TIMEOUT}"/></{FIX_ELEMENT}>'
        f'<check system="oval"><check-content-ref name="d"/></check><sub idref="{BANNER}"/>'
        f"</Rule></Group>{extra}</Benchmark>"
        f"</data-stream-collection>"
    ).encode()


def written(tmp_path: Path, data: bytes | None = None) -> tuple[str, str]:
    content = document() if data is None else data
    path = tmp_path / "ssg-test-ds.xml"
    path.write_bytes(content)
    return str(path), hashlib.sha256(content).hexdigest()


def values(tmp_path: Path) -> pv.StreamValues:
    return pv.read_values(*written(tmp_path))


def test_the_values_refinements_and_exports_of_the_benchmark_are_read(tmp_path: Path) -> None:
    found = values(tmp_path)
    assert found.content_sha256 == written(tmp_path)[1]
    assert found.values == {MINLEN: {"14": "14", "": "15"}, BANNER: {"dod": "^(You[\\s\\n]+are)$"}}
    assert found.refinements == {
        PROFILE + "cis": {MINLEN: "14", BANNER: ""},
        PROFILE + "stig": {},
        PROFILE + "odd": {MINLEN: "99"},
    }
    assert found.exports == {
        RULE + "accounts_password_pam_minlen": frozenset({MINLEN}),
        RULE + "banner_etc_issue": frozenset(),
        RULE + "sudo_require_reauthentication": frozenset(),
    }


def test_the_fix_elements_of_the_content_are_never_kept(tmp_path: Path) -> None:
    found = values(tmp_path)
    assert [field.name for field in dataclasses.fields(found)] == [
        "content_sha256",
        "values",
        "refinements",
        "exports",
    ]
    assert TIMEOUT not in found.values
    assert all(TIMEOUT not in exported for exported in found.exports.values())


def test_a_profile_takes_its_refined_option_or_the_default(tmp_path: Path) -> None:
    found = values(tmp_path)
    assert pv.profile_value(found, PROFILE + "cis", MINLEN) == "14"
    assert pv.profile_value(found, PROFILE + "stig", MINLEN) == "15"
    assert pv.profile_value(found, PROFILE + "unknown", MINLEN) == "15"


@pytest.mark.parametrize(
    ("profile", "value", "message"),
    [
        ("cis", VALUE + "missing", "the datastream does not define"),
        ("odd", MINLEN, "has no option '99', which"),
        ("cis", BANNER, "has no default, which"),
    ],
)
def test_a_value_that_the_profile_cannot_take_is_an_error(
    tmp_path: Path, profile: str, value: str, message: str
) -> None:
    with pytest.raises(pv.ProfileValueError, match=message):
        pv.profile_value(values(tmp_path), PROFILE + profile, value)


def test_a_digest_mismatch_is_refused_before_parsing(tmp_path: Path) -> None:
    path, _ = written(tmp_path)
    with pytest.raises(pv.ProfileValueError, match="digest mismatch"):
        pv.read_values(path, "0" * 64)


def test_content_that_changes_while_it_is_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = written(tmp_path)

    def verified(*_arguments: object) -> str:
        return "f" * 64

    monkeypatch.setattr(catalog, "verify_digest", verified)
    with pytest.raises(pv.ProfileValueError, match="changed while it was read"):
        pv.read_values(path, "f" * 64)


def test_unsafe_xml_is_refused(tmp_path: Path) -> None:
    data = b'<!DOCTYPE x [<!ENTITY a "b">]>' + document()
    with pytest.raises(pv.ProfileValueError, match="not allowed"):
        pv.read_values(*written(tmp_path, data))


def test_an_oversized_value_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pv, "MAX_VALUE_LENGTH", 4)
    with pytest.raises(pv.ProfileValueError, match="is longer than 4 characters"):
        values(tmp_path)


def test_chunks_render_within_the_width_and_join_back() -> None:
    text = "^(You[\\s\\n]+are" * 20
    pieces = pv.chunks(text, 30)
    assert "".join(pieces) == text
    assert all(len(json.dumps(piece)) <= 30 for piece in pieces)
    assert pv.chunks("") == [""]
    assert pv.chunks("14") == ["14"]


def streams(tmp_path: Path) -> list[pv.StreamProfiles]:
    found = values(tmp_path)
    return [
        pv.StreamProfiles(
            "test",
            found,
            {
                PROFILE + "cis": [
                    RULE + "accounts_password_pam_minlen",
                    RULE + "sudo_require_reauthentication",
                ],
                PROFILE + "stig": [RULE + "accounts_password_pam_minlen", RULE + "x"],
                PROFILE + "other": [RULE + "x"],
            },
        ),
        pv.StreamProfiles("unselected", found, {PROFILE + "cis": [RULE + "x"]}),
    ]


def test_resolve_groups_the_profiles_that_share_a_value(tmp_path: Path) -> None:
    resolved = pv.resolve(
        streams(tmp_path), RULE + "accounts_password_pam_minlen", "var_password_pam_minlen"
    )
    sha256 = written(tmp_path)[1]
    assert resolved == [
        {"datastream": "test", "content_sha256": sha256, "profiles": ["cis"], "value": ["14"]},
        {"datastream": "test", "content_sha256": sha256, "profiles": ["stig"], "value": ["15"]},
    ]


def test_resolve_refuses_a_rule_whose_checks_do_not_export_the_value(tmp_path: Path) -> None:
    with pytest.raises(pv.ProfileValueError, match="do not export"):
        pv.resolve(streams(tmp_path), RULE + "accounts_password_pam_minlen", "login_banner_text")


def test_resolve_takes_a_pinned_value_from_the_profile_refinements(tmp_path: Path) -> None:
    rule = RULE + "sudo_require_reauthentication"
    with pytest.raises(pv.ProfileValueError, match="do not export"):
        pv.resolve(streams(tmp_path), rule, "var_password_pam_minlen")
    resolved = pv.resolve(streams(tmp_path), rule, "var_password_pam_minlen", pinned=True)
    assert resolved == [
        {
            "datastream": "test",
            "content_sha256": written(tmp_path)[1],
            "profiles": ["cis"],
            "value": ["14"],
        }
    ]


def test_resolve_refuses_a_pinned_value_that_the_datastream_does_not_define(
    tmp_path: Path,
) -> None:
    rule = RULE + "sudo_require_reauthentication"
    with pytest.raises(pv.ProfileValueError, match=r"^test: the datastream does not define"):
        pv.resolve(streams(tmp_path), rule, "var_sudo_timestamp_timeout", pinned=True)


def test_resolve_names_the_datastream_of_a_profile_that_cannot_take_the_value(
    tmp_path: Path,
) -> None:
    found = values(tmp_path)
    odd = [
        pv.StreamProfiles("odd", found, {PROFILE + "odd": [RULE + "accounts_password_pam_minlen"]})
    ]
    with pytest.raises(pv.ProfileValueError, match=r"^odd: .*has no option '99'"):
        pv.resolve(odd, RULE + "accounts_password_pam_minlen", "var_password_pam_minlen")


def valued_document() -> dict[str, object]:
    data = source_document()
    native = cast("list[dict[str, object]]", data["native_rules"])
    native[0]["profile_value"] = "var_password_pam_minlen"
    return data


def with_values(tmp_path: Path) -> list[gen.StreamRules]:
    (tmp_path / "values").mkdir()
    found = values(tmp_path / "values")
    exports = dict(found.exports)
    exports[RULE + "file_permissions_crontab"] = frozenset({MINLEN})
    return [
        dataclasses.replace(stream, values=dataclasses.replace(found, exports=exports))
        for stream in read(tmp_path)
    ]


def test_a_native_rule_with_a_profile_value_gets_the_value_of_every_selecting_profile(
    tmp_path: Path,
) -> None:
    built = gen.build(gen.parse_source(valued_document()), with_values(tmp_path))
    crontab = next(
        rule for rule in built.rules if rule["rule_id"] == RULE + "file_permissions_crontab"
    )
    parameters = cast("dict[str, object]", crontab["parameters"])
    assert parameters["path"] == "/etc/crontab"
    assert parameters["value_id"] == "var_password_pam_minlen"
    entries = cast("list[dict[str, object]]", parameters["profile_values"])
    assert [(entry["datastream"], entry["profiles"], entry["value"]) for entry in entries] == [
        ("first", ["server"], ["15"]),
        ("second", ["stig"], ["15"]),
    ]
    assert "profile_values:" in gen.render_catalogue(built)


def test_a_pinned_profile_value_id_is_resolved_without_a_check_export(tmp_path: Path) -> None:
    data = source_document()
    native = cast("list[dict[str, object]]", data["native_rules"])
    native[0]["profile_value_id"] = MINLEN
    streams = [
        dataclasses.replace(
            stream,
            values=dataclasses.replace(cast("pv.StreamValues", stream.values), exports={}),
        )
        for stream in with_values(tmp_path)
    ]
    built = gen.build(gen.parse_source(data), streams)
    crontab = next(
        rule for rule in built.rules if rule["rule_id"] == RULE + "file_permissions_crontab"
    )
    parameters = cast("dict[str, object]", crontab["parameters"])
    assert parameters["value_id"] == "var_password_pam_minlen"
    entries = cast("list[dict[str, object]]", parameters["profile_values"])
    assert [(entry["datastream"], entry["profiles"], entry["value"]) for entry in entries] == [
        ("first", ["server"], ["15"]),
        ("second", ["stig"], ["15"]),
    ]
    assert "profile_value_id" not in crontab
    with pytest.raises(gen.GenerationError, match="do not export"):
        gen.build(gen.parse_source(valued_document()), streams)


def test_a_pinned_profile_value_id_that_the_content_does_not_define_is_an_error(
    tmp_path: Path,
) -> None:
    data = source_document()
    native = cast("list[dict[str, object]]", data["native_rules"])
    native[0]["profile_value_id"] = TIMEOUT
    with pytest.raises(gen.GenerationError, match="the datastream does not define"):
        gen.build(gen.parse_source(data), with_values(tmp_path))


def test_a_profile_value_needs_the_values_of_every_datastream(tmp_path: Path) -> None:
    streams = [dataclasses.replace(stream, values=None) for stream in with_values(tmp_path)]
    with pytest.raises(gen.GenerationError, match="the values of the datastream were not read"):
        gen.build(gen.parse_source(valued_document()), streams)


def test_a_profile_value_that_the_checks_do_not_export_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(gen.GenerationError, match="do not export"):
        gen.build(gen.parse_source(valued_document()), read(tmp_path))


def test_the_values_are_read_from_every_datastream(tmp_path: Path) -> None:
    assert all(stream.values is not None for stream in read(tmp_path))


def test_a_datastream_whose_values_cannot_be_read_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_arguments: object) -> pv.StreamValues:
        message = "unreadable values"
        raise pv.ProfileValueError(message)

    monkeypatch.setattr(pv, "read_values", refuse)
    with pytest.raises(gen.GenerationError, match="first: unreadable values"):
        read(tmp_path)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            {"profile_value": "Bad Name"},
            "profile_value must be the short identifier of an XCCDF value",
        ),
        ({"profile_value": 3}, "profile_value must be the short identifier of an XCCDF value"),
        ({"parameters": []}, "parameters must be a mapping without the generated keys"),
        (
            {"parameters": {"profile_values": []}},
            "parameters must be a mapping without the generated keys",
        ),
        ({"extra": 1}, "and an optional 'profile_value' or 'profile_value_id'"),
        ({"profile_value_source": "fix"}, "and an optional 'profile_value' or 'profile_value_id'"),
        (
            {"profile_value": "var_password_pam_minlen", "profile_value_source": "check"},
            "and an optional 'profile_value' or 'profile_value_id'",
        ),
        (
            {"profile_value": "var_password_pam_minlen", "profile_value_id": MINLEN},
            "may set 'profile_value' or 'profile_value_id', not both",
        ),
        (
            {"profile_value_id": "var_password_pam_minlen"},
            "profile_value_id must be the full identifier of an XCCDF value",
        ),
        (
            {"profile_value_id": MINLEN + "-x"},
            "profile_value_id must be the full identifier of an XCCDF value",
        ),
        ({"profile_value_id": 3}, "profile_value_id must be the full identifier"),
    ],
)
def test_an_invalid_profile_value_or_parameters_are_refused(
    change: dict[str, object], message: str
) -> None:
    data = source_document()
    native = cast("list[dict[str, object]]", data["native_rules"])
    native[0].update(change)
    with pytest.raises(gen.GenerationError, match=message):
        gen.parse_source(data)


def repository_yaml(relative: Path) -> dict[str, object]:
    return cast(
        "dict[str, object]",
        yaml.safe_load((REPOSITORY_ROOT / relative).read_text(encoding="utf-8")),
    )


def test_no_catalogue_entry_takes_a_value_from_the_content_fixes() -> None:
    native = cast("list[dict[str, object]]", repository_yaml(gen.SOURCE)["native_rules"])
    assert all("profile_value_source" not in entry for entry in native)
    pinned = {
        str(entry["rule_id"]): entry[gen.PROFILE_VALUE_ID_KEY]
        for entry in native
        if gen.PROFILE_VALUE_ID_KEY in entry
    }
    assert pinned == {PINNED_TIMEOUT_RULE: PINNED_TIMEOUT_VALUE_ID}


def test_the_generated_sudo_timeout_keeps_the_value_of_every_pinned_profile() -> None:
    rules = cast(
        "list[dict[str, object]]",
        repository_yaml(generate_toggles.CATALOGUE)[generate_toggles.RULES_KEY],
    )
    (rule,) = [rule for rule in rules if rule["rule_id"] == PINNED_TIMEOUT_RULE]
    parameters = cast("dict[str, object]", rule["parameters"])
    assert parameters["value_id"] == PINNED_TIMEOUT_VALUE_ID.removeprefix(pv.VALUE_PREFIX)
    found: dict[str, dict[str, str]] = {}
    for entry in cast("list[dict[str, object]]", parameters["profile_values"]):
        value = "".join(cast("list[str]", entry["value"]))
        for profile in cast("list[str]", entry["profiles"]):
            found.setdefault(str(entry["datastream"]), {})[profile] = value
    assert found == PINNED_TIMEOUT_VALUES
