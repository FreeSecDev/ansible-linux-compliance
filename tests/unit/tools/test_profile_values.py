from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import TYPE_CHECKING, cast

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.module_utils.compliance import (
    catalog,
)
from tests.unit.tools.test_generate_catalogue import RULE, read, source_document
from tools.roles import generate_catalogue as gen
from tools.roles import profile_values as pv

if TYPE_CHECKING:
    from pathlib import Path

XCCDF = "http://checklists.nist.gov/xccdf/1.2"
VALUE = pv.VALUE_PREFIX
PROFILE = pv.PROFILE_PREFIX
MINLEN = VALUE + "var_password_pam_minlen"
BANNER = VALUE + "login_banner_text"


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
        f'<Rule id="{RULE}sudo_require_reauthentication"><fix system="sh">t=<sub idref="{MINLEN}"/>'
        f'</fix><check system="oval"><check-content-ref name="d"/></check><sub idref="{BANNER}"/>'
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
    assert found.fixes == {
        RULE + "accounts_password_pam_minlen": frozenset(),
        RULE + "banner_etc_issue": frozenset(),
        RULE + "sudo_require_reauthentication": frozenset({MINLEN}),
    }


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


def test_resolve_takes_a_value_that_the_fixes_substitute(tmp_path: Path) -> None:
    rule = RULE + "sudo_require_reauthentication"
    with pytest.raises(pv.ProfileValueError, match="do not export"):
        pv.resolve(streams(tmp_path), rule, "var_password_pam_minlen")
    resolved = pv.resolve(streams(tmp_path), rule, "var_password_pam_minlen", pv.FIX_SOURCE)
    assert resolved == [
        {
            "datastream": "test",
            "content_sha256": written(tmp_path)[1],
            "profiles": ["cis"],
            "value": ["14"],
        }
    ]


def test_resolve_refuses_a_value_that_the_fixes_do_not_substitute(tmp_path: Path) -> None:
    rule = RULE + "sudo_require_reauthentication"
    with pytest.raises(pv.ProfileValueError, match="do not substitute"):
        pv.resolve(streams(tmp_path), rule, "login_banner_text", pv.FIX_SOURCE)
    with pytest.raises(pv.ProfileValueError, match="do not substitute"):
        pv.resolve(
            streams(tmp_path),
            RULE + "accounts_password_pam_minlen",
            "var_password_pam_minlen",
            "fix",
        )


def test_resolve_refuses_an_unknown_value_source(tmp_path: Path) -> None:
    with pytest.raises(pv.ProfileValueError, match="the value source 'oval' is not one of"):
        pv.resolve(
            streams(tmp_path),
            RULE + "accounts_password_pam_minlen",
            "var_password_pam_minlen",
            "oval",
        )


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


def test_a_profile_value_from_the_fixes_is_resolved_from_the_fixes(tmp_path: Path) -> None:
    data = valued_document()
    native = cast("list[dict[str, object]]", data["native_rules"])
    native[0]["profile_value_source"] = "fix"
    streams = with_values(tmp_path)
    with pytest.raises(gen.GenerationError, match="do not substitute"):
        gen.build(gen.parse_source(data), streams)
    fixed = [
        dataclasses.replace(
            stream,
            values=dataclasses.replace(
                cast("pv.StreamValues", stream.values),
                exports={},
                fixes={RULE + "file_permissions_crontab": frozenset({MINLEN})},
            ),
        )
        for stream in streams
    ]
    built = gen.build(gen.parse_source(data), fixed)
    crontab = next(
        rule for rule in built.rules if rule["rule_id"] == RULE + "file_permissions_crontab"
    )
    parameters = cast("dict[str, object]", crontab["parameters"])
    assert parameters["value_id"] == "var_password_pam_minlen"
    assert "profile_value_source" not in crontab


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
        ({"extra": 1}, "and an optional 'profile_value'"),
        (
            {"profile_value_source": "fix"},
            "profile_value_source must be one of \\['check', 'fix'\\] and needs 'profile_value'",
        ),
        (
            {"profile_value": "var_password_pam_minlen", "profile_value_source": "oval"},
            "profile_value_source must be one of",
        ),
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
