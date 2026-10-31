"""The filter that reads auditd.conf as auditd does (FREES-110)."""

from __future__ import annotations

import pytest

from ansible_collections.freesecdev.linux_compliance.plugins.filter import auditd_conf_reading

TEXT = "space_left = 75\nadmin_space_left = 50\n# note\nspace_left = 80\n"


def test_the_filter_returns_the_settings_auditd_reads() -> None:
    found = auditd_conf_reading.auditd_conf_reading(TEXT, 1000)
    assert found["accepted"] is True
    assert found["reason"] == ""
    assert found["settings"] == {
        "space_left": [
            {"line": 1, "value": "75", "text": "space_left = 75"},
            {"line": 4, "value": "80", "text": "space_left = 80"},
        ],
        "admin_space_left": [{"line": 2, "value": "50", "text": "admin_space_left = 50"}],
    }
    assert found["skipped"] == []


def test_the_filter_reports_a_refusal() -> None:
    found = auditd_conf_reading.auditd_conf_reading("space_left = 80\r\n")
    assert found["accepted"] is False
    assert "value that auditd refuses" in str(found["reason"])


@pytest.mark.parametrize(("text", "size"), [(b"x", None), ("x", True), ("x", "10")])
def test_the_filter_refuses_input_of_another_type(text: object, size: object) -> None:
    with pytest.raises(TypeError):
        auditd_conf_reading.auditd_conf_reading(text, size)


def test_the_plugin_names_the_filter() -> None:
    filters = auditd_conf_reading.FilterModule().filters()
    assert filters == {"auditd_conf_reading": auditd_conf_reading.auditd_conf_reading}
