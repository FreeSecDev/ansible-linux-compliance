"""The sysctl_effective filter hands the entries to the reader model (FREES-107)."""

from __future__ import annotations

from ansible_collections.freesecdev.linux_compliance.plugins.filter import sysctl_effective

RP_FILTER = "net.ipv4.conf.all.rp_filter"
ENTRIES: list[dict[str, object]] = [
    {"path": "/etc/sysctl.d/10-a.conf", "kind": "file", "text": f"{RP_FILTER} = 2\n"},
    {"path": "/etc/sysctl.conf", "kind": "file", "text": f"{RP_FILTER} = 0\n"},
    {"path": "/etc/ufw/sysctl.conf", "kind": "file", "text": "net/ipv4/conf/all/rp_filter=1\n"},
]


def test_the_filter_is_registered() -> None:
    filters = sysctl_effective.FilterModule().filters()
    assert filters == {"sysctl_effective": sysctl_effective.sysctl_effective}


def test_each_reader_gets_its_value_and_source() -> None:
    assert sysctl_effective.sysctl_effective(ENTRIES, RP_FILTER) == {
        "systemd": {"value": "2", "source": "/etc/sysctl.d/10-a.conf"},
        "procps": {"value": "0", "source": "/etc/sysctl.conf"},
        "unsupported": [],
    }


def test_ufw_s_file_comes_last_when_ufw_is_enabled() -> None:
    entries: list[dict[str, object]] = [
        *ENTRIES,
        {"path": "/etc/ufw/ufw.conf", "kind": "file", "text": "ENABLED=yes\n"},
        {"path": "/etc/default/ufw", "kind": "file", "text": "IPT_SYSCTL=/etc/ufw/sysctl.conf\n"},
    ]
    found = sysctl_effective.sysctl_effective(entries, RP_FILTER)
    assert found["systemd"] == found["procps"] == {"value": "1", "source": "/etc/ufw/sysctl.conf"}


def test_a_name_that_procps_expands_is_reported() -> None:
    entries: list[dict[str, object]] = [
        *ENTRIES,
        {"path": "/etc/sysctl.d/z*.conf", "kind": "file", "text": ""},
    ]
    found = sysctl_effective.sysctl_effective(entries, RP_FILTER)
    assert found["unsupported"] == [
        (
            "/etc/sysctl.d/z*.conf: sysctl --system expands the name of this file as a pattern,"
            " which may read other files a second time"
        )
    ]
