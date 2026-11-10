"""The sysctl_carriage_returns filter names the files that hold a carriage return (FREES-107)."""

from __future__ import annotations

from ansible_collections.freesecdev.linux_compliance.plugins.filter import sysctl_carriage_returns

UFW = "/etc/ufw/sysctl.conf"


def test_the_filter_is_registered() -> None:
    filters = sysctl_carriage_returns.FilterModule().filters()
    assert filters == {"sysctl_carriage_returns": sysctl_carriage_returns.sysctl_carriage_returns}


def test_a_lone_carriage_return_and_a_crlf_name_the_file() -> None:
    texts: dict[str, object] = {UFW: "a=1\rb=0\n", "/etc/sysctl.d/x.conf": "a=1\r\n", "/y": "a=1\n"}
    paths: list[object] = [UFW, "/etc/sysctl.d/x.conf", "/y"]
    assert sysctl_carriage_returns.sysctl_carriage_returns(texts, paths) == [
        UFW,
        "/etc/sysctl.d/x.conf",
    ]
