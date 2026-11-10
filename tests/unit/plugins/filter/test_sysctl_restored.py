"""The sysctl_restored filter applies the cleanup's vendor line restores (FREES-107)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ansible_collections.freesecdev.linux_compliance.plugins.filter import sysctl_restored

if TYPE_CHECKING:
    from collections.abc import Mapping

VENDOR = "/etc/sysctl.d/10-kernel-hardening.conf"


def test_the_filter_is_registered() -> None:
    filters = sysctl_restored.FilterModule().filters()
    assert filters == {"sysctl_restored": sysctl_restored.sysctl_restored}


def test_the_written_line_becomes_the_original_line() -> None:
    texts: dict[str, object] = {VENDOR: "a = 1\nb = 1\n"}
    restores: list[Mapping[str, object]] = [
        {"path": VENDOR, "written": "b = 1", "original": "b = 0"}
    ]
    assert sysctl_restored.sysctl_restored(texts, restores) == {VENDOR: "a = 1\nb = 0\n"}
